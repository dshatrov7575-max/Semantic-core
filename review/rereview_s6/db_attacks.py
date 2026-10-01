#!/usr/bin/env python3
"""S6 review: attacks on the registry of originals and on projection ac.custody (database side).
Usage: PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=review06x python3 db_attacks.py
The database must be freshly loaded with slice/load_s1.py. Nothing outside PGDATABASE is touched."""
import hashlib, json, os, subprocess, sys, time
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core")
import s3_tests as S3, s5_tests as S5
from ingest_s4 import ingest_sql, utc

assert os.environ.get("PGDATABASE", "").startswith("review06"), "run only in a review06x database"
OBJ = "sha256:7253d9f1e4c510878ccd703eee24511b42d36bbe8322a50e4094871b2254ad8d"   # the world's original
WAIT = 10

def psql(sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)
def bg(sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    p = subprocess.Popen(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.stdin.write(pre + sql); p.stdin.close(); return p
def one(sql, user=None):
    r = psql(sql, user)
    if r.returncode: raise RuntimeError(r.stderr.strip()[:400])
    return r.stdout.strip()
def custody(cid, as_of=None, user="ac_rd_wm"):
    a = f", '{as_of}'::timestamptz" if as_of else ""
    return json.loads(one(f"SELECT ac.custody('{cid}'{a});", user).splitlines()[-1])
def orig(c):
    return [(o.get("origin_uri"), o["original"]["status"], o["original"]["checks"]) for s in c["sources"] for o in s["observations"] if "original" in o]
def reg(addr, n, tenant="tnt_demo"):
    return (f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('{tenant}','{addr}',{n});\n"
            f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('{tenant}','{addr}','OK');\n")
def addr(tag): return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()

for _s in (S3.SETUP, S5.SETUP):
    try: one(_s)
    except RuntimeError: pass
C8 = one("SELECT claim_id FROM ac.claims WHERE predicate='wm.mentioned' AND recorded_at='2026-09-06T10:30:00Z' AND claim_id IN "
         f"(SELECT claim_id FROM ac.claim_evidence e JOIN ac.source_observations o USING (tenant_id, source_id) WHERE o.original_object='{OBJ}') LIMIT 1")
SRC = one(f"SELECT source_id FROM ac.source_observations WHERE original_object='{OBJ}' LIMIT 1")
def reports():
    ids = one("SELECT string_agg(check_id, ' ' ORDER BY check_id) FROM ac.checks WHERE status='COMPLETED'").split()
    return " ".join(k + "=" + json.loads(one(f"SELECT ac.check_report('{k}')", "ac_rd_full"))["digest"] for k in ids)
REPORTS0 = reports()
print("claim", C8[:24], "source", SRC[:24])
time.sleep(1.2)

print("\n== A1: a check committed late changes a PAST custody answer (claim 5: as-of answers do not change retroactively)")
p = bg(f"BEGIN;\nINSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo','{OBJ}','CORRUPT');\n"
       f"SELECT pg_sleep({WAIT});\nCOMMIT;", "ac_storage")
time.sleep(WAIT / 2)
T2 = one("SELECT clock_timestamp()")
a = custody(C8, T2)
p.wait()
time.sleep(0.5)
b = custody(C8, T2)
ck = one(f"SELECT string_agg(result || '@' || checked_at, ', ' ORDER BY checked_at) FROM ac.object_checks WHERE object_address='{OBJ}'")
print("  journal:", ck)
print(f"  asked at T2={T2} (while the scrub transaction was open): as_of={a['as_of']} originals={orig(a)} digest={a['digest'][:18]}")
print(f"  asked AGAIN for the same as_of after its commit:        as_of={b['as_of']} originals={orig(b)} digest={b['digest'][:18]}")
print("  RESULT:", "FINDING — same as_of, different answer" if a["digest"] != b["digest"] else "held")

print("\n== A2: an observation committed late changes a PAST custody answer")
p = bg("BEGIN;\nINSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES "
       f"('tnt_demo','{SRC}', now(), 'https://late.example/x', 'svc_x');\nSELECT pg_sleep({WAIT});\nCOMMIT;", "ac_loader")
time.sleep(WAIT / 2)
T2 = one("SELECT clock_timestamp()")
a = custody(C8, T2); p.wait(); err = p.stderr.read(); time.sleep(0.5); b = custody(C8, T2)
n = lambda c: [len(s["observations"]) for s in c["sources"]]
print(f"  loader stderr: {err.strip()[:120] or '-'}")
print(f"  observations per source at as_of=T2: first ask {n(a)} digest={a['digest'][:18]} | second ask {n(b)} digest={b['digest'][:18]}")
print("  RESULT:", "FINDING — same as_of, different answer" if a["digest"] != b["digest"] else "held")

print("\n== A3: race scrub vs observation: an observation naming an object whose LATEST check is not OK gets in")
X = addr("race-object"); one("BEGIN;\n" + reg(X, 10) + "COMMIT;", "ac_storage"); time.sleep(0.3)
p = bg(f"BEGIN;\nINSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo','{X}','MISSING');\n"
       f"SELECT pg_sleep({WAIT});\nCOMMIT;", "ac_storage")
time.sleep(WAIT / 2)
s = S5.source("Текст для гонки проверки и наблюдения, рецензия S6.", "https://news.example/race", utc(0))
s["observations"][0]["original"] = {"object": X, "media_type": "text/html", "byte_length": 10}
r = psql(ingest_sql([s], {}))
p.wait(); time.sleep(0.3)
print("  observation insert while MISSING was uncommitted:", "ACCEPTED" if r.returncode == 0 else "refused: " + r.stderr.strip()[:100])
print("  committed history:", one(f"SELECT 'check ' || result || '@' || checked_at FROM ac.object_checks WHERE object_address='{X}' "
      f"UNION ALL SELECT 'observation ingested@' || ingested_at FROM ac.source_observations WHERE original_object='{X}' ORDER BY 1").replace("\n", " ; "))
bad = one(f"SELECT count(*) FROM ac.source_observations o WHERE original_object='{X}' AND ac.object_status_at(o.tenant_id, o.original_object, o.ingested_at) <> 'OK'")
print("  observations whose original was NOT OK at their own ingestion time (invariant of claim 3):", bad, "->", "FINDING" if bad != "0" else "held")
w = bg(f"BEGIN;\nINSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo','{OBJ}','OK');\nSELECT pg_sleep(4);\nROLLBACK;", "ac_storage")
time.sleep(1.5)
print("  locks taken by an open scrub tx that an observation insert would wait on (pg_locks, this db, not granted):",
      one("SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database WHERE d.datname = current_database() AND NOT l.granted"))
w.wait()

print("\n== A4: custody shows fetches made for OTHER projects (sources are tenant-wide): URI, time, original")
Y = addr("foreign-original"); one("BEGIN;\n" + reg(Y, 4242) + "COMMIT;", "ac_storage"); time.sleep(0.3)
secret = "https://intranet.corp.example/cases/4471/target-ivanov?token=SECRET"
r = psql("BEGIN;\nINSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by, original_object, original_media_type, original_length) "
         f"VALUES ('tnt_demo','{SRC}', now(), '{secret}', 'svc_dossier_crawler', '{Y}', 'application/pdf', 4242);\nCOMMIT;", "ac_loader")
print("  another product's loader adds its own fetch of the same text:", "accepted" if r.returncode == 0 else r.stderr.strip()[:200])
time.sleep(1.2)
c = custody(C8)
leak = [o for s_ in c["sources"] for o in s_["observations"] if o.get("origin_uri") == secret]
print("  reader ac_rd_wm (PUBLIC clearance, project prj_wm_region only) sees in custody:", json.dumps(leak, ensure_ascii=False)[:330])
SUBJ = one(f"SELECT subject FROM ac.claims WHERE claim_id='{C8}'")
feed = one(f"SELECT ac.wm_feed('prj_wm_region', '{SUBJ}')", "ac_rd_wm")
prov = one(f"SELECT ac.provenance('{C8}')", "ac_rd_wm")
print("  same URI in wm_feed (D24):", secret in feed, "| in provenance:", secret in prov, "| custody marking label:", c["marking"])
print("  RESULT:", "FINDING — custody discloses what feed/provenance do not" if leak and secret not in feed and secret not in prov else "held/consistent")

print("\n== A5: registry accepts tenants that do not exist / cannot be a store prefix (no FK, no pattern on ac.objects.tenant_id)")
for t in ("tnt_ghost", "TNT/../tnt_demo", "a" + chr(9) + "b"):
    r = psql("BEGIN;\n" + f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES (E'{t.replace(chr(9), chr(92) + 't')}','{addr('g' + t)}',1);\n"
             f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES (E'{t.replace(chr(9), chr(92) + 't')}','{addr('g' + t)}','OK');\nROLLBACK;", "ac_storage")
    print(f"  tenant {t!r}:", "accepted" if r.returncode == 0 else "refused " + r.stderr.strip()[:80])

print("\n== A6: same-timestamp collisions on PRIMARY KEY (tenant, object, checked_at)")
r = psql(f"BEGIN;\nINSERT INTO ac.object_checks (tenant_id, object_address, result) SELECT 'tnt_demo','{OBJ}','OK' FROM generate_series(1,200000);\n"
         f"SELECT count(*), count(DISTINCT checked_at) FROM ac.object_checks WHERE object_address='{OBJ}';\nROLLBACK;", "ac_storage")
print("  200000 checks of one object in one statement:", (r.stdout.strip() or r.stderr.strip())[:160])

print("\n== A7: bounds parity (validator: integer >= 1, schema rejects 2**63; database bigint)")
for n in (9223372036854775807, 9223372036854775808):
    r = psql("BEGIN;\n" + reg(addr("big%d" % n), n) + "ROLLBACK;", "ac_storage")
    print(f"  byte_length={n}:", "accepted" if r.returncode == 0 else "refused " + r.stderr.strip().splitlines()[0][:80])
for mt in ("text/html" + chr(10), "text/html; charset=utf-8", "text/html;charset=utf-8", "text/html;  charset=utf-8", "tеxt/html"):
    print(f"  media_type {mt!r}: db", one(f"SELECT $m${mt}$m$ ~ '^[a-z]+/[a-z0-9.+-]+(; ?charset=[a-z0-9-]+)?$'"))

print("\n== A8: earlier projections unaffected by everything above")
REPORTS1 = reports()
print("  check_report digests unchanged:", REPORTS0 == REPORTS1, "| reports:", len(REPORTS0.split()))

print("\n== A9: refusals")
for user, cid, asof in (("ac_rd_none", C8, None), ("ac_rd_wm", "clm:sha256:" + "0" * 64, None), ("ac_rd_wm", C8, "2020-01-01"), ("ac_rd_wm", C8, "-infinity"),
                        ("ac_storage", C8, None), ("ac_loader", C8, None)):
    r = psql(f"SELECT ac.custody('{cid}'" + (f", '{asof}'" if asof else "") + ");", user)
    print(f"  {user:<11} {cid[:16]} as_of={asof}:", (r.stderr.strip().splitlines() or ["ANSWERED"])[0][:90])

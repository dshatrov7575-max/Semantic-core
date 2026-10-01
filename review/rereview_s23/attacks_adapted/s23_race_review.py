#!/usr/bin/env python3
"""S23-10: write skew between a live review and a live Check closing (both ac_loader, no historical mode).
T2 inserts REFUTED for claim X (recorded_at = its start time t0) but does not commit yet; T1 (started later, t1 > t0)
closes a Check citing X — it cannot see T2's row, so X is ACCEPTED at t1 for every guard; T1 commits, then T2 commits.
Result: status_at(X, completed_at) = REFUTED — a COMPLETED Check rests on a refuted claim and its report changed after closing."""
import subprocess
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
C.reload()
X = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'media.negative_mention' AND project_id = 'prj_compliance'")
C.ok(f"""BEGIN; INSERT INTO ac.checks VALUES ('chk_race', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
  (now() AT TIME ZONE 'UTC')::date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_race', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb)); COMMIT;""", "ac_loader")
time.sleep(1.1)


def session():
    return subprocess.Popen(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


t2 = session()
t2.stdin.write(f"SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nINSERT INTO ac.claim_reviews VALUES ('rev_race', '{X}', 'REFUTED', 'usr_y', now(), now());\n"
               "SELECT 'T2 review inserted, recorded_at=' || now();\n")
t2.stdin.flush()
time.sleep(1.5)
r1 = C.psql(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_race', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_race', 'NEGATIVE', '{X}');
INSERT INTO ac.check_searches VALUES ('chk_race', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН", "search_scope": "СМИ"}}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', body = body || '{{"status": "COMPLETED", "overall_risk": "MEDIUM"}}' WHERE check_id = 'chk_race';
COMMIT;""", "ac_loader")
print("T1 close:", "OK" if r1.returncode == 0 else r1.stderr.strip())
before = C.js("SELECT ac.check_report('chk_race');", "ac_rd_full")
t2.stdin.write("COMMIT;\nSELECT 'T2 committed';\n")
t2.stdin.close()
print("T2:", t2.stdout.read().strip().replace("\n", " | "))
after = C.js("SELECT ac.check_report('chk_race');", "ac_rd_full")


def st(r):
    return [c["status"] for d in r["dimensions"] for f in d.get("facts", []) for c in f["claims"]]


print("claim status in the closed report before/after:", st(before), st(after))
print("digest before/after:", before["digest"], after["digest"])
print(C.ok("SELECT 'completed_at=' || completed_at || ' review recorded_at=' || (SELECT recorded_at FROM ac.claim_reviews WHERE review_id = 'rev_race') "
           "|| ' status_at(X, completed_at)=' || ac.status_at('" + X + "', completed_at) FROM ac.checks WHERE check_id = 'chk_race'"))
C.verdict("S23-10", before["digest"] != after["digest"] or "REFUTED" in st(after),
          "гонка «рецензия ↔ закрытие Проверки»: закрытая Проверка опирается на опровергнутое утверждение, отчёт изменился")

#!/usr/bin/env python3
"""S6 review: do the earlier projections give the same answers with and without ddl_s5b.sql?
DB_OLD is loaded by slice_v0.6_frozen/load_s1.py (same world, no S5b DDL), DB_NEW by slice/load_s1.py.
Usage: PGHOST=... PGPORT=... PGUSER=postgres python3 regress_projections.py <db_old> <db_new>"""
import json, subprocess, sys
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core")
import s3_tests as S3, s5_tests as S5
VOLATILE = {"digest", "ingested_at", "generated_at", "as_of"}
def psql(db, sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db], input=pre + sql, capture_output=True, text=True)
def strip(j):
    if isinstance(j, dict): return {k: strip(v) for k, v in j.items() if k not in VOLATILE}
    if isinstance(j, list): return [strip(v) for v in j]
    return j
def collect(db):
    for s in (S3.SETUP, S5.SETUP): psql(db, s)
    out = {}
    rows = lambda q: [x for x in psql(db, q).stdout.strip().splitlines() if x]
    calls = [f"ac.check_report('{k}')" for k in rows("SELECT check_id FROM ac.checks ORDER BY 1")]
    calls += [f"ac.provenance('{c}')" for c in rows("SELECT claim_id FROM ac.claims ORDER BY 1")]
    calls += [f"ac.dossier('{p}','{e}','2026-09-30T00:00:00Z')" for p, e in (r.split("|") for r in rows("SELECT project_id, entity_id FROM ac.entities ORDER BY 1,2"))]
    calls += [f"ac.wm_feed('{p}','{e}','2026-09-30T00:00:00Z')" for p, e in (r.split("|") for r in rows("SELECT project_id, entity_id FROM ac.entities WHERE project_id='prj_wm_region' ORDER BY 1,2"))]
    calls += [f"ac.equipment_card('{p}','{e}')" for p, e in (r.split("|") for r in rows("SELECT project_id, entity_id FROM ac.entities WHERE entity_type LIKE 'EQUIPMENT%' ORDER BY 1,2"))]
    for call in calls:
        for user in ("ac_rd_full", "ac_rd_wm_conf", "ac_rd_wm", "ac_rd_ts", "ac_rd_public", "ac_rd_cs", "ac_rd_none"):
            r = psql(db, f"SELECT {call};", user)
            out[(call, user)] = json.dumps(strip(json.loads(r.stdout.strip().splitlines()[-1])), sort_keys=True, ensure_ascii=False) if r.returncode == 0 else "ERR " + r.stderr.strip().splitlines()[0][:60]
    return out
a, b = collect(sys.argv[1]), collect(sys.argv[2])
answered = sum(1 for v in b.values() if not v.startswith("ERR"))
diff = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
print(f"calls x readers compared: {len(b)}; answered in new: {answered}; different: {len(diff)}")
for k in diff[:10]:
    print("  DIFF", k, "\n    old:", str(a.get(k))[:300], "\n    new:", str(b.get(k))[:300])

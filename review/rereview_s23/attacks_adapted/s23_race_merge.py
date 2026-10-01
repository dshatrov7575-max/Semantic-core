#!/usr/bin/env python3
"""S23-10b: the same write skew for merges (S22-02 bypass without historical mode). T2 merges the object entity of a
claim (status_changed_at = T2 start, t0) and holds; T1 (t1 > t0) closes a Check citing the claim; T2 commits.
The closed report resolves names as of t1 >= t0 -> the object is now shown under the survivor's name."""
import subprocess
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
C.reload()
X = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'prop.owns' AND project_id = 'prj_compliance'")
C.ok(f"""BEGIN;
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name)
VALUES ('ent_k_plot_new', 'prj_compliance', 'REAL_ESTATE', '{{"cadastral_number": "50:12:0101001:998"}}', 'ACTIVE', now(),
        '{{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}}', 'НОВОЕ ИМЯ УЧАСТКА');
INSERT INTO ac.checks VALUES ('chk_race_m', 'prj_compliance', 'ent_k_developer', 'FULL', 'IN_PROGRESS', now(), NULL, NULL,
  (now() AT TIME ZONE 'UTC')::date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_race_m', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb)); COMMIT;""", "ac_loader")
time.sleep(1.1)
t2 = subprocess.Popen(["psql", "-X", "-q", "-At"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
t2.stdin.write("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_plot_new' WHERE entity_id = 'ent_k_land';\n")
t2.stdin.flush()
time.sleep(1.5)
dims = ["NEGATIVE", "TENDERS", "SOCIAL_MEDIA", "CORPORATE", "COURT"]
sql = "BEGIN;\nINSERT INTO ac.check_findings VALUES ('chk_race_m', 'PROPERTY', 'FOUND', 'LOW');\n"
sql += f"INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_race_m', 'PROPERTY', '{X}');\n"
sql += "INSERT INTO ac.check_searches VALUES ('chk_race_m', 'PROPERTY', 0, now(), 'tnt_demo', NULL, '{\"query\": \"q\"}');\n"
for d in dims:
    sql += f"INSERT INTO ac.check_findings VALUES ('chk_race_m', '{d}', 'NOT_FOUND', 'NONE');\n"
    sql += f"INSERT INTO ac.check_searches VALUES ('chk_race_m', '{d}', 0, now(), 'tnt_demo', NULL, '{{\"query\": \"q\"}}');\n"
sql += ("UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'LOW', body = body || '{\"status\": \"COMPLETED\", \"overall_risk\": \"LOW\"}' "
        "WHERE check_id = 'chk_race_m';\nCOMMIT;")
r1 = C.psql(sql, "ac_loader")
print("T1 close:", "OK" if r1.returncode == 0 else r1.stderr.strip())
before = C.js("SELECT ac.check_report('chk_race_m');", "ac_rd_full")
t2.stdin.write("COMMIT;\n")
t2.stdin.close()
print("T2:", t2.stdout.read().strip() or "committed")
after = C.js("SELECT ac.check_report('chk_race_m');", "ac_rd_full")
txt = lambda r: [f["text"] for d in r["dimensions"] if d["dimension"] == "PROPERTY" for f in d.get("facts", [])]  # noqa: E731
print("before:", txt(before), "\nafter: ", txt(after))
C.verdict("S23-10b", before["digest"] != after["digest"], "гонка «слияние ↔ закрытие Проверки»: имя в отчёте закрытой Проверки изменилось")

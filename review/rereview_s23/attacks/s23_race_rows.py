#!/usr/bin/env python3
"""S23-10c: the closed_xact rule (S22-04/05) is checked at INSERT against the committed state only. T2 adds a search trace
to an open Check and holds; T1 closes the Check and commits; T2 commits -> a row written by a transaction other than the
closing one lands in a closed Check and changes its report."""
import subprocess
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
C.reload()
C.ok(f"""BEGIN; INSERT INTO ac.checks VALUES ('chk_race_r', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
  (now() AT TIME ZONE 'UTC')::date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_race_r', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));
INSERT INTO ac.check_findings VALUES ('chk_race_r', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_race_r', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН", "search_scope": "СМИ"}}');
COMMIT;""", "ac_loader")
time.sleep(1.1)
t2 = subprocess.Popen(["psql", "-X", "-q", "-At"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
t2.stdin.write("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nINSERT INTO ac.check_searches VALUES ('chk_race_r', 'NEGATIVE', 1, now(), "
               "'tnt_demo', NULL, '{\"query\": \"ПОДБРОШЕННЫЙ ПОИСК\", \"search_scope\": \"-\"}');\n")
t2.stdin.flush()
time.sleep(1.5)
r1 = C.psql("""BEGIN; UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'NONE', body = body || '{"status": "COMPLETED", "overall_risk": "NONE"}'
 WHERE check_id = 'chk_race_r'; COMMIT;""", "ac_loader")
print("T1 close:", "OK" if r1.returncode == 0 else r1.stderr.strip())
before = C.js("SELECT ac.check_report('chk_race_r');", "ac_rd_full")
t2.stdin.write("COMMIT;\n")
t2.stdin.close()
print("T2:", t2.stdout.read().strip() or "committed")
after = C.js("SELECT ac.check_report('chk_race_r');", "ac_rd_full")
q = lambda r: [s["query"] for d in r["dimensions"] for s in d.get("searches", [])]  # noqa: E731
print("searches before:", q(before), "after:", q(after), "| status", after["status"])
C.verdict("S23-10c", before["digest"] != after["digest"], "гонка: след поиска чужой транзакции попал в закрытую Проверку")

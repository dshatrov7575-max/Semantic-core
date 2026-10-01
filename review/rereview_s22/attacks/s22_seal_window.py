#!/usr/bin/env python3
"""S22-05 (D20 residue): the history seal only protects Checks closed BEFORE the last seal. A Check completed live
after the seal stays writable for ac_migrator in historical mode: it back-dates a REFUTED review (recorded_at between
the seal and the Check's completion) and appends a search row into the COMPLETED Check -> the closed Check's
report changes (claim was ACCEPTED at completion, now REFUTED at completion; new search in the trace).
Also probes that the seal itself holds (writes before the seal / into Checks closed before the seal are refused)."""
import time
from common import reload, ok, err, js, verdict

reload()
CID = "clm:sha256:577b95338d259dd345e5be1e8684f192ce6dcb18d4257a907bd2c1d4c48ce36d"  # media.negative_mention, ACCEPTED
M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
time.sleep(2)
ok(f"""BEGIN;
INSERT INTO ac.checks VALUES ('chk_live', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
  current_date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_live', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));
COMMIT;""", "ac_loader")
time.sleep(2)
ok(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_live', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_live', 'NEGATIVE', '{CID}');
INSERT INTO ac.check_searches VALUES ('chk_live', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН 5012007313", "search_scope": "СМИ"}}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM',
  body = body || '{{"status": "COMPLETED", "overall_risk": "MEDIUM"}}' WHERE check_id = 'chk_live';
COMMIT;""", "ac_loader")
seal = ok("SELECT ac.sealed_at();")
comp = ok("SELECT completed_at FROM ac.checks WHERE check_id = 'chk_live';")
print("seal:", seal, "| chk_live completed_at:", comp)
before = js("SELECT ac.check_report('chk_live');", "ac_rd_full")
time.sleep(1)
# the migrator back-dates a review into (seal, completed_at) and appends a search into the COMPLETED Check
r2 = err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.check_searches VALUES ('chk_live', 'NEGATIVE', 1, (SELECT completed_at FROM ac.checks WHERE check_id = 'chk_live'),
  'tnt_demo', NULL, '{{"query": "подброшенный поиск", "search_scope": "задним числом"}}');
COMMIT;""", "ac_migrator")
print("ac_migrator appends a search row into COMPLETED chk_live:", r2)
r = err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews VALUES ('rev_backdated', '{CID}', 'REFUTED', 'usr_x',
  (SELECT completed_at - interval '1 second' FROM ac.checks WHERE check_id = 'chk_live'),
  (SELECT completed_at - interval '1 second' FROM ac.checks WHERE check_id = 'chk_live'));
COMMIT;""", "ac_migrator")
print("ac_migrator back-dated REFUTED review (recorded_at = completed_at - 1s):", r)
after = js("SELECT ac.check_report('chk_live');", "ac_rd_full")
st = [c["status"] for d in after["dimensions"] for f in d.get("facts", []) for c in f["claims"]]
print("claim status at completion now:", st, "| searches:", [s["query"] for d in after["dimensions"] for s in d["searches"]])
verdict("S22-05", before["digest"] != after["digest"],
        "ac_migrator задним числом изменил отчёт Проверки, завершённой после последней печати (рецензия + след поиска)")

# control: the seal itself
e1 = err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews VALUES ('rev_pre_seal', '{CID}', 'REFUTED', 'usr_x', '2026-09-09T10:00:00Z', '2026-09-09T10:00:00Z'); COMMIT;""", "ac_migrator")
e2 = err("""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.check_searches VALUES ('chk_full_1', 'NEGATIVE', 7, now(), 'tnt_demo', NULL, '{"query": "x"}'); COMMIT;""", "ac_migrator")
e3 = err("""BEGIN; SET LOCAL ac.historical_import = 'on'; INSERT INTO ac.history_seals VALUES ('2000-01-01'); COMMIT;
SELECT ac.sealed_at();""", "ac_migrator")
print("pre-seal review:", e1); print("search into chk_full_1 (closed before seal):", e2); print("seal backwards attempt:", e3)
held = "TEMPORAL_ORDER_INVALID" in e1 and "CHECK_CLOSED" in e2
verdict("S22-05ctl", not held, "печать: запись до печати и в Проверку, закрытую до печати, отклонены")

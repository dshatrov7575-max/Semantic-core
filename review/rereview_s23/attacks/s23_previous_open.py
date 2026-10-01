#!/usr/bin/env python3
"""S23-01: a CLOSED Check may cite an OPEN previous Check; closing the previous one later rewrites the closed
Check's report ('previous.overall_risk' appears) and its digest. All writes as ac_loader (live role)."""
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'


def new_check(cid, prof, as_of, prev=None):
    return (f"INSERT INTO ac.checks VALUES ('{cid}', 'prj_compliance', 'ent_k_developer', '{prof}', 'IN_PROGRESS', now(), NULL, NULL, "
            f"{as_of}, NULL, {repr(prev) if prev else 'NULL'}, '{M}', jsonb_build_object('check_id', '{cid}', 'project_id', "
            f"'prj_compliance', 'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));")


C.reload()
TODAY = "(now() AT TIME ZONE 'UTC')::date"
# K1: open Check, as_of yesterday.  K2: cites K1 as previous, as_of today, completed NOW (NOT_FOUND with a search).
C.ok("BEGIN;\n" + new_check("chk_prev_open", "EXPRESS_NEGATIVE", TODAY + " - 1") + "\nCOMMIT;", "ac_loader")
C.ok("BEGIN;\n" + new_check("chk_closed_k2", "EXPRESS_NEGATIVE", TODAY, "chk_prev_open") + """
INSERT INTO ac.check_findings VALUES ('chk_closed_k2', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_closed_k2', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{"query": "ИНН 5012007313", "search_scope": "СМИ"}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'NONE', body = body || '{"status": "COMPLETED", "overall_risk": "NONE"}'
 WHERE check_id = 'chk_closed_k2';
COMMIT;""", "ac_loader")
before = C.js("SELECT ac.check_report('chk_closed_k2');", "ac_rd_full")
print("before: status", before["status"], "previous", before.get("previous"), before["digest"])
# later, in another transaction: K1 is completed with HIGH risk
C.ok("""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_prev_open', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims SELECT 'prj_compliance', 'chk_prev_open', 'NEGATIVE', claim_id FROM ac.claims WHERE predicate = 'media.negative_mention';
INSERT INTO ac.check_searches VALUES ('chk_prev_open', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{"query": "x", "search_scope": "СМИ"}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', body = body || '{"status": "COMPLETED", "overall_risk": "MEDIUM"}'
 WHERE check_id = 'chk_prev_open';
COMMIT;""", "ac_loader")
after = C.js("SELECT ac.check_report('chk_closed_k2');", "ac_rd_full")
print("after:  status", after["status"], "previous", after.get("previous"), after["digest"])
C.verdict("S23-01", before["digest"] != after["digest"],
          "отчёт ЗАКРЫТОЙ Проверки изменился после закрытия её (открытой на тот момент) предыдущей Проверки")

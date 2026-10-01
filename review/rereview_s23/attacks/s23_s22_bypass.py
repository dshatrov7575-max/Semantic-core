#!/usr/bin/env python3
"""Bypass attempts for the S22-01…06 fixes (all writes as live roles). Prints held/FINDING per attempt."""
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
MCS = '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}'
TODAY = "(now() AT TIME ZONE 'UTC')::date"


def land(eid, cad, marking, status="ACTIVE", merged=None):
    return (f"INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, merged_into, created_at, marking, display_name) "
            f"VALUES ('{eid}', 'prj_compliance', 'REAL_ESTATE', '{{\"cadastral_number\": \"{cad}\"}}', '{status}', "
            f"{repr(merged) if merged else 'NULL'}, now(), '{marking}', 'Имя {eid}');")


def new_check(cid, prof="EXPRESS_NEGATIVE", status="IN_PROGRESS"):
    return (f"INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, as_of, overall_risk, marking, body, closed_xact) "
            f"VALUES ('{cid}', 'prj_compliance', 'ent_k_developer', '{prof}', '{status}', now(), {TODAY}, "
            f"{'$$NONE$$' if status == 'COMPLETED' else 'NULL'}, '{M}', jsonb_build_object('check_id', '{cid}', 'project_id', "
            f"'prj_compliance', 'subject_entity_id', 'ent_k_developer', 'status', '{status}', 'marking', '{M}'::jsonb), '12345');")


C.reload()
# S22-01 chains: A -> B, then B -> C (UPDATE path) and D -> B where B already MERGED (INSERT path)
C.ok("BEGIN;" + land("ent_k_a", "50:12:0101001:901", MCS) + land("ent_k_b", "50:12:0101001:902", MCS)
     + land("ent_k_c", "50:12:0101001:903", MCS) + "COMMIT;", "ac_loader")
C.ok("BEGIN; UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_b' WHERE entity_id = 'ent_k_a'; COMMIT;", "ac_loader")
e1 = C.err("BEGIN; UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_c' WHERE entity_id = 'ent_k_b'; COMMIT;", "ac_loader")
C.verdict("B-01a", "ENTITY_MERGE_INVALID" not in e1, "цепочка слияний A→B→C (UPDATE): " + e1[:90])
C.ok("BEGIN; UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_c' WHERE entity_id = 'ent_k_b' AND false; COMMIT;", "ac_loader")
e2 = C.err("BEGIN;" + land("ent_k_d", "50:12:0101001:904", MCS, "MERGED", "ent_k_a") + "COMMIT;", "ac_loader")
C.verdict("B-01b", "ENTITY_MERGE_INVALID" not in e2, "INSERT сразу MERGED в уже слитую сущность: " + e2[:90])
# retire-then-merge (historical import): a RETIRED broader target (times after the seal)
time.sleep(3)
e3 = C.err("""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, status_changed_at, created_at, marking, display_name)
VALUES ('ent_k_r', 'prj_compliance', 'REAL_ESTATE', '{"cadastral_number": "50:12:0101001:905"}', 'RETIRED', now() - interval '1 second',
        now() - interval '2 seconds', '{"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}', 'СЕКРЕТНО');
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, merged_into, status_changed_at, created_at, marking, display_name)
VALUES ('ent_k_m', 'prj_compliance', 'REAL_ESTATE', '{"cadastral_number": "50:12:0101001:906"}', 'MERGED', 'ent_k_r', now() - interval '1.5 seconds',
        now() - interval '2 seconds', '""" + MCS + """', 'm');
COMMIT;""", "ac_migrator")
C.verdict("B-01c", "ENTITY_MERGE_INVALID" not in e3, "историческое слияние в выведенную (RETIRED) более широкую сущность: " + e3[:90])

# S22-04/05: closed_xact cannot be forged; the column is not writable; rows only in the closing transaction
C.ok("BEGIN;" + new_check("chk_f1") + "COMMIT;", "ac_loader")
x = C.ok("SELECT coalesce(closed_xact::text, 'NULL') FROM ac.checks WHERE check_id = 'chk_f1'")
C.verdict("B-04a", x != "NULL", "closed_xact, переданный в INSERT открытой Проверки, перезаписан: " + x)
e4 = C.err("BEGIN; UPDATE ac.checks SET closed_xact = pg_current_xact_id() WHERE check_id = 'chk_express_1'; COMMIT;", "ac_loader")
C.verdict("B-04b", "permission denied" not in e4, "UPDATE closed_xact закрытой Проверки: " + e4[:80])
# close chk_f1 in T1; in T2 close another Check and try to add rows to chk_f1
C.ok("""BEGIN; INSERT INTO ac.check_findings VALUES ('chk_f1', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_f1', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{"query": "q"}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'NONE', body = body || '{"status": "COMPLETED", "overall_risk": "NONE"}' WHERE check_id = 'chk_f1';
COMMIT;""", "ac_loader")
e5 = C.err("BEGIN;" + new_check("chk_f2") + """
INSERT INTO ac.check_findings VALUES ('chk_f2', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_f2', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{"query": "q"}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'NONE', body = body || '{"status": "COMPLETED", "overall_risk": "NONE"}' WHERE check_id = 'chk_f2';
INSERT INTO ac.check_searches VALUES ('chk_f1', 'NEGATIVE', 1, now(), 'tnt_demo', NULL, '{"query": "подброшено"}');
COMMIT;""", "ac_loader")
C.verdict("B-04c", "CHECK_CLOSED" not in e5, "две Проверки в одной транзакции: строки в ранее закрытую: " + e5[:80])
# close twice in one transaction (CANCELLED then COMPLETED), and savepoint games
e6 = C.err("BEGIN;" + new_check("chk_f3") + """
UPDATE ac.checks SET status = 'CANCELLED', body = body || '{"status": "CANCELLED"}' WHERE check_id = 'chk_f3';
UPDATE ac.checks SET status = 'COMPLETED', cancelled_at = NULL, overall_risk = 'NONE', body = body || '{"status": "COMPLETED"}' WHERE check_id = 'chk_f3';
COMMIT;""", "ac_loader")
C.verdict("B-04d", "CHECK_CLOSED" not in e6, "отмена и завершение одной Проверки в одной транзакции: " + e6[:80])
e7 = C.err("""BEGIN; SAVEPOINT s1;
INSERT INTO ac.check_searches VALUES ('chk_f1', 'NEGATIVE', 2, now(), 'tnt_demo', NULL, '{"query": "sp"}');
RELEASE s1; COMMIT;""", "ac_loader")
C.verdict("B-04e", "CHECK_CLOSED" not in e7, "строка в закрытую Проверку из подтранзакции: " + e7[:80])
# directly-COMPLETED insert with a forged closed_xact, then rows in a LATER transaction
C.ok("BEGIN;" + new_check("chk_f4", status="COMPLETED") + """
INSERT INTO ac.check_findings VALUES ('chk_f4', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_f4', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{"query": "q"}');
COMMIT;""", "ac_loader")
e8 = C.err("BEGIN; INSERT INTO ac.check_searches VALUES ('chk_f4', 'NEGATIVE', 1, now(), 'tnt_demo', NULL, '{\"query\": \"late\"}'); COMMIT;", "ac_loader")
C.verdict("B-04f", "CHECK_CLOSED" not in e8, "Проверка, вставленная сразу COMPLETED: поздняя строка: " + e8[:80])

# S22-05: review horizon — historical review before closing of a Check that cites the claim, via CANCELLED Check
cid = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'court.party_to_case' AND project_id = 'prj_compliance'")
C.ok("BEGIN;" + new_check("chk_f5", "FULL") + f"""
INSERT INTO ac.check_findings VALUES ('chk_f5', 'COURT', 'FOUND', 'LOW');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_f5', 'COURT', '{cid}');
UPDATE ac.checks SET status = 'CANCELLED', body = body || '{{"status": "CANCELLED"}}' WHERE check_id = 'chk_f5';
COMMIT;""", "ac_loader")
before = C.js("SELECT ac.check_report('chk_f5');", "ac_rd_full")
time.sleep(1.1)
e9 = C.err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews VALUES ('rev_h', '{cid}', 'REFUTED', 'usr_x', (SELECT cancelled_at - interval '0.5 second' FROM ac.checks WHERE check_id = 'chk_f5'),
  (SELECT cancelled_at - interval '0.5 second' FROM ac.checks WHERE check_id = 'chk_f5')); COMMIT;""", "ac_migrator")
after = C.js("SELECT ac.check_report('chk_f5');", "ac_rd_full")
C.verdict("B-05", before["digest"] != after["digest"], "рецензия задним числом под отменённую Проверку: " + e9[:80])

# S22-06: marking shapes
cases = {
    "dup": '{"level": "PUBLIC", "categories": ["PERSONAL_DATA", "PERSONAL_DATA"]}',
    "case": '{"level": "public", "categories": []}',
    "extra": '{"level": "PUBLIC", "categories": [], "x": 1}',
    "nested": '{"level": "PUBLIC", "categories": [["PERSONAL_DATA"]]}',
    "nullcat": '{"level": "PUBLIC", "categories": null}',
    "nulllevel": '{"level": null, "categories": []}',
    "numlevel": '{"level": 0, "categories": []}',
    "unkcat": '{"level": "PUBLIC", "categories": ["SECRET"]}',
    "array": '[]', "null": 'null',
}
res = C.ok("SELECT string_agg(k || '=' || ac.marking_ok(v::jsonb)::text, ' ') FROM (VALUES "
           + ",".join(f"('{k}', '{v}')" for k, v in cases.items()) + ") t(k, v)")
res2 = C.ok("""SELECT ac.marking_ok('{"level": "PUBLIC", "categories": []}') AND ac.marking_ok('{"level": "RESTRICTED", "categories": ["OFFICIAL_USE", "PERSONAL_DATA", "COMMERCIAL_SECRET"]}')""")
C.verdict("B-06a", "true" in res or res2 != "t", "marking_ok на краевых формах: " + res + " / валидные: " + res2)
# clearance with an unknown or duplicated category: fail-closed (reader loses even PUBLIC data)
C.ok("""SET ROLE ac_trust_admin; INSERT INTO ac_trust.clearances (role_name, project_id, level, categories)
VALUES ('ac_rd_none', 'prj_wiki_whales', 'PUBLIC', '{public_data}'); RESET ROLE;""")
e10 = C.err("SELECT ac.dossier('prj_wiki_whales', 'ent_wk_blue') IS NOT NULL;", "ac_rd_none")
print("clearance with unknown category accepted by ac_trust.clearances; dossier:", e10[:90])
C.verdict("B-06b", "(выполнено)" in e10, "допуск с неизвестной категорией даёт доступ")

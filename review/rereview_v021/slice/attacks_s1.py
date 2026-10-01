#!/usr/bin/env python3
"""S2 acceptance: every database-level rule of ddl_s1.sql is attacked BYPASSING the validator,
as the live application role ac_loader (no historical import). Each attack runs in its own transaction and must
fail with the expected error text; each legitimate operation must succeed. Run after load_s1.py.

Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=... python3 slice/attacks_s1.py
"""
import subprocess
import sys

PRE = """BEGIN;
SET ROLE ac_loader;
CREATE FUNCTION pg_temp.nowz() RETURNS text LANGUAGE sql AS $$ SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') $$;
-- clone an existing claim (by predicate) under a new id, recorded "now"; extra jsonb patch applied on top
CREATE FUNCTION pg_temp.clone(pred text, new_id text, patch jsonb DEFAULT '{}') RETURNS void LANGUAGE plpgsql AS $$
DECLARE c ac.claims; b jsonb;
BEGIN
  SELECT c0.* INTO c FROM ac.claims c0 JOIN ac.entities e ON e.entity_id = c0.subject AND e.status = 'ACTIVE'
   WHERE c0.predicate = pred ORDER BY c0.claim_id LIMIT 1;
  b := c.body || jsonb_build_object('claim_id', new_id, 'recorded_at', pg_temp.nowz()) || patch;
  INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
  VALUES (b->>'claim_id', b->>'project_id', c.tenant_id, b->>'subject', b->>'predicate', b->'object'->>'entity',
          b->'produced_by'->>'kind', (b->>'recorded_at')::timestamptz, b->'marking', b);
END $$;
"""
NID = "'clm:sha256:" + "a" * 64 + "'"
NID2 = "'clm:sha256:" + "b" * 64 + "'"
EV0 = ("(SELECT c0.body->'evidence'->0 FROM ac.claims c0 JOIN ac.entities e ON e.entity_id = c0.subject AND e.status = 'ACTIVE' "
       "WHERE c0.predicate = 'person.birth_date' ORDER BY c0.claim_id LIMIT 1)")

ATTACKS = [
    # ---- identity (Dossier: one entity per project, strictly)
    ("DB-A01", "второй владелец сильного ключа (ОГРН) в проекте", "entity_keys_one_owner", """
INSERT INTO ac.entities SELECT 'ent_dup_org', project_id, entity_type, identity, 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_developer';
INSERT INTO ac.entity_keys SELECT project_id, entity_type, scheme, value, 'ent_dup_org', 'STRONG', NULL FROM ac.entity_keys WHERE owner_entity_id = 'ent_d_developer' AND scheme = 'ru.ogrn';"""),
    ("DB-A02", "тёзка с той же ФИО+датой: пометка только у одного (RR-03c)", "ENTITY_DUPLICATE_IN_PROJECT", """
INSERT INTO ac.entities SELECT 'ent_dup_lomov', project_id, entity_type, identity - 'inn', 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_lomov';
INSERT INTO ac.entity_keys SELECT project_id, entity_type, scheme, value, 'ent_dup_lomov', 'WEAK', 'other-lomov' FROM ac.entity_keys WHERE owner_entity_id = 'ent_d_lomov' AND strength = 'WEAK';"""),
    ("DB-A03", "ключ записан на слитую сущность", "ENTITY_KEY_OWNER",
     "INSERT INTO ac.entity_keys VALUES ('prj_dossier', 'PERSON', 'x.test', '1', 'ent_d_lomov_media', 'STRONG', NULL);"),
    ("DB-A04", "изменение идентичности сущности", "ENTITY_IMMUTABLE",
     "UPDATE ac.entities SET identity = identity || '{\"birth_date\": \"1970-01-01\"}' WHERE entity_id = 'ent_d_lomov';"),
    ("DB-A05", "слияние в сущность другого типа", "ENTITY_MERGE_INVALID",
     "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_d_developer' WHERE entity_id = 'ent_d_lomov';"),
    ("DB-A06", "слияние в выведенную из оборота сущность (RR-13)", "ENTITY_MERGE_INVALID", """
UPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = 'ent_d_developer';
INSERT INTO ac.entities SELECT 'ent_dup_org2', project_id, entity_type, '{"name": "x", "jurisdiction": "GB", "foreign_ids": [{"scheme": "gb.crn", "value": "1"}]}', 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_developer';
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_d_developer' WHERE entity_id = 'ent_dup_org2';"""),
    ("DB-A07", "воскрешение: RETIRED -> ACTIVE", "ENTITY_STATUS_TRANSITION", """
UPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = 'ent_d_developer';
UPDATE ac.entities SET status = 'ACTIVE', status_changed_at = NULL WHERE entity_id = 'ent_d_developer';"""),
    ("DB-A08", "удаление сущности", "APPEND_ONLY", "DELETE FROM ac.entities WHERE entity_id = 'ent_wk_baleen';"),
    ("DB-A09", "физлицо без категории PERSONAL_DATA", "person_has_pd",
     "INSERT INTO ac.entities VALUES ('ent_no_pd', 'prj_dossier', 'PERSON', '{}', 'ACTIVE', NULL, NULL, now(), '{\"level\": \"CONFIDENTIAL\", \"categories\": []}');"),
    # ---- claims and provenance (ONT-03)
    ("DB-A10", "утверждение о субъекте другого проекта", "violates foreign key constraint",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"subject\": \"ent_c_lomov\"}}');"),
    ("DB-A11", "подложный хэш цитаты", "EVIDENCE_SPAN_INVALID",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, jsonb_build_object('evidence', jsonb_build_array({EV0} || jsonb_build_object('quote_sha256', repeat('0', 64)))));"),
    ("DB-A12", "фрагмент режет символ UTF-8, хэш пересчитан", "режет символ", f"""
SELECT pg_temp.clone('person.birth_date', {NID}, jsonb_build_object('evidence', jsonb_build_array(
  ({EV0} - 'quote') || jsonb_build_object('span', jsonb_build_object('start', ({EV0}->'span'->>'start')::int + 1, 'end', ({EV0}->'span'->>'end')::int),
    'quote_sha256', (SELECT encode(sha256(substring(b.bytes FROM ({EV0}->'span'->>'start')::int + 2 FOR ({EV0}->'span'->>'end')::int - ({EV0}->'span'->>'start')::int - 1)), 'hex')
                     FROM ac.source_bytes b WHERE b.source_id = {EV0}->>'source_id')))));"""),
    ("DB-A13", "доказательство из источника чужого tenant", "CROSS_SCOPE_REFERENCE", f"""
INSERT INTO ac.sources SELECT 'tnt_other', source_id, byte_length, marking, body || '{{"tenant_id": "tnt_other"}}' FROM ac.sources WHERE source_id = {EV0}->>'source_id';
INSERT INTO ac.source_bytes SELECT 'tnt_other', source_id, bytes FROM ac.source_bytes WHERE source_id = {EV0}->>'source_id';
DELETE FROM pg_temp.nothing_here_just_to_be_explicit WHERE false;""".replace(
        "DELETE FROM pg_temp.nothing_here_just_to_be_explicit WHERE false;",
        "UPDATE ac.claim_evidence SET tenant_id = 'tnt_other' WHERE false;") + f"""
SELECT pg_temp.clone('person.birth_date', {NID}, jsonb_build_object('evidence', jsonb_build_array({EV0} || jsonb_build_object('source_id', 'src:sha256:' || repeat('c', 64)))));"""),
    ("DB-A14", "прямая запись доказательства в обход утверждения", "APPEND_ONLY",
     "INSERT INTO ac.claim_evidence SELECT claim_id, 99, tenant_id, source_id, span_start, span_end, quote_sha256, quote, graph_node FROM ac.claim_evidence LIMIT 1;"),
    ("DB-A15", "перенаправление доказательства на другую цитату (ONT-03 DB-R07a)", "APPEND_ONLY",
     "UPDATE ac.claim_evidence SET span_start = 0 WHERE ord = 0;"),
    ("DB-A16", "удаление доказательства", "APPEND_ONLY", "DELETE FROM ac.claim_evidence;"),
    ("DB-A17", "удаление утверждения (ONT-03 DB-R07b)", "APPEND_ONLY", "DELETE FROM ac.claims WHERE predicate = 'wiki.is_a';"),
    ("DB-A18", "изменение тела утверждения", "APPEND_ONLY", "UPDATE ac.claims SET body = body || '{\"note\": \"x\"}';"),
    ("DB-A19", "утверждение без доказательств (ONT-03 DB-R07c)", "claim_has_evidence",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"evidence\": []}}');"),
    ("DB-A20", "колонки расходятся с телом утверждения", "claim_columns_match_body", f"""
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT {NID}, project_id, tenant_id, 'ent_d_ip', predicate, object_entity, produced_kind, now(), marking,
       body || jsonb_build_object('claim_id', {NID}, 'recorded_at', pg_temp.nowz())
FROM ac.claims WHERE predicate = 'person.birth_date' ORDER BY claim_id LIMIT 1;"""),
    ("DB-A21", "утверждение задним числом в живом режиме", "TEMPORAL_ORDER_INVALID",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"recorded_at\": \"2026-01-01T00:00:00Z\"}}');"),
    ("DB-A22", "самовольный исторический режим без роли ac_migrator", "TEMPORAL_ORDER_INVALID",
     f"SET LOCAL ac.historical_import = 'on'; SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"recorded_at\": \"2026-01-01T00:00:00Z\"}}');"),
    ("DB-A23", "утверждение из будущего", "TEMPORAL_ORDER_INVALID",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"recorded_at\": \"2099-01-01T00:00:00Z\"}}');"),
    ("DB-A24", "маркировка утверждения уже маркировки сущности/источника", "MARKING_BROADER_THAN_INPUT",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"marking\": {{\"level\": \"PUBLIC\", \"categories\": []}}}}');"),
    ("DB-A25", "новое утверждение о слитой сущности", "CLAIM_ABOUT_MERGED_ENTITY",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"subject\": \"ent_d_lomov_media\"}}');"),
    # ---- reviews (append-only, system time)
    ("DB-A26", "изменение рецензии", "APPEND_ONLY", "UPDATE ac.claim_reviews SET status = 'ACCEPTED';"),
    ("DB-A27", "удаление рецензии", "APPEND_ONLY", "DELETE FROM ac.claim_reviews;"),
    # ---- Проверки
    ("DB-A28", "Проверка в проекте Dossier", "CHECK_PROJECT_NOT_COMPLIANCE", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of) SELECT 'chk_x', 'prj_dossier', 'ent_d_developer', profile, 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_x", "project_id": "prj_dossier", "subject_entity_id": "ent_d_developer", "status": "IN_PROGRESS"}', current_date
FROM ac.checks WHERE check_id = 'chk_tenders_1';"""),
    ("DB-A29", "утверждение другого проекта в Проверке", "CROSS_SCOPE_REFERENCE",
     "INSERT INTO ac.check_finding_claims SELECT 'prj_compliance', 'chk_tenders_1', 'TENDERS', claim_id FROM ac.claims WHERE project_id = 'prj_dossier' LIMIT 1;"),
    ("DB-A30", "дописать утверждение в закрытую Проверку", "CHECK_CLOSED",
     "INSERT INTO ac.check_finding_claims SELECT 'prj_compliance', 'chk_full_1', 'TENDERS', claim_id FROM ac.claims WHERE project_id = 'prj_compliance' AND predicate = 'tender.participated' LIMIT 1;"),
    ("DB-A31", "изменить закрытую Проверку", "CHECK_CLOSED",
     "UPDATE ac.checks SET body = body || '{\"overall_risk\": \"NONE\"}' WHERE check_id = 'chk_full_1';"),
    ("DB-A32", "Проверка уже маркировки утверждения (ONT-01)", "MARKING_BROADER_THAN_INPUT", """
SELECT pg_temp.clone('tender.participated', 'clm:sha256:""" + "d" * 64 + """', '{"marking": {"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET", "OFFICIAL_USE"]}}');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_tenders_1', 'TENDERS', 'clm:sha256:""" + "d" * 64 + """');"""),
    ("DB-A33", "след поиска на источник без байтов (RR-08b)", "SOURCE_CONTENT_UNAVAILABLE", """
INSERT INTO ac.sources SELECT tenant_id, 'src:sha256:' || repeat('e', 64), byte_length, marking, body || jsonb_build_object('source_id', 'src:sha256:' || repeat('e', 64))
FROM ac.sources LIMIT 1;
INSERT INTO ac.check_searches VALUES ('chk_tenders_1', 'TENDERS', 0, now(), 'tnt_demo', 'src:sha256:' || repeat('e', 64), '{}');"""),
    ("DB-A34", "удалить Проверку", "APPEND_ONLY", "DELETE FROM ac.checks WHERE check_id = 'chk_express_1';"),
    # ---- sources, receipts, trust
    ("DB-A35", "байты не соответствуют адресу", "source_bytes_address",
     "UPDATE ac.source_bytes SET bytes = bytes || '\\x00'::bytea WHERE false; INSERT INTO ac.source_bytes SELECT 'tnt_demo', 'src:sha256:' || repeat('e', 64), '\\x00'::bytea;"
     .replace("INSERT INTO ac.source_bytes", "INSERT INTO ac.sources SELECT tenant_id, 'src:sha256:' || repeat('e', 64), 1, marking, body || jsonb_build_object('source_id', 'src:sha256:' || repeat('e', 64), 'byte_length', 1) FROM ac.sources LIMIT 1; INSERT INTO ac.source_bytes", 1)),
    ("DB-A36", "второй receipt на то же утверждение", "receipt_claims_claim_id_key", """
INSERT INTO ac.artifact_receipts SELECT 'rcp:sha256:' || repeat('f', 64), project_id, tenant_id, key_id, service_id, now(),
       body || jsonb_build_object('receipt_id', 'rcp:sha256:' || repeat('f', 64)) FROM ac.artifact_receipts LIMIT 1;
INSERT INTO ac.receipt_inputs SELECT 'rcp:sha256:' || repeat('f', 64), tenant_id, source_id FROM ac.receipt_inputs;
INSERT INTO ac.receipt_claims SELECT 'rcp:sha256:' || repeat('f', 64), claim_id FROM ac.receipt_claims LIMIT 1;"""),
    ("DB-A37", "receipt с ключом вне реестра доверия tenant", "violates foreign key constraint", """
INSERT INTO ac.artifact_receipts SELECT 'rcp:sha256:' || repeat('f', 64), project_id, tenant_id, 'key_rogue', service_id, now(),
       body || jsonb_build_object('receipt_id', 'rcp:sha256:' || repeat('f', 64), 'key_id', 'key_rogue') FROM ac.artifact_receipts LIMIT 1;"""),
    ("DB-A38", "PIPELINE-утверждение без receipt (проверка при COMMIT)", "PIPELINE-утверждение без receipt",
     f"SELECT pg_temp.clone('ts.instance_of', {NID});"),
    ("DB-A39", "приложение пишет в реестр доверия", "permission denied",
     "INSERT INTO ac_trust.keys SELECT tenant_id, 'key_rogue', service_id, algorithm, public_key, not_before, not_after, NULL FROM ac_trust.keys LIMIT 1;"),
    # ---- registries and Check consistency enforced by the database (v0.2.1 S2 coverage)
    ("DB-A40", "предикат вне реестра", "claim_predicate_known",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"predicate\": \"person.shoe_size\"}}');"),
    ("DB-A41", "организация как субъект даты рождения (domain)", "PREDICATE_DOMAIN_VIOLATION",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"subject\": \"ent_d_developer\", \"marking\": {{\"level\": \"CONFIDENTIAL\", \"categories\": [\"PERSONAL_DATA\", \"COMMERCIAL_SECRET\"]}}}}');"),
    ("DB-A42", "дата рождения строкой (range)", "PREDICATE_RANGE_VIOLATION",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"object\": {{\"literal\": {{\"type\": \"STRING\", \"value\": \"14.03.1971\"}}}}}}');"),
    ("DB-A43", "valid_from позже valid_to", "claim_valid_time_order",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, '{{\"valid_from\": \"2020-01-01\", \"valid_to\": \"2019-01-01\"}}');"),
    ("DB-A44", "завершить Проверку с as_of позже даты завершения", "check_time_order", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of)
SELECT 'chk_n', project_id, subject_entity_id, 'TENDERS_ONLY', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_n", "status": "IN_PROGRESS", "profile": "TENDERS_ONLY"}', '2099-01-01' FROM ac.checks WHERE check_id = 'chk_tenders_1';
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'NONE', body = body || '{"status": "COMPLETED"}' WHERE check_id = 'chk_n';"""),
    ("DB-A45", "предыдущая Проверка по другому субъекту", "CHECK_PREVIOUS_INVALID", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of, previous_check_id)
SELECT 'chk_p', project_id, 'ent_k_lomov', 'SOCIAL_ONLY', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_p", "status": "IN_PROGRESS", "profile": "SOCIAL_ONLY", "subject_entity_id": "ent_k_lomov"}', current_date, 'chk_full_1'
FROM ac.checks WHERE check_id = 'chk_tenders_1';"""),
    ("DB-A46", "результат FOUND без утверждений (при COMMIT)", "CHECK_FINDING_INCONSISTENT",
     "INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'TENDERS', 'FOUND', 'LOW');"),
    ("DB-A47", "NOT_FOUND с риском", "not_found_no_risk",
     "INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'TENDERS', 'NOT_FOUND', 'LOW');"),
    ("DB-A48", "измерение вне профиля (при COMMIT)", "CHECK_DIMENSION_OUTSIDE_PROFILE",
     "INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'COURT', 'NOT_FOUND', 'NONE');"),
    ("DB-A49", "утверждение не того измерения", "CHECK_CLAIM_DIMENSION_MISMATCH", """
INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'TENDERS', 'FOUND', 'LOW');
INSERT INTO ac.check_finding_claims SELECT 'prj_compliance', 'chk_tenders_1', 'TENDERS', claim_id FROM ac.claims WHERE project_id = 'prj_compliance' AND predicate <> 'tender.participated' AND NOT EXISTS (SELECT 1 FROM ac.predicates pr WHERE pr.predicate_id = ac.claims.predicate AND 'TENDERS' = ANY (pr.dimensions)) LIMIT 1;"""),
    ("DB-A50", "утверждение не о субъекте Проверки", "CHECK_CLAIM_NOT_ABOUT_SUBJECT", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of)
SELECT 'chk_n', project_id, 'ent_k_lomov', 'TENDERS_ONLY', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_n", "status": "IN_PROGRESS", "profile": "TENDERS_ONLY", "subject_entity_id": "ent_k_lomov"}', current_date
FROM ac.checks WHERE check_id = 'chk_tenders_1';
INSERT INTO ac.check_findings VALUES ('chk_n', 'TENDERS', 'FOUND', 'LOW');
INSERT INTO ac.check_finding_claims SELECT 'prj_compliance', 'chk_n', 'TENDERS', claim_id FROM ac.claims WHERE project_id = 'prj_compliance' AND predicate = 'tender.participated' LIMIT 1;"""),
    ("DB-A51", "завершить Проверку без следа поиска (при COMMIT)", "CHECK_SEARCH_MISSING", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of) SELECT 'chk_n', project_id, subject_entity_id, 'TENDERS_ONLY', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_n", "status": "IN_PROGRESS", "profile": "TENDERS_ONLY"}', current_date FROM ac.checks WHERE check_id = 'chk_tenders_1';
INSERT INTO ac.check_findings VALUES ('chk_n', 'TENDERS', 'NOT_FOUND', 'NONE');
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'NONE', body = body || '{"status": "COMPLETED"}' WHERE check_id = 'chk_n';"""),
    ("DB-A52", "завершить Проверку без измерения профиля (при COMMIT)", "CHECK_DIMENSION_MISSING", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of) SELECT 'chk_n', project_id, subject_entity_id, 'TENDERS_ONLY', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_n", "status": "IN_PROGRESS", "profile": "TENDERS_ONLY"}', current_date FROM ac.checks WHERE check_id = 'chk_tenders_1';
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'NONE', body = body || '{"status": "COMPLETED"}' WHERE check_id = 'chk_n';"""),
    ("DB-A53", "HUMAN-утверждение с узлом графа", "узел графа допустим только у PIPELINE",
     f"SELECT pg_temp.clone('person.birth_date', {NID}, jsonb_build_object('evidence', jsonb_build_array({EV0} || '{{\"graph_node\": {{\"artifact_digest\": \"sha256:x\", \"node_id\": \"n1\"}}}}')));"),
]

OK = [
    ("OK-01", "новое утверждение «сейчас»: доказательство проверено по байтам",
     f"SELECT pg_temp.clone('person.birth_date', {NID2}); SELECT count(*) FROM ac.claim_provenance WHERE claim_id = {NID2} AND verified;", "1"),
    ("OK-02", "рецензия с заявленным «задним» временем: база ставит системное время", """
INSERT INTO ac.claim_reviews SELECT 'rev_live', claim_id, 'DISPUTED', 'usr_x', now() - interval '1 minute', '2026-01-01T00:00:00Z' FROM ac.claims WHERE predicate = 'person.birth_date' ORDER BY claim_id LIMIT 1;
SELECT (recorded_at > now() - interval '1 minute')::text FROM ac.claim_reviews WHERE review_id = 'rev_live';""", "true"),
    ("OK-03", "ещё одна Проверка того же субъекта (Compliance: многократность)", """
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of) SELECT 'chk_express_2', project_id, subject_entity_id, 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, marking,
       body || '{"check_id": "chk_express_2", "status": "IN_PROGRESS", "profile": "EXPRESS_NEGATIVE"}', current_date FROM ac.checks WHERE check_id = 'chk_tenders_1';
SELECT count(*) FROM ac.checks WHERE subject_entity_id = 'ent_k_developer';""", "4"),
    ("OK-04", "слияние нового дубля: ключи переходят к выжившей сущности, время ставит база", """
INSERT INTO ac.entities SELECT 'ent_dup_ok', project_id, entity_type, '{"name": "x", "jurisdiction": "GB", "foreign_ids": [{"scheme": "gb.crn", "value": "777"}]}', 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_developer';
INSERT INTO ac.entity_keys VALUES ('prj_dossier', 'ORGANIZATION', 'gb.crn', '777', 'ent_dup_ok', 'STRONG', NULL);
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_d_developer' WHERE entity_id = 'ent_dup_ok';
SELECT owner_entity_id || ' ' || (SELECT (status_changed_at > now() - interval '1 minute')::text FROM ac.entities WHERE entity_id = 'ent_dup_ok')
FROM ac.entity_keys WHERE scheme = 'gb.crn' AND value = '777';""", "ent_d_developer true"),
    ("OK-05", "все цитаты всех утверждений подтверждаются байтами источников",
     "SELECT count(*) FILTER (WHERE verified) || '/' || count(*) FROM ac.claim_provenance;", None),
]


def run(sql):
    return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"], input=sql, capture_output=True, text=True)


def main():
    bad = 0
    for aid, desc, expect, sql in ATTACKS:
        r = run(PRE + sql + "\nCOMMIT;\n")
        ok = r.returncode != 0 and expect in r.stderr
        bad += not ok
        msg = (r.stderr.strip().splitlines() or ["(принято!)"])[0].replace("psql:<stdin>:", "")[:150]
        print(f"{aid} {'REJECTED' if ok else 'NOT REJECTED'} | {desc} | {msg}")
    for oid, desc, sql, want in OK:
        r = run(PRE + sql + "\nCOMMIT;\n")
        out = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        ok = r.returncode == 0 and (want is None or out == want)
        if want is None and ok:
            a, b = out.split("/")
            ok = a == b
        bad += not ok
        print(f"{oid} {'OK' if ok else 'FAIL'} | {desc} | {out or r.stderr.strip()[:150]}")
    print(f"\nattacks={len(ATTACKS)} legit={len(OK)} failures={bad}")
    print("S2_RESULT=" + ("PASS" if bad == 0 else "FAIL"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

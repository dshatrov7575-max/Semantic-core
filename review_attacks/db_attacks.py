#!/usr/bin/env python3
"""RS re-review v0.2.1: attacks on the S1 database layer, BYPASSING the validator, as the live role ac_loader.

Stricter than slice/attacks_s1.py: the session is switched with SET SESSION AUTHORIZATION ac_loader (so the
session user itself is ac_loader and cannot RESET ROLE back to a superuser). Before EVERY attack the reference
world is reloaded (slice/load_s1.py), the attack SQL is COMMITTED, then a proof query (as postgres) shows the
invariant that the database claims to enforce but now is violated.

Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=review021 SLICE=<path to slice> python3 db_attacks.py [D01 D05 ...]
Verdict: FINDING = the write was committed and the proof shows the violation; held = the DB refused.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

SLICE = Path(os.environ.get("SLICE", Path(__file__).resolve().parent.parent / "slice"))

PRE = """SET SESSION AUTHORIZATION ac_loader;
BEGIN;
CREATE FUNCTION pg_temp.nowz() RETURNS text LANGUAGE sql AS $$ SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') $$;
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
-- new Check in prj_compliance, cloned from chk_tenders_1
CREATE FUNCTION pg_temp.newcheck(id text, subj text, prof text, mk jsonb, req timestamptz DEFAULT now()) RETURNS void LANGUAGE sql AS $$
INSERT INTO ac.checks (check_id, project_id, subject_entity_id, profile, status, requested_at, completed_at, marking, body, as_of)
SELECT id, project_id, subj, prof, 'IN_PROGRESS', req, NULL, mk,
       body || jsonb_build_object('check_id', id, 'subject_entity_id', subj, 'profile', prof, 'status', 'IN_PROGRESS', 'marking', mk) - 'previous_check_id',
       (req AT TIME ZONE 'UTC')::date
FROM ac.checks WHERE check_id = 'chk_tenders_1' $$;
"""
CL = lambda ch: "'clm:sha256:" + ch * 64 + "'"  # noqa: E731
RESTR = '{"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET", "OFFICIAL_USE"]}'
CSPD = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'

ATTACKS = [
    # ------------------------------------------------------------------ identity (D4)
    ("D01", "P0", "DELETE ключа идентичности освобождает ОГРН: вторая ACTIVE-карточка той же организации",
     """DELETE FROM ac.entity_keys WHERE owner_entity_id = 'ent_d_developer';
INSERT INTO ac.entities SELECT 'ent_dup_org', project_id, entity_type, identity, 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_developer';
INSERT INTO ac.entity_keys VALUES ('prj_dossier', 'ORGANIZATION', 'ru.ogrn', '1215000007310', 'ent_dup_org', 'STRONG', NULL),
                                  ('prj_dossier', 'ORGANIZATION', 'ru.inn', '5012007313', 'ent_dup_org', 'STRONG', NULL);""",
     "SELECT 'ACTIVE с ОГРН 1215000007310 в prj_dossier: ' || count(*) FROM ac.entities WHERE project_id = 'prj_dossier' AND identity->>'ogrn' = '1215000007310' AND status = 'ACTIVE'"),
    ("D02", "P0", "сущность без строк entity_keys: БД не выводит ключи из identity, дубль Ломова (тот же ИНН) принят",
     "INSERT INTO ac.entities SELECT 'ent_dup_lomov', project_id, entity_type, identity, 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_lomov';",
     "SELECT 'ACTIVE с ИНН 695203141810 в prj_dossier: ' || count(*) FROM ac.entities WHERE project_id = 'prj_dossier' AND identity->>'inn' = '695203141810' AND status = 'ACTIVE'"),
    ("D03", "P0", "UPDATE ключа (значение/тип) и ложный ИНН для told_apart: слабый ключ обойдён",
     """UPDATE ac.entity_keys SET value = 'x' WHERE owner_entity_id = 'ent_d_lomov' AND scheme = 'ru.inn';
INSERT INTO ac.entities SELECT 'ent_dup_lomov', project_id, entity_type, identity, 'ACTIVE', NULL, NULL, created_at, marking FROM ac.entities WHERE entity_id = 'ent_d_lomov';
INSERT INTO ac.entity_keys VALUES ('prj_dossier', 'PERSON', 'ru.inn', '695203141810', 'ent_dup_lomov', 'STRONG', NULL);
INSERT INTO ac.entity_keys SELECT project_id, entity_type, scheme, value, 'ent_dup_lomov', 'WEAK', qual FROM ac.entity_keys WHERE owner_entity_id = 'ent_d_lomov' AND strength = 'WEAK';""",
     "SELECT 'владельцев ключа ФИО+дата Ломова: ' || count(DISTINCT owner_entity_id) || '; ACTIVE с ИНН Ломова: ' || (SELECT count(*) FROM ac.entities WHERE identity->>'inn' = '695203141810' AND project_id = 'prj_dossier') FROM ac.entity_keys WHERE scheme = 'person.fio_dob' AND project_id = 'prj_dossier' AND value LIKE 'ломов аркадий%'"),
    ("D04", "P1", "омоним после неквалифицированного оригинала: пометка у новой сущности не помогает, а старую нельзя изменить (ENTITY_IMMUTABLE)",
     """INSERT INTO ac.entities VALUES ('ent_wk_blue2', 'prj_wiki_whales', 'CONCEPT', '{"label": "синий кит", "lang": "ru", "namespace": "whales", "disambiguator": "colour-name"}', 'ACTIVE', NULL, NULL, now(), '{"level": "PUBLIC", "categories": []}');
INSERT INTO ac.entity_keys SELECT project_id, entity_type, scheme, value, 'ent_wk_blue2', 'WEAK', 'colour-name' FROM ac.entity_keys WHERE owner_entity_id = 'ent_wk_blue' AND strength = 'WEAK';""",
     None),
    ("D04b", "P1", "... и исправить оригинал (добавить ему disambiguator) база не даёт",
     """UPDATE ac.entities SET identity = identity || '{"disambiguator": "whale"}' WHERE entity_id = 'ent_wk_blue';""", None),
    # ------------------------------------------------------------------ provenance
    ("D05", "P0", "обход pg_trigger_depth(): доказательство, которого нет в теле утверждения, вписано через триггер временной таблицы",
     """CREATE TEMP TABLE t(x int);
CREATE FUNCTION pg_temp.inj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO ac.claim_evidence (claim_id, ord, tenant_id, source_id, span_start, span_end, quote_sha256, quote, graph_node)
  SELECT c.claim_id, 99, e.tenant_id, e.source_id, e.span_start, e.span_end, e.quote_sha256, e.quote, NULL
  FROM ac.claims c, ac.claim_evidence e
  WHERE c.subject = 'ent_d_lomov' AND c.predicate = 'person.birth_date'
    AND e.claim_id = (SELECT claim_id FROM ac.claims WHERE predicate = 'wiki.is_a' ORDER BY claim_id LIMIT 1) AND e.ord = 0;
  RETURN NULL;
END $$;
CREATE TRIGGER inj AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION pg_temp.inj();
INSERT INTO t VALUES (1);""",
     "SELECT 'доказательств в теле: ' || jsonb_array_length(c.body->'evidence') || ', строк claim_evidence: ' || (SELECT count(*) FROM ac.claim_evidence e WHERE e.claim_id = c.claim_id) || ', цитата ord=99 в проекции: ' || coalesce((SELECT quote FROM ac.claim_provenance p WHERE p.claim_id = c.claim_id AND p.ord = 99), '-') FROM ac.claims c WHERE c.subject = 'ent_d_lomov' AND c.predicate = 'person.birth_date'"),
    ("D06", "P0", "повышение маркировки источника UPDATE-ом: существующие PUBLIC-утверждения теперь шире источника; понижение = рассекречивание",
     f"""UPDATE ac.sources SET marking = '{RESTR}', body = jsonb_set(body, '{{marking}}', '{RESTR}')
 WHERE source_id IN (SELECT source_id FROM ac.claim_evidence e JOIN ac.claims c USING (claim_id) WHERE c.project_id = 'prj_wiki_whales');
UPDATE ac.sources SET marking = '{{"level": "PUBLIC", "categories": []}}', body = jsonb_set(body, '{{marking}}', '{{"level": "PUBLIC", "categories": []}}')
 WHERE marking->>'level' = 'CONFIDENTIAL';""",
     "SELECT 'доказательств, где утверждение шире источника: ' || count(*) FILTER (WHERE NOT ac.dominates(c.marking, s.marking)) || '; CONFIDENTIAL-источников осталось: ' || (SELECT count(*) FROM ac.sources WHERE marking->>'level' = 'CONFIDENTIAL') FROM ac.claim_evidence e JOIN ac.claims c USING (claim_id) JOIN ac.sources s ON s.tenant_id = e.tenant_id AND s.source_id = e.source_id"),
    ("D07", "P1", "DELETE байтов источника, на которые ссылаются доказательства; UPDATE byte_length",
     """DELETE FROM ac.source_bytes WHERE source_id IN (SELECT source_id FROM ac.claim_evidence WHERE claim_id IN (SELECT claim_id FROM ac.claims WHERE project_id = 'prj_dossier'));
UPDATE ac.sources SET byte_length = byte_length + 1, body = jsonb_set(body, '{byte_length}', to_jsonb(byte_length + 1)) WHERE source_id IN (SELECT source_id FROM ac.source_bytes);""",
     "SELECT 'доказательств без байтов: ' || count(*) FILTER (WHERE b.source_id IS NULL) || ' из ' || count(*) || '; источников с byte_length <> длины байтов: ' || (SELECT count(*) FROM ac.sources s JOIN ac.source_bytes b USING (tenant_id, source_id) WHERE length(b.bytes) <> s.byte_length) FROM ac.claim_evidence e LEFT JOIN ac.source_bytes b USING (tenant_id, source_id)"),
    ("D08", "P1", "системное время наблюдений: UPDATE observed_at в будущее / DELETE наблюдений (INSERT штампуется, UPDATE/DELETE нет)",
     """UPDATE ac.source_observations SET observed_at = '2099-01-01T00:00:00Z', ingested_at = '2000-01-01' WHERE source_id IN (SELECT source_id FROM ac.claim_evidence LIMIT 3);
DELETE FROM ac.source_observations WHERE source_id IN (SELECT source_id FROM ac.claim_evidence WHERE claim_id IN (SELECT claim_id FROM ac.claims WHERE project_id = 'prj_wiki_whales'));""",
     "SELECT 'доказательств, где источник получен позже записи утверждения или не получен вовсе: ' || count(*) FROM ac.claim_evidence e JOIN ac.claims c USING (claim_id) WHERE coalesce((SELECT min(observed_at) FROM ac.source_observations o WHERE o.tenant_id = e.tenant_id AND o.source_id = e.source_id), 'infinity') > c.recorded_at"),
    # ------------------------------------------------------------------ Checks
    ("D09", "P0", "Проверка завершена UPDATE-ом с утверждением REFUTED (ACCEPTED на момент завершения не проверяется на этом пути)",
     f"""SELECT pg_temp.clone('tender.participated', {CL('1')});
INSERT INTO ac.claim_reviews VALUES ('rev_rs09', {CL('1')}, 'REFUTED', 'usr_x', now(), now());
SELECT pg_temp.newcheck('chk_rs09', 'ent_k_developer', 'TENDERS_ONLY', '{CSPD}');
INSERT INTO ac.check_findings VALUES ('chk_rs09', 'TENDERS', 'FOUND', 'HIGH');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_rs09', 'TENDERS', {CL('1')});
INSERT INTO ac.check_searches VALUES ('chk_rs09', 'TENDERS', 0, now(), 'tnt_demo', NULL, '{{}}');
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'HIGH', body = body || '{{"status": "COMPLETED"}}' WHERE check_id = 'chk_rs09';""",
     f"SELECT 'chk_rs09: ' || status || ', статус утверждения на момент завершения = ' || ac.status_at({CL('1')}, completed_at) FROM ac.checks WHERE check_id = 'chk_rs09'"),
    ("D10", "P0", "понижение маркировки открытой Проверки после привязки RESTRICTED-утверждения, затем завершение",
     f"""SELECT pg_temp.clone('tender.participated', {CL('2')}, '{{"marking": {RESTR}}}');
INSERT INTO ac.claim_reviews VALUES ('rev_rs10', {CL('2')}, 'ACCEPTED', 'usr_x', now(), now());
SELECT pg_temp.newcheck('chk_rs10', 'ent_k_developer', 'TENDERS_ONLY', '{RESTR}');
INSERT INTO ac.check_findings VALUES ('chk_rs10', 'TENDERS', 'FOUND', 'LOW');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_rs10', 'TENDERS', {CL('2')});
INSERT INTO ac.check_searches VALUES ('chk_rs10', 'TENDERS', 0, now(), 'tnt_demo', NULL, '{{}}');
UPDATE ac.checks SET marking = '{CSPD}', body = body || '{{"marking": {CSPD}}}' WHERE check_id = 'chk_rs10';
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'LOW', body = body || '{{"status": "COMPLETED"}}' WHERE check_id = 'chk_rs10';""",
     "SELECT 'Проверка ' || (k.marking->>'level') || ' ' || (k.marking->'categories')::text || ' ' || k.status || ', утверждение ' || (c.marking->>'level') || ', dominates=' || ac.dominates(k.marking, c.marking) FROM ac.checks k JOIN ac.check_finding_claims f USING (check_id) JOIN ac.claims c USING (claim_id) WHERE k.check_id = 'chk_rs10'"),
    ("D11", "P1", "смена субъекта открытой Проверки после привязки утверждений, затем завершение",
     f"""SELECT pg_temp.clone('tender.participated', {CL('3')});
INSERT INTO ac.claim_reviews VALUES ('rev_rs11', {CL('3')}, 'ACCEPTED', 'usr_x', now(), now());
SELECT pg_temp.newcheck('chk_rs11', 'ent_k_developer', 'TENDERS_ONLY', '{CSPD}');
INSERT INTO ac.check_findings VALUES ('chk_rs11', 'TENDERS', 'FOUND', 'LOW');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_rs11', 'TENDERS', {CL('3')});
INSERT INTO ac.check_searches VALUES ('chk_rs11', 'TENDERS', 0, now(), 'tnt_demo', NULL, '{{}}');
UPDATE ac.checks SET subject_entity_id = 'ent_k_lomov', body = body || '{{"subject_entity_id": "ent_k_lomov"}}' WHERE check_id = 'chk_rs11';
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'LOW', body = body || '{{"status": "COMPLETED"}}' WHERE check_id = 'chk_rs11';""",
     "SELECT 'субъект Проверки ' || k.subject_entity_id || ', субъект утверждения ' || c.subject || ', объект ' || coalesce(c.object_entity, '-') FROM ac.checks k JOIN ac.check_finding_claims f USING (check_id) JOIN ac.claims c USING (claim_id) WHERE k.check_id = 'chk_rs11'"),
    ("D12", "P1", "тело Проверки расходится с колонками и строками; requested_at задним числом делает 25-летний «поиск» допустимым",
     """SELECT pg_temp.newcheck('chk_rs12', 'ent_k_developer', 'TENDERS_ONLY', '""" + CSPD + """', '2001-01-01T00:00:00Z');
INSERT INTO ac.check_findings VALUES ('chk_rs12', 'TENDERS', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_rs12', 'TENDERS', 0, '2001-06-01T00:00:00Z', 'tnt_demo', NULL, '{"search_scope": "x", "query": "x"}');
UPDATE ac.checks SET status = 'COMPLETED', completed_at = now(), overall_risk = 'NONE',
  body = body || '{"status": "COMPLETED", "completed_at": "2020-01-01T00:00:00Z", "overall_risk": "HIGH", "as_of": "2020-01-01",
                  "findings": [{"dimension": "TENDERS", "result": "FOUND", "risk": "HIGH", "claim_ids": [], "searches": []}]}' WHERE check_id = 'chk_rs12';""",
     "SELECT 'колонки: risk=' || overall_risk || ' completed=' || completed_at::date || ' requested=' || requested_at::date || ' | тело: risk=' || (body->>'overall_risk') || ' completed=' || (body->>'completed_at') || ' findings=' || (body->'findings'->0->>'result') || ' | строка: ' || (SELECT result FROM ac.check_findings WHERE check_id = 'chk_rs12') FROM ac.checks WHERE check_id = 'chk_rs12'"),
    ("D13", "P2", "дописать след поиска в ЗАКРЫТУЮ Проверку (строки check_searches не защищены CHECK_CLOSED)",
     "INSERT INTO ac.check_searches VALUES ('chk_full_1', 'COURT', 99, now(), 'tnt_demo', NULL, '{\"search_scope\": \"задним числом\", \"query\": \"x\"}');",
     "SELECT 'строк следа поиска после закрытия chk_full_1: ' || count(*) FROM ac.check_searches s JOIN ac.checks k USING (check_id) WHERE k.check_id = 'chk_full_1' AND s.performed_at > k.completed_at"),
    # ------------------------------------------------------------------ registries and projects
    ("D23", "P1", "cancelled_at задаёт пишущий: Проверка отменена «в 2099 году» (completed_at штампуется, cancelled_at — нет)",
     """UPDATE ac.checks SET status = 'CANCELLED', cancelled_at = '2099-01-01T00:00:00Z', body = body || '{"status": "CANCELLED"}' WHERE check_id = 'chk_tenders_1';""",
     "SELECT 'chk_tenders_1: ' || status || ' cancelled_at=' || cancelled_at FROM ac.checks WHERE check_id = 'chk_tenders_1'"),
    ("D14", "P1", "живая роль меняет реестр: профиль FULL из одного измерения, domain person.birth_date += ORGANIZATION, продукт проекта Compliance",
     f"""UPDATE ac.check_profiles SET dimensions = ARRAY['TENDERS'] WHERE profile = 'FULL';
UPDATE ac.predicates SET domain = domain || 'ORGANIZATION'::text WHERE predicate_id = 'person.birth_date';
SELECT pg_temp.clone('person.birth_date', {CL('4')}, '{{"subject": "ent_d_developer"}}');
UPDATE ac.projects SET product = 'DOSSIER', body = body || '{{"product": "DOSSIER"}}' WHERE project_id = 'prj_compliance';""",
     f"SELECT 'FULL=' || (SELECT array_to_string(dimensions, ',') FROM ac.check_profiles WHERE profile = 'FULL') || '; дата рождения у ' || (SELECT e.entity_type FROM ac.claims c JOIN ac.entities e ON e.entity_id = c.subject WHERE c.claim_id = {CL('4')}) || '; Проверок вне COMPLIANCE: ' || (SELECT count(*) FROM ac.checks k JOIN ac.projects p USING (project_id) WHERE p.product <> 'COMPLIANCE')"),
    # ------------------------------------------------------------------ receipts
    ("D15", "P1", "receipt: строки receipt_claims/receipt_inputs не связаны с подписанным телом (emitted_claim_ids, input_source_ids); подпись — мусор",
     f"""SELECT pg_temp.clone('ts.instance_of', {CL('5')});
INSERT INTO ac.artifact_receipts SELECT 'rcp:sha256:' || repeat('9', 64), project_id, tenant_id, key_id, service_id, now(),
       body || jsonb_build_object('receipt_id', 'rcp:sha256:' || repeat('9', 64), 'issued_at', pg_temp.nowz(), 'signature', 'AAAA',
                                  'emitted_claim_ids', '["clm:sha256:{'0' * 64}"]'::jsonb, 'input_source_ids', '[]'::jsonb) FROM ac.artifact_receipts LIMIT 1;
INSERT INTO ac.receipt_inputs SELECT 'rcp:sha256:' || repeat('9', 64), tenant_id, source_id FROM ac.receipt_inputs;
INSERT INTO ac.receipt_claims VALUES ('rcp:sha256:' || repeat('9', 64), {CL('5')});
INSERT INTO ac.receipt_inputs SELECT receipt_id, tenant_id, (SELECT source_id FROM ac.sources WHERE source_id NOT IN (SELECT source_id FROM ac.receipt_inputs) LIMIT 1) FROM ac.artifact_receipts WHERE receipt_id <> 'rcp:sha256:' || repeat('9', 64);""",
     f"SELECT 'утверждение в теле receipt: ' || (r.body->'emitted_claim_ids' ? {CL('5')}) || '; привязано строкой: ' || EXISTS (SELECT 1 FROM ac.receipt_claims x WHERE x.claim_id = {CL('5')} AND x.receipt_id = r.receipt_id) || '; подпись=' || (r.body->>'signature') || '; входов у исходного receipt: в теле ' || (SELECT jsonb_array_length(body->'input_source_ids') FROM ac.artifact_receipts WHERE receipt_id <> r.receipt_id) || ', строк ' || (SELECT count(*) FROM ac.receipt_inputs i JOIN ac.artifact_receipts a USING (receipt_id) WHERE a.receipt_id <> r.receipt_id) FROM ac.artifact_receipts r WHERE r.receipt_id = 'rcp:sha256:' || repeat('9', 64)"),
    # ------------------------------------------------------------------ merges and time
    ("D16", "P1", "цепочка слияний: выживший Ломов слит в новую карточку; дубль остаётся merged_into MERGED-сущности (валидатор такой набор отвергает)",
     """INSERT INTO ac.entities VALUES ('ent_d_lomov2', 'prj_dossier', 'PERSON', '{"surname": "Ломов", "given_name": "Аркадий", "disambiguator": "later-card"}', 'ACTIVE', NULL, NULL, now(), '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}');
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_d_lomov2' WHERE entity_id = 'ent_d_lomov';""",
     "SELECT e.entity_id || ' -> ' || e.merged_into || ' (статус цели ' || t.status || ')' FROM ac.entities e JOIN ac.entities t ON t.entity_id = e.merged_into WHERE t.status <> 'ACTIVE'"),
    ("D17", "P2", "created_at сущности задаёт пишущий: будущее 2099 принято и навсегда блокирует слияние/вывод этой сущности",
     """INSERT INTO ac.entities VALUES ('ent_future', 'prj_dossier', 'PERSON', '{"surname": "Будущев", "given_name": "Ян", "disambiguator": "from-2099"}', 'ACTIVE', NULL, NULL, '2099-01-01', '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}');""",
     None),
    ("D17b", "P2", "... попытка вывести её из оборота",
     """INSERT INTO ac.entities VALUES ('ent_future', 'prj_dossier', 'PERSON', '{"surname": "Будущев", "given_name": "Ян", "disambiguator": "from-2099"}', 'ACTIVE', NULL, NULL, '2099-01-01', '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}');
COMMIT; BEGIN;
UPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = 'ent_future';""", None),
    ("D18", "P2", "окно 5 минут: живое утверждение с recorded_at на 4 минуты раньше транзакции принято",
     f"""SELECT pg_temp.clone('person.birth_date', {CL('6')}, jsonb_build_object('recorded_at', to_char((now() - interval '4 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')));""",
     f"SELECT 'recorded_at - ingested_at = ' || (recorded_at - ingested_at)::text FROM ac.claims WHERE claim_id = {CL('6')}"),
]

# attacks run with a different session identity
SPECIAL = [
    ("D19", "P1", "модель ролей харнесса: после SET ROLE ac_loader (сессия суперпользователя) можно SET ROLE ac_migrator и писать историю",
     """BEGIN;
SET ROLE ac_loader;
SET ROLE ac_migrator;
SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews SELECT 'rev_rs19', claim_id, 'REFUTED', 'usr_x', '2026-09-26T14:59:00Z', '2026-09-26T14:59:30Z'
  FROM ac.check_finding_claims WHERE check_id = 'chk_full_1' LIMIT 1;""",
     "SELECT 'рецензия REFUTED задним числом: recorded_at=' || recorded_at || ', статус утверждения на момент завершения chk_full_1 = ' || ac.status_at(claim_id, (SELECT completed_at FROM ac.checks WHERE check_id = 'chk_full_1')) FROM ac.claim_reviews WHERE review_id = 'rev_rs19'"),
    ("D19b", "-", "контроль: при SET SESSION AUTHORIZATION ac_loader переход в ac_migrator запрещён",
     "SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nSET ROLE ac_migrator;", None),
    ("D20", "P2", "ac_migrator задним числом меняет основание ЗАКРЫТОЙ Проверки (REFUTED за 30 с до её завершения) — окно истории не ограничено",
     """SET SESSION AUTHORIZATION ac_migrator;
BEGIN;
SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews SELECT 'rev_rs20', claim_id, 'REFUTED', 'usr_x', '2026-09-26T14:59:00Z', '2026-09-26T14:59:30Z'
  FROM ac.check_finding_claims WHERE check_id = 'chk_full_1' LIMIT 1;""",
     "SELECT 'статус утверждения закрытой chk_full_1 на момент её завершения = ' || ac.status_at(claim_id, (SELECT completed_at FROM ac.checks WHERE check_id = 'chk_full_1')) FROM ac.claim_reviews WHERE review_id = 'rev_rs20'"),
    ("D21", "P2", "ac_trust_admin задним числом снимает отзыв и подменяет открытый ключ (реестр доверия не версионируется)",
     """SET SESSION AUTHORIZATION ac_trust_admin;
BEGIN;
UPDATE ac_trust.keys SET public_key = repeat('A', 43), revoked_at = NULL, not_before = '2000-01-01' WHERE key_id = 'key_ts_1';""",
     "SELECT 'key_ts_1: not_before=' || not_before::date || ' public_key=' || left(public_key, 8) || '…' FROM ac_trust.keys WHERE key_id = 'key_ts_1'"),
]


def psql(sql, user_sql=True):
    return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"], input=sql, capture_output=True, text=True)


def reload():
    r = subprocess.run([sys.executable, str(SLICE / "load_s1.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def race():
    """D22: concurrent weak-key inserts (trigger without lock) -> two owners of one weak key."""
    reload()
    body = """SET SESSION AUTHORIZATION ac_loader;
BEGIN;
INSERT INTO ac.entities VALUES ('ent_race_{s}', 'prj_dossier', 'PERSON', '{{"surname": "Иванов", "given_name": "Иван", "birth_date": "1980-01-01"}}', 'ACTIVE', NULL, NULL, now(), '{{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}}');
INSERT INTO ac.entity_keys VALUES ('prj_dossier', 'PERSON', 'person.fio_dob', 'иванов иван|1980-01-01', 'ent_race_{s}', 'WEAK', NULL);
SELECT pg_sleep({d});
COMMIT;
"""
    p1 = subprocess.Popen(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p1.stdin.write(body.format(s="a", d=3)); p1.stdin.close()  # noqa: E702
    time.sleep(1)
    r2 = psql(body.format(s="b", d=0))
    p1.wait()
    e1 = p1.stderr.read().strip()
    proof = psql("SELECT 'владельцев слабого ключа иванов иван|1980-01-01 (оба без пометки): ' || count(*) FROM ac.entity_keys WHERE value = 'иванов иван|1980-01-01'").stdout.strip()
    seq_ = psql(body.format(s="c", d=0)).stderr.strip().splitlines()
    ok = not e1 and r2.returncode == 0
    print(f"D22 {'FINDING' if ok else 'held':<7} P1 | гонка слабых ключей: два параллельных INSERT без блокировки | "
          f"s1={e1 or 'COMMIT'} s2={(r2.stderr.strip() or 'COMMIT')[:60]} | {proof} | контроль (третий, последовательно): {(seq_ or ['COMMIT'])[0][:70]}")


def main():
    only = set(sys.argv[1:])
    found = 0
    for aid, sev, desc, sql, proof in ATTACKS + SPECIAL:
        if only and aid not in only:
            continue
        reload()
        full = sql if aid in {a[0] for a in SPECIAL} else PRE + sql
        r = psql(full + "\nCOMMIT;\n")
        committed = r.returncode == 0
        err = (r.stderr.strip().splitlines() or [""])[0].replace("psql:<stdin>:", "")
        pr = psql(proof).stdout.strip().replace("\n", " ; ") if (proof and committed) else ""
        verdict = "FINDING" if committed and sev != "-" else ("held" if not committed else "ok")
        if aid in ("D04", "D04b", "D17b", "D19b"):
            verdict = "FINDING" if not committed and aid != "D19b" else ("ok" if aid == "D19b" and not committed else verdict)
        found += verdict == "FINDING"
        print(f"{aid:<4} {verdict:<7} {sev} | {desc} | {'COMMIT' if committed else err[:150]}{' | ' + pr if pr else ''}", flush=True)
    if not only or "D22" in only:
        race()
    reload()


if __name__ == "__main__":
    main()

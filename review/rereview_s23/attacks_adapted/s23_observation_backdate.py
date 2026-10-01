#!/usr/bin/env python3
"""S23-02: ac_migrator (historical mode, after the seal) adds an EARLIER observation of a source cited by a Check
closed after the seal -> evidence.first_observed_at in the closed Check's report changes, and so does its digest.
(S22-05 closed the search / review / finding paths, not source_observations.)"""
import hashlib
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
MC = '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}'
TEXT = "Новая статья: к ООО «Заречье-Девелопмент» предъявлен ещё один иск."
B = TEXT.encode()
SID = "src:sha256:" + hashlib.sha256(B).hexdigest()
QSHA = hashlib.sha256(B).hexdigest()
CID = "clm:sha256:" + "ab" * 32

C.reload()
time.sleep(2)
C.ok(f"""BEGIN;
INSERT INTO ac.sources VALUES ('tnt_demo', '{SID}', {len(B)}, '{{"level": "PUBLIC", "categories": []}}',
  jsonb_build_object('source_id', '{SID}', 'tenant_id', 'tnt_demo', 'byte_length', {len(B)}, 'title', 'Новая статья', 'source_kind', 'MEDIA',
                     'marking', '{{"level": "PUBLIC", "categories": []}}'::jsonb));
INSERT INTO ac.source_bytes VALUES ('tnt_demo', '{SID}', convert_to('{TEXT}', 'UTF8'));
INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES ('tnt_demo', '{SID}', now(), 'https://x/1', 'crawler');
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT '{CID}', 'prj_compliance', 'tnt_demo', 'ent_k_developer', 'media.negative_mention', NULL, 'HUMAN', now(), '{MC}',
  jsonb_build_object('kind', 'Claim', 'claim_id', '{CID}', 'project_id', 'prj_compliance', 'subject', 'ent_k_developer',
    'predicate', 'media.negative_mention', 'object', jsonb_build_object('literal', jsonb_build_object('type', 'STRING', 'value', 'ещё один иск')),
    'qualifiers', jsonb_build_object('severity', 'MEDIUM'), 'marking', '{MC}'::jsonb, 'produced_by', '{{"kind": "HUMAN", "actor_id": "usr_x"}}'::jsonb,
    'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'evidence', jsonb_build_array(jsonb_build_object('source_id', '{SID}', 'span', jsonb_build_object('start', 0, 'end', {len(B)}),
                                                     'quote_sha256', '{QSHA}')));
INSERT INTO ac.claim_reviews VALUES ('rev_new_1', '{CID}', 'ACCEPTED', 'usr_x', now(), now());
INSERT INTO ac.checks VALUES ('chk_obs', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
  (now() AT TIME ZONE 'UTC')::date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_obs', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));
COMMIT;""", "ac_loader")
time.sleep(1.1)
C.ok(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_obs', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_obs', 'NEGATIVE', '{CID}');
INSERT INTO ac.check_searches VALUES ('chk_obs', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН", "search_scope": "СМИ"}}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', body = body || '{{"status": "COMPLETED", "overall_risk": "MEDIUM"}}' WHERE check_id = 'chk_obs';
COMMIT;""", "ac_loader")


def fo(r):
    return [e["first_observed_at"] for d in r["dimensions"] for f in d.get("facts", []) for c in f["claims"] for e in c["evidence"]]


before = C.js("SELECT ac.check_report('chk_obs');", "ac_rd_full")
time.sleep(1.1)
e = C.err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by)
VALUES ('tnt_demo', '{SID}', (SELECT max(sealed_at) + interval '1 second' FROM ac.history_seals), 'https://x/backdated', 'migrator');
COMMIT;""", "ac_migrator")
after = C.js("SELECT ac.check_report('chk_obs');", "ac_rd_full")
print("migrator insert:", e)
print("first_observed_at before:", fo(before), before["digest"])
print("first_observed_at after: ", fo(after), after["digest"])
C.verdict("S23-02", before["digest"] != after["digest"],
          "ac_migrator задним числом (после печати) меняет first_observed_at в отчёте закрытой Проверки")

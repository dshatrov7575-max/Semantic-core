#!/usr/bin/env python3
"""S22-06: ac.dominates() returns NULL for a marking whose level is not one of the four known values (typo,
lower case, missing). Every guard uses `IF NOT ac.dominates(..) THEN fail` and ac.require_clearance uses
`IF clr IS NULL OR NOT ac.dominates(..)` — NULL is not TRUE, so the check is skipped (fail-open). The DB stores such
markings (no CHECK on marking shape). A claim marked {"level": "Restricted"} cites a RESTRICTED source (evidence_guard
passes) and ac.provenance() shows the RESTRICTED quote to a PUBLIC reader."""
import hashlib
import time
from common import reload, ok, err, js, verdict

reload()
text = "СЕКРЕТНЫЙ ДОКЛАД: синий кит замечен у объекта 7".encode()
sid = "src:sha256:" + hashlib.sha256(text).hexdigest()
qsha = hashlib.sha256(text).hexdigest()
cid = "clm:sha256:" + "ab" * 32
ok(f"""BEGIN;
INSERT INTO ac.sources VALUES ('tnt_demo', '{sid}', {len(text)}, '{{"level": "RESTRICTED", "categories": []}}',
  jsonb_build_object('source_id', '{sid}', 'tenant_id', 'tnt_demo', 'byte_length', {len(text)}, 'title', 'Секретный доклад',
                     'marking', '{{"level": "RESTRICTED", "categories": []}}'::jsonb));
INSERT INTO ac.source_bytes VALUES ('tnt_demo', '{sid}', decode('{text.hex()}', 'hex'));
INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES ('tnt_demo', '{sid}', now(), 'urn:x', 'svc_x');
COMMIT;""", "ac_loader")
M = '{"level": "Restricted", "categories": []}'   # a typo'd level
time.sleep(1.2)
r = err(f"""BEGIN;
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT '{cid}', 'prj_wiki_whales', 'tnt_demo', 'ent_wk_blue', 'wiki.property', NULL, 'HUMAN', now(), '{M}'::jsonb,
  jsonb_build_object('claim_id', '{cid}', 'project_id', 'prj_wiki_whales', 'subject', 'ent_wk_blue', 'predicate', 'wiki.property',
    'object', jsonb_build_object('literal', jsonb_build_object('type', 'STRING', 'value', 'секрет')),
    'qualifiers', jsonb_build_object('property', 'наблюдение'),
    'produced_by', jsonb_build_object('kind', 'HUMAN', 'actor_id', 'usr_x'), 'marking', '{M}'::jsonb,
    'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'evidence', jsonb_build_array(jsonb_build_object('source_id', '{sid}', 'span', jsonb_build_object('start', 0, 'end', {len(text)}),
                                                     'quote_sha256', '{qsha}')));
COMMIT;""", "ac_loader")
print("ac_loader: claim with marking level 'Restricted' citing a RESTRICTED source:", r)
e0 = err(f"SELECT ac.provenance('{cid}');", "ac_rd_none")
print("reader with no clearance for the project:", e0)
try:
    pv = js(f"SELECT ac.provenance('{cid}');", "ac_rd_public")
    quote = pv["evidence"][0]["quote"]
    print("PUBLIC reader provenance:", pv["text"], "| quote:", quote, "| source:", pv["evidence"][0]["source_title"])
    leak = "СЕКРЕТНЫЙ" in quote
except RuntimeError as ex:
    print("PUBLIC reader:", ex)
    leak = False
verdict("S22-06", r == "(выполнено)" and leak,
        "маркировка с неизвестным уровнем проходит все проверки доминирования (NULL); цитата RESTRICTED-источника выдана читателю PUBLIC")

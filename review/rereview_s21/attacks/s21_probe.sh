#!/bin/bash
# Quick confirmation battery for RS-01..04 P0 fixes + new merge attacks, as live role ac_loader.
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=${PGDATABASE:-review022}
SLICE=${SLICE:-/home/claude/s21/slice}
run(){ echo "--- $1"; python3 $SLICE/load_s1.py >/dev/null 2>&1; psql -X -q -At <<SQL
SET SESSION AUTHORIZATION ac_loader;
BEGIN;
$2
COMMIT;
SQL
}
run "RS-01 direct entity_keys write"          "INSERT INTO ac.entity_keys VALUES ('prj_dossier','PERSON','ru.inn','695203141810','ent_d_lomov_media','STRONG',NULL);"
run "RS-01 delete a key then dup"             "DELETE FROM ac.entity_keys WHERE owner_entity_id='ent_d_developer';"
run "RS-02 direct claim_evidence write"       "INSERT INTO ac.claim_evidence VALUES ((SELECT claim_id FROM ac.claims LIMIT 1),99,(SELECT tenant_id FROM ac.claims LIMIT 1),(SELECT source_id FROM ac.sources LIMIT 1),0,1,repeat('0',64),NULL,NULL);"
run "RS-04 update source marking"             "UPDATE ac.sources SET marking='{\"level\":\"PUBLIC\",\"categories\":[]}' WHERE marking->>'level'='CONFIDENTIAL';"
run "RS-04 delete source bytes"               "DELETE FROM ac.source_bytes;"
run "RS-03 complete check w/ REFUTED claim (UPDATE path)"  "UPDATE ac.checks SET status='COMPLETED', completed_at=now(), overall_risk='NONE' WHERE check_id='chk_full_1';"
run "NEW merge chain: retire survivor then merge it onward" "
UPDATE ac.entities SET status='MERGED', merged_into='ent_d_developer' WHERE entity_id='ent_d_lomov_media' AND entity_type='ORGANIZATION';"

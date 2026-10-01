-- S21-01: SQL identity norm (keys_s1.sql) diverges from validator (Python) on halfwidth CJK forms
-- (U+FF5F..FFDC). validator.tag_norm applies NFKC folding halfwidth katakana ｱ(FF71) -> ア(30A2); ac.tag_norm does not.
-- Result: two EQUIPMENT the validator treats as ONE entity are accepted by the DB as two (duplicate identity, RS-01).
SET SESSION AUTHORIZATION ac_loader;
BEGIN;
INSERT INTO ac.entities VALUES ('ent_hw_1','prj_ts_pumps','EQUIPMENT',
  jsonb_build_object('tag', U&'\30A2' || '-9', 'site_id','site_ns2'),'ACTIVE',NULL,NULL,now(),
  '{"level":"INTERNAL","categories":[]}');
INSERT INTO ac.entities VALUES ('ent_hw_2','prj_ts_pumps','EQUIPMENT',
  jsonb_build_object('tag', U&'\FF71' || '-9', 'site_id','site_ns2'),'ACTIVE',NULL,NULL,now(),
  '{"level":"INTERNAL","categories":[]}');
COMMIT;
SELECT 'EQUIPMENT в site_ns2 с NFKC-эквивалентным тегом (валидатор считает их одной сущностью): '
       || count(*) FROM ac.entities WHERE entity_id IN ('ent_hw_1','ent_hw_2');
SELECT owner_entity_id, scheme, value FROM ac.entity_keys WHERE owner_entity_id IN ('ent_hw_1','ent_hw_2');

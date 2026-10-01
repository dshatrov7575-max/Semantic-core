#!/usr/bin/env python3
"""S23-08: the database does not constrain qualifier types / date values that the projections cast
(share_bp::numeric, contract_amount_minor::bigint, valid_from::date). One claim written by the application
role ac_app (bypassing the loader, as the DB threat model assumes) makes ac.dossier() fail for EVERY reader.
S23-09: template placeholders are re-expanded inside substituted values (display name / qualifier text)."""
import common as C

C.reload()
ev = C.ok("SELECT body->'evidence' FROM ac.claims WHERE predicate = 'corp.founder_of' AND body->'qualifiers'->>'share_bp' = '6000'")
MPD = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}'


def claim(cid, quals, extra=""):
    return f"""BEGIN;
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT '{cid}', 'prj_dossier', 'tnt_demo', 'ent_d_lomov', 'corp.founder_of', 'ent_d_trub', 'HUMAN', now(), '{MPD}',
  jsonb_build_object('kind', 'Claim', 'claim_id', '{cid}', 'project_id', 'prj_dossier', 'subject', 'ent_d_lomov',
    'predicate', 'corp.founder_of', 'object', '{{"entity": "ent_d_trub"}}'::jsonb, 'qualifiers', '{quals}'::jsonb {extra},
    'marking', '{MPD}'::jsonb, 'produced_by', '{{"kind": "HUMAN", "actor_id": "usr_x"}}'::jsonb,
    'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'evidence', '{ev}'::jsonb);
COMMIT;"""


ok0 = C.err("SELECT ac.dossier('prj_dossier', 'ent_d_lomov') IS NOT NULL;", "ac_rd_full")
w = C.err(claim("clm:sha256:" + "c1" * 32, '{"share_bp": "шестьдесят"}'), "ac_app")
e = C.err("SELECT ac.dossier('prj_dossier', 'ent_d_lomov') IS NOT NULL;", "ac_rd_full")
e2 = C.err("SELECT ac.dossier('prj_dossier', 'ent_d_trub') IS NOT NULL;", "ac_rd_full")
print("before:", ok0, "| ac_app insert:", w, "| dossier(lomov):", e, "| dossier(trub):", e2)
C.verdict("S23-08a", "(выполнено)" in w and "ERROR" in e, "строка ac_app со строковым share_bp ломает досье для всех читателей")

C.reload()
w = C.err(claim("clm:sha256:" + "c2" * 32, '{"title": "директор"}', ", 'valid_from', '2021-02-30'").replace("corp.founder_of", "corp.director_of"), "ac_app")
e = C.err("SELECT ac.dossier('prj_dossier', 'ent_d_lomov') IS NOT NULL;", "ac_rd_full")
print("valid_from 2021-02-30 insert:", w, "| dossier:", e)
C.verdict("S23-08b", "(выполнено)" in w and "ERROR" in e, "valid_from «2021-02-30» принят базой и ломает досье")

# S23-09: placeholder re-expansion; qualifier title of the same claim is a template fragment
C.reload()
w = C.err(claim("clm:sha256:" + "c3" * 32, '{"share_bp": 100}').replace("corp.founder_of", "corp.director_of")
          .replace('{"share_bp": 100}', '{"title": "{O} и {O}"}'), "ac_app")
d = C.js("SELECT ac.dossier('prj_dossier', 'ent_d_lomov');", "ac_rd_full")
txt = [f["text"] for s in d["sections"] for f in s.get("facts", []) if "Трубопрокат" in f["text"]]
print("insert:", w, "| text:", txt)
C.verdict("S23-09", any(t.count("Трубопрокат") > 1 for t in txt), "плейсхолдер внутри значения квалификатора раскрывается шаблоном")

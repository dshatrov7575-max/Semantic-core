#!/usr/bin/env python3
"""S23-07: dossier digests at a past-but-recent or future as_of are not reproducible: the DB accepts claims with a
writer-supplied recorded_at up to 5 minutes in the past, and as_of in the future is not refused."""
import time
import common as C

C.reload()
ev = C.ok("SELECT body->'evidence' FROM ac.claims WHERE predicate = 'corp.founder_of' AND body->'qualifiers'->>'share_bp' = '6000'")
MPD = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}'
t = C.ok("SELECT now() - interval '1 minute'")
fut = C.ok("SELECT now() + interval '1 day'")
d_past = C.js(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', '{t}');", "ac_rd_full")["digest"]
d_fut = C.js(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', '{fut}');", "ac_rd_full")["digest"]
cid = "clm:sha256:" + "d1" * 32
w = C.err(f"""BEGIN;
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT '{cid}', 'prj_dossier', 'tnt_demo', 'ent_d_lomov', 'corp.founder_of', 'ent_d_trub', 'HUMAN', now(), '{MPD}',
  jsonb_build_object('kind', 'Claim', 'claim_id', '{cid}', 'project_id', 'prj_dossier', 'subject', 'ent_d_lomov',
    'predicate', 'corp.founder_of', 'object', '{{"entity": "ent_d_trub"}}'::jsonb, 'qualifiers', '{{"share_bp": 2500}}'::jsonb,
    'marking', '{MPD}'::jsonb, 'produced_by', '{{"kind": "HUMAN", "actor_id": "usr_x"}}'::jsonb,
    'recorded_at', to_char((now() - interval '4 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'evidence', '{ev}'::jsonb);
COMMIT;""", "ac_loader")
d_past2 = C.js(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', '{t}');", "ac_rd_full")["digest"]
d_fut2 = C.js(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', '{fut}');", "ac_rd_full")["digest"]
print("insert (recorded_at = now - 4 min):", w)
print(f"as_of={t}: {d_past} -> {d_past2}")
print(f"as_of={fut}: {d_fut} -> {d_fut2}")
C.verdict("S23-07", d_past != d_past2 or d_fut != d_fut2, "досье «на момент as_of» в прошлом (окно 5 мин) и в будущем меняется задним числом")

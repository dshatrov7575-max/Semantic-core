#!/usr/bin/env python3
"""S24: DB vs validator parity on qualifier values and literal ranges (S23-08 follow-up).
Each vector is written by ac_app directly (bypassing the loader) and, separately, checked by the normative
validator logic (same predicate spec from core/predicates.json). A vector the validator rejects but the DB accepts
is a parity gap. Afterwards ac.dossier() must still render for a cleared reader."""
import json
import sys
from pathlib import Path

sys.path.insert(0, "/home/claude/s24/s23_attacks_adapted")
import common as C  # noqa: E402

C.reload()
ev = C.ok("SELECT body->'evidence' FROM ac.claims WHERE predicate = 'corp.founder_of' AND body->'qualifiers'->>'share_bp' = '6000'")
MPD = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}'


def claim(cid, pred, obj, quals):
    return f"""BEGIN;
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT '{cid}', 'prj_dossier', 'tnt_demo', 'ent_d_lomov', '{pred}', {("'" + json.loads(obj)["entity"] + "'") if "entity" in obj else "NULL"},
  'HUMAN', now(), '{MPD}',
  jsonb_build_object('kind', 'Claim', 'claim_id', '{cid}', 'project_id', 'prj_dossier', 'subject', 'ent_d_lomov',
    'predicate', '{pred}', 'object', '{obj}'::jsonb, 'qualifiers', '{quals}'::jsonb,
    'marking', '{MPD}'::jsonb, 'produced_by', '{{"kind": "HUMAN", "actor_id": "usr_x"}}'::jsonb,
    'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'evidence', '{ev}'::jsonb);
COMMIT;"""


# (label, predicate, object json, qualifiers json text, validator verdict per core/validator.py rules)
VEC = [
    ("share_bp как 1e2 (JSON-число с экспонентой)", "corp.founder_of", '{"entity": "ent_d_trub"}', '{"share_bp": 1e2}', "reject"),
    ("share_bp = 60.0", "corp.founder_of", '{"entity": "ent_d_trub"}', '{"share_bp": 60.0}', "reject"),
    ("share_bp = true", "corp.founder_of", '{"entity": "ent_d_trub"}', '{"share_bp": true}', "reject"),
    ("share_bp = 0 (ниже min)", "corp.founder_of", '{"entity": "ent_d_trub"}', '{"share_bp": 0}', "reject"),
    ("court: схема идентификатора вне range.schemes", "court.party_to_case",
     '{"literal": {"type": "IDENTIFIER", "scheme": "x.bogus", "value": "A40-1/2026"}}', '{"role": "DEFENDANT"}', "reject"),
]
bad = []
for i, (lbl, pred, obj, q, vexp) in enumerate(VEC):
    C.reload()
    w = C.err(claim("clm:sha256:" + f"{0xd0 + i:02x}" * 32, pred, obj, q), "ac_app")
    db = "accept" if w == "(выполнено)" else "reject"
    d = C.err("SELECT ac.dossier('prj_dossier', 'ent_d_lomov') IS NOT NULL;", "ac_rd_full")
    gap = db != vexp
    bad.append(gap)
    print(f"  {lbl}: DB={db} validator={vexp} | досье: {d[:60]} | {w[:90]}")
C.verdict("S24-QP", any(bad), f"расхождение база/валидатор по квалификаторам и range: {sum(bad)} из {len(bad)}")
C.reload()

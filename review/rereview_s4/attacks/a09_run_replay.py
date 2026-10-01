"""S4R: the SAME TechSense run (same run_id, same graph) ingested twice in the DB via a byte variant of the artifact
(non-canonical JSON: extra whitespace). Validator refuses non-canonical bytes (D8), the DB is the guard for ac_loader.
Expectation per S4-09 «повтор того же прогона отвергнут»: refused. Also: canonical variant with one extra dummy node."""
import sys, json, time, copy, hashlib
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core"); sys.path.insert(0, "/home/claude/as/adapter")
from ingest_s4 import ingest_sql, psql, utc
from jcs import digest, canon_bytes
from fixtures import SEEDS
from vectors import build
from techsense_umr import adapt, _b64u
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import samples as SM
import validator as VAL

ds, tr, ct = build()
recs = lambda k: [r for r in ds["records"] if r["kind"] == k]
PRJ = next(p for p in recs("Project") if p["project_id"] == "prj_ts_pumps")
SRC = {s["source_id"]: s for s in recs("Source")}
# the valve source and run_ts_0002 are already in review041 (s4_tests S4-02); entities: read live ones
out = psql("SELECT json_agg(json_build_object('kind','Entity','entity_id',entity_id,'project_id',project_id,'entity_type',entity_type,"
           "'identity',identity,'status',status,'merged_into',merged_into,'marking',marking)) FROM ac.entities WHERE project_id='prj_ts_pumps';").stdout
ENT = json.loads(out.strip().splitlines()[-1])
src_id = psql("SELECT source_id FROM ac.sources s WHERE body->>'title' = %s;" % ("$q$" + SM.VALVE_TITLE + "$q$")).stdout.strip().splitlines()[-1]
vs = json.loads(psql(f"SELECT body FROM ac.sources WHERE source_id = '{src_id}';").stdout.strip().splitlines()[-1])
vs["content_inline"] = SM.VALVE_TEXT
SRC[src_id] = vs
canon_art = SM.valve_artifact(src_id)              # run_ts_0002, already ingested by s4_tests
print("canonical run_ts_0002 stored:", psql(f"SELECT count(*) FROM ac.artifacts WHERE artifact_digest = 'sha256:{hashlib.sha256(canon_art).hexdigest()}';").stdout.strip())

def live_entities():
    out = psql("SELECT json_agg(json_build_object('kind','Entity','entity_id',entity_id,'project_id',project_id,'entity_type',entity_type,"
               "'identity',identity,'status',status,'merged_into',merged_into,'marking',marking)) FROM ac.entities WHERE project_id='prj_ts_pumps';").stdout
    return json.loads(out.strip().splitlines()[-1])

def redo(variant_bytes, label, with_entities=False):
    rec, iss = utc(3), utc(2)
    res = adapt(canon_art, PRJ, SRC, {}, live_entities(), rec, iss, "key_ts_1", SEEDS["key_ts_1"])
    dg = "sha256:" + hashlib.sha256(variant_bytes).hexdigest()
    out = []
    for r in res.records:
        r = copy.deepcopy(r)
        if r["kind"] == "Claim":
            for e in r["evidence"]:
                e["graph_node"]["artifact_digest"] = dg
            r["claim_id"] = "clm:sha256:" + digest({k: v for k, v in r.items() if k != "claim_id"})
        out.append(r)
    cl = [r for r in out if r["kind"] == "Claim"]
    rc = next(r for r in out if r["kind"] == "ArtifactReceipt")
    rc["artifact_digest"] = dg; rc["emitted_claim_ids"] = [c["claim_id"] for c in cl]
    rc["receipt_id"] = "rcp:sha256:" + digest({k: v for k, v in rc.items() if k not in ("receipt_id", "signature")})
    rc["signature"] = _b64u(Ed25519PrivateKey.from_private_bytes(SEEDS["key_ts_1"]).sign(rc["receipt_id"].encode()))
    newe = [r for r in out if r["kind"] == "Entity"]
    ok, why = VAL.parse_artifact(variant_bytes)
    r = psql(ingest_sql((newe if with_entities else []) + cl + [rc], {dg: variant_bytes}, artifacts=[dg]))
    print(f"[{label}] parse_artifact={'OK' if ok else why} new_entities={len(newe)} | DB: {'ACCEPTED' if r.returncode == 0 else r.stderr.strip()[:200]}")
    time.sleep(1.1)

redo(canon_art, "эталон: канонический прогон run_ts_0002", with_entities=True)
pretty = json.dumps(json.loads(canon_art), ensure_ascii=False, indent=1).encode()
redo(pretty, "тот же прогон run_ts_0002, артефакт с отступами (неканонический)")
dummy = json.loads(canon_art); dummy["nodes"].append({"id": "zz", "type": "CONDITION", "text": "x", "anchor": dummy["nodes"][5]["anchor"]})
redo(canon_bytes(dummy), "тот же прогон run_ts_0002, канонический артефакт + лишний узел")
print("receipts of run_ts_0002:", psql("SELECT count(*) FROM ac.artifact_receipts WHERE body->>'run_id' = 'run_ts_0002';").stdout.strip(),
      "| claims 'номинальное давление' of the valve:", psql("SELECT count(*) FROM ac.claims WHERE subject='ent_ts_valve_a' AND predicate='ts.has_parameter';").stdout.strip())

"""S4R-13 candidate: an artifact can be stored WITHOUT a receipt; with artifacts_one_per_run it then occupies the run id,
and the genuine run with that run_id is refused. Also: is an orphan artifact (no receipt) allowed at all?"""
import sys, json, hashlib
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core"); sys.path.insert(0, "/home/claude/as/adapter")
from ingest_s4 import psql, q, b64
import samples as SM
from jcs import canon_bytes
sid = psql("SELECT source_id FROM ac.sources WHERE body->>'title' = %s;" % q(SM.VALVE_TITLE)).stdout.strip().splitlines()[-1]
junk = json.loads(SM.valve_artifact(sid, run_id="run_ts_0099")); junk["nodes"] = junk["nodes"][:1]
jb = canon_bytes(junk); dg = "sha256:" + hashlib.sha256(jb).hexdigest()
r = psql(f"SET SESSION AUTHORIZATION ac_loader; BEGIN; INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ('tnt_demo', {q(dg)}, {b64(jb)}); COMMIT;")
print("артефакт без receipt (run_ts_0099, один узел), отдельная транзакция ac_loader:", "COMMITTED" if r.returncode == 0 else r.stderr.strip()[:200])
real = SM.valve_artifact(sid, run_id="run_ts_0099"); rd = "sha256:" + hashlib.sha256(real).hexdigest()
r = psql(f"SET SESSION AUTHORIZATION ac_loader; BEGIN; INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ('tnt_demo', {q(rd)}, {b64(real)}); ROLLBACK;")
print("настоящий артефакт прогона run_ts_0099:", "ACCEPTED" if r.returncode == 0 else r.stderr.strip().splitlines()[0][:160])
print("артефактов без receipt в базе:", psql("SELECT count(*) FROM ac.artifacts a WHERE NOT EXISTS (SELECT 1 FROM ac.artifact_receipts r WHERE r.tenant_id=a.tenant_id AND r.body->>'artifact_digest'=a.artifact_digest);").stdout.strip())

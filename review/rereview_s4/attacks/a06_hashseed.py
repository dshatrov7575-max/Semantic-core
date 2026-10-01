import sys, subprocess, hashlib
code = r'''
import sys; sys.path.insert(0,"/home/claude/as/review/rereview_s4/attacks")
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    import a02_adapter as X
import samples as SM
from jcs import canon
ds, tr, ct = X.world()
recs = lambda k: [r for r in ds["records"] if r["kind"] == k]
PRJ = next(p for p in recs("Project") if p["project_id"] == "prj_ts_pumps")
SRC = {s["source_id"]: s for s in recs("Source")}; SRC[X.vs["source_id"]] = X.vs
res = X.adapt(SM.valve_artifact(X.SID, tweak=X.twins), PRJ, SRC, ct, list(reversed(recs("Entity"))), X.REC, X.ISS, "key_ts_1", X.KEY)
import hashlib; print(hashlib.sha256(canon(__import__("json").loads(__import__("json").dumps({"r": res.records, "rep": res.report}))).encode()).hexdigest())
'''
outs = set()
for seed in ["0", "1", "2", "12345"]:
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"})
    outs.add(r.stdout.strip() or r.stderr[-200:])
print("PYTHONHASHSEED 0/1/2/12345, обратный порядок сущностей -> различных результатов:", len(outs), outs)

"""S4R: the validator on the same run ingested twice with two canonical artifacts (one has an extra dummy node)."""
import sys, json, copy
sys.path.insert(0, "/home/claude/as/review/rereview_s4/attacks")
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    import a02_adapter as X
import samples as SM
import validator as VAL
from jcs import canon_bytes
ds, tr, ct = X.world()
recs = lambda k: [r for r in ds["records"] if r["kind"] == k]
PRJ = next(p for p in recs("Project") if p["project_id"] == "prj_ts_pumps")
SRC = {s["source_id"]: s for s in recs("Source")}; SRC[X.SID] = X.vs
a1 = SM.valve_artifact(X.SID)
d = json.loads(a1); d["nodes"].append({"id": "zz", "type": "CONDITION", "text": "x", "anchor": d["nodes"][5]["anchor"]}); a2 = canon_bytes(d)
r1 = X.adapt(a1, PRJ, SRC, ct, recs("Entity"), X.REC, X.ISS, "key_ts_1", X.KEY)
ents = recs("Entity") + [r for r in r1.records if r["kind"] == "Entity"]
r2 = X.adapt(a2, PRJ, SRC, ct, ents, "2026-09-08T09:01:00Z", "2026-09-08T09:01:30Z", "key_ts_1", X.KEY)
ds2 = copy.deepcopy(ds); ds2["records"] += [X.vs] + r1.records + r2.records
ct2 = dict(ct); ct2[r1.artifact_digest] = a1; ct2[r2.artifact_digest] = a2
rep = VAL.validate(ds2, tr, ct2)
print("two receipts of run_ts_0002 (canonical, +dummy node): new entities in run 2 =", len(r2.report["new_entities"]),
      "| validator errors =", rep.codes() or "NONE", "| warnings =", sorted({w["code"] for w in rep.warnings}))

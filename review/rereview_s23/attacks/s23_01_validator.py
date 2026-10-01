#!/usr/bin/env python3
"""S23-01 at ontology level: the normative validator accepts a COMPLETED Check whose previous Check is still open
(or was CANCELLED / completed later than it)."""
import copy, os, sys
CORE = os.path.join(os.environ.get("SLICE", "/home/claude/s23/slice"), "..", "core")
sys.path.insert(0, CORE)
import validator as V
from vectors import build
ds, tr, ct = build()
K = {r["check_id"]: r for r in ds["records"] if r["kind"] == "Check"}
print("chk_full_1.previous =", K["chk_full_1"].get("previous_check_id"), "| chk_tenders_1.status =", K["chk_tenders_1"]["status"])
pv = K["chk_express_1"]
pv["status"] = "IN_PROGRESS"
for f in ("completed_at", "overall_risk"):
    pv.pop(f, None)
r = V.validate(ds, tr, ct)
print("previous IN_PROGRESS, current COMPLETED -> errors:", r.codes())
print("S23-01v:", "FINDING" if not r.errors else "held", "| валидатор принимает закрытую Проверку с открытой предыдущей")

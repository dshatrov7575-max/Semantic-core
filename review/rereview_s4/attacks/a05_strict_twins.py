"""S4R-03 follow-up: strict mode with skeleton twins and NO unmapped relation; PYTHONHASHSEED determinism."""
import sys, os, subprocess, hashlib
sys.path.insert(0, "/home/claude/as/review/rereview_s4/attacks")
import a02_adapter as X  # reruns a02 prints; fine
import samples as SM
def twins_only(art):
    art["nodes"] = [n for n in art["nodes"] if n["id"] != "r5" and n["id"] != "v7"]
    X.twins(art)
print("--- strict, без неотображённых отношений:")
X.go("двойники внутри артефакта, strict=True", SM.valve_artifact(X.SID, tweak=twins_only), extra_src=X.vs, strict=True)

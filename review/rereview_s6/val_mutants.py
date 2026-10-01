#!/usr/bin/env python3
"""S6 review: own mutants of the ORIGINAL rule against the author's vectors (do the vectors notice?)."""
import importlib.util, sys, tempfile, os
sys.path.insert(0, "/home/claude/as/core")
import mutants as MU
from vectors import VECTORS, build
src = open("/home/claude/as/core/validator.py", encoding="utf-8").read()
MINE = [("R1", "проверяется оригинал только первого наблюдения", 'for n, o in enumerate(s["observations"]):\n            og = o.get("original")',
         'for n, o in enumerate(s["observations"][:1]):\n            og = o.get("original")'),
        ("R2", "длина: достаточно, чтобы объект был не короче заявленного", 'or len(ob) != og["byte_length"]:', 'or len(ob) < og["byte_length"]:'),
        ("R3", "длина: достаточно, чтобы объект был не длиннее заявленного", 'or len(ob) != og["byte_length"]:', 'or len(ob) > og["byte_length"]:'),
        ("R4", "оригинал проверяется только у источников с текстом в хранилище", 'og = o.get("original")\n            if og is None:',
         'og = o.get("original")\n            if og is None or sid not in source_bytes:')]
cases = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
d = tempfile.mkdtemp()
for mid, desc, old, new in MINE:
    assert src.count(old) == 1, mid
    p = os.path.join(d, f"validator_{mid}.py"); open(p, "w", encoding="utf-8").write(src.replace(old, new))
    for f in ("core.schema.json", "predicates.json"):
        if not os.path.exists(os.path.join(d, f)): os.symlink("/home/claude/as/core/" + f, os.path.join(d, f))
    if not os.path.exists(os.path.join(d, "schemas")): os.symlink("/home/claude/as/core/schemas", os.path.join(d, "schemas"))
    spec = importlib.util.spec_from_file_location(f"validator_{mid}", p); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    killer = next((k for k in (MU.killed_by(mod, *c) for c in cases) if k), None)
    print(f"{mid} {'KILLED by ' + killer if killer else 'SURVIVED':<22} {desc}")

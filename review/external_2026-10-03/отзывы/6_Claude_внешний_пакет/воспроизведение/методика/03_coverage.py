"""Построчное покрытие validator.py каждым вектором (sys.settrace). Запуск из core/.
Выход: findings/coverage.json  {vector_id: [строки]}, + сводка непокрытых строк."""
import sys, json, types, threading
sys.path.insert(0, '.')
from pathlib import Path
from vectors import VECTORS, build
HERE = Path('.').resolve()
SRC = (HERE / "validator.py").read_text(encoding="utf-8")
FN = "validator_cov"
mod = types.ModuleType("validator_cov"); mod.__file__ = str(HERE / "validator.py")
cur = set()
def local(frame, event, arg):
    if event == "line":
        cur.add(frame.f_lineno)
    return local
def tracer(frame, event, arg):
    if frame.f_code.co_filename == FN:
        cur.add(frame.f_lineno)
        return local
    return None
sys.settrace(tracer)
exec(compile(SRC, FN, "exec"), mod.__dict__)
sys.settrace(None)
module_lines = sorted(cur)
out = {"__module__": module_lines}
cases = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
for v, ds, tr, ct in cases:
    cur = set()
    sys.settrace(tracer)
    try:
        r = mod.validate(ds, tr, ct)
    finally:
        sys.settrace(None)
    vid = v["id"] if v else "BASE"
    if v: assert r.codes() == v["expected"], vid
    out[vid] = sorted(cur)
json.dump(out, open("../findings/coverage.json", "w"))
print("done", len(out))

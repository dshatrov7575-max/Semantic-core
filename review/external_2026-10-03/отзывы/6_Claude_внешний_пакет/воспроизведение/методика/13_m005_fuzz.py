"""M005 («ключи не проверяются» объявлен эквивалентным): в КАЖДЫЙ объект эталонного мира, реестра доверия и артефакта по
очереди добавляется ключ с управляющим символом / суррогатом; сравниваются коды оригинала и мутанта. Запуск из core/."""
import sys, types, copy, json
sys.path.insert(0, ".")
from pathlib import Path
import mutants
from vectors import build, V
SRC = Path("validator.py").read_text(encoding="utf-8")
m = next(x for x in mutants.M if x[0] == "M005")
def load(src):
    mod = types.ModuleType("validator_mut"); mod.__file__ = str(Path("validator.py").resolve())
    exec(compile(src, "validator_mut", "exec"), mod.__dict__); return mod
assert SRC.count(m[2]) == 1
ORIG, MUT = load(SRC), load(SRC.replace(m[2], m[3]))
def dicts(node, p=()):
    if isinstance(node, dict):
        yield p
        for k, v in node.items(): yield from dicts(v, p + (k,))
    elif isinstance(node, list):
        for n, v in enumerate(node): yield from dicts(v, p + (n,))
def get(node, p):
    for k in p: node = node[k]
    return node
def codes(mod, ds, tr, ct):
    try: return mod.validate(ds, tr, ct).codes()
    except BaseException as ex: return ["<исключение %s>" % type(ex).__name__]
ds, tr, ct = build()
diff = total = 0
for label, root in (("dataset", ds), ("trust", tr)):
    paths = list(dicts(root))
    step = 1
    for p in paths[::step]:
        for bad in ("\u0001k", "\ud800"):
            d2, t2 = copy.deepcopy(ds), copy.deepcopy(tr)
            get(d2 if label == "dataset" else t2, p)[bad] = "x"
            a, b = codes(ORIG, d2, t2, ct), codes(MUT, d2, t2, ct)
            total += 1
            if a != b:
                diff += 1
                if diff <= 15: print("РАЗНИЦА", label, "/".join(map(str, p)), repr(bad), a, b)
    print(label, "объектов:", len(paths), flush=True)
# артефакт: плохой ключ в каждом объекте артефакта (байты пересчитываются фикстурой)
W_paths = None
def art_pre(path, bad):
    def f(W):
        get(W["__artifacts__"]["umr_ns2"], path)[bad] = "x"
    return f
from fixtures import world
apaths = list(dicts(world()["__artifacts__"]["umr_ns2"]))
for p in apaths:
    for bad in ("\u0001k",):
        try:
            d2, t2, c2 = build(V("x", [], "", pre=art_pre(p, bad)))
        except Exception as ex:
            print("артефакт: build не смог", p, type(ex).__name__); continue
        a, b = codes(ORIG, d2, t2, c2), codes(MUT, d2, t2, c2)
        total += 1
        if a != b:
            diff += 1; print("РАЗНИЦА artifact", "/".join(map(str, p)), repr(bad), a, b)
print("artifact объектов:", len(apaths))
print(f"всего проб {total}, различий оригинал/мутант M005: {diff}")

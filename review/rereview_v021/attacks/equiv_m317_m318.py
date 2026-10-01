# Probe: try to kill M317/M318 with depth-70 nesting at every path of the world and in trust. Run from core/: python3 ../attacks/equiv_m317_m318.py
import copy, sys
sys.path.insert(0,'.')
import mutants as MU
from vectors import build
import validator as V
src = MU.SRC
m317 = MU.load(src.replace("if depth >= MAX_DEPTH:", "if False:"))
m318 = MU.load(src.replace("    except RecursionError:\n        R.err(\"SCHEMA_INVALID\", \"/\", \"слишком глубокая вложенность\")\n        return R", "    except ZeroDivisionError:\n        return R"))
ds, tr, ct = build()
def paths(n, p=()):
    yield p
    if isinstance(n, dict):
        for k, v in n.items(): yield from paths(v, p+(k,))
    elif isinstance(n, list):
        for i, v in enumerate(n): yield from paths(v, p+(i,))
def nest(d, leaf):
    x = leaf
    for i in range(d): x = [x] if i % 2 else {"a": x}
    return x
diff = 0; n = 0
for p in list(paths(ds))[1:]:
    for leaf in ("x",):
        for d in (70,):
            dd = copy.deepcopy(ds); node = dd
            for k in p[:-1]: node = node[k]
            node[p[-1]] = nest(d, leaf)
            a = V.validate(dd, tr, ct).codes(); b = m317.validate(dd, tr, ct).codes(); c = m318.validate(dd, tr, ct).codes()
            n += 1
            if a != b or a != c: diff += 1; print("DIFF", p, d, a, b, c)
# also add extra key at qualifiers level and in trust
for d in (70, 5000):
    t2 = copy.deepcopy(tr); t2["keys"][0]["x"] = nest(d, "x")
    a = V.validate(ds, t2, ct).codes(); b = m317.validate(ds, t2, ct).codes(); c = m318.validate(ds, t2, ct).codes(); n += 1
    if a != b or a != c: diff += 1; print("DIFF trust", d, a, b, c)
print("cases", n, "diff", diff)

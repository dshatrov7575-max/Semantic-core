"""Статистика векторов: коды, распределение, предупреждения, pre/post. Запуск из core/."""
import sys, re, collections, inspect
sys.path.insert(0, '.')
from vectors import VECTORS
import validator
SRC = open('validator.py', encoding='utf-8').read()
neg = [v for v in VECTORS if v["expected"]]
pos = [v for v in VECTORS if not v["expected"]]
# vectors per code
per = collections.Counter(c for v in neg for c in v["expected"])
single = collections.Counter(v["expected"][0] for v in neg if len(v["expected"]) == 1)
# R.err call sites per code
sites = collections.Counter(re.findall(r'R\.err\("([A-Z_]+)"', SRC))
# codes returned indirectly (why-strings): count return "..." in helper functions
print("%-40s %8s %8s %8s" % ("code", "vectors", "solo", "err-sites"))
for c in validator.ERROR_CODES:
    print("%-40s %8d %8d %8d" % (c, per[c], single[c], sites[c]))
print("neg with >1 code:", sum(1 for v in neg if len(v["expected"]) > 1))
print("multi-code combos:", collections.Counter(tuple(v["expected"]) for v in neg if len(v["expected"]) > 1).most_common(40))
print("warn checked (warn is not None): total", sum(1 for v in VECTORS if v["warn"] is not None),
      "neg", sum(1 for v in neg if v["warn"] is not None), "pos", sum(1 for v in pos if v["warn"] is not None))
print("warn values:", collections.Counter(tuple(v["warn"]) for v in VECTORS if v["warn"] is not None))
print("pre only", sum(1 for v in VECTORS if v["pre"] and not v["post"]), "post only", sum(1 for v in VECTORS if v["post"] and not v["pre"]),
      "both", sum(1 for v in VECTORS if v["post"] and v["pre"]), "neither", sum(1 for v in VECTORS if not v["post"] and not v["pre"]))
print("id prefixes:", collections.Counter(re.match(r'[A-Z]+', v["id"]).group() for v in VECTORS))

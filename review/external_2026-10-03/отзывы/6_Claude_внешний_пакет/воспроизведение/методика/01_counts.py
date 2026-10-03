"""Сверка чисел: векторы, мутанты, коды. Запуск из core/: python3 ../findings/01_counts.py"""
import sys, re, collections
sys.path.insert(0, '.')
from vectors import VECTORS, build
import mutants, validator
neg = [v for v in VECTORS if v["expected"]]
pos = [v for v in VECTORS if not v["expected"]]
print("vectors", len(VECTORS), "neg", len(neg), "pos", len(pos), "unique ids", len({v['id'] for v in VECTORS}))
print("keys of a vector:", sorted(VECTORS[0].keys()))
print("mutants", len(mutants.M), "unique ids", len({m[0] for m in mutants.M}), "equivalent", len(mutants.EQUIVALENT))
print("ERROR_CODES", len(validator.ERROR_CODES))
for name in dir(validator):
    if 'WARN' in name.upper(): print(name, getattr(validator, name))
base, trust, content = build()
print("base records", len(base["records"]), collections.Counter(r.get("record_type") for r in base["records"]))

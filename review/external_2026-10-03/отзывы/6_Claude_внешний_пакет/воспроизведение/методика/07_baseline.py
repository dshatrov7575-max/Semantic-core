"""Эталонный полный вывод немутированного валидатора на каждом векторе: ошибки (code, ref, msg) + строка validator.py,
из которой вызван R.err (или из которой пришла причина), предупреждения. Запуск из core/. Выход: findings/baseline.json"""
import sys, json
sys.path.insert(0, '.')
from vectors import VECTORS, build
import validator
sites = []
orig = validator.Report.err
def err(self, code, ref, msg):
    sites.append(sys._getframe(1).f_lineno)
    orig(self, code, ref, msg)
validator.Report.err = err
out = {}
for v, ds, tr, ct in [(None, *build())] + [(v, *build(v)) for v in VECTORS]:
    sites.clear()
    r = validator.validate(ds, tr, ct)
    vid = v["id"] if v else "BASE"
    out[vid] = {"errors": [[e["code"], e["ref"], e["msg"]] for e in r.errors], "lines": list(sites),
                "warnings": [[w["code"], w["ref"], w["msg"]] for w in r.warnings],
                "expected": v["expected"] if v else [], "warn": v["warn"] if v else None, "desc": v["desc"] if v else "BASE"}
json.dump(out, open("../findings/baseline.json", "w"), ensure_ascii=False, indent=0)
print("ok", len(out))

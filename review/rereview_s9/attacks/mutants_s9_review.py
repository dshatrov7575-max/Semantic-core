#!/usr/bin/env python3
"""Рецензия цикла 9: правила валидатора цикла 9 БЕЗ убивающего вектора.
Каждый мутант — текстовая правка validator.py (в памяти), затем ВСЕ векторы vectors.VECTORS.
SURVIVED = ни один вектор не изменил набор кодов."""
import sys, types, time
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot" / "core"
sys.path.insert(0, str(SNAP))
import vectors as VX
SRC = (SNAP / "validator.py").read_text(encoding="utf-8")

def load(src):
    m = types.ModuleType("validator_mut"); m.__file__ = str(SNAP / "validator.py")
    exec(compile(src, m.__file__, "exec"), m.__dict__)
    return m

MUT = [
 ("R1 цикл наследования не проверяется",
  'if pid in seen_chain:\n                R.err("SCHEMA_INVALID", cdef_id, "циклическое наследование классов")\n                break',
  'if pid in seen_chain:\n                break'),
 ("R2 LinkDef: tenant domain/range не проверяется (CROSS_SCOPE)",
  'elif ref_cls["tenant_id"] != ldef["tenant_id"]:\n                R.err("CROSS_SCOPE_REFERENCE", ldef_id, f"{ref_field} из другого tenant")', 'elif False:\n                pass'),
 ("R3 LinkDef: inverse_predicate_id не проверяется (PREDICATE_UNKNOWN)",
  'if inv_pred not in preds:\n                R.err("PREDICATE_UNKNOWN", ldef_id, f"inverse_predicate_id {inv_pred} не зарегистрирован")', 'if False:\n                pass'),
 ("R4 IdentifierDef: applies_to_root_type не проверяется",
  'if idef["applies_to_root_type"] not in valid_entity_types:', 'if False:'),
 ("R5 schema.is_a: tenant класса не сверяется с tenant проекта (CROSS_SCOPE)",
  'if claim_tenant is not None and cls["tenant_id"] != claim_tenant:', 'if False:'),
 ("R6 LinkDef: range_class_id не проверяется (только domain)",
  'for ref_field in ("domain_class_id", "range_class_id"):', 'for ref_field in ("domain_class_id",):'),
 ("R7 SchemaChange: цели LinkDef и IdentifierDef не проверяются (только ClassDef)",
  'kind_map = {"ClassDef": CD, "LinkDef": LD, "IdentifierDef": IDD}', 'kind_map = {"ClassDef": CD}'),
 ("R8 THING: ключи идентичности не строятся",
  'weak.append(("thing", ns + base_key(i["label"]), i.get("disambiguator")))\n        soft.append(("thing", ns + norm(i["label"])))', 'pass'),
 ("R9 (контроль, мутант автора M830) class_id не проверяется на существование",
  'if cls is None:\n            R.err("REF_UNRESOLVED", cid, f"schema.is_a: class_id {class_id} не найден")\n            continue', 'if False:\n            continue'),
]
t0 = time.time()
data = [(v, VX.build(v)) for v in VX.VECTORS]
print(f"векторов: {len(data)}; построены за {time.time()-t0:.0f}s")
for name, old, new in MUT:
    assert SRC.count(old) == 1, (name, SRC.count(old))
    m = load(SRC.replace(old, new))
    killers = []
    for v, (ds, tr, ct) in data:
        try:
            got = m.validate(ds, tr, ct).codes()
        except Exception as ex:
            got = ["CRASH:" + type(ex).__name__]
        if got != v["expected"]:
            killers.append(v["id"])
    print(f"{'KILLED  ' if killers else 'SURVIVED'} {name}" + (f"  (векторы: {killers[:5]})" if killers else ""))
print(f"total {time.time()-t0:.0f}s")

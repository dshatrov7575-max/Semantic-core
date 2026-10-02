#!/usr/bin/env python3
"""Раунд 2: мои мутанты на правила цикла 9 (validator.py снимка 2); прогон как у автора (runs/mut9.py):
только векторы цикла 9 (N9xx/P9xx) + базовый мир, через mutants.run_one (сравнение кодов и предупреждений)."""
import sys, time
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot2" / "core"
sys.path.insert(0, str(SNAP))
import mutants as mt
from vectors import VECTORS, build
sel = [v for v in VECTORS if v["id"][1] == "9" and len(v["id"]) == 4]
mt.CASES = [(None, *build())] + [(v, *build(v)) for v in sel]
M = [
 ("R01", "версия после deprecated допускается", 'if prev.get("deprecated"):\n        return None', 'if False:\n        return None'),
 ("R02", "CHANGE_ATTRIBUTE: value_type не заморожен", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("unit", "scheme")'),
 ("R03", "CHANGE_ATTRIBUTE: unit не заморожен", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("value_type", "scheme")'),
 ("R04", "CHANGE_ATTRIBUTE: scheme не заморожен", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("value_type", "unit")'),
 ("R05", "ADD_ATTRIBUTE: можно добавить несколько", 'if len(added) == 1 and not removed and not diff:', 'if len(added) >= 1 and not removed and not diff:'),
 ("R06", "REMOVE_ATTRIBUTE: можно убрать несколько", 'if len(removed) == 1 and not added and not diff:', 'if len(removed) >= 1 and not added and not diff:'),
 ("R07", "CHANGE_ATTRIBUTE: можно изменить несколько", 'if len(diff) == 1 and not added and not removed and all(', 'if len(diff) >= 1 and not added and not removed and all('),
 ("R08", "версия в тот же момент, что предыдущая, допускается", 'r["change"]["recorded_at"] <= prev["change"]["recorded_at"]', 'r["change"]["recorded_at"] < prev["change"]["recorded_at"]'),
 ("R09", "схема на момент t: строго раньше t", 'ok = [r for r in lst if t is None or r["change"]["recorded_at"] <= t]', 'ok = [r for r in lst if t is None or r["change"]["recorded_at"] < t]'),
 ("R10", "родитель: deprecated не проверяется", 'if par.get("deprecated"):', 'if False:'),
 ("R11", "родитель: маркировка не проверяется", 'if not dominates(first["marking"], par["marking"]):', 'if False:'),
 ("R12", "связь: класс deprecated не проверяется", 'if cl.get("deprecated"):', 'if False:'),
 ("R13", "связь: маркировка не проверяется", 'if not dominates(first["marking"], cl["marking"]):', 'if False:'),
 ("R14", "связь: проверяется только domain", 'for f in ("domain_class_id", "range_class_id"):', 'for f in ("domain_class_id",):'),
 ("R15", "симметричная связь между разными классами", 'if first.get("symmetric") and first["domain_class_id"] != first["range_class_id"]:', 'if False:'),
 ("R16", "уникальность схемы идентификатора без учёта корня", 'k1 = (tn, first["scheme"], first["applies_to_root_type"])', 'k1 = (tn, first["scheme"], did)'),
 ("R17", "уникальность приоритета не проверяется", 'if seen_prio.setdefault(k2, did) != did:', 'if False:'),
 ("R18", "формат: min > max допускается", 'any(x["min"] > x["max"] for x in first["format"] if "chars" in x)', 'False'),
 ("R19", "формат: длина > 64 допускается", 'sum(x.get("max", 1) for x in first["format"]) > 64', 'False'),
 ("R20", "deprecated-связь остаётся действующим предикатом", 'if v is None or v.get("deprecated"):\n                return None', 'if v is None:\n                return None'),
 ("R21", "idef_at: deprecated тип идентификатора действует", 'if v is not None and not v.get("deprecated"):\n                    return v', 'if v is not None:\n                    return v'),
 ("R22", "idef_at: корневой тип не сверяется", 'lst[0]["scheme"] == scheme and lst[0]["applies_to_root_type"] == root_type:', 'lst[0]["scheme"] == scheme:'),
 ("R23", "принадлежность: время is_a не учитывается", 'return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k)', 'return any(stands(icid, t) and class_id in ancestors(tn, k)'),
 ("R24", "принадлежность: отзыв is_a не учитывается", 'return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k)', 'return any(rt <= t and class_id in ancestors(tn, k)'),
 ("R25", "принадлежность: наследники не считаются", 'return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k)', 'return any(rt <= t and stands(icid, t) and class_id == k'),
 ("R26", "stands: рецензии из будущего учитываются", 'lst = [x for x in rv_idx.get(cid, ()) if x[0] <= t]', 'lst = [x for x in rv_idx.get(cid, ())]'),
 ("R27", "stands: REFUTED не снимает принадлежность", 'return not lst or max(lst)[1] not in ("REFUTED", "WITHDRAWN")', 'return not lst or max(lst)[1] not in ("WITHDRAWN",)'),
 ("R28", "stands: WITHDRAWN не снимает принадлежность", 'return not lst or max(lst)[1] not in ("REFUTED", "WITHDRAWN")', 'return not lst or max(lst)[1] not in ("REFUTED",)'),
 ("R29", "атрибут: единица не сверяется", "lit is None or lit[\"type\"] != a[\"value_type\"] or lit.get(\"unit\") != a.get(\"unit\")", "lit is None or lit[\"type\"] != a[\"value_type\"]"),
 ("R30", "атрибут: схема идентификатора не сверяется", 'or (lit["type"] == "IDENTIFIER" and lit["scheme"] != a["scheme"])):', 'or False):'),
 ("R31", "связь: литерал вместо сущности допускается", 'if lit is not None or (obj_ent is not None', 'if (obj_ent is not None'),
 ("R32", "связь: объект не обязан быть экземпляром диапазона", 'and not instance_of(tn, c["project_id"], obj_ent["entity_id"], rng_class, t_rec)):', 'and False):'),
 ("R33", "x-предикат: квалификаторы допускаются", 'if c.get("qualifiers"):\n                    R.err("QUALIFIER_INVALID"', 'if False:\n                    R.err("QUALIFIER_INVALID"'),
 ("R34", "x-предикат: маркировка определения не проверяется", 'if not dominates(c["marking"], xp["marking"]):', 'if False:'),
 ("R35", "is_a: абстрактный класс допускается", 'if cl.get("is_abstract") or cl.get("deprecated"):', 'if cl.get("deprecated"):'),
 ("R36", "is_a: deprecated класс допускается", 'if cl.get("is_abstract") or cl.get("deprecated"):', 'if cl.get("is_abstract"):'),
 ("R37", "is_a: маркировка класса не проверяется", 'if not dominates(c["marking"], cl["marking"]):', 'if False:'),
 ("R38", "идентификатор tenant: fullmatch -> match (хвост не проверяется)", 'elif not re.fullmatch(format_regex(idf["format"]), lit["value"]):', 'elif not re.match(format_regex(idf["format"]), lit["value"]):'),
 ("R39", "владелец предиката: последний, а не первый", 'first = min(who, key=lambda d: (who[d], d))', 'first = max(who, key=lambda d: (who[d], d))'),
 ("R40", "атрибут IDENTIFIER: тип идентификатора ищется без учёта времени версии", 'and idef_at(tn, a["scheme"], r["root_type"], r["change"]["recorded_at"]) is None:', 'and idef_at(tn, a["scheme"], r["root_type"], None) is None:'),
 ("R41", "обязательные атрибуты: только собственные, без унаследованных", 'for anc in ancestors(tn, k):\n                for a in at(CLS[(tn, anc)], None)', 'for anc in [k]:\n                for a in at(CLS[(tn, anc)], None)'),
 ("R42", "обязательные атрибуты: отозванная принадлежность всё равно требует", 'if status_at(icid, None) in ("REFUTED", "WITHDRAWN"):\n                continue', 'if False:\n                continue'),
 ("R43", "цикл наследования не проверяется", 'if did in ancestors(tn, first["parent_class_id"]):', 'if False:'),
 ("R44", "версии не подряд допускаются", 'if [r["version"] for r in lst] != list(range(1, len(lst) + 1)):', 'if False:'),
 ("R45", "корневой тип наследника не сверяется", 'if par["root_type"] != first["root_type"]:', 'if False:'),
]
t = time.time(); surv = 0
for m in M:
    r = mt.run_one(m)
    tag = r[1]
    if not tag.startswith("KILLED"): surv += 1
    print(f"{r[0]:<4} {tag:<34} {m[1]}", flush=True)
print(f"мутантов={len(M)} не убито={surv} векторов цикла 9={len(sel)} время={int(time.time()-t)}c")

#!/usr/bin/env python3
"""Раунд 2: валидатор против базы (историческая загрузка без валидатора — как S9-08) на моих наборах.
PGDATABASE=review09r6 python3 r2_parity.py"""
import sys, subprocess, os, json, re
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot2"
for d in ("slice", "core", "store"): sys.path.insert(0, str(SNAP / d))
import validator as VAL
import vectors as VX
from vectors import V, build, cls, nextv, isa, xclaim, idef, sd, lit, seq, T_SD, T_LATE, add_review
import load_s1 as L

def both(title, pre):
    ds, tr, ct = build(V("X", [], title, pre=pre))
    rep = VAL.validate(ds, tr, ct)
    L.psql(L.DDL_ALL); L.register_originals(ds, ct)
    r = L.psql(L.load_sql(ds, tr, ct))
    msg = next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), "ПРИНЯТО").replace("psql:<stdin>:", "")[:170]
    v = rep.codes() or "ПРИНЯТО"
    flag = "РАСХОЖДЕНИЕ" if bool(rep.errors) != bool(r.returncode) else "совпадает"
    print(f"{title}\n    валидатор: {v}\n    база:      {msg}\n    => {flag}", flush=True)

A = lambda pid, vt, **kw: {"predicate_id": pid, "name": "атрибут рецензии", "value_type": vt, "cardinality": "ONE", "required": False, **kw}
K = lambda **kw: cls("zz_k", "sdf_rv_cls", **kw)
both("P1 атрибут tenant со встроенной схемой ru.inn, значение с неверной контрольной суммой",
     seq(K(attributes=[A("x.rv_inn", "IDENTIFIER", scheme="ru.inn")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         xclaim("zz_x", "ent_wk_blue", "x.rv_inn", lit(type="IDENTIFIER", scheme="ru.inn", value="1234567890"))))
both("P1k контроль: то же с верным ИНН", 
     seq(K(attributes=[A("x.rv_inn", "IDENTIFIER", scheme="ru.inn")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         xclaim("zz_x", "ent_wk_blue", "x.rv_inn", lit(type="IDENTIFIER", scheme="ru.inn", value=VX.INN_DEV))))
both("P2 версия 2: DEPRECATE_CLASS с явным deprecated=false (ничего не выведено из употребления)",
     seq(K(), nextv("zz_k", "zz_k2", "DEPRECATE_CLASS", at=T_LATE, deprecated=False)))
both("P3 версия 2: RENAME_CLASS + явное is_abstract=false",
     seq(K(), nextv("zz_k", "zz_k2", "RENAME_CLASS", at=T_LATE, name="Новое имя", is_abstract=False)))
both("P4 версия 2: RENAME_CLASS + явное attributes=[]",
     seq(K(), nextv("zz_k", "zz_k2", "RENAME_CLASS", at=T_LATE, name="Новое имя", attributes=[])))
both("P5 утверждение с атрибутом класса, выведенного из употребления до утверждения",
     seq(K(attributes=[A("x.rv_note", "STRING")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         nextv("zz_k", "zz_k2", "DEPRECATE_CLASS", at="2026-09-03T09:45:00Z", deprecated=True),
         xclaim("zz_x", "ent_wk_blue", "x.rv_note", lit(type="STRING", value="заметка"))))
both("P6 is_a отозван (WITHDRAWN) ровно в момент записи x-утверждения",
     seq(K(attributes=[A("x.rv_note", "STRING")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         add_review("zz_r", "zz_i", "WITHDRAWN", "2026-09-03T10:00:00Z", "2026-09-03T10:00:00Z"),
         xclaim("zz_x", "ent_wk_blue", "x.rv_note", lit(type="STRING", value="заметка"))))
both("P7 класс и is_a записаны в один и тот же момент",
     seq(cls("zz_k", "sdf_rv_cls", at="2026-09-03T09:30:00Z"), isa("zz_i", "ent_wk_blue", "sdf_rv_cls")))
both("P8 атрибут и связь объявляют один предикат в один момент",
     seq(K(attributes=[A("x.rv_same", "STRING")]),
         sd("zz_l", "LinkDef", "sdf_rv_lnk", 1, "ADD_LINK", predicate_id="x.rv_same", name="связь", domain_class_id="sdf_rv_cls",
            range_class_id="sdf_rv_cls", cardinality="MANY")))
both("P9 x-утверждение с пустыми квалификаторами {}",
     seq(K(attributes=[A("x.rv_note", "STRING")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         xclaim("zz_x", "ent_wk_blue", "x.rv_note", lit(type="STRING", value="заметка"), q={})))
both("P10 версия 2 меняет маркировку определения (PUBLIC -> INTERNAL) под видом RENAME",
     seq(K(), nextv("zz_k", "zz_k2", "RENAME_CLASS", at=T_LATE, name="Новое имя", marking=VX.INT)))
both("P11 атрибут MONEY, значение QUANTITY без единицы у атрибута",
     seq(K(attributes=[A("x.rv_cost", "MONEY")]), isa("zz_i", "ent_wk_blue", "sdf_rv_cls"),
         xclaim("zz_x", "ent_wk_blue", "x.rv_cost", lit(type="QUANTITY", value="5", unit="m"))))
L.psql(L.DDL_ALL)

print("\n== формат идентификатора: Python re.fullmatch(format_regex) против PostgreSQL value ~ ac.format_regex ==")
subprocess.run([sys.executable, str(SNAP / "slice" / "load_s1.py")], capture_output=True, text=True)
fmts = [[{"chars": c, "min": 1, "max": 3}] for c in ("DIGIT", "UPPER", "LOWER", "ALNUM", "ALNUM_UPPER")] + \
       [[{"lit": x}] for x in "./-_a0"] + [[{"chars": "DIGIT", "min": 1, "max": 2}, {"lit": x}, {"chars": "UPPER", "min": 1, "max": 1}] for x in "./-_"]
vals = ["", "1", "12", "1234", "１", "١", "²", "1\n", "\n1", "a", "A", "é", "É", "ß", "İ", "ı", "я", "Я", ".", "-", "/", "_", "\\", "x",
        "1.A", "1-A", "1/A", "1_A", "1xA", "12.A", "1.a", " 1", "1 ", "Á", "1​", "0", "a\n"]
n = bad = 0
for f in fmts:
    rx = VAL.format_regex(f)
    q = "SELECT " + ", ".join(f"({L.q(v)} ~ ac.format_regex({L.q(f)}::jsonb))::int" for v in vals) + ";"
    out = L.psql(q).stdout.strip().split(" | ")
    for v, o in zip(vals, out):
        n += 1
        py = bool(re.fullmatch(rx, v))
        if py != (o == "1"):
            bad += 1; print(f"  РАСХОЖДЕНИЕ формат={json.dumps(f)} значение={v!r}: python={py} postgres={o}")
print(f"сравнений={n} расхождений={bad}")

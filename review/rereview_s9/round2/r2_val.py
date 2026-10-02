#!/usr/bin/env python3
"""Раунд 2: вердикт валидатора на наборе, равном состоянию базы из r2_live.py §3 (вывод класса из употребления
записан раньше is_a и x-утверждения), и на изменениях замороженных полей атрибута (мутанты R02–R04)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "snapshot2" / "core"))
import validator as VAL
from vectors import V, build, cls, nextv, isa, xclaim, lit, seq, T_SD, T_LATE
A = lambda pid, vt, **kw: {"predicate_id": pid, "name": "атрибут рецензии", "value_type": vt, "cardinality": "ONE", "required": False, **kw}
def run(title, pre):
    r = VAL.validate(*build(V("X", [], title, pre=pre)))
    print(f"{title}\n    -> {r.codes() or 'ПРИНЯТО'}")
run("класс выведен из употребления в 09:00, is_a в 09:30, x-утверждение в 10:00",
    seq(cls("zz_k", "sdf_rv_cls", attributes=[A("x.rv_note", "STRING")]),
        nextv("zz_k", "zz_k2", "DEPRECATE_CLASS", at="2026-09-03T09:00:00Z", deprecated=True),
        isa("zz_i", "ent_wk_blue", "sdf_rv_cls"), xclaim("zz_x", "ent_wk_blue", "x.rv_note", lit(type="STRING", value="з"))))
K = lambda a: cls("zz_k", "sdf_rv_cls", attributes=[a])
run("CHANGE_ATTRIBUTE меняет value_type STRING -> DATE", seq(K(A("x.rv_a", "STRING")), nextv("zz_k", "zz_k2", "CHANGE_ATTRIBUTE", at=T_LATE, attributes=[A("x.rv_a", "DATE")])))
run("CHANGE_ATTRIBUTE меняет unit m -> km", seq(K(A("x.rv_a", "QUANTITY", unit="m")), nextv("zz_k", "zz_k2", "CHANGE_ATTRIBUTE", at=T_LATE, attributes=[A("x.rv_a", "QUANTITY", unit="km")])))
run("CHANGE_ATTRIBUTE меняет scheme ru.inn -> ru.ogrn", seq(K(A("x.rv_a", "IDENTIFIER", scheme="ru.inn")), nextv("zz_k", "zz_k2", "CHANGE_ATTRIBUTE", at=T_LATE, attributes=[A("x.rv_a", "IDENTIFIER", scheme="ru.ogrn")])))
run("класс с change.recorded_at = 2099-01-01 (валидатор не знает «сейчас»)", cls("zz_k", "sdf_rv_cls", at="2099-01-01T00:00:00Z"))

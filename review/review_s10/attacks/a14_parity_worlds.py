#!/usr/bin/env python3
"""S10R / направление 2: паритет валидатор ↔ база на мирах-свидетелях рецензента — тем же способом, что S10-PARITY автора:
мир (fixtures + записи) целиком загружается в СВЕЖУЮ базу без валидатора перед ней (load_s1.load_sql, исторический импорт).
Запуск: PGDATABASE=review10_p python3 a14_parity_worlds.py"""
import os
os.environ["PGDATABASE"] = os.environ.get("PGDATABASE", "review10_p")
from common import *
import load_s1 as L
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    import a7_extra_witnesses as XW          # берём оттуда построители миров
    import a7_equivalence_witnesses as EW
print("\n================ ПАРИТЕТ НА МИРАХ-СВИДЕТЕЛЯХ ================")
OBS, REC = "2026-09-05T08:00:00Z", "2026-09-26T09:00:00Z"
def run(tag, desc, records):
    ds, tr, ct = world(); ds["records"] = ds["records"] + copy.deepcopy(records)
    rep = VAL.validate(ds, tr, ct)
    try:
        sql = L.load_sql(ds, tr, ct)
    except Exception as ex:
        print(f"{tag:<5}{desc}\n      валидатор: {py_verdict(rep)[:120]}\n      база: N/A ({type(ex).__name__}: {str(ex)[:80]})"); return
    L.psql(L.DDL_ALL); L.register_originals(ds, ct)
    r = L.psql(sql)
    py_ok, db_ok = not rep.errors, r.returncode == 0
    print(f"{tag:<5}{desc}\n      валидатор: {py_verdict(rep)[:130]}\n      база:      {verdict(r)[:150]}{'   <<< РАСХОЖДЕНИЕ' if py_ok != db_ok else ''}", flush=True)

# ---- row_key: подмена типа (Python: [True] == [1])
def keyed(ktype, kval, fake):
    cols = [{"name": "k", "type": ktype, "marking": PUB}, {"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
            {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}]
    dv = DatasetVersion("dst_rev_key", T, f"rev-a14 {ktype} {kval!r}", cols, ["k"], [{"k": kval, "ogrn": OGRN_DEV, "address": REGISTRY_ROWS[0]["address"]}], subject=("ogrn",))
    ev = dv.evidence([kval], ["ogrn", "address"]); ev["row_key"] = [fake]
    return [source_rec(dv, observed=OBS), mk_claim(ev, recorded=REC)]
run("K1", "ключ — булева колонка, ячейка true, row_key = [1]", keyed("BOOLEAN", True, 1))
run("K2", "ключ — булева колонка, ячейка false, row_key = [0]", keyed("BOOLEAN", False, 0))
run("K3", "ключ — целая колонка, ячейка 1, row_key = [true]", keyed("INTEGER", 1, True))
run("K4", "ключ — целая колонка, ячейка 0, row_key = [false]", keyed("INTEGER", 0, False))
run("K0", "контроль: ключ — целая колонка, ячейка 1, row_key = [1]", keyed("INTEGER", 1, 1))
# ---- свидетели мутантов
run("X01", "объект — выжившая сущность, ячейка называет ОГРН влитой ДО утверждения", XW.rival_world("2026-09-20T10:00:00Z"))
run("X02", "то же, слияние ПОЗЖЕ утверждения", XW.rival_world("2026-09-27T10:00:00Z"))
run("X03", "колонка дат подтверждает литерал DATE (person.birth_date)", [source_rec(XW.dp, observed=OBS, marking=XW.cm), XW.c3])
run("MR21", "хэш строки посчитан не в порядке колонок манифеста", [EW.src, mk_claim(EW.ev, recorded=REC)])
run("MR29", "rows = 1, а rows_root — корень двух строк; путь с лишним хэшем", [source_rec(EW.dvb, observed=OBS), mk_claim(EW.ev2, recorded=REC)])
# ---- типы: INTEGER/BOOLEAN-литерал против колонки того же типа (предикат реестра этого не допускает — код отказа другой, вердикт общий)
L.psql(L.DDL_ALL)

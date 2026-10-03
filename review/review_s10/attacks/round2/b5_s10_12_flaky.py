#!/usr/bin/env python3
"""S10R раунд 2: почему приёмочный тест S10-12 автора то проходит, то нет. Повторяем его шаг: версия зарегистрирована, сразу за ней
утверждение с recorded_at = utc(0) (секунды усечены) — как в s10_tests.py; затем то же с паузой 1,1 с (как в S10-08)."""
from r2common import *
for pause in (0, 0, 0, 1.1):
    dv = relabel(demo_registry(), f"rev-b5 {time.time()}")
    r = db_try([source_rec(dv)], commit=True); assert r.returncode == 0
    time.sleep(pause)
    c = mk_claim(dv.evidence([OGRN_DEV], ["address"]))
    print(f"пауза {pause} с: утверждение сразу после регистрации версии —", verdict(db_try([c]))[:120])

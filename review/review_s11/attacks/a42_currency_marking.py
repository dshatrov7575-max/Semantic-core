#!/usr/bin/env python3
"""«Актуальность строки» и маркировки колонок последней версии. Заявлено: «сравниваются по значению только колонки,
маркировку которых в последней версии доминирует маркировка утверждения». Но UNCHANGED выводится из равенства ХЭШЕЙ
строк, т. е. из равенства ВСЕХ ячеек, включая те, что в новой версии закрыты для читателя утверждения:
 M1  колонка address в новой версии стала ПД, значение не изменилось -> UNCHANGED: читатель без категории ПД узнаёт
     значение закрытой для него ячейки новой версии (оно равно известному ему старому);
 M2  изменилась только скрытая колонка -> CHANGED_ELSEWHERE против UNCHANGED: факт изменения скрытой ячейки.
Для сравнения: что тот же читатель получает от ac.dataset_row по новой версии."""
import copy, json, time
from rv import *
from a40_helpers import *

fresh()
time.sleep(1.1)
ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"
PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
c1 = cols(extra=[{"name": "director", "type": "STRING", "marking": PD}])
c2 = copy.deepcopy(c1); next(c for c in c2 if c["name"] == "address")["marking"] = PD
a = ver("dst_r_mark", "v1", c1, ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR, "director": "Ломов"},
                                             {"code": "B", "ogrn": REGISTRY_ROWS[1]["ogrn"], "address": "x", "director": "Седов"}])
time.sleep(1.1)
cl = mk_claim(a, ["A"], ADDR)                                   # утверждение CONFIDENTIAL/COMMERCIAL_SECRET, без ПД
b = ver("dst_r_mark", "v2", c2, ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR, "director": "Ломов"},
                                             {"code": "B", "ogrn": REGISTRY_ROWS[1]["ogrn"], "address": "x", "director": "Седов"}], previous=a.source_id)
m1 = currency(cl)
row = json.loads(one(f"SELECT ac.dataset_row('{PRJ}', '{b.source_id}', '[\"A\"]');", "ac_rd_cs"))
print("M1 address в v2 — ПД, значение то же: currency =", m1["status"], "| ac.dataset_row(v2) читателю без ПД: видит", sorted(row["cells"]), "скрыто", row["withheld"])
c = ver("dst_r_mark", "v3", c2, ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR, "director": "Новый"},
                                             {"code": "B", "ogrn": REGISTRY_ROWS[1]["ogrn"], "address": "x", "director": "Седов"}], previous=b.source_id)
m2 = currency(cl)
print("M2 в v3 изменён только директор (ПД):", m2["status"])
report("M1", m1["status"] == "UNCHANGED" and "address" in row["withheld"],
       "UNCHANGED раскрывает читателю утверждения, что закрытая для него в новой версии ячейка равна известному ему значению; "
       f"CHANGED_ELSEWHERE ({m2['status']}) — что изменилась скрытая ячейка")

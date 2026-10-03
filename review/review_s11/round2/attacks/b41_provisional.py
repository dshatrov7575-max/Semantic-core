#!/usr/bin/env python3
"""S11R-13 (не исправлено кодом, принятое ограничение): помечен ли ответ в окне «печать выполнена, транзакция не зафиксирована»
как предварительный (provisional), и что будет, если транзакция печати держится дольше окна (здесь окно не ждём: проверяется
ответ на тот же прошлый момент, запрошенный как «не недавний» через 5 минут, — расчётно)."""
import json, time
from rv import *
from a40_helpers import *

fresh()
time.sleep(1.1)
ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"
a = ver("dst_p_repro", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
b = ver("dst_p_repro", "v2", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR + " (новый)"}], previous=a.source_id, seal=False)
th, o = bg(L + f"BEGIN;\nSELECT ac.dataset_seal('{T}', '{b.source_id}');\nSELECT pg_sleep(4);\nCOMMIT;")
time.sleep(2.0)
t_mid = one("SELECT clock_timestamp()")
d1 = json.loads(dossier(f"'{t_mid}'").stdout)
th.join()
d2 = json.loads(dossier(f"'{t_mid}'").stdout)
print(f"досье на момент t (печать не зафиксирована): provisional = {d1.get('provisional')}, digest {d1['digest'][:22]}; позже на тот же t: provisional = {d2.get('provisional')}, digest {d2['digest'][:22]}")
report("P13", d1.get("provisional") is not True, "ответ, который потом изменился, не был помечен предварительным")

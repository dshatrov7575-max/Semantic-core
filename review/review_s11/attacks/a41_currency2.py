#!/usr/bin/env python3
"""«Актуальность строки», продолжение.
K2  «последняя» = версия с самым поздним ПЕРВЫМ НАБЛЮДЕНИЕМ; поле previous и метка версии не читаются. Дозагруженная
    позже СТАРАЯ версия (архив за прошлый год) становится «последней».
K3  ответ на прошлый момент невоспроизводим: sealed_at ставится внутри транзакции печати, до её фиксации.
K4  NOT_AVAILABLE выдаёт читателю существование версии выше его допуска.
K6  незапечатанная (открытая) версия; две ветви от одной previous.
"""
import copy, json, time
from rv import *
from a40_helpers import *

dv0 = fresh()
time.sleep(1.1)
ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"

# ---- K2
v2 = ver("dst_r_order", "2026-10-01", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR + ", оф. 2"}])
time.sleep(1.1)
c = mk_claim(v2, ["A"], ADDR + ", оф. 2")
before = currency(c)
v1 = ver("dst_r_order", "2025-01-01 (архив)", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": "старый адрес 2025 года"}])
after = currency(c)
print("K2 утверждение на версии 2026-10-01; до дозагрузки архива:", before["status"], "| после дозагрузки архивной версии 2025-01-01:", json.dumps(after, ensure_ascii=False)[:200])
# то же с честной цепочкой previous: v3.previous = v2, затем архив v0 без previous
v3 = ver("dst_r_order", "2026-10-02", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR + ", оф. 3"}], previous=v2.source_id)
time.sleep(1.1)
c3 = mk_claim(v3, ["A"], ADDR + ", оф. 3")
b3 = currency(c3)
v0 = ver("dst_r_order", "2024-01-01 (архив)", cols(), ["code"], [{"code": "B", "ogrn": OGRN_DEV, "address": "адрес 2024"}])
a3 = currency(c3)
print("   утверждение на вершине цепочки previous (2026-10-02): до:", b3["status"], "| после дозагрузки архива 2024 года:", json.dumps(a3, ensure_ascii=False)[:160])
report("K2", before["status"] == "CURRENT" and after["status"] != "CURRENT" and a3["status"] != "CURRENT",
       f"дозагруженная старая версия объявлена «последней»: строка свежей версии — {after['status']} / {a3['status']}; previous не читается")

# ---- K3 reproducibility of a past answer
a = ver("dst_r_repro", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
b = ver("dst_r_repro", "v2", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR + " (новый)"}], previous=a.source_id, seal=False)
th, o = bg(L + f"BEGIN;\nSELECT ac.dataset_seal('{T}', '{b.source_id}');\nSELECT pg_sleep(4);\nCOMMIT;")
time.sleep(2.0)
t_mid = one("SELECT clock_timestamp()")
d1 = json.loads(dossier(f"'{t_mid}'").stdout)
cur1 = currency(c, f"'{t_mid}'")
th.join()
assert o[0].returncode == 0, first_err(o[0])
d2 = json.loads(dossier(f"'{t_mid}'").stdout)
cur2 = currency(c, f"'{t_mid}'")
print(f"K3 момент t = {t_mid} (печать v2 выполнена, транзакция ещё не зафиксирована)")
print(f"   currency на t, прочитано в момент t: {cur1['status']}; прочитано позже на тот же t: {cur2['status']}")
sealed = one(f"SELECT sealed_at FROM ac.dataset_tables WHERE source_id = '{b.source_id}'")
print(f"   digest досье на t: тогда {d1.get('digest', '')[:24]} | позже {d2.get('digest', '')[:24]} | sealed_at = {sealed}")
report("K3", cur1["status"] != cur2["status"], "досье на прошлый момент невоспроизводимо: печать версии «задним числом» (sealed_at раньше фиксации) меняет ответ на уже прошедший момент")

# ---- K4 NOT_AVAILABLE: existence of a version above the reader's clearance
a = ver("dst_r_secret", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)


def reader_view():
    d = json.loads(dossier(user="ac_rd_cs").stdout)
    return [e["currency"] for f in S3.facts_of(d) for cl in f["claims"] + f.get("other_claims", []) for e in cl["evidence"]
            if e.get("source_id") == a.source_id]


seen1 = reader_view()
b = ver("dst_r_secret", "v2-secret", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}], previous=a.source_id,
        marking={"level": "RESTRICTED", "categories": []})
seen2 = reader_view()
info = psql(f"SELECT ac.dataset_info('{PRJ}', '{b.source_id}');", "ac_rd_cs")
print("K4 читатель ac_rd_cs (CONFIDENTIAL) до появления версии RESTRICTED:", seen1, "| после:", seen2)
print("   тот же читатель спрашивает о закрытой версии прямо (dataset_info):", first_err(info)[:80])
report("K4", bool(seen1) and seen1[0]["status"] == "CURRENT" and seen2[0]["status"] == "NOT_AVAILABLE",
       "читатель без допуска узнаёт из досье, что у набора появилась версия выше его допуска (факт существования)")

# ---- K6 an open (unsealed) version; two branches
a = ver("dst_r_branch", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
ver("dst_r_branch", "v2-open", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": "X"}], previous=a.source_id, seal=False)
s_open = currency(c)["status"]
ver("dst_r_branch", "v2a", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}], previous=a.source_id)
ver("dst_r_branch", "v2b", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": "ветвь Б"}], previous=a.source_id)
s_br = currency(c)
print("K6 открытая незапечатанная версия:", s_open, "| две ветви от v1 (v2a — та же строка, v2b — другая):", json.dumps(s_br, ensure_ascii=False)[:150])

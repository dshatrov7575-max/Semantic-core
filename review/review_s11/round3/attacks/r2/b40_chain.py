#!/usr/bin/env python3
"""Раунд 2 (в): ac.row_currency по цепочке previous.
C1  закрытая версия в середине: v1 -> v2 (RESTRICTED) -> v3 (PUBLIC, строка изменена). Для утверждения ниже RESTRICTED
    цепочка обрывается перед v2, статус CURRENT («следующих версий нет»), хотя открытая v3 с изменённой строкой
    читателю доступна (ac.dataset_info, ac.dataset_row).
C2  ветвление, одна из ветвей закрыта: BRANCHED не выдаётся (контроль утечки).
C3  несовместимый ключ в середине: v1 -> v2 (другой ключ) -> v3 (прежний ключ): сравнение идёт с последней.
C4  незапечатанная версия в середине; загруженная, но не запечатанная последняя.
C5  длинная цепочка: цена одного evidence_json при 60 версиях (каждый шаг — отдельные запросы).
C6  цикл previous невозможен по построению (source_id — хэш манифеста, включающего previous): проверка отказа на самоссылке.
"""
import json, time
from rv import *
from a40_helpers import *

fresh()
time.sleep(1.1)
ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"
RESTR = {"level": "RESTRICTED", "categories": []}
row = lambda addr, code="A": [{"code": code, "ogrn": OGRN_DEV, "address": addr}]   # noqa: E731

# C1
v1 = ver("dst_c_hid", "v1", cols(), ["code"], row(ADDR))
time.sleep(1.1)
c = mk_claim(v1, ["A"], ADDR)
v2 = ver("dst_c_hid", "v2-secret", cols(), ["code"], row(ADDR + " (секретно)"), previous=v1.source_id, marking=RESTR)
v3 = ver("dst_c_hid", "v3", cols(), ["code"], row("новый открытый адрес"), previous=v2.source_id)
cur = currency(c)
info = psql(f"SELECT ac.dataset_info('{PRJ}', '{v3.source_id}');", "ac_rd_cs")
rw = psql(f"SELECT ac.dataset_row('{PRJ}', '{v3.source_id}', '[\"A\"]');", "ac_rd_cs")
vis = json.loads(rw.stdout)["cells"].get("address") if rw.returncode == 0 else first_err(rw)[:60]
print(f"C1 v1 -> v2 (RESTRICTED) -> v3 (PUBLIC, адрес другой): currency = {cur}; тот же читатель видит v3: dataset_info "
      f"{'ok, previous=' + str(json.loads(info.stdout)['previous']) if info.returncode == 0 else first_err(info)[:50]}; адрес в v3 для него: {vis!r}")
report("C1", cur == {"status": "CURRENT"} and vis == "новый открытый адрес",
       "закрытая версия в середине цепочки: статус CURRENT («следующих версий нет») при доступной читателю более новой версии с изменённой строкой")

# C2
a = ver("dst_c_br", "v1", cols(), ["code"], row(ADDR))
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
ver("dst_c_br", "v2-open", cols(), ["code"], row(ADDR), previous=a.source_id)
b1 = currency(c)
ver("dst_c_br", "v2-secret", cols(), ["code"], row("x"), previous=a.source_id, marking=RESTR)
b2 = currency(c)
print(f"C2 ветвь открытая: {b1['status']}; добавлена закрытая ветвь от той же версии: {b2['status']}")
report("C2", b1["status"] != b2["status"], "закрытая ветвь меняет ответ читателю без допуска")

# C3
a = ver("dst_c_key", "v1", cols(), ["code"], row(ADDR))
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
b = ver("dst_c_key", "v2", cols(), ["ogrn"], row(ADDR), previous=a.source_id)
s2 = currency(c)["status"]
ver("dst_c_key", "v3", cols(), ["code"], row(ADDR + " 3"), previous=b.source_id)
s3 = currency(c)
print(f"C3 v2 с другим ключом: {s2}; затем v3 с прежним ключом и новым адресом: {s3['status']} {s3.get('changed_columns')}")

# C4
a = ver("dst_c_open", "v1", cols(), ["code"], row(ADDR))
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
b = ver("dst_c_open", "v2", cols(), ["code"], row("y"), previous=a.source_id, seal=False)
s_a = currency(c)["status"]
d = ver("dst_c_open", "v3", cols(), ["code"], row("z"), previous=b.source_id)
s_b = currency(c)
e = ver("dst_c_open", "v4", cols(), ["code"], row("w"), previous=d.source_id, load=False)
s_c = currency(c)
print(f"C4 v2 не запечатана: {s_a}; v3 запечатана: {s_b['status']} (latest {s_b['latest']['version_label']}); v4 зарегистрирована без строк: {s_c['status']} (latest {s_c['latest']['version_label']})")

# C5
a = ver("dst_c_long", "v000", cols(), ["code"], row(ADDR))
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
t0 = time.time(); r = psql("\n".join([f"SELECT ac.evidence_json('{c['claim_id']}', now());"] * 20)); base_ms = (time.time() - t0) * 50
prev = a
N = 60
for i in range(1, N + 1):
    prev = ver("dst_c_long", f"v{i:03d}", cols(), ["code"], row(ADDR + f" {i}"), previous=prev.source_id, load=(i == N))
t0 = time.time(); r = psql("\n".join([f"SELECT ac.evidence_json('{c['claim_id']}', now());"] * 20)); long_ms = (time.time() - t0) * 50
print(f"C5 evidence_json: без следующих версий {base_ms:.1f} мс; цепочка из {N} версий {long_ms:.1f} мс; статус {currency(c)['status']}")
report("C5", long_ms > 5 * base_ms, f"цена растёт с длиной цепочки: {base_ms:.1f} -> {long_ms:.1f} мс на доказательство при {N} версиях")

# C6
from dataset import DatasetVersion
from fixtures import DEMO_DATASET_KEY
x = DatasetVersion("dst_c_self", T, "v1", cols(), ["code"], row(ADDR), subject=("ogrn",), dataset_key=DEMO_DATASET_KEY, previous="src:sha256:" + "0" * 64)
print("C6 самоссылка: source_id версии — хэш манифеста с полем previous, поэтому previous = собственный адрес подобрать нельзя; цикл длины 2 требует того же. Проверено разбором.")

#!/usr/bin/env python3
"""«Актуальность строки» (ac.row_currency, поле currency в досье).
K1  тип ключевой колонки сменился между версиями (то же имя ключа): приведение типа падает -> падает всё досье
K2  «последняя» версия выбирается по первому наблюдению, поле previous не читается: дозагруженная СТАРАЯ версия
    становится «последней», и строка свежей версии объявляется изменённой/исключённой
K3  ответ на прошлый момент невоспроизводим: sealed_at ставится до фиксации транзакции печати
K4  NOT_AVAILABLE сообщает читателю о существовании версии выше его допуска (и момент её появления)
K5  составной ключ, ключ INTEGER/DATE/BOOLEAN, набор без ключа, версия с другим набором колонок — статусы
"""
import copy, json, time, hashlib
from rv import *
from dataset import DatasetVersion
from fixtures import DEMO_DATASET_KEY

dv0 = fresh()
PUB = {"level": "PUBLIC", "categories": []}
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def ver(dsid, label, columns, keycols, rows, subject=("ogrn",), previous=None, marking=PUB, load=True, seal=True):
    dv = DatasetVersion(dsid, T, label, columns, list(keycols), rows, subject=subject, dataset_key=DEMO_DATASET_KEY, previous=previous)
    src, r = D.register(dv.manifest_bytes, T, f"{dsid} {label}", marking=marking)
    assert r.returncode == 0, first_err(r)
    if load:
        _, bad = D.load_rows(T, dv.source_id, copy_file(dv), columns, seal=seal)
        assert bad is None, first_err(bad)
    return dv


def cols(key_type="STRING", extra=()):
    return [{"name": "code", "type": key_type, "marking": PUB},
            {"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
            {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}] + list(extra)


def mk_claim(dv, keyvals, address, quote=("address", "ogrn")):
    c = claim(dv.evidence(list(keyvals), list(quote)), address=address)
    r = psql(ingest_sql([c], {}))
    assert r.returncode == 0, first_err(r)
    return c


def currency(c, t="now()"):
    r = psql(f"SELECT ac.evidence_json('{c['claim_id']}', {t});")
    return json.loads(r.stdout)[0]["currency"] if r.returncode == 0 else "ОШИБКА: " + first_err(r)[:110]


def dossier(t=None, user="ac_rd_cs"):
    return psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer'{', ' + t if t else ''});", user)


ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"
time.sleep(1.1)

# ---- K5 статусы на разных ключах (контроль)
res = {}
for name, ktype, k1 in (("INTEGER", "INTEGER", 7), ("DATE", "DATE", "2021-02-12"), ("BOOLEAN", "BOOLEAN", True)):
    a = ver(f"dst_r_k_{name.lower()}", "v1", cols(ktype), ["code"], [{"code": k1, "ogrn": OGRN_DEV, "address": ADDR}])
    time.sleep(1.1)
    c = mk_claim(a, [k1], ADDR)
    b = ver(f"dst_r_k_{name.lower()}", "v2", cols(ktype), ["code"], [{"code": k1, "ogrn": OGRN_DEV, "address": ADDR + " (новый)"}], previous=a.source_id)
    res[name] = currency(c)
a = ver("dst_r_k_comp", "v1", cols(), ["code", "ogrn"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A", OGRN_DEV], ADDR)
ver("dst_r_k_comp", "v2", cols(), ["code", "ogrn"], [{"code": "B", "ogrn": OGRN_DEV, "address": ADDR}], previous=a.source_id)
res["составной (ключ исчез)"] = currency(c)
a = ver("dst_r_k_none", "v1", cols(), [], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c0 = claim(a.evidence(a.rows[0][3].hex(), ["address", "ogrn"]), address=ADDR)
assert psql(ingest_sql([c0], {})).returncode == 0
ver("dst_r_k_none", "v2", cols(), [], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR + " (новый)"}], previous=a.source_id)
res["без ключа (адрес изменён)"] = currency(c0)
a = ver("dst_r_k_cols", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
c2 = [x for x in cols() if x["name"] != "address"] + [{"name": "addr2", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}]
ver("dst_r_k_cols", "v2", c2, ["code"], [{"code": "A", "ogrn": OGRN_DEV, "addr2": ADDR}], previous=a.source_id)
res["колонка переименована (значение то же)"] = currency(c)
for k, v in res.items():
    print(f"K5 {k}: {json.dumps(v, ensure_ascii=False)[:150]}")
report("K5a", isinstance(res["без ключа (адрес изменён)"], dict) and res["без ключа (адрес изменён)"]["status"] == "ABSENT",
       "набор без ключа: изменённая строка — ABSENT (строку нечем найти), статус CHANGED недостижим — названо ли это в документации?")

# ---- K1 the key column changes its type
ok_before = dossier().returncode == 0
a = ver("dst_r_ktype", "v1", cols("STRING"), ["code"], [{"code": "A-1", "ogrn": OGRN_DEV, "address": ADDR}])
time.sleep(1.1)
c = mk_claim(a, ["A-1"], ADDR)
mid = dossier().returncode == 0
b = ver("dst_r_ktype", "v2", cols("INTEGER"), ["code"], [{"code": 1, "ogrn": OGRN_DEV, "address": ADDR}], previous=a.source_id)
cur = currency(c)
r = dossier()
r2 = psql(f"SELECT count(*) FROM ac.claim_provenance WHERE claim_id = '{c['claim_id']}'")
print(f"K1 досье до: {ok_before}/{mid}; после версии с ключом INTEGER: currency = {cur}")
print("   ac.dossier:", "ok" if r.returncode == 0 else first_err(r)[:140])
report("K1", r.returncode != 0, "новая версия набора с тем же именем ключа другого типа роняет досье сущности (любой загрузчик версии — отказ в обслуживании читателей)")
# починить нельзя: версия запечатана навсегда. Проверим, что досье других дат тоже не читается
r3 = dossier("now() - interval '1 second'")
print("   досье на момент секунду назад:", "ok" if r3.returncode == 0 else first_err(r3)[:100])

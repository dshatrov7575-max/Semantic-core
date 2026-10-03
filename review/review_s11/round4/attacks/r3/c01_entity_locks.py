#!/usr/bin/env python3
"""Раунд 3: новая схема ключей entity: (исключительно — то, что меняет сущность; разделяемо — то, что на неё опирается,
включая слияние В неё). Раньше два слияния в одну цель исключали друг друга; теперь идут параллельно.
M1  «различны» в обход: решение DISTINCT(C, D) записано; C -> A и D -> A сливаются параллельно. Каждое слияние
    проверяет ac.distinct_decided(себя, A) и не видит незафиксированного слияния второго. Итог: C и D слиты в одну
    сущность при действующем решении «различны».
M2  два слияния в одну цель переносят одинаковый слабый ключ (два тёзки с разными ИНН): перенос ключей идентичности.
M3  цепочка: A -> B параллельно с D -> A (контроль: ключ A исключительный у первого, разделяемый у второго).
M4  закрытие Проверки против слияния субъекта её утверждения (утверждение об объекте-сущности, которую сливают).
M5  строка Проверки против слияния субъекта утверждения.
M6  взаимные блокировки: утверждение о X + решение «различны»(X, Y) в одной транзакции, два сеанса.
"""
import copy, json, time, threading
from rv import *
from ingest_s4 import q as Q

dv = fresh()
ds0, trust, content = build()
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def ent_rec(eid):
    return json.loads(one("SELECT jsonb_strip_nulls(jsonb_build_object('kind','Entity','schema_version','core-ontology/0.4','entity_id',entity_id,'project_id',project_id,"
                          "'entity_type',entity_type,'identity',identity,'status',status,'merged_into',merged_into,"
                          "'status_changed_at',to_char(status_changed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                          "'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'marking',marking,'display_name',display_name)) "
                          f"FROM ac.entities WHERE entity_id = '{eid}'"))


def validate_with(*recs):
    ds = copy.deepcopy(ds0); ds["records"] += list(recs)
    rep = VAL.validate(ds, trust, content)
    return rep.codes(), [e.get("msg", "")[:100] for e in rep.errors]


def merge(a, b, pause=0.0):
    return L + f"BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = '{b}' WHERE entity_id = '{a}';\nSELECT pg_sleep({pause});\nCOMMIT;"


def dec_sql(did, a, b, at=None):
    d = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": did, "project_id": PRJ, "decision": "DISTINCT",
         "entity_ids": [a, b], "decided_by": "usr_analyst1", "decided_at": at or utc(0)}
    return d, (f"INSERT INTO ac.identity_decisions VALUES ({Q(did)},{Q(PRJ)},'DISTINCT',{Q(a)},{Q(b)},NULL,NULL,'usr_analyst1',{Q(d['decided_at'])},{Q(d)});")


# ---- M1
ents = [org("ent_m1_a", "ООО «Цель»", inn=D._inn10(783000001)), org("ent_m1_c", "ООО «Первый»", inn=D._inn10(783000002)), org("ent_m1_d", "ООО «Второй»", inn=D._inn10(783000003))]
assert psql(ingest_sql(ents, {})).returncode == 0
time.sleep(1.2)
dec, dsql = dec_sql("idd_m1", "ent_m1_c", "ent_m1_d")
assert psql(L + "BEGIN;\n" + dsql + "\nCOMMIT;").returncode == 0
time.sleep(1.2)
th, o1 = bg(merge("ent_m1_c", "ent_m1_a", 3))
time.sleep(1.5)
t0 = time.time(); r2 = psql(merge("ent_m1_d", "ent_m1_a")); waited = time.time() - t0
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"M1 C -> A: {first_err(o1[0])[:60]}; D -> A (параллельно, ждал {waited:.1f} с): {first_err(r2)[:90]}")
codes = None
if both:
    dec_db = dict(dec, decided_at=iso(one("SELECT decided_at FROM ac.identity_decisions WHERE decision_id = 'idd_m1'")))
    codes, msgs = validate_with(ent_rec("ent_m1_a"), ent_rec("ent_m1_c"), ent_rec("ent_m1_d"), dec_db)
    print("   в базе:", one("SELECT string_agg(entity_id || '->' || coalesce(merged_into, '-'), ', ' ORDER BY 1) FROM ac.entities WHERE entity_id LIKE 'ent_m1_%'"),
          "| ac.distinct_decided(A, A):", one("SELECT ac.distinct_decided('ent_m1_a', 'ent_m1_a')"))
    print("   валидатор на мире из базы:", codes, msgs[:2])
    # контроль: последовательно
    e2 = [org("ent_m1_a2", "ООО «Цель 2»", inn=D._inn10(783000011)), org("ent_m1_c2", "ООО «Первый 2»", inn=D._inn10(783000012)), org("ent_m1_d2", "ООО «Второй 2»", inn=D._inn10(783000013))]
    assert psql(ingest_sql(e2, {})).returncode == 0
    time.sleep(1.2)
    assert psql(L + "BEGIN;\n" + dec_sql("idd_m1b", "ent_m1_c2", "ent_m1_d2")[1] + "\nCOMMIT;").returncode == 0
    time.sleep(1.2)
    s1 = psql(merge("ent_m1_c2", "ent_m1_a2")); s2 = psql(merge("ent_m1_d2", "ent_m1_a2"))
    print("   контроль (последовательно): первое слияние", first_err(s1)[:30], "| второе:", first_err(s2)[:100])
report("S11R3-M1", both and bool(codes), f"READ COMMITTED: сущности, решённые «различны», слиты в одну (два слияния в одну цель больше не исключают друг друга); валидатор: {codes}")

# ---- M2: the same weak key moves to one survivor from two merged entities
def person(eid, inn, sur="Тёзкин"):
    return {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
            "identity": {"surname": sur, "given_name": "Иван", "birth_date": "1970-05-05", **({"inn": inn} if inn else {})}, "display_name": sur,
            "created_at": utc(0), "marking": CONF_PD}
r = psql(ingest_sql([person("ent_m2_a", D._inn12(5100000001), "Целев"), person("ent_m2_p", D._inn12(5100000002)), person("ent_m2_q", D._inn12(5100000003))], {}))
if r.returncode:
    print("M2 мир не создан:", first_err(r)[:100])
else:
    time.sleep(1.2)
    th, o1 = bg(merge("ent_m2_p", "ent_m2_a", 3).replace(PRJ, "prj_dossier"))
    time.sleep(1.5)
    r2 = psql(merge("ent_m2_q", "ent_m2_a"))
    th.join()
    print(f"M2 два тёзки (один слабый ключ, разные ИНН) в одну цель: 1: {first_err(o1[0])[:60]} | 2: {first_err(r2)[:110]}")
    print("   ключи цели:", one("SELECT string_agg(scheme || '=' || left(value, 22) || '/' || coalesce(qual, '-'), '; ' ORDER BY 1) FROM ac.entity_keys WHERE owner_entity_id = 'ent_m2_a'"))
    e3 = [person("ent_m2_a2", D._inn12(5100000011), "Целев"), person("ent_m2_p2", D._inn12(5100000012), "Двойников"), person("ent_m2_q2", D._inn12(5100000013), "Двойников")]
    assert psql(ingest_sql(e3, {})).returncode == 0
    time.sleep(1.2)
    s1 = psql(merge("ent_m2_p2", "ent_m2_a2")); s2 = psql(merge("ent_m2_q2", "ent_m2_a2"))
    print("   контроль (последовательно):", first_err(s1)[:30], "|", first_err(s2)[:100])
    report("S11R3-M2", o1[0].returncode == 0 and r2.returncode != 0 and s2.returncode == 0,
           "два слияния в одну цель с общим слабым ключом: параллельно второе падает сырой ошибкой индекса, последовательно проходит")

# ---- M3 chain control
ents = [org("ent_m3_a", "А3", inn=D._inn10(783000021)), org("ent_m3_b", "Б3", inn=D._inn10(783000022)), org("ent_m3_d", "Д3", inn=D._inn10(783000023))]
assert psql(ingest_sql(ents, {})).returncode == 0
time.sleep(1.2)
th, o1 = bg(merge("ent_m3_d", "ent_m3_a", 3))
time.sleep(1.5)
r2 = psql(merge("ent_m3_a", "ent_m3_b"))
th.join()
print(f"M3 D -> A: {first_err(o1[0])[:40]}; A -> B параллельно: {first_err(r2)[:90]}")
report("M3", o1[0].returncode == 0 and r2.returncode == 0, "цепочка слияний")
th, o1 = bg(merge("ent_m3_b", "ent_m3_d", 3))            # B -> D (D уже слита) — контроль отказа; затем A2 -> B2 / B2 -> C2
th.join()

# ---- M6 deadlock: claim about X, then DISTINCT(X, Y) in one transaction, two sessions
BETA = REGISTRY_ROWS[3]
ents = [org("ent_m6_x", "ООО «Бета»", ogrn=BETA["ogrn"]), org("ent_m6_y", "И6", inn=D._inn10(783000031)), org("ent_m6_z", "К6", inn=D._inn10(783000032))]
assert psql(ingest_sql(ents, {})).returncode == 0
time.sleep(1.2)
c1 = claim(dv.evidence([BETA["ogrn"]], ["address"]), subj="ent_m6_x", address=BETA["address"])
c2 = claim(dv.evidence([BETA["ogrn"]], ["address", "name"]), subj="ent_m6_x", address=BETA["address"])
def tx(c, did, other):
    return L + "BEGIN;\n" + body_of([c]) + "\nSELECT pg_sleep(1.5);\n" + dec_sql(did, "ent_m6_x", other)[1] + "\nCOMMIT;"
oa, ob = [], []
ta = threading.Thread(target=lambda: oa.append(psql(tx(c1, "idd_m6a", "ent_m6_y")))); tb = threading.Thread(target=lambda: ob.append(psql(tx(c2, "idd_m6b", "ent_m6_z"))))
ta.start(); tb.start(); ta.join(); tb.join()
print(f"M6 утверждение о X + «различны»(X, ·) в одной транзакции, два сеанса: A: {first_err(oa[0])[:60]} | B: {first_err(ob[0])[:60]}")
report("M6", "deadlock" in (oa[0].stderr + ob[0].stderr), "взаимная блокировка: утверждение о сущности и решение об её идентичности в одной транзакции")

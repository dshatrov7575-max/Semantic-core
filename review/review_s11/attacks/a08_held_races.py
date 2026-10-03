#!/usr/bin/env python3
"""Гонки, которые УСТОЯЛИ (для полноты: что пытались сломать и не смогли).
H1  ac.soft_keys_check (отложенная проверка скелетов при COMMIT): два понятия «нёбо N» / «небо N» (скелет один),
    два сеанса READ COMMITTED в обоих порядках фиксации и смешанные уровни.
H3  слабые ключи (ФИО + дата рождения) — READ COMMITTED против REPEATABLE READ/SERIALIZABLE (смешанные уровни).
"""
import json, time
from rv import *
from s9_tests import entity as entity9

fresh(load_rows=False)
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def two(sql1, sql2, gap=1.5, lv2=None):
    th, o1 = bg(sql1)
    time.sleep(gap)
    r2 = psql(sql2 if lv2 is None else sql2.replace("BEGIN;", f"BEGIN ISOLATION LEVEL {lv2};", 1))
    th.join()
    return o1[0], r2


def ent_sql(e, pause=0.0, level=None):
    s = ingest_sql([e], {})
    if level:
        s = s.replace("BEGIN;", f"BEGIN ISOLATION LEVEL {level};", 1)
    return s.replace("COMMIT;", f"SELECT pg_sleep({pause});\nCOMMIT;")


n = 0
res = []
for la, lb in ((None, None), (None, "REPEATABLE READ"), ("REPEATABLE READ", None), ("SERIALIZABLE", "SERIALIZABLE")):
    for pa, pb in ((3.0, 0.0), (0.0, 3.0)):
        n += 1
        a = entity9(f"ent_r8_a{n}", f"нёбо {n}")
        b = entity9(f"ent_r8_b{n}", f"небо {n}")
        th, o1 = bg(ent_sql(a, pa, la))
        time.sleep(1.0)
        r2 = psql(ent_sql(b, pb, lb))
        th.join()
        cnt = one(f"SELECT count(*) FROM ac.entities WHERE entity_id IN ('ent_r8_a{n}', 'ent_r8_b{n}')")
        res.append(cnt)
        print(f"H1 скелеты {la or 'READ COMMITTED'} / {lb or 'READ COMMITTED'}, паузы {pa}/{pb}: зафиксировано {cnt}; "
              f"1: {first_err(o1[0])[:60]} | 2: {first_err(r2)[:60]}")
report("H1", any(c == "2" for c in res), f"два понятия с одним скелетом без решения аналитика: зафиксировано {res}")

seq = psql(ingest_sql([entity9("ent_r8_s1", "нёбо 99")], {})), psql(ingest_sql([entity9("ent_r8_s2", "небо 99")], {}))
print("H1 контроль (последовательно):", first_err(seq[0])[:40], "|", first_err(seq[1])[:90])
res = []
n = 0
for la, lb in ((None, "REPEATABLE READ"), ("REPEATABLE READ", None), ("SERIALIZABLE", None), (None, "SERIALIZABLE"), (None, None)):
    n += 1
    def person(eid):
        return {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
                "identity": {"surname": f"Гонкин{n}", "given_name": "Пётр", "birth_date": "1980-01-01"}, "display_name": "Гонкин Пётр",
                "created_at": utc(0), "marking": CONF_PD}
    th, o1 = bg(ent_sql(person(f"ent_r8_p{n}"), 2.5, la))
    time.sleep(1.0)
    r2 = psql(ent_sql(person(f"ent_r8_q{n}"), 0, lb))
    th.join()
    cnt = one(f"SELECT count(*) FROM ac.entities WHERE entity_id IN ('ent_r8_p{n}', 'ent_r8_q{n}')")
    res.append(cnt)
    print(f"H3 слабые ключи {la or 'READ COMMITTED'} / {lb or 'READ COMMITTED'}: зафиксировано {cnt}")
report("H3", any(c == "2" for c in res), f"два физлица с одним ФИО и датой рождения: {res}")

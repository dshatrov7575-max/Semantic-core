#!/usr/bin/env python3
"""Раунд 2 (б): новое правило схемы «версия определения строго позже последнего утверждения схемы tenant».
S1  S11R-08 повторно: утверждение и удаление его предиката в одну секунду — версия отвергается; в следующую секунду принимается.
S2  пока в tenant идёт запись утверждений схемы (одно в ~0,3 с), удаётся ли конструктору модели записать версию повтором."""
import json, time, threading
from rv import *
from s9_tests import claim as claim9, sd
from schema_s9 import schema_sql

fresh(load_rows=False)
assert psql("DO $$ BEGIN CREATE ROLE ac_s9_modeler LOGIN IN ROLE ac_modeler; EXCEPTION WHEN duplicate_object THEN NULL; END $$;").returncode == 0
cur = json.loads(one("SELECT to_jsonb(k) FROM ac.class_defs k WHERE class_id = 'sdf_whale_species' ORDER BY version DESC LIMIT 1"))


def rename(n, ver):
    v = sd("ClassDef", "sdf_whale_species", ver, "RENAME_CLASS", root_type="CONCEPT", name=f"Вид китов ({n})", parent_class_id=cur["parent_class_id"], attributes=cur["attributes"])
    return psql("SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n" + schema_sql([v]) + "\nCOMMIT;")


time.sleep(1.2)
while time.time() % 1 > 0.08:
    time.sleep(0.005)
c = claim9("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": "31", "unit": "m"}}, "30 метров")
r1 = psql(ingest_sql([c], {})); r2 = rename("a", cur["version"] + 1)
time.sleep(1.1)
r3 = rename("a", cur["version"] + 1)
print(f"S1 утверждение: {first_err(r1)}; версия в ту же секунду: {first_err(r2)[:90]}; секундой позже: {first_err(r3)}")
report("S1", r2.returncode == 0, "S11R-08: версия в секунду утверждения принята")

stop, n_claims = False, [0]
def writer():
    i = 0
    while not stop:
        i += 1
        cc = claim9("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": str(100 + i), "unit": "m"}}, "30 метров")
        if psql(ingest_sql([cc], {})).returncode == 0:
            n_claims[0] += 1
        time.sleep(0.3)
th = threading.Thread(target=writer); th.start()
time.sleep(1.0)
ok = fail = 0; errs = set()
t0 = time.time()
while time.time() - t0 < 15:
    r = rename("b", cur["version"] + 2)
    if r.returncode == 0:
        ok += 1; break
    fail += 1; errs.add(first_err(r)[:60]); time.sleep(0.37)
stop = True; th.join()
print(f"S2 за 15 с: утверждений схемы записано {n_claims[0]}; попыток записать версию {ok + fail}, успешных {ok}; ошибки: {errs}")
time.sleep(1.2)
r = rename("b", cur["version"] + 2)
print("   после остановки записи утверждений:", first_err(r))
report("S2", ok == 0 and fail >= 10, "при непрерывной записи утверждений схемы tenant версия определения не записывается никогда (нет ожидания, только отказ)")

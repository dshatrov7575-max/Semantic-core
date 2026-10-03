#!/usr/bin/env python3
"""S11R-08: схема tenant (страж S9) — без гонки и в READ COMMITTED: время версии определения округляется ВНИЗ до секунды
(date_trunc('second', clock) после блокировки), поэтому версия, записанная ПОСЛЕ утверждения в ту же секунду, получает
время «не позже» утверждения. Утверждение принято по старой версии (атрибут есть), потом в ту же секунду атрибут
удалён версией с временем = секунде утверждения -> в записанном мире утверждение стоит на предикате, которого в схеме
на его момент нет. Валидатор такой мир отвергает."""
import copy, json, time
from rv import *
from s9_tests import claim as claim9, sd
from schema_s9 import schema_sql

fresh(load_rows=False)
ds0, trust, content = build()
assert psql("DO $$ BEGIN CREATE ROLE ac_s9_modeler LOGIN IN ROLE ac_modeler; EXCEPTION WHEN duplicate_object THEN NULL; END $$;").returncode == 0
cur = json.loads(one("SELECT to_jsonb(k) FROM ac.class_defs k WHERE class_id = 'sdf_whale_species' ORDER BY version DESC LIMIT 1"))
keep = [a for a in cur["attributes"] if a["predicate_id"] != "x.max_length"]
time.sleep(1.2)
for attempt in range(6):
    while time.time() % 1 > 0.08:                   # начало секунды
        time.sleep(0.005)
    c = claim9("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": str(31 + attempt), "unit": "m"}}, "30 метров")
    v = sd("ClassDef", "sdf_whale_species", cur["version"] + 1, "REMOVE_ATTRIBUTE", root_type="CONCEPT", name=cur["name"],
           parent_class_id=cur["parent_class_id"], attributes=keep)
    r1 = psql(ingest_sql([c], {}))
    r2 = psql("SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n" + schema_sql([v]) + "\nCOMMIT;") if r1.returncode == 0 else None
    if r1.returncode or r2.returncode:
        print("попытка", attempt, first_err(r1)[:90], first_err(r2)[:90] if r2 else "")
        break
    same = one(f"SELECT (SELECT recorded_at FROM ac.class_defs WHERE class_id = 'sdf_whale_species' ORDER BY version DESC LIMIT 1) <= "
               f"(SELECT recorded_at FROM ac.claims WHERE claim_id = '{c['claim_id']}')") == "t"
    if same:
        break
    # не попали в одну секунду: вернуть атрибут нельзя (предикат удалён) — следующая попытка бессмысленна
    break
print("утверждение x.max_length:", "ПРИНЯТО" if r1.returncode == 0 else first_err(r1)[:100], "| версия класса без атрибута:",
      "ПРИНЯТА" if r2 is not None and r2.returncode == 0 else "-")
print("в базе:", one("SELECT 'версия ' || k.version || ' (' || k.change_type || ') записана ' || k.recorded_at || '; утверждение записано ' || c.recorded_at || ', принято базой в ' || c.ingested_at "
                     f"FROM ac.class_defs k, ac.claims c WHERE k.class_id = 'sdf_whale_species' AND k.version = {cur['version'] + 1} AND c.claim_id = '{c['claim_id']}'"))
vdb = copy.deepcopy(v); vdb["schema_version"] = "core-ontology/0.3"; vdb["change"]["recorded_at"] = iso(one(f"SELECT recorded_at FROM ac.class_defs WHERE class_id = 'sdf_whale_species' AND version = {cur['version'] + 1}"))
ds = copy.deepcopy(ds0); ds["records"] += [vdb, c]
rep = VAL.validate(ds, trust, content)
print("валидатор на мире из базы:", rep.codes(), [e.get("msg", "")[:110] for e in rep.errors][:2])
time.sleep(1.2)
again = psql(ingest_sql([claim9("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": "40", "unit": "m"}}, "30 метров")], {}, commit=False))
print("контроль (то же утверждение секундой позже):", first_err(again)[:110])
report("S11R-08", same and bool(rep.codes()), f"утверждение и удаление его предиката в одну секунду, оба приняты; валидатор: {rep.codes()}")

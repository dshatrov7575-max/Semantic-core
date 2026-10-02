#!/usr/bin/env python3
"""Раунд 2: живые атаки на базу (снимок 2). PGDATABASE=review09r7 python3 r2_live.py"""
import sys, subprocess, os, json, time, threading
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot2"
for d in ("slice", "core", "store"): sys.path.insert(0, str(SNAP / d))
import s9_tests as S9
import s3_tests as S3
from s9_tests import sd, claim, entity, kref, ingest, first_err, PUB, INT, T, WK
from schema_s9 import write_schema, schema_sql
from ingest_s4 import ingest_sql, utc
RESTR = {"level": "RESTRICTED", "categories": ["COMMERCIAL_SECRET"]}

def show(label, res):
    print(f"  {label}\n      => {res}", flush=True)
def ws(label, *recs, user="ac_modeler"):
    r = write_schema(list(recs), user=user); res = first_err(r); show(label, res); return res
def ing(label, *recs, user="ac_loader"):
    r = ingest(*recs, user=user); res = first_err(r); show(label, res); return res
def q(label, s, user=None):
    r = S3.psql(s, user)
    res = (r.stdout.strip() + " " + (first_err(r) if r.returncode else "")).strip() or "(принято)"
    show(label, res[:500]); return res
CLS = lambda did, ver=1, ct="ADD_CLASS", **kw: sd("ClassDef", did, ver, ct, **{"root_type": "CONCEPT", "name": "Класс рецензии", **kw})

r = subprocess.run([sys.executable, str(SNAP / "slice" / "load_s1.py")], capture_output=True, text=True); print(r.stdout.strip())
S9.sql1(S3.SETUP); S9.sql1(S9.SETUP)

print("=== 1. прежние находки на живой базе ===")
q("S9R-04 гранты на таблицы схемы", "SELECT string_agg(grantee || ':' || table_name || ':' || privilege_type, ' ' ORDER BY 1) FROM information_schema.table_privileges WHERE table_schema='ac' AND table_name IN ('class_defs','class_closure','schema_predicates') AND grantee <> 'postgres';")
ws("S9R-04 ac_loader пишет класс", CLS("sdf_r2_a"), user="ac_loader")
ws("ac_modeler пишет класс sdf_r2_a (recorded_at подан 1999-01-01)", CLS("sdf_r2_a", at="1999-01-01T00:00:00Z"))
q("S9R-08 время версии поставила база", "SELECT recorded_at > now() - interval '1 minute' FROM ac.class_defs WHERE class_id='sdf_r2_a';")
q("S9R-08 ac_modeler с ac.historical_import=on и временем 2099", "SET ac.historical_import='on'; " + schema_sql([CLS("sdf_r2_fut", at="2099-01-01T00:00:00Z")]) + " SELECT recorded_at < now() + interval '1 minute' FROM ac.class_defs WHERE class_id='sdf_r2_fut';", "ac_modeler")
q("S9R-08 ac_migrator, исторический импорт, время до печати истории (1999)", "SET ac.historical_import='on'; " + schema_sql([CLS("sdf_r2_old", at="1999-01-01T00:00:00Z")]), "ac_migrator")
q("S9R-08 ac_migrator, исторический импорт, время из будущего (2099)", "SET ac.historical_import='on'; " + schema_sql([CLS("sdf_r2_fut2", at="2099-01-01T00:00:00Z")]), "ac_migrator")
for role in ("ac_modeler", "ac_loader", "ac_migrator"):
    q(f"S9R-05 {role}: INSERT в class_closure", "INSERT INTO ac.class_closure VALUES ('tnt_demo','sdf_x1','sdf_x2',1);", role)
    q(f"S9R-05 {role}: INSERT в schema_predicates", "INSERT INTO ac.schema_predicates VALUES ('tnt_demo','x.zz','ClassDef','sdf_x');", role)
q("S9R-05 владелец: DELETE из class_closure", "DELETE FROM ac.class_closure;")
q("S9R-05 владелец: UPDATE schema_predicates", "UPDATE ac.schema_predicates SET definer_id='sdf_zzz';")
q("S9R-05 ac_modeler: TRUNCATE class_defs", "TRUNCATE ac.class_defs;", "ac_modeler")
q("S9R-07 маркировка-мусор", "INSERT INTO ac.class_defs (tenant_id,class_id,version,root_type,name,marking,change_type,description,recorded_at,recorded_by) VALUES ('tnt_demo','sdf_r2_m',1,'CONCEPT','x','{\"level\":\"TOP_SECRET\",\"zzz\":1}','ADD_CLASS','d',now(),'usr_modeler1');", "ac_modeler")
q("S9R-07 имя из пробелов", "INSERT INTO ac.class_defs (tenant_id,class_id,version,root_type,name,marking,change_type,description,recorded_at,recorded_by) VALUES ('tnt_demo','sdf_r2_m',1,'CONCEPT','   ','{\"level\":\"PUBLIC\",\"categories\":[]}','ADD_CLASS','d',now(),'usr_modeler1');", "ac_modeler")
time.sleep(1.2)
ws("S9R-13 версия 2 (RENAME_CLASS) класса sdf_r2_a", CLS("sdf_r2_a", 2, "RENAME_CLASS", name="Переименован"))
ws("S9R-13 первая запись сразу version=7", CLS("sdf_r2_v7", 7))
ws("S9R-10 tnt_other создаёт класс с тем же id sdf_r2_a", sd("ClassDef", "sdf_r2_a", 1, "ADD_CLASS", tenant="tnt_other", root_type="PERSON", name="Чужой"))
ws("класс только в tnt_other: sdf_r2_foreign", sd("ClassDef", "sdf_r2_foreign", 1, "ADD_CLASS", tenant="tnt_other", root_type="CONCEPT", name="Чужой"))
time.sleep(1.2)
a = ing("S9R-10 is_a из проекта tnt_demo на класс, существующий только в tnt_other", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_foreign"), "Синий кит"))
b = ing("S9R-10 is_a на несуществующий класс", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_nonexistent"), "Синий кит"))
print("      сообщения отличаются только идентификатором:", a.replace("sdf_r2_foreign", "X") == b.replace("sdf_r2_nonexistent", "X"))
c = claim("ent_wk_blue", "schema.is_a", {"literal": {"type": "CLASS_REF", "class_id": "sdf_r2_a", "tenant_id": "tnt_someone_else"}}, "Синий кит")
ing("S9R-09 CLASS_REF с лишним tenant_id", c)
ws("абстрактный класс sdf_r2_abs", CLS("sdf_r2_abs", is_abstract=True)); ws("RESTRICTED-класс sdf_r2_secret", CLS("sdf_r2_secret", marking=RESTR, name="Секретная таксономия"))
ws("S9R-24 PUBLIC-наследник RESTRICTED-родителя", CLS("sdf_r2_pubchild", parent_class_id="sdf_r2_secret"))
time.sleep(1.2)
ing("S9R-18 is_a на абстрактный класс", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_abs"), "Синий кит"))
ing("S9R-24 PUBLIC is_a на RESTRICTED-класс", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_secret"), "Синий кит"))
ing("S9R-06 сущность THING", {**entity("ent_r2_thing", "Акулы рецензии", etype="THING"), "schema_version": "core-ontology/0.3"})
ing("S9R-03 валидный is_a (ent_wk_baleen -> sdf_r2_a)", claim("ent_wk_baleen", "schema.is_a", kref("sdf_r2_a"), "усатых китов"))
d = S9.js(f"SELECT ac.dossier('{WK}','ent_wk_baleen');", "ac_rd_public")
print("  S9R-25 досье, предложения про класс:", [f["text"] for s in d.get("sections", []) for f in s.get("facts", []) if "класс" in f.get("text", "")][:4])

print("\n=== 2. одна секунда: класс создан, is_a пишется сразу ===")
ws("ac_modeler: класс sdf_r2_fast", CLS("sdf_r2_fast"))
res = ing("ac_loader: is_a на sdf_r2_fast сразу же (recorded_at = текущая секунда)", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_fast"), "Синий кит"))
time.sleep(1.2)
ing("то же через 1,2 с", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_fast"), "Синий кит"))

print("\n=== 3. исторический импорт (ac_migrator) задним числом под живые утверждения ===")
ws("ac_modeler: класс sdf_r2_hist с атрибутом x.rv_note", CLS("sdf_r2_hist", attributes=[{"predicate_id": "x.rv_note", "name": "заметка", "value_type": "STRING", "cardinality": "MANY", "required": False}]))
t_mid = None
time.sleep(2.2); t_mid = utc(1); time.sleep(1.2)
ing("ac_loader: живой is_a на sdf_r2_hist", claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_hist"), "Синий кит"))
time.sleep(1.2)
ing("ac_loader: живое x.rv_note", claim("ent_wk_blue", "x.rv_note", {"literal": {"type": "STRING", "value": "заметка"}}, "Синий кит"))
q(f"ac_migrator: DEPRECATE_CLASS sdf_r2_hist с recorded_at={t_mid} (раньше обоих утверждений)",
  "SET ac.historical_import='on'; " + schema_sql([CLS("sdf_r2_hist", 2, "DEPRECATE_CLASS", at=t_mid, deprecated=True, attributes=[{"predicate_id": "x.rv_note", "name": "заметка", "value_type": "STRING", "cardinality": "MANY", "required": False}])]), "ac_migrator")
q("итог в базе: is_a записан ПОСЛЕ вывода класса из употребления", "SELECT c.predicate, c.recorded_at > k.recorded_at AS claim_after_deprecation, k.deprecated FROM ac.claims c, ac.class_defs k WHERE k.class_id='sdf_r2_hist' AND k.version=2 AND c.predicate = 'schema.is_a' AND c.body->'object'->'literal'->>'class_id'='sdf_r2_hist';")

print("\n=== 4. воспроизводимость ac.model на прошлый момент при незафиксированной записи is_a ===")
res = {}
def writer():
    c = claim("ent_wk_baleen", "schema.is_a", kref("sdf_r2_fast"), "усатых китов")
    sql = ingest_sql([c], {}, user="ac_loader").replace("COMMIT;", "SELECT pg_sleep(4); COMMIT;")
    res["w"] = S3.psql(sql.replace("SET SESSION AUTHORIZATION ac_loader;\n", ""), "ac_loader")
th = threading.Thread(target=writer); th.start(); time.sleep(2)
T0 = S9.sql1("SELECT clock_timestamp();")
def snap():
    m = S9.js(f"SELECT ac.model('{WK}', '{T0}'::timestamptz);", "ac_rd_public")
    return m["digest"], next(k["instances"] for k in m["classes"] if k["class_id"] == "sdf_r2_fast")
d1 = snap(); th.join(); d2 = snap()
print(f"  писатель: {first_err(res['w'])}\n  as_of={T0}\n  до фиксации:    digest={d1[0][:23]}… экземпляров sdf_r2_fast={d1[1]}\n  после фиксации: digest={d2[0][:23]}… экземпляров sdf_r2_fast={d2[1]}\n      => {'ВОСПРОИЗВОДИМ' if d1 == d2 else 'НЕ ВОСПРОИЗВОДИМ: тот же as_of, другой ответ'}")

print("\n=== 5. гонка: изменение схемы против записи утверждения ===")
ws("класс sdf_r2_race", CLS("sdf_r2_race")); time.sleep(1.2)
def w2():
    c = claim("ent_wk_blue", "schema.is_a", kref("sdf_r2_race"), "Синий кит")
    res["c"] = S3.psql(ingest_sql([c], {}, user="ac_loader").replace("COMMIT;", "SELECT pg_sleep(3); COMMIT;").replace("SET SESSION AUTHORIZATION ac_loader;\n", ""), "ac_loader")
th = threading.Thread(target=w2); th.start(); time.sleep(1)
t = time.time(); r = ws("ac_modeler: DEPRECATE_CLASS sdf_r2_race во время незафиксированного is_a", CLS("sdf_r2_race", 2, "DEPRECATE_CLASS", deprecated=True)); th.join()
print(f"  изменение схемы ждало {time.time()-t:.1f} c; писатель утверждения: {first_err(res['c'])}")
q("is_a записан раньше вывода из употребления", "SELECT (SELECT max(recorded_at) FROM ac.claims WHERE body->'object'->'literal'->>'class_id'='sdf_r2_race') < (SELECT recorded_at FROM ac.class_defs WHERE class_id='sdf_r2_race' AND version=2);")
res2 = {}
def m1(n): res2[n] = write_schema([CLS(f"sdf_r2_par{n}", parent_class_id="sdf_r2_a")])
ths = [threading.Thread(target=m1, args=(n,)) for n in (1, 2, 3)]; [x.start() for x in ths]; [x.join() for x in ths]
print("  S9R-27 три одновременных наследника одного родителя:", [first_err(res2[n]) for n in (1, 2, 3)])

print("\n=== 6. S9R-26 цена замыкания ===")
for n in (1000,):
    t = time.time()
    r = S3.psql(f"INSERT INTO ac.class_defs (tenant_id,class_id,version,root_type,name,marking,change_type,description,recorded_at,recorded_by) SELECT 'tnt_perf','sdf_flat_' || g,1,'CONCEPT','k','{{\"level\":\"PUBLIC\",\"categories\":[]}}','ADD_CLASS','d',now(),'usr_modeler1' FROM generate_series(1,{n}) g;", "ac_modeler")
    print(f"  {n} плоских классов одним INSERT: {time.time()-t:.1f} c {first_err(r)}")
t = time.time()
r = S3.psql("DO $$ BEGIN FOR g IN 1..400 LOOP INSERT INTO ac.class_defs (tenant_id,class_id,version,root_type,name,parent_class_id,marking,change_type,description,recorded_at,recorded_by) VALUES ('tnt_chain','sdf_ch_' || g,1,'CONCEPT','k',CASE WHEN g>1 THEN 'sdf_ch_' || (g-1) END,'{\"level\":\"PUBLIC\",\"categories\":[]}','ADD_CLASS','d',now(),'usr_modeler1'); END LOOP; END $$; SELECT count(*) FROM ac.class_closure WHERE tenant_id='tnt_chain';", "ac_modeler")
print(f"  цепочка глубиной 400: {time.time()-t:.1f} c строк closure={r.stdout.strip()} {first_err(r)}")

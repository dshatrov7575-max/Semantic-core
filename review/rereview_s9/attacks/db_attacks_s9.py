#!/usr/bin/env python3
"""Рецензия цикла 9: атаки на базу. Создаёт СВОИ базы review09d (DDL как сдано), review09e (patch1: только
кавычки у "symmetric"), review09f (patch2: + NEW.body вместо NEW.object в страже is_a + гранты).
Запуск: PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres python3 db_attacks_s9.py > db_attacks_s9.out 2>&1"""
import os, sys, subprocess, json, time, threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
HERE = Path(__file__).resolve().parent
SNAP = HERE.parent / "snapshot"
sys.path.insert(0, str(SNAP / "core")); sys.path.insert(0, str(SNAP / "slice"))
import vectors as VX
from vectors import V, build, _classdef, _isa_claim_world, add_entity
from validator import validate
import ingest_s4 as ING
PUB = VX.PUB

def sh(cmd, db=None, inp=None):
    env = dict(os.environ)
    if db: env["PGDATABASE"] = db
    return subprocess.run(cmd, input=inp, capture_output=True, text=True, env=env, cwd=str(SNAP))

def sql(db, text, user=None, show=True, label=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    r = sh(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], db, pre + text)
    out = (r.stdout.strip() + (" | " if r.stdout.strip() and r.stderr.strip() else "") + " ".join(r.stderr.strip().split("\n")[:2])).strip()
    if show:
        print(f"  [{db}{'/' + user if user else ''}] {label or ' '.join(text.split())[:230]}\n      => {out[:600] if out else 'OK (принято)'}")
    return r

def mkdb(db, ddl):
    sh(["dropdb", "--if-exists", db]); sh(["createdb", db])
    r = sh([sys.executable, "slice/load_s1.py"], db); assert r.returncode == 0, r.stderr
    r = sh(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", str(ddl)], db)
    print(f"  {db}: load_s1 OK; psql -v ON_ERROR_STOP=1 -f {Path(ddl).name} -> rc={r.returncode} {r.stderr.strip()[:300]}")
    return r

def now(s=0):
    return (datetime.now(timezone.utc) - timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")

def isa_case(subject="ent_c_developer", cls="sdf_org_sub", project="prj_conflict_land", classes=(), mut=None, src="s2",
             quote="Генеральный директор компании Аркадий Ломов", marking=None, extra=None):
    """-> (codes валидатора, запись Claim) для schema.is_a с recorded_at = сейчас"""
    def pre(W):
        if extra: extra(W)
        for c in classes: W["zz_" + c["class_id"]] = c
        _isa_claim_world(W, "zz_claim", subject, cls, project_id=project, source_key=src)
        W["zz_claim"]["recorded_at"] = now(2)
        W["zz_claim"]["evidence"] = [{"$ev": [src, quote]}]
        if marking: W["zz_claim"]["marking"] = marking
        if mut: mut(W["zz_claim"])
    ds, tr, ct = build(V("X", [], "", pre=pre))
    codes = validate(ds, tr, ct).codes()
    claim = [r for r in ds["records"] if r["kind"] == "Claim" and r["predicate"] == "schema.is_a"][-1]
    return codes, claim

def q(v): return ING.q(v)
def class_sql(c):
    return ("INSERT INTO ac.class_defs (class_id, tenant_id, root_type, name, label_ru, parent_class_id, is_abstract, version, created_at, created_by, marking) VALUES "
            f"({q(c['class_id'])},{q(c['tenant_id'])},{q(c['root_type'])},{q(c['name'])},{q(c.get('label_ru'))},{q(c.get('parent_class_id'))},"
            f"{q(c.get('is_abstract'))},{c['version']},{q(c['created_at'])},{q(c['created_by'])},{q(c['marking'])});")
def cls(name, **kw):
    c = _classdef(name, **kw); c["created_at"] = kw.get("created_at", now(5)); return c
def claim_sql(c):
    return ING.ingest_sql([c], {}, user="ac_loader").replace("SET SESSION AUTHORIZATION ac_loader;\n", "")

D, E_, F = "review09d", "review09e", "review09f"
print("=== 0. применение DDL ===")
mkdb(D, SNAP / "slice" / "ddl_s9.sql")
mkdb(E_, HERE / "ddl_s9_patch1.sql")
mkdb(F, HERE / "ddl_s9_patch2.sql")
sql(D, "SELECT string_agg(relname, ',' ORDER BY relname) FROM pg_class WHERE relnamespace='ac'::regnamespace AND relkind='r' AND relname IN ('class_defs','class_closure','link_defs','identifier_defs','schema_changes'); SELECT 'триггеров claims_isa_guard: ' || count(*) FROM pg_trigger WHERE tgname='claims_isa_guard';", label="что осталось в базе после сданного DDL")

print("\n=== 1. база КАК СДАНО (review09d): schema.is_a без стража ===")
v, c = isa_case(cls="sdf_nonexistent_class")
print("  валидатор:", v); sql(D, claim_sql(c), "ac_loader", label="ac_loader: is_a на несуществующий класс")
v, c = isa_case(subject="ent_c_lomov", cls="sdf_org_sub", classes=[cls("org_sub")])
print("  валидатор:", v)
sql(D, class_sql(cls("org_sub")), label="postgres: ClassDef sdf_org_sub (ORGANIZATION)")
sql(D, claim_sql(c), "ac_loader", label="ac_loader: is_a PERSON -> класс ORGANIZATION")
sql(D, "SELECT count(*) FROM ac.claims WHERE predicate='schema.is_a';", label="сколько is_a-утверждений база приняла")

print("\n=== 2. patch1 (review09e): права ===")
C1 = cls("org_sub")
sql(E_, class_sql(C1), "ac_loader", label="ac_loader: INSERT ClassDef")
sql(E_, class_sql(C1), "ac_migrator", label="ac_migrator: INSERT ClassDef")
sql(E_, "SELECT count(*) FROM ac.class_defs;", "ac_loader")
sql(E_, "SELECT count(*) FROM ac.class_closure;", "ac_projector")
sql(E_, "SELECT grantee, privilege_type FROM information_schema.table_privileges WHERE table_schema='ac' AND table_name IN ('class_defs','class_closure','link_defs','identifier_defs','schema_changes') AND grantee <> 'postgres';", label="гранты на 5 новых таблиц, кроме владельца (пустой ответ = грантов нет)")
sql(E_, class_sql(C1), label="postgres: ClassDef sdf_org_sub")
v, c = isa_case(classes=[C1])
print("  валидатор (валидный is_a, аналог P802):", v)
sql(E_, claim_sql(c), "ac_loader", label="ac_loader: валидный is_a")
sql(E_, claim_sql(c), None, label="postgres: тот же валидный is_a")

print("\n=== 3. THING ===")
def thing(W): add_entity("ent_zz_thing", "prj_wiki_whales", "THING", {"label": "Акулы", "lang": "ru"}, PUB)(W); W["ent_zz_thing"]["created_at"] = now(3)
ds, tr, ct = build(V("X", [], "", pre=thing)); print("  валидатор (сущность THING):", validate(ds, tr, ct).codes())
ent = [r for r in ds["records"] if r.get("entity_id") == "ent_zz_thing"]
sql(F, ING.ingest_sql(ent, {}).replace("SET SESSION AUTHORIZATION ac_loader;\n", ""), "ac_loader", label="ac_loader: INSERT сущности THING")
sql(F, "SELECT * FROM ac.identity_keys('THING', '{\"label\":\"Акулы\",\"lang\":\"ru\"}'::jsonb);", label="ac.identity_keys для THING (ключи идентичности)")

print("\n=== 4. маркировка, время, версии, неизменяемость (review09e, владелец) ===")
sql(E_, class_sql({**cls("mark_junk"), "marking": {"level": "TOP_SECRET", "zzz": 1}}), label="ClassDef с marking={level:TOP_SECRET,zzz:1}")
sql(E_, "INSERT INTO ac.class_defs VALUES ('sdf_mark_str2','tnt_demo','PERSON','x',NULL,NULL,NULL,1,now(),'usr_rev','\"строка\"'::jsonb);", label="ClassDef с marking='\"строка\"'::jsonb")
sql(E_, "SELECT class_id, marking, ac.marking_ok(marking) FROM ac.class_defs WHERE class_id LIKE 'sdf_mark%';")
sql(E_, class_sql({**cls("future"), "created_at": "2099-01-01T00:00:00Z"}), label="ClassDef created_at=2099-01-01")
sql(E_, class_sql({**cls("past"), "created_at": "1970-01-01T00:00:00Z"}), label="ClassDef created_at=1970-01-01 (после печати истории)")
sql(E_, "INSERT INTO ac.schema_changes VALUES ('scx_backdated','tnt_demo','ADD_CLASS','sdf_future','ClassDef','задним числом',NULL,'1999-12-31T00:00:00Z','usr_rev','{}'::jsonb);", label="SchemaChange recorded_at=1999, marking={}")
sql(E_, "SELECT change_id, recorded_at, marking FROM ac.schema_changes; SELECT 'печать истории: ' || ac.sealed_at();")
sql(E_, class_sql({**cls("org_sub"), "version": 2, "name": "Новое имя"}), label="версия 2 класса sdf_org_sub")
sql(E_, class_sql({**cls("v7only"), "version": 7}), label="первая запись класса сразу version=7")
sql(E_, "UPDATE ac.class_defs SET name='x' WHERE class_id='sdf_org_sub';", label="UPDATE class_defs (контроль)")
sql(E_, "DELETE FROM ac.schema_changes WHERE change_id='scx_backdated';", label="DELETE schema_changes (контроль)")
sql(E_, "\\d ac.class_defs", label="колонки ac.class_defs (есть ли attributes / body?)")

print("\n=== 5. closure: прямое изменение (review09e, владелец; у прежних производных таблиц стоит ac.forbid) ===")
sql(E_, "SELECT count(*) FROM ac.class_closure;")
sql(E_, "INSERT INTO ac.class_closure VALUES ('sdf_past','sdf_org_sub',1,'tnt_demo');", label="INSERT ложной строки: sdf_past — предок sdf_org_sub")
sql(E_, "UPDATE ac.class_closure SET depth = 99 WHERE ancestor_id='sdf_future';", label="UPDATE closure")
sql(E_, "DELETE FROM ac.class_closure WHERE descendant_id='sdf_v7only';", label="DELETE из closure")
sql(E_, "SELECT (SELECT count(*) FROM ac.class_defs WHERE tenant_id='tnt_demo') AS classes, (SELECT count(*) FROM ac.class_closure WHERE depth=0) AS self_rows, (SELECT count(*) FROM ac.class_closure WHERE depth<>0) AS fake_rows;", label="классы / строки depth=0 / прочие")
sql(E_, "DELETE FROM ac.claim_evidence;", label="для сравнения: DELETE из производной ac.claim_evidence")

print("\n=== 6. tenant (review09e, владелец; поведение стражей) ===")
sql(E_, class_sql({**cls("org_sub"), "tenant_id": "tnt_other"}), label="tenant tnt_other создаёт класс с id, занятым в tnt_demo")
sql(E_, class_sql({**cls("child_x", parent="org_sub"), "tenant_id": "tnt_other"}), label="tnt_other: наследник чужого sdf_org_sub (контроль)")
sql(E_, "INSERT INTO ac.schema_changes VALUES ('scx_foreign','tnt_other','ADD_CLASS','sdf_org_sub','ClassDef','чужая цель',NULL,now(),'usr_rev','{\"level\":\"PUBLIC\",\"categories\":[]}');", label="SchemaChange tnt_other на класс tnt_demo (валидатор: принято, см. val D3)")
sql(E_, "INSERT INTO ac.link_defs VALUES ('sdf_lnk_x','tnt_demo','no.such_thing',NULL,'sdf_org_sub','sdf_org_sub','MANY',true,'no.such_inverse',1,now(),'usr_rev','{\"level\":\"PUBLIC\",\"categories\":[]}');", label="LinkDef: predicate и inverse не зарегистрированы (валидатор: PREDICATE_UNKNOWN, см. val F10)")
sql(E_, "INSERT INTO ac.identifier_defs VALUES ('sdf_id_a','tnt_demo','ru.inn',NULL,'ORGANIZATION','WEAK',1,NULL,'([',1,now(),'usr_rev','{}'), ('sdf_id_b','tnt_demo','ru.inn',NULL,'ORGANIZATION','STRONG',1,'(a+)+$',NULL,1,'2099-01-01','usr_rev','{}'); SELECT idef_id, scheme, strength, validation_regex, normalization_regex FROM ac.identifier_defs;", label="IdentifierDef: два определения ru.inn (WEAK и STRONG), regex '([' и '(a+)+$'")
sql(E_, "INSERT INTO ac.schema_changes VALUES ('scx_mis','tnt_demo','CHANGE_IDENTIFIER_STRENGTH','sdf_lnk_x','LinkDef','тип не подходит цели',NULL,now(),'usr_rev','{\"level\":\"PUBLIC\",\"categories\":[]}');", label="SchemaChange CHANGE_IDENTIFIER_STRENGTH на LinkDef")

print("\n=== 7. patch2 (review09f): живой загрузчик ac_loader ===")
C1 = cls("org_sub")
sql(F, class_sql(C1), "ac_loader", label="ac_loader: INSERT ClassDef (INSERT на class_defs выдан)")
sql(F, "GRANT INSERT, DELETE ON ac.class_closure TO ac_loader, ac_migrator;", label="рецензент: добавляю INSERT, DELETE на class_closure загрузчику (иначе класс создать нельзя)")
sql(F, class_sql(C1), "ac_loader", label="ac_loader: INSERT ClassDef")
sql(F, "DELETE FROM ac.class_closure; SELECT count(*) FROM ac.class_closure;", "ac_loader", label="ac_loader: DELETE FROM ac.class_closure (теперь обязанное право)")
sql(F, "SELECT ac.rebuild_class_closure('tnt_demo'); SELECT count(*) FROM ac.class_closure;", label="владелец: пересчёт")
v, c = isa_case(classes=[C1]); print("  валидатор (валидный is_a):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader: валидный is_a (контроль)")
v, c = isa_case(classes=[C1], mut=lambda k: k["object"]["literal"].__setitem__("tenant_id", "tnt_someone_else")); print("  валидатор (CLASS_REF.tenant_id=tnt_someone_else):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader: is_a с CLASS_REF.tenant_id = tnt_someone_else")
sql(F, "SELECT tenant_id AS claim_tenant, body->'object'->'literal' FROM ac.claims WHERE predicate='schema.is_a' ORDER BY ingested_at;")
CF = {**cls("future_cls"), "created_at": "2099-01-01T00:00:00Z"}
sql(F, class_sql(CF), "ac_loader", label="ac_loader: ClassDef created_at=2099")
v, c = isa_case(cls="sdf_future_cls", classes=[CF]); print("  валидатор (is_a на класс, «созданный» в 2099):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader: is_a на класс из 2099")
CA = cls("abs_org", is_abstract=True)
sql(F, class_sql(CA), "ac_loader", label="ClassDef is_abstract=true")
v, c = isa_case(cls="sdf_abs_org", classes=[CA]); print("  валидатор (is_a на абстрактный класс):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader: is_a на абстрактный класс")
CO = {**cls("foreign_cls"), "tenant_id": "tnt_other"}
sql(F, class_sql(CO), label="класс чужого tenant tnt_other")
v, c = isa_case(cls="sdf_foreign_cls", classes=[CO]); print("  валидатор (is_a на чужой класс):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader(tnt_demo): is_a на СУЩЕСТВУЮЩИЙ класс чужого tenant")
v, c = isa_case(cls="sdf_no_such_cls"); 
sql(F, claim_sql(c), "ac_loader", label="ac_loader(tnt_demo): is_a на НЕсуществующий класс")
CR = cls("secret_cls", root_type="CONCEPT", marking={"level": "RESTRICTED", "categories": ["COMMERCIAL_SECRET"]}, label_ru="Секретная таксономия")
sql(F, class_sql(CR), label="ClassDef RESTRICTED+COMMERCIAL_SECRET")
v, c = isa_case(subject="ent_wk_blue", cls="sdf_secret_cls", project="prj_wiki_whales", classes=[CR], src="s10",
                quote="Синий кит — вид усатых китов", marking=PUB, mut=lambda k: k["object"]["literal"].__setitem__("label", "Секретная таксономия"))
print("  валидатор (PUBLIC is_a на RESTRICTED-класс, имя класса в label литерала):", v)
sql(F, claim_sql(c), "ac_loader", label="ac_loader: PUBLIC is_a на RESTRICTED-класс")
sql(F, """DO $$ BEGIN CREATE ROLE ac_rd_public LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin; INSERT INTO ac_trust.clearances (role_name, project_id, level, categories, granted_at) VALUES ('ac_rd_public','prj_wiki_whales','PUBLIC','{}','2000-01-01');""", show=False)
r = sql(F, "SELECT jsonb_pretty(ac.dossier('prj_wiki_whales','ent_wk_blue'));", "ac_rd_public", show=False)
print("  [review09f/ac_rd_public] ac.dossier('prj_wiki_whales','ent_wk_blue') — строки про is_a/класс:")
hit = [ln.strip() for ln in (r.stdout + r.stderr).split("\n") if "is_a" in ln or "Секретн" in ln or "ERROR" in ln]
print("      => " + ("\n         ".join(hit[:8]) if hit else "(is_a-утверждение в досье не попало)"))

print("\n=== 8. гонка: два одновременных INSERT наследников одного родителя (review09f, ac_loader, READ COMMITTED) ===")
res = {}
def worker(n, delay):
    c = cls(f"race_{n}", parent="org_sub")
    res[n] = sql(F, f"BEGIN; SELECT pg_sleep({delay}); {class_sql(c)} SELECT pg_sleep(3); COMMIT;", "ac_loader", show=False)
ts = [threading.Thread(target=worker, args=(1, 0)), threading.Thread(target=worker, args=(2, 1))]
[t.start() for t in ts]; [t.join() for t in ts]
for n in (1, 2):
    print(f"  сессия {n}: rc={res[n].returncode} {' '.join(res[n].stderr.split())[:300] or 'COMMIT'}")
sql(F, "SELECT class_id FROM ac.class_defs WHERE class_id LIKE 'sdf_race%' ORDER BY 1;", label="какие классы остались")

print("\n=== 9. цена полного пересчёта closure (review09f, владелец) ===")
for n in (250, 500, 1000):
    t = time.time()
    r = sql(F, f"SET statement_timeout='300s'; INSERT INTO ac.class_defs SELECT 'sdf_flat{n}_' || g, 'tnt_perf{n}', 'CONCEPT', 'k' || g, NULL, NULL, NULL, 1, now(), 'usr_rev', '{{\"level\":\"PUBLIC\",\"categories\":[]}}' FROM generate_series(1,{n}) g;", show=False)
    print(f"  {n} плоских классов одним INSERT ... SELECT: {time.time()-t:.1f} c  rc={r.returncode} {r.stderr.strip()[:120]}")
for n in (100, 200, 400):
    t = time.time()
    r = sql(F, f"SET statement_timeout='300s'; DO $$ BEGIN FOR g IN 1..{n} LOOP INSERT INTO ac.class_defs VALUES ('sdf_ch{n}_' || g, 'tnt_chain{n}', 'CONCEPT', 'k', NULL, CASE WHEN g > 1 THEN 'sdf_ch{n}_' || (g-1) END, NULL, 1, now(), 'usr_rev', '{{\"level\":\"PUBLIC\",\"categories\":[]}}'); END LOOP; END $$; SELECT 'строк closure: ' || count(*) FROM ac.class_closure WHERE tenant_id='tnt_chain{n}';", show=False)
    print(f"  цепочка глубиной {n}: {time.time()-t:.1f} c  rc={r.returncode} {r.stdout.strip()} {r.stderr.strip()[:120]}")
sql(F, """WITH RECURSIVE t(a, d, depth) AS (SELECT class_id, class_id, 0 FROM ac.class_defs UNION ALL SELECT t.a, c.class_id, t.depth+1 FROM t JOIN ac.class_defs c ON c.parent_class_id = t.d)
SELECT 'closure == рекурсивный расчёт: ' || (NOT EXISTS (SELECT a, d, depth FROM t EXCEPT SELECT ancestor_id, descendant_id, depth FROM ac.class_closure) AND NOT EXISTS (SELECT ancestor_id, descendant_id, depth FROM ac.class_closure EXCEPT SELECT a, d, depth FROM t));""", label="контроль корректности closure после всех вставок")
print("\n=== 10. используется ли closure / LinkDef / IdentifierDef хоть одной функцией базы ===")
sql(F, "SELECT coalesce(string_agg(p.proname, ', '), '(нет)') FROM pg_proc p WHERE p.pronamespace='ac'::regnamespace AND p.prosrc ~ 'class_closure' AND p.proname NOT IN ('rebuild_class_closure','class_defs_closure_refresh');", label="функции ac.*, читающие class_closure (кроме самого пересчёта)")
sql(F, "SELECT coalesce(string_agg(p.proname, ', '), '(нет)') FROM pg_proc p WHERE p.pronamespace='ac'::regnamespace AND p.prosrc ~ '(link_defs|identifier_defs|schema_changes)' AND p.proname NOT IN ('link_defs_guard','schema_changes_guard');", label="функции ac.*, читающие link_defs / identifier_defs / schema_changes (кроме их собственных стражей)")

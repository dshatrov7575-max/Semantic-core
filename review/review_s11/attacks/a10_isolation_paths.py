#!/usr/bin/env python3
"""Изоляция: пути записи и чтения мимо/под запретом (цикл 11, п. 1).
P1  строки версии набора (схема acd) пишутся в REPEATABLE READ / SERIALIZABLE (COPY/INSERT загрузчика) — стража нет
P2  ac.dataset_reset (TRUNCATE секции) в REPEATABLE READ
P3  печать версии в REPEATABLE READ
P4  TRUNCATE таблиц ядра: роли и уровень изоляции (триггер уровня оператора — только INSERT/UPDATE/DELETE)
P5  подмена уровня: SET LOCAL / set_config / default_transaction_isolation / BEGIN … READ ONLY DEFERRABLE
P6  чтение проекций в REPEATABLE READ: досье, custody, model, schema_gaps, dataset_* («чтение не запрещено»?)
P7  таблицы без стража: все схемы, все виды отношений
P8  подготовленные транзакции
"""
import json, time
from rv import *

dv = fresh(load_rows=False)
L = "SET SESSION AUTHORIZATION ac_loader;\n"
sid = dv.source_id
tbl = one(L + f"SELECT ac.dataset_open('{T}', '{sid}');").splitlines()[-1]
cols = ", ".join(["file_no", "row_no", "row_hash", "row_secret"] + ['"c_%s"' % c["name"] for c in dv.columns])
path = copy_file(dv)
res = {}
for lv in ("REPEATABLE READ", "SERIALIZABLE"):
    import subprocess
    with open(path, "rb") as fh:
        cp = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", "SET SESSION AUTHORIZATION ac_loader", "-c",
                             f"BEGIN ISOLATION LEVEL {lv}", "-c", f"COPY {tbl} ({cols}) FROM STDIN", "-c", "ROLLBACK" if lv == "SERIALIZABLE" else "COMMIT"],
                            stdin=fh, capture_output=True, text=True)
    res[lv] = "принято" if cp.returncode == 0 else cp.stderr.strip()[:100]
n = one(f"SELECT count(*) FROM {tbl}")
print(f"P1 COPY строк версии в acd: {res}; строк в секции после COMMIT в REPEATABLE READ: {n}")
report("P1", int(n) > 0, "строки версии набора (схема acd) записаны в REPEATABLE READ — на таблицах acd стража изоляции нет")
r = psql(L + f"BEGIN ISOLATION LEVEL REPEATABLE READ;\nSELECT ac.dataset_reset('{T}', '{sid}');\nCOMMIT;")
print("P2 dataset_reset в REPEATABLE READ:", "принято" if r.returncode == 0 else first_err(r)[:100], "| строк:", one(f"SELECT count(*) FROM {tbl}"))
report("P2", r.returncode == 0, "ac.dataset_reset (SECURITY DEFINER, TRUNCATE секции) выполняется в REPEATABLE READ")
with open(path, "rb") as fh:
    subprocess.run(["psql", "-X", "-q", "-c", "SET SESSION AUTHORIZATION ac_loader", "-c", f"COPY {tbl} ({cols}) FROM STDIN"], stdin=fh, capture_output=True)
r = psql(L + f"BEGIN ISOLATION LEVEL REPEATABLE READ;\nSELECT ac.dataset_seal('{T}', '{sid}');\nCOMMIT;")
print("P3 печать в REPEATABLE READ:", "принято" if r.returncode == 0 else first_err(r)[:100])
report("P3", r.returncode == 0, "печать версии в REPEATABLE READ")
assert psql(L + f"SELECT ac.dataset_seal('{T}', '{sid}');").returncode == 0

# P4 TRUNCATE
out = []
for role in ("ac_loader", "ac_migrator", "ac_modeler", "ac_trust_admin", "ac_storage", "ac_projector"):
    for t in ("ac.claims", "ac.entity_keys", "ac.claim_evidence", "ac_trust.keys", "ac.datasets"):
        r = psql(f"SET ROLE {role};\nBEGIN;\nTRUNCATE {t} CASCADE;\nROLLBACK;")
        if r.returncode == 0:
            out.append(f"{role}:{t}")
print("P4 TRUNCATE ролями приложения принят:", out or "нигде")
report("P4", bool(out), "TRUNCATE таблицы ядра ролью приложения")
r = psql("BEGIN ISOLATION LEVEL SERIALIZABLE;\nTRUNCATE ac.claim_reviews;\nROLLBACK;")
print("P4b TRUNCATE владельцем в SERIALIZABLE (страж уровня оператора TRUNCATE не ловит):", "принято (откатано)" if r.returncode == 0 else first_err(r)[:100])
r2 = psql("BEGIN;\nTRUNCATE ac.claim_reviews;\nROLLBACK;")
print("P4c TRUNCATE владельцем в READ COMMITTED (append-only):", "принято (откатано)" if r2.returncode == 0 else first_err(r2)[:100])
report("P4b", r.returncode == 0, "TRUNCATE таблицы ядра не проходит ни стража изоляции, ни стража append-only (только владелец/суперпользователь)")

# P5 spoofing the level
ins = "INSERT INTO ac.claim_reviews SELECT * FROM ac.claim_reviews LIMIT 0;"
tests = {"SET LOCAL до первого запроса": f"BEGIN;\nSET LOCAL transaction_isolation = 'repeatable read';\n{ins}\nCOMMIT;",
         "set_config(local)": f"BEGIN;\nSELECT set_config('transaction_isolation', 'serializable', true);\n{ins}\nCOMMIT;",
         "SET SESSION CHARACTERISTICS": f"SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE;\nBEGIN;\n{ins}\nCOMMIT;",
         "ALTER ROLE … SET default (сеанс)": f"SET default_transaction_isolation = 'serializable';\n{ins}",
         "READ UNCOMMITTED": f"BEGIN ISOLATION LEVEL READ UNCOMMITTED;\n{ins}\nCOMMIT;"}
for name, s in tests.items():
    r = psql(L + s)
    print(f"P5 {name}: {'ПРИНЯТО' if r.returncode == 0 else first_err(r)[:70]}")
r = psql(L + f"BEGIN ISOLATION LEVEL READ UNCOMMITTED;\n{ins}\nCOMMIT;")
report("P5", False, "подмена уровня не удалась (READ UNCOMMITTED в PostgreSQL = READ COMMITTED, но страж его отвергает: "
       + ("принят" if r.returncode == 0 else "отвергнут") + ")")

# P6 reads
assert psql(S3.SETUP).returncode == 0
cid = one("SELECT claim_id FROM ac.claims WHERE project_id = 'prj_compliance' ORDER BY 1 LIMIT 1")
reads = {"dossier": f"SELECT ac.dossier('{PRJ}', 'ent_k_developer')", "custody": f"SELECT ac.custody('{cid}')",
         "model": f"SELECT ac.model('{PRJ}')", "schema_gaps": f"SELECT ac.schema_gaps('{PRJ}')",
         "dataset_row": f"SELECT ac.dataset_row('{PRJ}', '{sid}', {key(OGRN_DEV)})", "dataset_subject": f"SELECT ac.dataset_subject('{PRJ}', '{sid}', {key(OGRN_DEV)})"}
broken = []
for name, s in reads.items():
    rc = psql(f"BEGIN;\n{s};\nCOMMIT;", "ac_rd_full")
    rr = psql(f"BEGIN ISOLATION LEVEL REPEATABLE READ;\n{s};\nCOMMIT;", "ac_rd_full")
    ro = psql(f"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n{s};\nCOMMIT;", "ac_rd_full")
    print(f"P6 {name:<16} READ COMMITTED: {'ok' if rc.returncode == 0 else first_err(rc)[:60]} | REPEATABLE READ: {'ok' if rr.returncode == 0 else first_err(rr)[:60]} | RR READ ONLY: {'ok' if ro.returncode == 0 else first_err(ro)[:50]}")
    if rc.returncode == 0 and rr.returncode != 0:
        broken.append(name)
report("P6", bool(broken), f"проекции чтения, отвергаемые в REPEATABLE READ: {broken} (остальные читаются) — заявлено «чтение не запрещено»")

# P7 tables without the guard
rows = one("SELECT coalesce(string_agg(n.nspname || '.' || c.relname || '(' || c.relkind::text || ')', ' '), 'нет') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
           "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r', 'p', 'f') "
           "AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND t.tgname = 'a_isolation_guard')")
print("P7 таблицы без стража изоляции:", rows)
print("P8 max_prepared_transactions =", one("SHOW max_prepared_transactions"))

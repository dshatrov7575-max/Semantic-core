#!/usr/bin/env python3
"""S10R / направление 3: запечатывание таблицы, не равной манифесту; необратимость неудачной загрузки; права ac_loader;
доказательство, собранное базой, которое её же страж отвергает."""
from common import *
import tempfile
from s10_tests import copy_file

COLS = ", ".join(["file_no", "row_no", "row_hash", "row_secret"])
def colsql(dv): return COLS + ", " + ", ".join('"c_%s"' % c["name"] for c in dv.columns)
def reg(dv):
    r = db_try([source_rec(dv)], commit=True); assert r.returncode == 0, first_err(r); return dv
def open_(dv, user="ac_loader"):
    r = psql(f"SELECT ac.dataset_open('{T}', '{dv.source_id}');", user); assert r.returncode == 0, first_err(r); return r.stdout.strip()
def copy_(dv, tbl, path, user="ac_loader"):
    with open(path, "rb") as fh:
        return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"SET SESSION AUTHORIZATION {user}",
                               "-c", f"COPY {tbl} ({colsql(dv)}) FROM STDIN"], stdin=fh, capture_output=True, text=True)
def seal(dv, user="ac_loader"): return psql(f"SELECT ac.dataset_seal('{T}', '{dv.source_id}');", user)
stamp = utc(0)

print("== L1. Таблица ≠ манифест: дата до н.э. хэшируется как дата н.э. (to_char без эры); ±infinity хэшируется как пустая ячейка")
rows = copy.deepcopy(REGISTRY_ROWS); rows[0]["registered_on"] = "0044-03-15"; rows[1]["registered_on"] = None
dv = reg(relabel(demo_registry(rows=rows, key=("registered_on", "ogrn")[1:]), "rev-a3-L1 " + stamp))
tbl = open_(dv)
def mut(rs):
    for x in rs:
        i = [c["name"] for c in dv.columns].index("registered_on")
        if x[4][0] == OGRN_DEV: x[4][i] = "0044-03-15 BC"
        if x[4][0] == OGRN_TRUB: x[4][i] = "infinity"
cp = copy_(dv, tbl, copy_file(dv, mut)); print("   COPY с подменой дат:", "ок" if cp.returncode == 0 else cp.stderr[:200])
print("   seal:", verdict(seal(dv)))
print("   в таблице:", psql(f"SELECT c_ogrn || ' -> ' || c_registered_on::text FROM {tbl} WHERE c_ogrn IN ('{OGRN_DEV}','{OGRN_TRUB}') ORDER BY 1").stdout.replace("\n", "; "))
print("   в манифесте (по доказательству производителя):", [(c["name"], c["value"]) for k in ([OGRN_DEV], [OGRN_TRUB])
      for c in dv.evidence(k, ["registered_on"])["cells"] if c["name"] == "registered_on"])

print("== L1b. То же при ключе-дате: строка манифеста с ключом 0044-03-15 в запечатанной таблице по ключу не находится")
rows = [dict(r, registered_on=d) for r, d in zip(copy.deepcopy(REGISTRY_ROWS), ["0044-03-15", "2002-06-03", "2002-11-18", "2015-04-01", "2020-08-20"])]
dk = reg(relabel(demo_registry(rows=rows, key=("registered_on",)), "rev-a3-L1b " + stamp))
tbl = open_(dk)
def mutk(rs):
    i = [c["name"] for c in dk.columns].index("registered_on")
    for x in rs:
        if x[4][i] == "0044-03-15": x[4][i] = "0044-03-15 BC"
cp = copy_(dk, tbl, copy_file(dk, mutk)); print("   COPY:", "ок" if cp.returncode == 0 else cp.stderr[:200])
print("   seal:", verdict(seal(dk)))
r = psql(f"SELECT coalesce(ac.dataset_row('{PRJ}', '{dk.source_id}', '[\"0044-03-15\"]')::text, 'NULL — строки нет');", "ac_rd_full")
print("   ac.dataset_row по ключу манифеста [\"0044-03-15\"]:", (r.stdout.strip() or first_err(r))[:160])
r = psql(f"SELECT ac.dataset_evidence('{PRJ}', '{dk.source_id}', '[\"0044-03-15\"]', ARRAY['address']);", "ac_rd_full")
print("   ac.dataset_evidence по тому же ключу:", (r.stdout.strip()[:80] or first_err(r))[:160])
ev = dk.evidence(["0044-03-15"], ["address", "ogrn"])
print("   а утверждение на эту строку (доказательство производителя) база принимает:",
      verdict(db_try([mk_claim(ev)])) if not __import__("time").sleep(1.1) else "")

print("== L2. Неудачная загрузка необратима: файл строк загружен дважды -> seal отказывает, исправить нельзя никому, кроме суперпользователя")
d2 = reg(relabel(demo_registry(), "rev-a3-L2 " + stamp))
tbl = open_(d2); f = copy_file(d2)
print("   COPY №1:", copy_(d2, tbl, f).returncode, " COPY №2 (повтор):", copy_(d2, tbl, f).returncode)
print("   seal:", verdict(seal(d2)))
for u in ("ac_loader", "ac_migrator"):
    for what, q in [("DELETE", f"DELETE FROM {tbl};"), ("TRUNCATE", f"TRUNCATE {tbl};"), ("повторное открытие", f"SELECT ac.dataset_open('{T}', '{d2.source_id}');"),
                    ("удаление записи каталога", f"DELETE FROM ac.dataset_tables WHERE source_id = '{d2.source_id}';")]:
        print(f"   {u}: {what} ->", verdict(psql(q, u)))
print("   функций сброса/повторного открытия в схеме:", psql("SELECT coalesce(string_agg(proname, ','), 'нет') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
      "WHERE n.nspname = 'ac' AND proname ~ 'dataset_(reset|reopen|abort|drop|close)'").stdout.strip())

print("== L3. Любой держатель роли ac_loader срывает чужую загрузку: одна строка в открытую секцию")
d3 = reg(relabel(demo_registry(), "rev-a3-L3 " + stamp))
tbl = open_(d3)
r = psql(f"INSERT INTO {tbl} (file_no, row_no, row_hash, row_secret) VALUES (0, 99, '\\x00', '\\x00');", "ac_app")
print("   ac_app (член ac_loader): мусорная строка ->", verdict(r))
print("   честная загрузка:", copy_(d3, tbl, copy_file(d3)).returncode, " seal:", verdict(seal(d3)))

print("== L4. Что ещё может ac_loader над таблицей строк")
d4 = reg(relabel(demo_registry(), "rev-a3-L4 " + stamp)); tbl = open_(d4); copy_(d4, tbl, copy_file(d4))
for what, q in [("SELECT строк (секреты)", f"SELECT row_secret FROM {tbl} LIMIT 1;"), ("INSERT ... RETURNING", f"INSERT INTO {tbl} (file_no,row_no,row_hash,row_secret) VALUES (9,9,'\\x00','\\x00') RETURNING c_director;"),
                ("COPY TO", f"COPY {tbl} TO STDOUT;"), ("UPDATE", f"UPDATE {tbl} SET c_name = 'x';"),
                ("CREATE TABLE в acd", "CREATE TABLE acd.evil (x int);"), ("запись каталога ac.datasets", f"INSERT INTO ac.datasets SELECT tenant_id, 'src:sha256:' || repeat('0',64), dataset_id, version_label, previous, row_count, manifest FROM ac.datasets LIMIT 1;"),
                ("UPDATE sealed_at", f"UPDATE ac.dataset_tables SET sealed_at = now() WHERE source_id = '{d4.source_id}';"),
                ("INSERT в ac.dataset_tables", f"INSERT INTO ac.dataset_tables (tenant_id, source_id, version_no, table_name, parent_name) SELECT tenant_id, source_id, 999999, 'v_x', 'p' FROM ac.datasets WHERE source_id = '{d3.source_id}';")]:
    print(f"   {what} ->", verdict(psql(q, "ac_loader")))
print("   seal:", verdict(seal(d4)))
for what, q in [("INSERT после печати", f"INSERT INTO {tbl} (file_no,row_no,row_hash,row_secret) VALUES (9,9,'\\x00','\\x00');"),
                ("чтение читателем напрямую", f"SELECT count(*) FROM {tbl};")]:
    print(f"   {what} ->", verdict(psql(q, "ac_loader" if "INSERT" in what else "ac_rd_full")))
par = psql(f"SELECT 'acd.' || parent_name FROM ac.dataset_tables WHERE source_id = '{d4.source_id}'").stdout.strip()
for what, q in [("суперпользователь: UPDATE через родителя", f"UPDATE {par} SET c_name = 'x' WHERE version_no = (SELECT version_no FROM ac.dataset_tables WHERE source_id = '{d4.source_id}');"),
                ("суперпользователь: TRUNCATE родителя", f"BEGIN; TRUNCATE {par}; ROLLBACK;"),
                ("суперпользователь: DETACH секции (и тогда DML мимо родителя уже не нужен)", f"BEGIN; ALTER TABLE {par} DETACH PARTITION {tbl}; DROP TABLE {tbl}; SELECT 'каталог всё ещё говорит sealed: ' || (sealed_at IS NOT NULL) FROM ac.dataset_tables WHERE source_id = '{d4.source_id}'; ROLLBACK;")]:
    r = psql(q); print(f"   {what} ->", verdict(r), r.stdout.strip()[:80])

print("== L5. Доказательство, собранное базой, отвергает её же страж: ключ передан числом (колонка-строка)")
r = psql(f"SELECT ac.dataset_evidence('{PRJ}', '{d4.source_id}', '[{OGRN_DEV}]', ARRAY['address']);", "ac_rd_full")
if r.returncode: print("   ", first_err(r))
else:
    ev = json.loads(r.stdout.strip()); print("   row_key в выданном доказательстве:", ev["row_key"], "| значение ячейки ключа:", repr(ev["cells"][0]["value"]))
    __import__("time").sleep(1.1)
    c = mk_claim(ev); print("   валидатор:", py_verdict(validate_with([source_rec(d4), c])), "\n   база:", verdict(db_try([c])))

print("== L6. Производитель вне профиля: целое > 2^53 и год 10000 в строке; seal принимает, чтение выдаёт значение вне профиля")
rows = copy.deepcopy(REGISTRY_ROWS); rows[0]["employees"] = 2 ** 53 + 1
import dataset as DS
try:
    d6 = relabel(demo_registry(rows=rows, check=False), "rev-a3-L6 " + stamp)
except Exception as ex:
    d6 = None; print("   производитель dataset.py отказался:", type(ex).__name__, str(ex)[:80])
if d6 is None:
    # собираем хэш строки вручную, как это сделал бы чужой производитель
    import validator as V
    names = [c["name"] for c in REGISTRY_COLUMNS]
    def leaf(salt, n, v):
        txt = "[" + json.dumps(n) + "," + (json.dumps(v, ensure_ascii=False) if not isinstance(v, int) or isinstance(v, bool) else str(v)) + "]"
        return hashlib.sha256(b"\x00" + salt + txt.encode()).digest()
    base = demo_registry()
    recs = []
    for key, kv, secret, h, vals in base.rows:
        vals = list(vals)
        if kv == [OGRN_DEV]: vals[names.index("employees")] = 2 ** 53 + 1
        h2 = V.merkle_root([leaf(cell_salt(secret, n), n, v) for n, v in zip(names, vals)])
        recs.append((key, kv, secret, h2, vals))
    base.rows = recs
    files = []
    for st in range(0, len(recs), base.chunk_rows):
        part = recs[st:st + base.chunk_rows]
        files.append(dict(base.manifest["files"][st // base.chunk_rows], rows_root=V.merkle_root([V.row_leaf(x[3]) for x in part]).hex()))
    base.manifest["files"] = files
    d6 = relabel(base, "rev-a3-L6 " + stamp)
reg(d6); tbl = open_(d6); cp = copy_(d6, tbl, copy_file(d6)); print("   COPY:", cp.returncode, cp.stderr[:120])
print("   seal:", verdict(seal(d6)))
r = psql(f"SELECT ac.dataset_row('{PRJ}', '{d6.source_id}', '[\"{OGRN_DEV}\"]')->'cells'->'employees';", "ac_rd_full")
print("   ac.dataset_row -> employees =", r.stdout.strip() or first_err(r), "(2^53−1 =", 2 ** 53 - 1, ")")
r = psql(f"SELECT ac.dataset_evidence('{PRJ}', '{d6.source_id}', '[\"{OGRN_DEV}\"]', ARRAY['address','employees']);", "ac_rd_full")
if r.returncode == 0:
    ev = json.loads(r.stdout.strip())
    print("   ac.dataset_evidence выдала доказательство с ячейкой employees =", next(c["value"] for c in ev["cells"] if c["name"] == "employees"))
    try:
        mk_claim(ev)
    except Exception as ex:
        print("   утверждение с таким доказательством нельзя даже адресовать:", type(ex).__name__, ex)
    txt = json.dumps(ev, ensure_ascii=False)
    r = psql(f"SELECT ac.cell_value_ok('INTEGER', '{2 ** 53 + 1}'::jsonb), ac.row_shape_ok($e${txt}$e$::jsonb);")
    print("   страж: cell_value_ok / row_shape_ok для этого доказательства ->", r.stdout.strip())

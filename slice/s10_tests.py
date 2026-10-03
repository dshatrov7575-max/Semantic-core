#!/usr/bin/env python3
"""S10 acceptance (cycle 10 part 1, D27.2 / D27.4): versions of datasets and evidence by a ROW in PostgreSQL.

S10-01 the world loads: the version of the demo registry is in the catalog (from its manifest), the claim c50 rests on
       a row; the dossier shows the quoted cells of that row and «verified» (recomputed by the database when read).
S10-02 one arithmetic in two languages: JCS of a string for EVERY Unicode scalar value, cell leaves of every type,
       tree roots, audit paths and inclusion roots for all (size, index) up to 70 — SQL equals Python.
S10-03 rows into the wide table: open -> COPY -> seal (as ac_loader); the evidence of a row built by the DATABASE from
       that table is byte-for-byte the evidence built by the Python producer, and the validator accepts it.
S10-04 seal refuses a load that is not the manifest: changed cell, missing row, extra row, swapped rows, repeated
       number, foreign secret; an unsealed version is not readable.
S10-05 a sealed version is immutable — also for the superuser and through the parent table; the catalog is derived.
S10-06 reading a row with the reader's clearance: columns above it are withheld by name; no table access at all.
S10-07 search by identifier across sealed versions honours column markings.
S10-08 live: a claim with database-built evidence is accepted; a tampered one, one about another subject and one
       that quotes a personal-data column without that category are refused with the validator's codes.
S10-09 «previous»: a second version of the dataset; a version whose previous is a document is refused — in either
       order of arrival.
S10-10 roles: the loader cannot write the catalog or seal a foreign... (the catalog comes only from the trigger),
       the reader cannot open or seal.
S10-PARITY every cycle-10 vector into a fresh database WITHOUT the validator in front: refused ⇔ refused.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s10_tests.py [--no-parity]
"""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
import validator as VAL  # noqa: E402
from jcs import canon, digest  # noqa: E402
from vectors import VECTORS, build  # noqa: E402
from fixtures import REGISTRY_ROWS, OGRN_DEV, OGRN_TRUB, INN_DEV, demo_registry  # noqa: E402
from dataset import audit_path  # noqa: E402
from ingest_s4 import ingest_sql, utc  # noqa: E402
import load_s1 as L  # noqa: E402
import s3_tests as S3  # noqa: E402
import dataset_s10 as D  # noqa: E402

RES = []
T, PRJ = "tnt_demo", "prj_compliance"
CONF_CS = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<10} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def sql1(s, user=None):
    r = S3.psql(s, user)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def js(s, user):
    return json.loads(sql1(s, user).splitlines()[-1])


def err(s, user=None):
    r = S3.psql(s, user)
    return next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr.strip()) if r.returncode else "(принято)"


def first_err(r):
    return next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), "(принято)").replace("psql:<stdin>:", "")


def copy_file(dv, mutate=None):
    """the COPY text of the rows of a DatasetVersion (dataset.py); mutate(rows) edits [file_no, row_no, hash, secret, values]"""
    rows = [[n // dv.chunk_rows, n % dv.chunk_rows, h, s, list(vals)] for n, (_, kv, s, h, vals) in enumerate(dv.rows)]
    if mutate:
        mutate(rows)
    f = tempfile.NamedTemporaryFile("w", suffix=".copy", delete=False, encoding="utf-8", newline="")
    for fno, rno, h, s, vals in rows:
        f.write("\t".join([str(fno), str(rno), "\\\\x" + h.hex(), "\\\\x" + s.hex()] + [D._copy_text(v) for v in vals]) + "\n")
    f.close()
    return f.name


def new_version(label, rows=None, **kw):
    """a fresh version of the demo registry (another label -> another manifest), registered live by the loader"""
    dv = demo_registry(rows=rows, **kw)
    dv.manifest["version_label"] = label
    dv.manifest_bytes = canon(dv.manifest).encode("utf-8")
    dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
    src, r = D.register(dv.manifest_bytes, T, "Реестр (тест S10) " + label)
    return dv, r


def claim(ev, subj="ent_k_developer", address=REGISTRY_ROWS[0]["address"], marking=CONF_CS):
    c = {"kind": "Claim", "schema_version": "core-ontology/0.4", "project_id": PRJ, "subject": subj,
         "predicate": "entity.registered_address", "object": {"literal": {"type": "STRING", "value": address}},
         "evidence": [ev], "produced_by": {"kind": "HUMAN", "actor_id": "usr_bank_officer"}, "recorded_at": utc(0), "marking": marking}
    c["claim_id"] = "clm:sha256:" + digest(c)
    return c


# vectors whose defect the database cannot hold or sees differently — each with the reason
NOT_IN_DB = {"NR1F": "пометка версии набора записей (конверта) в базе не хранится: в базе нет конверта"}
# the row FILES of a version: the database never reads them (D8) — its own check of the rows is the seal of the row table
# (S10-04, S10-11); the validator checks a file when the object store holds it
NOT_IN_DB.update({v["id"]: "файлы строк база не читает; её проверка строк — печать таблицы (S10-04)" for v in VECTORS
                  if v["id"].startswith("NRF")})
# accepted by the validator, refused by the database with a rule that only the database has (D8)
DB_STRICTER = {"PR28": "CLAIM_ABOUT_MERGED_ENTITY"}


def parity():
    rows, wrong = [], []
    for v in VECTORS:
        if v["id"][1] != "R":
            continue
        ds, tr, ct = build(v)
        rep = VAL.validate(ds, tr, ct)
        must_refuse = bool(rep.errors)
        if v["id"] in NOT_IN_DB:
            rows.append((v["id"], "N/A", NOT_IN_DB[v["id"]]))
            continue
        try:
            sql = L.load_sql(ds, tr, ct)
        except Exception as ex:  # noqa: BLE001
            rows.append((v["id"], "N/A", type(ex).__name__))
            if not must_refuse:
                wrong.append(v["id"])
            continue
        L.psql(L.DDL_ALL)
        L.register_originals(ds, ct)
        r = L.psql(sql)
        refused = r.returncode != 0
        msg = first_err(r)[:130]
        code = next((c for c in VAL.ERROR_CODES if c in msg), "")
        same = bool(code) and code in rep.codes()
        rows.append((v["id"], "REFUSED" if refused else "ACCEPTED", ("=" if same else "~") + " " + msg if refused else ""))
        if refused != must_refuse and not (v["id"] in DB_STRICTER and DB_STRICTER[v["id"]] in msg):
            wrong.append(v["id"])
    for r in rows:
        print("   ", " | ".join(r))
    neg = sum(1 for r in rows if r[1] == "REFUSED")
    same = sum(1 for r in rows if r[2].startswith("="))
    other = [r[0] for r in rows if r[1] == "REFUSED" and not r[2].startswith("=")]
    check("S10-PARITY", not wrong, "паритет с валидатором на векторах цикла 10: отвергнутое валидатором база отвергает, принятое — принимает",
          f"векторов={len(rows)} отвергнуто={neg} (тем же кодом {same}; другим {other}) принято={sum(1 for r in rows if r[1] == 'ACCEPTED')} "
          f"не представимо в базе={sum(1 for r in rows if r[1] == 'N/A')} (файлы строк {sum(1 for k in NOT_IN_DB if k.startswith('NRF'))}, "
          f"конверт 1) строже базы по своему правилу={sorted(DB_STRICTER)} расхождений={len(wrong)} {wrong}")
    L.psql(L.DDL_ALL)


def main():
    if "--no-parity" not in sys.argv:
        parity()
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    sql1(S3.SETUP)
    ds, _, _ = build()
    s30 = next(x for x in ds["records"] if x["kind"] == "Source" and x["source_kind"] == "DATASET_VERSION")
    c50 = next(x for x in ds["records"] if x["kind"] == "Claim" and x["evidence"][0].get("kind") == "ROW")
    sid = s30["source_id"]
    dv = demo_registry()
    assert dv.source_id == sid

    # S10-01
    cat = sql1("SELECT dataset_id || ' ' || version_label || ' ' || row_count || ' ' || jsonb_array_length(manifest->'files') FROM ac.datasets")
    evrow = sql1(f"SELECT kind || ' ' || (row_ev = body->'evidence'->0) FROM ac.claim_evidence e JOIN ac.claims c USING (claim_id) "
                 f"WHERE claim_id = '{c50['claim_id']}'")
    dos = js(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer', '2026-09-30T00:00:00Z');", "ac_rd_cs")
    evs = [e for f in S3.facts_of(dos) for c in f["claims"] + f.get("other_claims", []) for e in c["evidence"]
           if e.get("source_kind") == "DATASET_VERSION"]
    check("S10-01", cat == "dst_registry_demo 2026-09-01 5 2" and evrow == "ROW true" and len(evs) == 1 and evs[0]["verified"] is True
          and evs[0]["cells"] == {"ogrn": OGRN_DEV, "address": REGISTRY_ROWS[0]["address"]} and evs[0]["row_key"] == [OGRN_DEV],
          "версия набора — в каталоге из манифеста; утверждение опирается на строку; досье показывает процитированные ячейки и verified",
          f"{cat}; {evrow}; ячейки в досье: {sorted(evs[0]['cells']) if evs else None}")

    # S10-02 arithmetic parity
    ranges = "(SELECT i FROM generate_series(1, 55295) i UNION ALL SELECT i FROM generate_series(57344, 1114111) i) g"
    db_h = sql1(f"SELECT encode(sha256(string_agg(convert_to(ac.jcs(to_jsonb(chr(i))), 'UTF8'), '\\x0a'::bytea ORDER BY i)), 'hex') FROM {ranges}")
    cps = [i for i in range(1, 0x110000) if not 0xD800 <= i <= 0xDFFF]
    py_h = hashlib.sha256(b"\n".join(canon(chr(i)).encode("utf-8") for i in cps)).hexdigest()
    fast_ok = all(D.cell_json(chr(i)) == canon(chr(i)) for i in cps) and all(D.cell_json(v) == canon(v) for v in (None, True, False, 0, -7, 2 ** 53 - 1, "а\"б\\в"))
    salt = hashlib.sha256(b"s").digest()
    vals = [None, True, False, 0, -1, 48, 9007199254740991, "", "ООО «Заречье»", "a\tb\nc\"d\\e\u007f ", "2021-02-12", "𝄞"]
    db_leaves = sql1("SELECT string_agg(encode(ac.cell_leaf(decode('" + salt.hex() + "','hex'), 'имя_n', v), 'hex'), ',' ORDER BY o) FROM "
                     f"jsonb_array_elements({L.q(json.dumps(vals, ensure_ascii=False))}::jsonb) WITH ORDINALITY a(v, o)")
    py_leaves = ",".join(VAL.cell_leaf(salt, "имя_n", v).hex() for v in vals)
    leaf = [hashlib.sha256(b"leaf%d" % i).digest() for i in range(70)]
    arr = "ARRAY[" + ",".join("'\\x" + x.hex() + "'::bytea" for x in leaf) + "]"
    db_roots = sql1(f"SELECT string_agg(encode(ac.merkle_root(({arr})[1:n]), 'hex'), ',' ORDER BY n) FROM generate_series(1, 70) n")
    py_roots = ",".join(VAL.merkle_root(leaf[:n]).hex() for n in range(1, 71))
    db_paths = sql1(f"""SELECT encode(sha256(convert_to(string_agg(
        (SELECT coalesce(string_agg(encode(h, 'hex'), '' ORDER BY o), '') FROM unnest(ac.audit_path(({arr})[1:n], i)) WITH ORDINALITY a(h, o))
        || ':' || encode(ac.inclusion_root(({arr})[i + 1], i, n, ac.audit_path(({arr})[1:n], i)), 'hex'), ',' ORDER BY n, i), 'UTF8')), 'hex')
        FROM generate_series(1, 70) n, generate_series(0, n - 1) i""")
    py_paths = hashlib.sha256(",".join(
        "".join(h.hex() for h in audit_path(leaf[:n], i)) + ":" + VAL.inclusion_root(leaf[i], i, n, audit_path(leaf[:n], i)).hex()
        for n in range(1, 71) for i in range(n)).encode()).hexdigest()
    bad_incl = sql1(f"""SELECT count(*) FROM generate_series(1, 20) n, generate_series(0, n - 1) i, generate_series(0, n + 2) j
        WHERE j <> i AND ac.inclusion_root(({arr})[i + 1], j, n, ac.audit_path(({arr})[1:n], i)) IS NOT DISTINCT FROM ac.merkle_root(({arr})[1:n])""")
    py_bad = sum(1 for n in range(1, 21) for i in range(n) for j in range(n + 3)
                 if j != i and VAL.inclusion_root(leaf[i], j, n, audit_path(leaf[:n], i)) == VAL.merkle_root(leaf[:n]))
    check("S10-02", db_h == py_h and fast_ok and db_leaves == py_leaves and db_roots == py_roots and db_paths == py_paths
          and bad_incl == "0" and py_bad == 0,
          "одна арифметика на двух языках: JCS строки для каждого из 1 112 063 символов Юникода, листья ячеек всех типов, корни "
          "деревьев 1–70, пути и корни включения для всех (размер, номер); чужой номер строки не проходит ни там, ни там",
          f"jcs={db_h == py_h} быстрый_путь={fast_ok} листья={db_leaves == py_leaves} корни={db_roots == py_roots} "
          f"пути={db_paths == py_paths} чужой_номер: база {bad_incl}, валидатор {py_bad}")

    # S10-03 load and seal; evidence built by the database
    cols = dv.columns
    t, bad = D.load_rows(T, sid, copy_file(dv), cols)
    sealed = sql1("SELECT count(*) FROM ac.dataset_tables WHERE sealed_at IS NOT NULL")
    ev_db = js(f"SELECT ac.dataset_evidence('{PRJ}', '{sid}', '[\"{OGRN_DEV}\"]', ARRAY['address']);", "ac_rd_cs") if bad is None else None
    ev_py = dv.evidence([OGRN_DEV], ["address"])
    world_ok = c50["evidence"][0] == ev_py
    check("S10-03", bad is None and sealed == "1" and ev_db == ev_py and world_ok,
          "строки версии загружены загрузчиком и запечатаны; доказательство строки, собранное базой из таблицы, побайтно равно "
          "доказательству производителя на Python (оно же — в утверждении мира)",
          (first_err(bad) if bad is not None else f"запечатано={sealed} база==python: {ev_db == ev_py}"))

    # S10-04 seal refuses what is not the manifest
    def attempt(label, mutate):
        v, r = new_version(label)
        if r.returncode:
            return "register: " + first_err(r)
        _, b = D.load_rows(T, v.source_id, copy_file(v, mutate), cols)
        return first_err(b) if b is not None else "(принято)"

    def swap(rows):
        rows[0][1], rows[1][1] = rows[1][1], rows[0][1]

    att = {
        "изменённая ячейка": attempt("t04a", lambda rows: rows[0][4].__setitem__(3, "г. Москва, ул. Выдуманная, д. 1")),
        "нет строки": attempt("t04b", lambda rows: rows.pop()),
        "лишняя строка": attempt("t04c", lambda rows: rows.append([1, 1] + copy.deepcopy(rows[-1][2:]))),
        "строки переставлены": attempt("t04d", swap),
        "номер повторён": attempt("t04e", lambda rows: rows[1].__setitem__(1, 0)),
        "чужой секрет": attempt("t04f", lambda rows: rows[0].__setitem__(3, b"\x00" * 16)),
        "секрет не той длины": attempt("t04g", lambda rows: rows[0].__setitem__(3, b"\x00" * 15)),
        "пустая ячейка вместо значения": attempt("t04h", lambda rows: rows[0][4].__setitem__(3, None)),
        "файл не тот": attempt("t04i", lambda rows: rows[4].__setitem__(0, 0) or rows[4].__setitem__(1, 4)),
    }
    # an unsealed load that went wrong is reset and repeated (S10R-11)
    vr, _ = new_version("t04r")
    _, b1 = D.load_rows(T, vr.source_id, copy_file(vr, lambda rows: rows.append([1, 1] + copy.deepcopy(rows[-1][2:]))), cols)
    again = err(f"SELECT ac.dataset_seal('{T}', '{vr.source_id}');", "ac_loader")
    sql1(f"SELECT ac.dataset_reset('{T}', '{vr.source_id}');", "ac_loader")
    tblr = sql1(f"SELECT 'acd.' || table_name FROM ac.dataset_tables WHERE source_id = '{vr.source_id}'")
    colsql = ", ".join(["file_no", "row_no", "row_hash", "row_secret"] + ['"c_%s"' % c["name"] for c in cols])
    with open(copy_file(vr), "rb") as fh:
        cp = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", "SET SESSION AUTHORIZATION ac_loader",
                             "-c", f"COPY {tblr} ({colsql}) FROM STDIN"], stdin=fh, capture_output=True)
    resealed = err(f"SELECT ac.dataset_seal('{T}', '{vr.source_id}');", "ac_loader")
    att["сброс и повтор"] = "DATASET_LOAD_INVALID" if (b1 is not None and "DATASET_LOAD_INVALID" in again and cp.returncode == 0
                                                         and resealed == "(принято)") else f"{again} / {resealed}"
    att["сброс запечатанной"] = err(f"SELECT ac.dataset_reset('{T}', '{sid}');", "ac_loader").replace("APPEND_ONLY", "DATASET_LOAD_INVALID")

    # values outside the profile cannot be sealed (S10R-02, S10R-16): the loader writes its own hash of «what it loaded»
    def profile(label, column, sqlvalue, ctype):
        v, r = new_version(label)
        tb = sql1(f"SELECT ac.dataset_open('{T}', '{v.source_id}');", "ac_loader").splitlines()[-1]
        with open(copy_file(v), "rb") as fh:
            subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"COPY {tb} ({colsql}) FROM STDIN"], stdin=fh, capture_output=True)
        # the attacker (owner of the table) replaces a value and the hash by what the seal's own formula gives
        sql1(f"UPDATE {tb} SET c_{column} = {sqlvalue} WHERE c_ogrn = '{OGRN_DEV}';")
        sql1(f"UPDATE {tb} SET row_hash = " + sql1(f"SELECT ac.row_hash_expr(manifest->'columns') FROM ac.datasets WHERE source_id = '{v.source_id}'")
             + f" WHERE c_ogrn = '{OGRN_DEV}';")
        return err(f"SELECT ac.dataset_seal('{T}', '{v.source_id}');", "ac_loader")
    att["дата до н. э."] = profile("t04p1", "registered_on", "DATE '2021-02-12 BC'", "DATE")
    att["дата infinity"] = profile("t04p2", "registered_on", "'infinity'", "DATE")
    att["целое больше 2^53"] = profile("t04p3", "employees", "9007199254740993", "INTEGER")

    v_open, _ = new_version("t04z")
    sql1(f"SELECT ac.dataset_open('{T}', '{v_open.source_id}');", "ac_loader")
    unread = err(f"SELECT ac.dataset_row('{PRJ}', '{v_open.source_id}', '[\"{OGRN_DEV}\"]');", "ac_rd_cs")
    unsealed = sql1("SELECT count(*) FROM ac.dataset_tables WHERE sealed_at IS NULL")
    check("S10-04", all("DATASET_LOAD_INVALID" in x for x in att.values()) and "SOURCE_CONTENT_UNAVAILABLE" in unread,
          "запечатывание отвергает загрузку, не равную манифесту; незапечатанная версия не читается",
          "; ".join(f"{k}: {'отказ' if 'DATASET_LOAD_INVALID' in x else x}" for k, x in att.items()) + f"; незапечатанных={unsealed}; чтение: {unread[:60]}")

    # S10-05 immutability
    tbl = sql1(f"SELECT table_name FROM ac.dataset_tables WHERE source_id = '{sid}'")
    parent = sql1(f"SELECT parent_name FROM ac.dataset_tables WHERE source_id = '{sid}'")
    imm = {
        "loader INSERT": err(f"INSERT INTO acd.{tbl} SELECT * FROM acd.{tbl} LIMIT 1;", "ac_loader"),
        "superuser UPDATE": err(f"UPDATE acd.{tbl} SET c_address = 'x';"),
        "superuser DELETE": err(f"DELETE FROM acd.{tbl};"),
        "superuser TRUNCATE": err(f"TRUNCATE acd.{tbl};"),
        "через родителя": err(f"INSERT INTO acd.{parent} SELECT * FROM acd.{tbl} LIMIT 1;"),
        "UPDATE родителя": err(f"UPDATE acd.{parent} SET c_address = 'x';"),
        "каталог UPDATE": err("UPDATE ac.datasets SET row_count = 1;"),
        "каталог DELETE": err("DELETE FROM ac.datasets;"),
        "снять печать": err(f"UPDATE ac.dataset_tables SET sealed_at = NULL WHERE source_id = '{sid}';"),
        "удалить запись о таблице": err(f"DELETE FROM ac.dataset_tables WHERE source_id = '{sid}';"),
        "открыть повторно": err(f"SELECT ac.dataset_open('{T}', '{sid}');", "ac_loader"),
        "запечатать повторно": err(f"SELECT ac.dataset_seal('{T}', '{sid}');", "ac_loader"),
        "loader пишет каталог": err(f"INSERT INTO ac.datasets SELECT tenant_id, source_id, 'dst_fake', 'x', NULL, 1, manifest FROM ac.datasets;", "ac_loader"),
    }
    check("S10-05", all(x != "(принято)" for x in imm.values()) and sum("APPEND_ONLY" in x for x in imm.values()) >= 9,
          "запечатанная версия неизменяема — и для суперпользователя, и через родительскую таблицу; каталог — производный",
          "; ".join(f"{k}: {'отказ' if x != '(принято)' else 'ПРИНЯТО'}" for k, x in imm.items()))

    # S10-06 clearance
    key = f"'[\"{OGRN_DEV}\"]'"
    r_cs = js(f"SELECT ac.dataset_row('{PRJ}', '{sid}', {key});", "ac_rd_cs")
    r_full = js(f"SELECT ac.dataset_row('{PRJ}', '{sid}', {key});", "ac_rd_full")
    r_none = err(f"SELECT ac.dataset_row('{PRJ}', '{sid}', {key});", "ac_rd_none")
    ev_pd = err(f"SELECT ac.dataset_evidence('{PRJ}', '{sid}', {key}, ARRAY['director']);", "ac_rd_cs")
    direct = [err(f"SELECT * FROM acd.{tbl};", "ac_rd_full"), err("SELECT * FROM ac.datasets;", "ac_rd_full"),
              err(f"SELECT ac.dataset_cells('{T}', '{sid}', {key});", "ac_rd_full")]
    other_prj = err(f"SELECT ac.dataset_row('prj_wiki_whales', '{sid}', {key});", "ac_rd_cs")
    check("S10-06", r_cs["withheld"] == ["director"] and "director" not in r_cs["cells"] and r_cs["cells"]["employees"] == 48
          and r_full["withheld"] == [] and r_full["cells"]["director"] == REGISTRY_ROWS[0]["director"]
          and "ACCESS_DENIED" in r_none and "CLEARANCE_INSUFFICIENT" in ev_pd and all("permission denied" in x for x in direct)
          and "ACCESS_DENIED" in other_prj,
          "чтение строки по допуску: колонка с персональными данными скрыта у читателя без этой категории и названа в withheld; "
          "доказательство с такой колонкой он не получит; прямого доступа к таблицам нет",
          f"без ПД: withheld={r_cs['withheld']}; с ПД: withheld={r_full['withheld']}; без допуска: {r_none[:40]}; "
          f"доказательство с ПД: {ev_pd[:60]}")

    # S10-07 search by identifier
    f_inn = js(f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', '{INN_DEV}');", "ac_rd_cs")
    f_ogrn = js(f"SELECT ac.dataset_find('{PRJ}', 'ru.ogrn', '{OGRN_TRUB}');", "ac_rd_cs")
    f_none = js(f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', '0000000000');", "ac_rd_cs")
    mine = lambda f: [h for h in f["hits"] if h["source_id"] == sid]  # noqa: E731 - other sealed versions of the test also answer
    check("S10-07", [h["row"] for h in mine(f_inn)] == [[OGRN_DEV]] and mine(f_inn)[0]["column"] == "inn"
          and [h["row"] for h in mine(f_ogrn)] == [[OGRN_TRUB]] and f_none["hits"] == [],
          "поиск по идентификатору по запечатанным версиям: ИНН -> строка (ключ), ОГРН -> строка, неизвестный -> пусто",
          f"ИНН: {mine(f_inn)}; версий с этим ИНН: {len(f_inn['hits'])}")

    # S10-08 live claims
    ok = S3.psql(ingest_sql([claim(ev_py)], {}))
    tampered = copy.deepcopy(ev_py)
    next(c for c in tampered["cells"] if c["name"] == "address")["value"] = "г. Москва, ул. Выдуманная, д. 1"
    bad1 = first_err(S3.psql(ingest_sql([claim(tampered, address="г. Москва, ул. Выдуманная, д. 1")], {})))
    ev_trub = dv.evidence([OGRN_TRUB], ["address"])
    bad2 = first_err(S3.psql(ingest_sql([claim(ev_trub, address=REGISTRY_ROWS[1]["address"])], {})))
    bad3 = first_err(S3.psql(ingest_sql([claim(dv.evidence([OGRN_DEV], ["address", "director"]))], {})))
    old = claim(ev_py)
    old["schema_version"] = "core-ontology/0.3"
    old["claim_id"] = "clm:sha256:" + digest({k: v for k, v in old.items() if k != "claim_id"})
    bad4 = first_err(S3.psql(ingest_sql([old], {})))
    check("S10-08", ok.returncode == 0 and "EVIDENCE_ROW_INVALID" in bad1 and "EVIDENCE_ROW_INVALID" in bad2
          and "MARKING_BROADER_THAN_INPUT" in bad3 and "SCHEMA_INVALID" in bad4,
          "вживую: утверждение с доказательством-строкой принято; с подменённой ячейкой, о чужой строке, с колонкой ПД без этой "
          "категории, в записи 0.3 — отвергнуты кодами валидатора",
          f"{first_err(ok)}; подмена: {bad1[:60]}; чужая строка: {bad2[:70]}; ПД: {bad3[:50]}; 0.3: {bad4[:40]}")

    # S10-09 previous
    v2, r2 = new_version("2026-10-01", previous=sid)
    time.sleep(1.1)
    doc = sql1("SELECT source_id FROM ac.sources WHERE body->>'source_kind' <> 'DATASET_VERSION' AND tenant_id = 'tnt_demo' LIMIT 1")
    _, r3 = new_version("t09-doc", previous=doc)
    text = "Документ, который придёт позже версии набора, назвавшей его предыдущей версией."
    later = "src:sha256:" + hashlib.sha256(text.encode()).hexdigest()
    _, r4 = new_version("t09-later", previous=later)
    src_doc = {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_kind": "DOCUMENT",
               "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "поздний документ", "content_inline": text,
               "byte_length": len(text.encode()), "source_id": later, "marking": D.PUB,
               "observations": [{"observed_at": utc(0), "origin_uri": "urn:demo:late", "observed_by": "svc_webmon"}]}
    r5 = S3.psql(ingest_sql([src_doc], {}))
    check("S10-09", r2.returncode == 0 and "DATASET_MANIFEST_INVALID" in first_err(r3) and r4.returncode == 0
          and "DATASET_MANIFEST_INVALID" in first_err(r5),
          "previous: вторая версия набора принята; версия, чья предыдущая — документ, отвергнута; если документ пришёл позже "
          "версии, назвавшей его предыдущей, отвергнут он",
          f"v2: {first_err(r2)}; документ как previous: {first_err(r3)[:50]}; поздний документ: {first_err(r5)[:50]}")

    # S10-10 roles
    roles = {
        "reader open": err(f"SELECT ac.dataset_open('{T}', '{v2.source_id}');", "ac_rd_full"),
        "reader seal": err(f"SELECT ac.dataset_seal('{T}', '{v_open.source_id}');", "ac_rd_full"),
        "loader CREATE в acd": err("CREATE TABLE acd.x (a int);", "ac_loader"),
        "loader читает строки": err(f"SELECT * FROM acd.{tbl};", "ac_loader"),
        "loader пишет dataset_tables": err(f"UPDATE ac.dataset_tables SET sealed_at = now() WHERE source_id = '{v_open.source_id}';", "ac_loader"),
    }
    check("S10-10", all(x != "(принято)" for x in roles.values()),
          "роли: читатель не открывает и не запечатывает; загрузчик не создаёт таблиц, не читает строки напрямую, не ставит печать сам",
          "; ".join(f"{k}: {'отказ' if x != '(принято)' else 'ПРИНЯТО'}" for k, x in roles.items()))

    # S10-11 «previous» in either order, also when the named source has no bytes yet (S10R-01)
    def src_doc(text, with_bytes=True):
        b = text.encode()
        d = {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_kind": "DOCUMENT", "media_type": "text/plain; charset=utf-8",
             "language": "ru", "title": "документ S10-11", "byte_length": len(b), "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest(),
             "marking": D.PUB, "observations": [{"observed_at": utc(0), "origin_uri": "urn:demo:s1011", "observed_by": "svc_webmon"}]}
        sqltxt = ingest_sql([dict(d, content_inline=text)], {})
        if not with_bytes:
            sqltxt = "\n".join(ln for ln in sqltxt.splitlines() if "INSERT INTO ac.source_bytes" not in ln)
        return d["source_id"], sqltxt
    s_a, sql_a = src_doc("Документ без байтов, названный предыдущей версией (S10-11 a).", with_bytes=False)
    _, ra = new_version("t11a", previous=s_a)
    ra2 = S3.psql(sql_a)
    s_b, sql_b = src_doc("Документ без байтов, пришедший раньше версии (S10-11 b).", with_bytes=False)
    rb1 = S3.psql(sql_b)
    _, rb2 = new_version("t11b", previous=s_b)
    dvc = demo_registry()
    dvc.manifest["version_label"], dvc.manifest["previous"] = "t11c", "src:sha256:" + "0" * 64
    check("S10-11", ra.returncode == 0 and "DATASET_MANIFEST_INVALID" in first_err(ra2) and rb1.returncode == 0
          and "DATASET_MANIFEST_INVALID" in first_err(rb2),
          "previous проверяется при фиксации транзакции в любом порядке прихода, и когда названный источник записан без байтов",
          f"версия, затем документ без байтов: {first_err(ra2)[:60]}; документ без байтов, затем версия: {first_err(rb2)[:60]}")

    # S10-12 a wide version (150 columns): rows, evidence, reading (S10R-12)
    wide_cols = [{"name": "ogrn", "type": "STRING", "marking": D.PUB, "identifier_scheme": "ru.ogrn"},
                 {"name": "address", "type": "STRING", "marking": D.PUB, "predicate": "entity.registered_address"}] + \
                [{"name": f"c{n}", "type": ["STRING", "INTEGER", "BOOLEAN", "DATE"][n % 4], "marking": D.PUB} for n in range(148)]
    wide_rows = [{"ogrn": OGRN_DEV, "address": REGISTRY_ROWS[0]["address"],
                  **{f"c{n}": ["x%d" % n, n, n % 3 == 0, "2020-01-%02d" % (n % 28 + 1)][n % 4] for n in range(148)}}]
    from dataset import DatasetVersion
    wv = DatasetVersion("dst_wide_demo", T, "w1", wide_cols, ["ogrn"], wide_rows, subject=("ogrn",))
    _, rw = D.register(wv.manifest_bytes, T, "Широкий набор (150 колонок)")
    _, bw = D.load_rows(T, wv.source_id, copy_file(wv), wide_cols)
    wkey = f"'[\"{OGRN_DEV}\"]'"
    time.sleep(1.1)                                  # the claim is recorded after the version was received (S10R-27)
    w_ev = js(f"SELECT ac.dataset_evidence('{PRJ}', '{wv.source_id}', {wkey}, ARRAY['address', 'c5']);", "ac_rd_cs") if bw is None else None
    w_row = js(f"SELECT ac.dataset_row('{PRJ}', '{wv.source_id}', {wkey});", "ac_rd_cs") if bw is None else {"cells": {}}
    w_ok = S3.psql(ingest_sql([claim(w_ev)], {})) if w_ev else None
    check("S10-12", rw.returncode == 0 and bw is None and w_ev == wv.evidence([OGRN_DEV], ["address", "c5"]) and len(w_row["cells"]) == 150
          and w_ok is not None and w_ok.returncode == 0,
          "набор из 150 колонок: загружен, запечатан, строка читается, доказательство из базы равно доказательству производителя и принято стражем",
          (first_err(bw) if bw is not None else f"ячеек в строке {len(w_row['cells'])}, доказательство {len(canon(w_ev))} знаков"))

    # S10-13 no oracle «the version exists» (S10R-10); the key in evidence is the key of the cells (S10R-15)
    ghost = "src:sha256:" + "1" * 64
    o1 = [err(f"SELECT ac.{fn}('{PRJ}', '{x}'{rest});", "ac_rd_none") for x in (sid, ghost)
          for fn, rest in (("dataset_row", f", {key}"), ("dataset_evidence", f", {key}, ARRAY['address']"), ("dataset_info", ""))]
    o2 = [err(f"SELECT ac.{fn}('{PRJ}', '{ghost}'{rest});", "ac_rd_full")
          for fn, rest in (("dataset_row", f", {key}"), ("dataset_evidence", f", {key}, ARRAY['address']"), ("dataset_info", ""))]
    vn, _ = new_version("t13", key=("employees",), rows=[dict(r, employees=n + 1) for n, r in enumerate(REGISTRY_ROWS)])
    D.load_rows(T, vn.source_id, copy_file(vn), cols)
    ev_n = js(f"SELECT ac.dataset_evidence('{PRJ}', '{vn.source_id}', '[\"1\"]', ARRAY['address', 'ogrn']);", "ac_rd_cs")
    check("S10-13", len(set(o1)) == 1 and len(set(o2)) == 1 and o1[0] == o2[0] and "ACCESS_DENIED" in o1[0] and ev_n["row_key"] == [1],
          "существует ли версия — не узнать: без допуска и для несуществующей версии ответ один; ключ в доказательстве — как в ячейках",
          f"ответы: {set(o1) | set(o2)}; ключ, переданный строкой \"1\", в доказательстве: {ev_n['row_key']}")

    # S10-14 versions of one dataset are one support (S10R-13)
    n_before = sql1(f"SELECT count(DISTINCT ac.support_key(e.tenant_id, e.source_id, now())) FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) "
                    f"WHERE c.subject = 'ent_k_developer' AND c.predicate = 'entity.registered_address' AND c.project_id = '{PRJ}'")
    time_ok = S3.psql(ingest_sql([claim(dict(ev_py, source_id=v2.source_id))], {}))
    n_after = sql1(f"SELECT count(DISTINCT ac.support_key(e.tenant_id, e.source_id, now())) || ' ' || count(DISTINCT e.source_id) FROM ac.claims c "
                   f"JOIN ac.claim_evidence e USING (claim_id) WHERE c.subject = 'ent_k_developer' AND c.predicate = 'entity.registered_address' "
                   f"AND c.project_id = '{PRJ}'")
    check("S10-14", time_ok.returncode == 0 and n_after.split()[0] == n_before and int(n_after.split()[1]) > int(n_before),
          "поддержка считается по семейству набора: утверждение на той же строке из второй версии реестра не добавляет поддержки",
          f"{first_err(time_ok)}; поддержек до {n_before}, после {n_after.split()[0]} (версий-источников {n_after.split()[1]})")

    # S10-15 the files of a version in a projection; a file the store holds must have the stated length (S10R-07)
    info = js(f"SELECT ac.dataset_info('{PRJ}', '{sid}');", "ac_rd_cs")
    f0 = dv.manifest["files"][0]
    o_addr, o_len = sql1(f"SELECT object_address || ' ' || byte_length FROM ac.objects WHERE tenant_id = '{T}' LIMIT 1").split()
    dvf = demo_registry()
    dvf.manifest["version_label"] = "t15"
    dvf.manifest["files"][0].update(object=o_addr, byte_length=int(o_len) + 1)   # an object the store holds, another length
    _, rf = D.register(canon(dvf.manifest).encode("utf-8"), T, "t15")
    prov = sql1("SELECT count(*) FILTER (WHERE verified) || '/' || count(*) FROM ac.claim_provenance WHERE source_kind = 'DATASET_VERSION'")
    check("S10-15", [x["object"] for x in info["files"]] == [x["object"] for x in dv.manifest["files"]] and info["files"][0]["status"] == "NOT_STORED"
          and info["rows_loaded"] is True and "DATASET_MANIFEST_INVALID" in first_err(rf) and prov.split("/")[0] == prov.split("/")[1] != "0",
          "файлы версии видны читателю (адрес, длина, хранится ли объект); длина в манифесте сверяется с длиной объекта в хранилище; "
          "ac.claim_provenance показывает и проверяет доказательства-строки",
          f"файл 0: {info['files'][0]['status']}, {f0['byte_length']} байт; чужая длина: {first_err(rf)[:60]}; строки в provenance: {prov}")

    # S10-16 the race «a version names P as previous» / «the document P arrives» under every isolation level (S10R-20)
    def race(level, tag, level_doc=None):
        text = f"Документ гонки S10-16 {tag} {utc(0)}."
        pid = "src:sha256:" + hashlib.sha256(text.encode()).hexdigest()
        dvr = demo_registry(previous=pid)
        dvr.manifest["version_label"] = "t16-" + tag
        mb = canon(dvr.manifest).encode("utf-8")
        s_ver = ingest_sql([D.source_record(mb, T, "t16 " + tag)], {D.source_record(mb, T, "x")["source_id"]: mb})
        s_doc = ingest_sql([{"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_kind": "DOCUMENT",
                             "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "гонка", "content_inline": text,
                             "byte_length": len(text.encode()), "source_id": pid, "marking": D.PUB,
                             "observations": [{"observed_at": utc(0), "origin_uri": "urn:demo:race", "observed_by": "svc_webmon"}]}], {})
        out = []

        def run(sqltxt, lv, pause):
            body = sqltxt.replace("BEGIN;", f"BEGIN ISOLATION LEVEL {lv};\nSELECT 1;", 1).replace("COMMIT;", f"SELECT pg_sleep({pause});\nCOMMIT;")
            out.append(S3.psql(body).returncode)
        import threading
        # a mixed pair: the first transaction is slow (it holds its snapshot while the second one commits)
        th = [threading.Thread(target=run, args=(s_ver, level, 1.5 if level_doc is None else 3)),
              threading.Thread(target=run, args=(s_doc, level_doc or level, 1.5 if level_doc is None else 0.3))]
        [x.start() for x in th]
        [x.join() for x in th]
        both = sql1(f"SELECT (SELECT count(*) FROM ac.sources WHERE source_id = '{pid}') + (SELECT count(*) FROM ac.datasets WHERE previous = '{pid}')")
        return out, both
    races = {lv: race(lv, tg) for lv, tg in (("READ COMMITTED", "rc"), ("REPEATABLE READ", "rr"), ("SERIALIZABLE", "ser"))}
    races["SERIALIZABLE (медленная) + READ COMMITTED"] = race("SERIALIZABLE", "mix1", "READ COMMITTED")
    races["REPEATABLE READ (медленная) + READ COMMITTED"] = race("REPEATABLE READ", "mix2", "READ COMMITTED")
    check("S10-16", all(both != "2" for _, both in races.values()),
          "гонка «версия называет P предыдущей» и «приходит документ P»: ни на одном уровне изоляции и ни в одной смешанной паре не фиксируются обе",
          "; ".join(f"{lv}: коды {out}, записей из двух {both}" for lv, (out, both) in races.items()))

    print("ALL PASS" if all(RES) else f"FAILED: {RES.count(False)}")
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())

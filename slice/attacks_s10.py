#!/usr/bin/env python3
"""S10 attacks (cycle 10 part 1): datasets and evidence by a row — no validator in front of the database.

F1  differential fuzzing of the MANIFEST: N random mutations of a valid manifest go to the validator (parse_manifest)
    and to the database (the trigger on the bytes of the source); the verdicts must be equal for every case.
F2  differential fuzzing of the EVIDENCE ROW: N random mutations of the valid evidence of c50 go to the whole
    validator and to ac.row_evidence_guard; the verdicts must be equal for every case.
A.. targeted attacks: each must be refused («held»); «законная» lines must be accepted.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s10.py [N]
"""
import copy
import hashlib
import json
import random
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
import validator as VAL  # noqa: E402
from jcs import canon, digest  # noqa: E402
from vectors import build  # noqa: E402
from fixtures import REGISTRY_ROWS, REGISTRY_COLUMNS, OGRN_DEV, OGRN_TRUB, INN_DEV, demo_registry  # noqa: E402
from ingest_s4 import ingest_sql, psql  # noqa: E402
import s3_tests as S3  # noqa: E402
import dataset_s10 as D  # noqa: E402
from s10_tests import claim, copy_file, new_version, first_err, T, PRJ  # noqa: E402

BAD = []
TAG = "$fz$"
POOL = [None, True, False, 0, 1, -1, 5, 1.5, 2 ** 53, 2 ** 60, "", " ", "x", " ", " ", "a\tb", "A", "ogrn", "inn",
        "0" * 64, "f" * 64, "F" * 64, "0" * 63, [], {}, ["ogrn"], "STRING", "INTEGER", "DATE", "BOOLEAN", "ROW", "tnt_demo", "tnt_other",
        "dst_x", "2021-02-12", "2021-02-30", {"level": "PUBLIC", "categories": []}, {"level": "SECRET", "categories": []},
        "ru.ogrn", "entity.registered_address", "src:sha256:" + "0" * 64, 4096, 4, "48", 48]


def held(aid, ok, desc, detail=""):
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def attack(aid, desc, sql, expect, legit=False, user=None):
    r = S3.psql(sql, user)
    e = first_err(r)
    ok = (r.returncode == 0) if legit else (r.returncode != 0 and any(x in r.stderr for x in expect))
    held(aid, ok, ("законная: " if legit else "") + desc, e[:110] if r.returncode else "принято")


def paths(node, here=()):
    yield here
    if isinstance(node, dict):
        for k, v in node.items():
            yield from paths(v, here + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from paths(v, here + (i,))


def mutate(doc, rnd):
    """one random structural mutation of a JSON document (a deep copy is returned)"""
    d = copy.deepcopy(doc)
    ps = [p for p in paths(d) if p]
    p = rnd.choice(ps)
    parent = d
    for k in p[:-1]:
        parent = parent[k]
    last, cur = p[-1], parent[p[-1]]
    op = rnd.randrange(9)
    if op == 0:
        del parent[last]
    elif op == 1:
        parent[last] = copy.deepcopy(rnd.choice(POOL))
    elif op == 2 and isinstance(cur, str) and cur:
        i = rnd.randrange(len(cur))
        parent[last] = cur[:i] + rnd.choice("0123456789abcdefAZ я\t_.") + cur[i + 1:]
    elif op == 3 and isinstance(cur, int) and not isinstance(cur, bool):
        parent[last] = cur + rnd.choice([-1, 1, 2, -cur, 10 ** 6])
    elif op == 4 and isinstance(cur, list) and len(cur) > 1:
        i, j = rnd.sample(range(len(cur)), 2)
        cur[i], cur[j] = cur[j], cur[i]
    elif op == 5 and isinstance(cur, list) and cur:
        cur.append(copy.deepcopy(rnd.choice(cur)))
    elif op == 6 and isinstance(cur, dict):
        cur[rnd.choice(["zz", "name", "leaf", "salt", "value", "kind", "predicate", "identifier_scheme", "subject", "previous"])] = \
            copy.deepcopy(rnd.choice(POOL))
    elif op == 7 and isinstance(cur, str):
        parent[last] = cur + rnd.choice([" ", "\n", "0", "x", "́"])
    elif op == 8 and isinstance(cur, list) and cur:
        cur.pop(rnd.randrange(len(cur)))
    else:
        parent[last] = copy.deepcopy(rnd.choice(POOL))
    return d


def dumps(doc, rnd):
    """bytes of a mutated document: canonical when possible, sometimes deliberately not"""
    style = rnd.randrange(10)
    try:
        if style == 0:
            return json.dumps(doc, ensure_ascii=False).encode("utf-8")              # spaces, insertion order
        if style == 1:
            return json.dumps(doc, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")   # \\uXXXX escapes
        return canon(doc).encode("utf-8")
    except Exception:  # noqa: BLE001 - floats / big integers are not canonicalizable: send them as plain JSON
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def run_sql_verdicts(setup, calls):
    r = psql(setup + "\n" + "\n".join(calls))
    if r.returncode:
        sys.exit("fuzz harness failed: " + r.stderr[:2000])
    return r.stdout.splitlines()


def fuzz_manifest(n, rnd):
    base = demo_registry().manifest
    cases, seen = [], {canon(base).encode("utf-8")}
    while len(cases) < n:
        m = mutate(base, rnd)
        if rnd.random() < 0.3:
            m = mutate(m, rnd)
        b = dumps(m, rnd)
        if b"\\u0000" in b or b"\x00" in b or b in seen:      # the unchanged manifest is already a source of the world
            continue
        seen.add(b)
        cases.append(b)
    setup = """
CREATE FUNCTION pg_temp.manifest_verdict(b64 text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE b bytea := decode(b64, 'base64'); sid text; pub jsonb := '{"level":"PUBLIC","categories":[]}';
BEGIN
  sid := 'src:sha256:' || encode(sha256(b), 'hex');
  BEGIN
    INSERT INTO ac.sources VALUES ('tnt_demo', sid, length(b), pub, jsonb_build_object('kind', 'Source', 'schema_version', 'core-ontology/0.4',
      'tenant_id', 'tnt_demo', 'source_kind', 'DATASET_VERSION', 'media_type', 'application/vnd.ac.dataset-manifest+json',
      'language', 'ru', 'title', 'fuzz', 'marking', pub, 'byte_length', length(b), 'source_id', sid));
    INSERT INTO ac.source_bytes VALUES ('tnt_demo', sid, b);
    INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by)
      VALUES ('tnt_demo', sid, '2026-09-05T08:00:00Z', 'urn:fuzz', 'svc_dataset_loader');
    SET CONSTRAINTS ALL IMMEDIATE;                 -- the checks of COMMIT (previous, predicates of the columns)
    RAISE EXCEPTION 'FUZZ_ACCEPTED';
  EXCEPTION WHEN others THEN
    RETURN replace(SQLERRM, E'\\n', ' ');
  END;
END $f$;"""
    import base64
    out = run_sql_verdicts(setup, [f"SELECT pg_temp.manifest_verdict('{base64.b64encode(b).decode()}');" for b in cases])
    diff, acc = [], 0
    ds, tr, ct = build()
    # the validator is asked what the database can be asked: the manifest, not the row files (the database never reads
    # them — its check of the rows is the seal, S10-04)
    ct = {k: v for k, v in ct.items() if v[:5] != b'{"h":'}
    recs = ds["records"]
    si = next(i for i, x in enumerate(recs) if x["kind"] == "Source" and x["source_kind"] == "DATASET_VERSION")
    for b, verdict in zip(cases, out):
        # the whole validator: the world plus one more version of the dataset with these bytes as its manifest
        why = None
        try:
            text = b.decode("utf-8")
            extra = dict(recs[si], content_inline=text, byte_length=len(b), source_id="src:sha256:" + hashlib.sha256(b).hexdigest(), title="fuzz")
            rep = VAL.validate(dict(ds, records=recs + [extra]), tr, dict(ct, **{extra["source_id"]: b}))
            py_ok, why = not rep.errors, [e["msg"][:80] for e in rep.errors][:1]
        except UnicodeDecodeError:
            py_ok = False
        db_ok = verdict.startswith("FUZZ_ACCEPTED")
        acc += py_ok
        if py_ok != db_ok:
            diff.append((b[:300].decode("utf-8", "replace"), why, verdict[:100]))
    for d in diff[:8]:
        print("      расхождение:", d)
    held("F1", not diff and 0 < acc < n, f"манифест: {n} случайных мутаций — вердикт валидатора и базы совпал на каждой",
         f"принято обоими {acc}, отвергнуто обоими {n - acc - len(diff)}, расхождений {len(diff)}")


def fuzz_row(n, rnd):
    ds, tr, ct = build()
    recs = ds["records"]
    ci = next(i for i, x in enumerate(recs) if x["kind"] == "Claim" and x["evidence"][0].get("kind") == "ROW")
    c50 = recs[ci]
    sid = c50["evidence"][0]["source_id"]
    variants = [demo_registry().evidence([OGRN_DEV], q) for q in (["address"], ["address", "name", "registered_on", "active", "employees"],
                                                                 ["address", "inn"])]
    for v in variants:
        v["source_id"] = sid
    cases = []
    while len(cases) < n:
        ev = copy.deepcopy(rnd.choice(variants))
        if rnd.random() > 0.08:                      # some cases stay valid: both sides must ACCEPT them
            ev = mutate(ev, rnd)
            if rnd.random() < 0.25:
                ev = mutate(ev, rnd)
        txt = json.dumps(ev, ensure_ascii=False)
        if "\\u0000" in txt or TAG in txt:
            continue
        cases.append((ev, txt))
    setup = f"""
CREATE FUNCTION pg_temp.row_verdict(txt text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE c ac.claims; src ac.sources; ev jsonb;
BEGIN
  SELECT * INTO c FROM ac.claims WHERE claim_id = '{c50['claim_id']}';
  SELECT * INTO src FROM ac.sources WHERE source_id = '{sid}';
  BEGIN
    ev := txt::jsonb;
    IF ev->>'source_id' IS DISTINCT FROM src.source_id THEN RETURN 'REF_UNRESOLVED'; END IF;
    c.body := jsonb_set(c.body, '{{evidence,0}}', ev);
    PERFORM ac.row_evidence_guard(c, src, ev);
    RETURN 'FUZZ_ACCEPTED';
  EXCEPTION WHEN others THEN
    RETURN replace(SQLERRM, E'\\n', ' ');
  END;
END $f$;"""
    out = run_sql_verdicts(setup, [f"SELECT pg_temp.row_verdict({TAG}{t}{TAG});" for _, t in cases])
    diff, acc, same_code = [], 0, 0
    for (ev, txt), verdict in zip(cases, out):
        c = dict(c50, evidence=[ev])
        try:
            c["claim_id"] = "clm:sha256:" + digest({k: v for k, v in c.items() if k != "claim_id"})
        except Exception:  # noqa: BLE001 - not canonicalizable (a float, a huge integer): the validator refuses it at phase 0
            c["claim_id"] = c50["claim_id"]
        d2 = dict(ds, records=recs[:ci] + [c] + recs[ci + 1:])
        rep = VAL.validate(d2, tr, ct)
        py_ok = not [e for e in rep.errors if e["code"] != "CLAIM_ID_MISMATCH"]
        db_ok = verdict.startswith("FUZZ_ACCEPTED")
        acc += py_ok
        if py_ok != db_ok:
            diff.append((txt[:400], rep.codes(), [e["msg"][:80] for e in rep.errors][:2], verdict[:100]))
        elif not py_ok and any(code in verdict for code in rep.codes()):
            same_code += 1
    for d in diff[:8]:
        print("      расхождение:", d)
    held("F2", not diff and 0 < acc < n, f"доказательство-строка: {n} случайных мутаций — вердикт валидатора и базы совпал на каждой",
         f"принято обоими {acc}, отвергнуто обоими {n - acc - len(diff)} (тем же кодом {same_code}), расхождений {len(diff)}")


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    S3.psql(S3.SETUP)
    rnd = random.Random(20261002)
    fuzz_manifest(n, rnd)
    fuzz_row(n, rnd)

    dv = demo_registry()
    sid = dv.source_id
    t, bad = D.load_rows(T, sid, copy_file(dv), dv.columns)
    assert bad is None, first_err(bad)
    ev = dv.evidence([OGRN_DEV], ["address"])
    RI, SI, MB = ["EVIDENCE_ROW_INVALID"], ["SCHEMA_INVALID"], ["MARKING_BROADER_THAN_INPUT"]

    def ing(*records):
        return ingest_sql(list(records), {}, commit=False)

    def ev_with(fn, base=None):
        e = copy.deepcopy(base or ev)
        fn(e)
        return e

    attack("A01", "утверждение с доказательством-строкой (контроль)", ing(claim(ev)), [], legit=True)
    attack("A02", "ячейка и со значением, и с листом", ing(claim(ev_with(lambda e: e["cells"][0].__setitem__("leaf", "0" * 64)))), SI)
    attack("A03", "лишнее поле в доказательстве", ing(claim(ev_with(lambda e: e.__setitem__("note", "x")))), SI)
    attack("A04", "хэш строки в верхнем регистре", ing(claim(ev_with(lambda e: e.__setitem__("row_sha256", e["row_sha256"].upper())))), SI)
    attack("A05", "номер файла 2^53−1", ing(claim(ev_with(lambda e: e["proof"].__setitem__("file", 2 ** 53 - 1)))), RI)
    attack("A06", "номер файла отрицательный", ing(claim(ev_with(lambda e: e["proof"].__setitem__("file", -1)))), SI)
    attack("A07", "номер строки 2^53−1", ing(claim(ev_with(lambda e: e["proof"].__setitem__("index", 2 ** 53 - 1)))), RI)
    attack("A08", "65 хэшей в пути", ing(claim(ev_with(lambda e: e["proof"].__setitem__("hashes", ["0" * 64] * 65)))), SI)
    attack("A09", "row_key — объект", ing(claim(ev_with(lambda e: e.__setitem__("row_key", [{"a": 1}])))), SI)
    attack("A10", "вид доказательства «row» строчными", ing(claim(ev_with(lambda e: e.__setitem__("kind", "row")))), SI + ["violates check constraint"])
    attack("A11", "доказательство-строка и фрагмент в одном элементе",
           ing(claim(ev_with(lambda e: e.update(span={"start": 0, "end": 5}, quote_sha256="0" * 64)))), SI)
    two = claim(ev)
    two["evidence"].append(ev_with(lambda e: _cell(e, "address").__setitem__("value", "подмена")))
    two["claim_id"] = "clm:sha256:" + digest({k: v for k, v in two.items() if k != "claim_id"})
    attack("A12", "два доказательства: верная строка и подменённая", ing(two), RI)
    pipe = claim(ev)
    pipe["produced_by"] = {"kind": "PIPELINE", "pipeline_id": "svc_x", "run_id": "r1"}
    pipe["claim_id"] = "clm:sha256:" + digest({k: v for k, v in pipe.items() if k != "claim_id"})
    attack("A13", "PIPELINE-утверждение на строке без квитанции", ingest_sql([pipe], {}, commit=True),
           ["RECEIPT", "GRAPH_NODE_INVALID", "violates"])
    attack("A14", "строка другой версии набора с тем же содержимым: source_id подменён на чужой",
           ing(claim(ev_with(lambda e: e.__setitem__("source_id", "src:sha256:" + "0" * 64)))), ["foreign key", "CROSS_SCOPE", "REF_UNRESOLVED"])
    v2, r2 = new_version("a15")
    assert r2.returncode == 0, first_err(r2)
    time.sleep(1.1)                                  # the claim is recorded after the version was received
    attack("A15", "доказательство версии 2026-09-01 предъявлено как строка другой версии (другой манифест, те же строки)",
           ing(claim(ev_with(lambda e: e.__setitem__("source_id", v2.source_id)))), [], legit=True)
    v3, r3 = new_version("a16", rows=[dict(REGISTRY_ROWS[0], director="Другой Директор")] + REGISTRY_ROWS[1:])
    attack("A16", "доказательство строки предъявлено версии, где эта строка другая (скрытая ячейка изменилась)",
           ing(claim(ev_with(lambda e: e.__setitem__("source_id", v3.source_id)))), RI)

    # reading
    key = f"'[\"{OGRN_DEV}\"]'"
    attack("A20", "SQL-инъекция в ключе строки", f"SELECT ac.dataset_row('{PRJ}', '{sid}', $k$[\"x' OR '1'='1\"]$k$);", [], legit=True, user="ac_rd_cs")
    inj = S3.psql(f"SELECT ac.dataset_row('{PRJ}', '{sid}', $k$[\"x' OR '1'='1\"]$k$);", "ac_rd_cs").stdout.strip()
    held("A21", inj == "", "инъекция в ключе не вернула строк", repr(inj[:40]))
    f = S3.psql(f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', $k$x' OR '1'='1$k$);", "ac_rd_cs").stdout
    held("A22", '"hits": []' in f, "инъекция в значении идентификатора не вернула строк", f[:60].strip())
    attack("A23", "инъекция в имени колонки для цитаты", f"SELECT ac.dataset_evidence('{PRJ}', '{sid}', {key}, ARRAY['address\"; DROP TABLE ac.claims; --']);",
           ["REF_UNRESOLVED"], user="ac_rd_cs")
    attack("A24", "читатель без допуска ищет по идентификатору", f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', '{INN_DEV}');", ["CLEARANCE_INSUFFICIENT"], user="ac_rd_none")
    attack("A28", "поиск через несуществующий проект", f"SELECT ac.dataset_find('prj_no_such', 'ru.inn', '{INN_DEV}');", ["CLEARANCE_INSUFFICIENT"], user="ac_rd_cs")
    attack("A25", "версия набора через несуществующий проект", f"SELECT ac.dataset_row('prj_no_such', '{sid}', {key});", ["ACCESS_DENIED"], user="ac_rd_cs")
    # a dataset whose KEY is personal data: search by a public identifier must not give the key away
    cols = copy.deepcopy(REGISTRY_COLUMNS)
    cols[0]["marking"] = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
    vk, rk = new_version("a26", columns=cols)
    _, b = D.load_rows(T, vk.source_id, copy_file(vk), cols)
    assert rk.returncode == 0 and b is None, first_err(rk if rk.returncode else b)
    hits = [h for h in json.loads(S3.psql(f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', '{INN_DEV}');", "ac_rd_cs").stdout)["hits"]
            if h["source_id"] == vk.source_id]
    held("A26", len(hits) == 1 and "row" not in hits[0] and "row_sha256" in hits[0],
         "ключ набора — персональные данные: поиск по открытому ИНН называет строку хэшем, ключ не выдаёт", json.dumps(hits, ensure_ascii=False)[:120])
    attack("A27", "чтение строки по ключу с ПД читателем без этой категории: доказательство не выдаётся",
           f"SELECT ac.dataset_evidence('{PRJ}', '{vk.source_id}', {key}, ARRAY['address']);", ["CLEARANCE_INSUFFICIENT"], user="ac_rd_cs")

    attack("A29", "чтение строки по ключу с ПД читателем без этой категории: есть ли такая строка — не узнать",
           f"SELECT ac.dataset_row('{PRJ}', '{vk.source_id}', {key});", ["CLEARANCE_INSUFFICIENT"], user="ac_rd_cs")
    attack("A30", "тот же ключ читателю с категорией ПД", f"SELECT ac.dataset_row('{PRJ}', '{vk.source_id}', {key});", [], legit=True, user="ac_rd_full")

    # races
    vr, rr = new_version("a30")
    res = []
    th = [threading.Thread(target=lambda: res.append(S3.psql(f"SELECT ac.dataset_open('{T}', '{vr.source_id}');", "ac_loader").returncode)) for _ in range(4)]
    [x.start() for x in th]
    [x.join() for x in th]
    held("R1", sorted(res) == [0, 1, 1, 1] or res.count(0) == 1, "гонка: четыре одновременных открытия одной версии — прошло одно", str(res))
    tbl = S3.psql(f"SELECT 'acd.' || table_name FROM ac.dataset_tables WHERE source_id = '{vr.source_id}'").stdout.strip()
    cols_sql = ", ".join(["file_no", "row_no", "row_hash", "row_secret"] + ['"c_%s"' % c["name"] for c in vr.columns])
    with open(copy_file(vr), "rb") as fh:
        cp = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"COPY {tbl} ({cols_sql}) FROM STDIN"], stdin=fh, capture_output=True)
    assert cp.returncode == 0, cp.stderr
    res = []
    th = [threading.Thread(target=lambda: res.append(S3.psql(f"SELECT ac.dataset_seal('{T}', '{vr.source_id}');", "ac_loader").returncode)) for _ in range(4)]
    [x.start() for x in th]
    [x.join() for x in th]
    held("R2", res.count(0) == 1, "гонка: четыре одновременных запечатывания — прошло одно", str(res))
    # a writer that holds an uncommitted row while seal runs: seal waits for it and then counts it
    vw, _ = new_version("a31")
    tblw = S3.psql(f"SELECT ac.dataset_open('{T}', '{vw.source_id}');", "ac_loader").stdout.strip()
    with open(copy_file(vw), "rb") as fh:
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"COPY {tblw} ({cols_sql}) FROM STDIN"], stdin=fh, capture_output=True)
    slow = subprocess.Popen(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    slow.stdin.write(f"BEGIN; INSERT INTO {tblw} SELECT * FROM {tblw} LIMIT 1; SELECT pg_sleep(3); COMMIT;\n")
    slow.stdin.flush()
    time.sleep(1)
    seal = S3.psql(f"SELECT ac.dataset_seal('{T}', '{vw.source_id}');", "ac_loader")
    slow.stdin.close()
    slow.wait()
    held("R3", seal.returncode != 0 and "DATASET_LOAD_INVALID" in seal.stderr,
         "гонка: строка, вставленная незавершённой транзакцией во время запечатывания, — печать её дождалась и отвергла загрузку",
         first_err(seal)[:90])

    print(f"\nattacks={len(BAD)} findings={sum(BAD)}")
    return 1 if any(BAD) else 0


def _cell(ev, name):
    return next(x for x in ev["cells"] if x["name"] == name)


if __name__ == "__main__":
    sys.exit(main())

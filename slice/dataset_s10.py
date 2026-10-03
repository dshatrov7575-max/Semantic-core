#!/usr/bin/env python3
"""S10 (cycle 10, D27.2): a dataset version into PostgreSQL — the «massive profile».

    build_stream(...)        rows (sorted by key) -> row files + COPY file + manifest, one pass, constant memory
    register_and_load(...)   Source(DATASET_VERSION) with the manifest -> ac.dataset_open -> COPY -> ac.dataset_seal
    synthetic_registry(n)    n rows shaped like the register of legal entities (ЕГРЮЛ): 12 columns, two identifiers

The database trusts nothing of this module: the manifest is parsed and checked by a trigger, every row hash and every
file root is recomputed at ac.dataset_seal and compared with the manifest.

Measurement:  PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<db> python3 slice/dataset_s10.py measure 1000000 [out_dir]
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
from jcs import canon  # noqa: E402
from validator import merkle_root  # noqa: E402
from dataset import row_secret  # noqa: E402
from ingest_s4 import ingest_sql, utc  # noqa: E402

PUB = {"level": "PUBLIC", "categories": []}
INT = {"level": "INTERNAL", "categories": []}
CONF_PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
MEDIA = "application/vnd.ac.dataset-manifest+json"
_sha = hashlib.sha256


def cell_json(v):
    """the JCS text of a cell value; equal to jcs.canon(v) for the four column types (checked by S10-03)"""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(v, ensure_ascii=False)


def row_hash_fast(secret, prefixes, values):
    """= dataset.row_hash; prefixes[i] = (salt suffix bytes of the column name, b'["name",')"""
    level = []
    for (nm, pre), v in zip(prefixes, values):
        salt = _sha(b"\x03" + secret + nm).digest()
        level.append(_sha(b"\x00" + salt + pre + cell_json(v).encode("utf-8") + b"]").digest())
    n = len(level)
    while n > 1:
        nxt = [_sha(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, n - 1, 2)]
        if n % 2:
            nxt.append(level[-1])
        level, n = nxt, len(nxt)
    return level[0]


def _copy_text(v):
    if v is None:
        return "\\N"
    if v is True:
        return "t"
    if v is False:
        return "f"
    if isinstance(v, int):
        return str(v)
    return v.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def build_stream(dataset_id, tenant_id, version_label, columns, key, rows, out_dir, chunk_rows=4096, dataset_key=None,
                 subject=(), previous=None):
    """rows: iterable of value lists in column order, sorted by canon(key values). Writes into out_dir:
    objects/<sha256> (row files, JSON lines) and rows.copy (COPY text for the wide table: file_no, row_no, row_hash,
    row_secret, the cells). dataset_key: the 32 secret bytes of the dataset (dataset.row_secret); by default random —
    then the loader must keep it if later versions are to share unchanged rows. -> (manifest, manifest bytes, source_id)"""
    dataset_key = dataset_key or os.urandom(32)
    out = Path(out_dir)
    (out / "objects").mkdir(parents=True, exist_ok=True)
    names = [c["name"] for c in columns]
    kpos = [names.index(k) for k in key]
    prefixes = [(n.encode("utf-8"), ("[" + canon(n) + ",").encode("utf-8")) for n in names]
    files, total, last_key = [], 0, None
    copy = open(out / "rows.copy", "w", encoding="utf-8", newline="")

    def flush(part, file_no):
        data = "".join(canon({"h": h.hex(), "k": kv, "s": s.hex(), "v": vals}) + "\n" for kv, s, h, vals in part).encode("utf-8")
        addr = "sha256:" + _sha(data).hexdigest()
        (out / "objects" / addr[7:]).write_bytes(data)
        files.append({"object": addr, "byte_length": len(data), "rows": len(part),
                      "rows_root": merkle_root([_sha(b"\x02" + h).digest() for _, _, h, _ in part]).hex()})
        for i, (kv, s, h, vals) in enumerate(part):
            copy.write("\t".join([str(file_no), str(i), "\\\\x" + h.hex(), "\\\\x" + s.hex()]
                                 + [_copy_text(v) for v in vals]) + "\n")

    part = []
    for values in rows:
        kv = [values[p] for p in kpos]
        secret = row_secret(dataset_key, dataset_id, values)
        h = row_hash_fast(secret, prefixes, values)
        order = canon(kv) if key else h.hex()
        if last_key is not None and order <= last_key:
            raise ValueError("строки не упорядочены по ключу или ключ повторяется")
        last_key = order if key else None            # rows without a key are ordered by the caller (by hash)
        part.append((kv, secret, h, values))
        total += 1
        if len(part) == chunk_rows:
            flush(part, len(files))
            part = []
    if part:
        flush(part, len(files))
    copy.close()
    manifest = {"manifest_format": "ac-dataset-manifest/0.1", "dataset_id": dataset_id, "tenant_id": tenant_id,
                "version_label": version_label, "columns": columns, "key": list(key), "row_count": total, "files": files}
    if previous:
        manifest["previous"] = previous
    if subject:
        manifest["subject"] = list(subject)
    b = canon(manifest).encode("utf-8")
    (out / "manifest.json").write_bytes(b)
    return manifest, b, "src:sha256:" + _sha(b).hexdigest()


def source_record(manifest_bytes, tenant_id, title, marking=PUB, observed_at=None, origin_uri="urn:demo:dataset"):
    return {"kind": "Source", "schema_version": "core-ontology/0.4", "tenant_id": tenant_id, "source_kind": "DATASET_VERSION",
            "media_type": MEDIA, "language": "ru", "title": title, "marking": marking, "byte_length": len(manifest_bytes),
            "source_id": "src:sha256:" + _sha(manifest_bytes).hexdigest(),
            "observations": [{"observed_at": observed_at or utc(0), "origin_uri": origin_uri, "observed_by": "svc_dataset_loader"}]}


def psql(sql, user=None, stdin_file=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)


def register(manifest_bytes, tenant_id, title, marking=PUB, user="ac_loader", **kw):
    """the Source of the version with its manifest -> the database parses, checks and registers the version"""
    src = source_record(manifest_bytes, tenant_id, title, marking, **kw)
    return src, psql(ingest_sql([src], {src["source_id"]: manifest_bytes}, tenant=tenant_id, user=user))


def load_rows(tenant_id, source_id, copy_path, columns, user="ac_loader", seal=True):
    """open -> COPY -> seal; -> (timings dict, psql result of the failing step or None)"""
    t = {}
    t0 = time.time()
    r = psql(f"SELECT ac.dataset_open('{tenant_id}', '{source_id}');", user)
    if r.returncode:
        return t, r
    table = r.stdout.strip().splitlines()[-1]
    cols = ", ".join(["file_no", "row_no", "row_hash", "row_secret"] + ['"c_%s"' % c["name"] for c in columns])
    with open(copy_path, "rb") as fh:
        cp = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"SET SESSION AUTHORIZATION {user}",
                             "-c", f"COPY {table} ({cols}) FROM STDIN"], stdin=fh, capture_output=True)
    if cp.returncode:
        cp.stderr = cp.stderr.decode("utf-8", "replace")
    t["copy_s"] = round(time.time() - t0, 2)
    if cp.returncode:
        return t, cp
    if seal:
        t0 = time.time()
        r = psql(f"SELECT ac.dataset_seal('{tenant_id}', '{source_id}');", user)
        t["seal_s"] = round(time.time() - t0, 2)
        if r.returncode:
            return t, r
    return t, None


# ---------------------------------------------------------------- synthetic register of legal entities
REGISTRY_COLUMNS = [
    {"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
    {"name": "inn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.inn"},
    {"name": "kpp", "type": "STRING", "marking": PUB},
    {"name": "name", "type": "STRING", "marking": PUB},
    {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"},
    {"name": "okved", "type": "STRING", "marking": PUB},
    {"name": "registered_on", "type": "DATE", "marking": PUB},
    {"name": "active", "type": "BOOLEAN", "marking": PUB},
    {"name": "capital_minor", "type": "INTEGER", "marking": PUB},
    {"name": "employees", "type": "INTEGER", "marking": INT},
    {"name": "director", "type": "STRING", "marking": CONF_PD},
    {"name": "director_inn", "type": "STRING", "marking": CONF_PD, "identifier_scheme": "ru.inn"}]
_FORMS = ["ООО", "АО", "ПАО", "ООО", "ООО", "НКО"]
_WORDS = ["Вектор", "Заречье", "Север", "Альфа", "Монолит", "Гранит", "Восток", "Прогресс", "Техно", "Строй", "Агро", "Транс",
          "Инвест", "Ресурс", "Балтика", "Урал", "Сибирь", "Волга", "Орион", "Кедр"]
_CITIES = ["г. Москва", "г. Санкт-Петербург", "г. Казань", "г. Новосибирск", "г. Екатеринбург", "Московская обл., г. Заречный",
           "г. Архангельск", "г. Самара", "г. Краснодар", "г. Владивосток"]
_STREETS = ["ул. Ленина", "ул. Мира", "пр. Ломоносова", "ул. Лесная", "ул. Заречная", "ул. Садовая", "наб. Реки", "ш. Энтузиастов"]
_SUR = ["Иванов", "Петров", "Сидоров", "Ломов", "Седов", "Крылов", "Нечаев", "Орлов", "Волков", "Зайцев"]
_GIV = ["Иван", "Пётр", "Аркадий", "Олег", "Сергей", "Андрей", "Николай", "Дмитрий"]
_PAT = ["Иванович", "Петрович", "Семёнович", "Олегович", "Ильич", "Андреевич"]


def _ogrn(n):
    p = "1%011d" % n
    return p + str(int(p) % 11 % 10)


def _inn10(n):
    d = [int(c) for c in "%09d" % n]
    return "".join(map(str, d)) + str(sum(w * x for w, x in zip([2, 4, 10, 3, 5, 9, 4, 6, 8], d)) % 11 % 10)


def _inn12(n):
    d = [int(c) for c in "%010d" % n]
    d.append(sum(w * x for w, x in zip([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d)) % 11 % 10)
    d.append(sum(w * x for w, x in zip([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d)) % 11 % 10)
    return "".join(map(str, d))


def synthetic_registry(n, seed=20261002, start=0):
    """n rows in column order of REGISTRY_COLUMNS, sorted by OGRN (the key)"""
    rnd = random.Random(seed)
    for i in range(start, start + n):
        w1, w2 = rnd.choice(_WORDS), rnd.choice(_WORDS)
        y, mth, dd = rnd.randint(1992, 2026), rnd.randint(1, 12), rnd.randint(1, 28)
        liquidated = rnd.random() < 0.12
        yield [_ogrn(20_000_000_000 + i * 7), _inn10(770_000_000 + i), "%04d01001" % (7700 + i % 2000),
               f"{rnd.choice(_FORMS)} «{w1}-{w2} {i}»",
               f"{rnd.choice(_CITIES)}, {rnd.choice(_STREETS)}, д. {rnd.randint(1, 200)}, оф. {rnd.randint(1, 900)}",
               "%02d.%02d" % (rnd.randint(1, 96), rnd.randint(1, 99)), "%04d-%02d-%02d" % (y, mth, dd), not liquidated,
               rnd.choice([10_000, 10_000, 10_000, 100_000, 1_000_000, 50_000_000]) * 100,
               None if rnd.random() < 0.3 else rnd.randint(0, 5000),
               None if liquidated else f"{rnd.choice(_SUR)} {rnd.choice(_GIV)} {rnd.choice(_PAT)}",
               None if liquidated else _inn12(5_000_000_000 + rnd.randint(0, 3_000_000))]


def measure(n, out_dir, tenant="tnt_demo"):
    out = Path(out_dir)
    res = {"rows": n}
    t0 = time.time()
    m, b, sid = build_stream("dst_egrul_synth", tenant, f"synthetic-{n}", REGISTRY_COLUMNS, ["ogrn"], synthetic_registry(n), out,
                             subject=("ogrn", "inn"))
    res["build_s"] = round(time.time() - t0, 1)
    res["files"] = len(m["files"])
    res["manifest_bytes"] = len(b)
    res["row_files_mb"] = round(sum(f["byte_length"] for f in m["files"]) / 2 ** 20, 1)
    t0 = time.time()
    src, r = register(b, tenant, f"Синтетический реестр юридических лиц, {n} строк")
    if r.returncode:
        sys.exit("register failed: " + r.stderr)
    res["register_s"] = round(time.time() - t0, 2)
    t, bad = load_rows(tenant, sid, out / "rows.copy", REGISTRY_COLUMNS)
    if bad is not None:
        sys.exit("load failed: " + bad.stderr)
    res.update(t)
    tbl = psql(f"SELECT 'acd.' || table_name FROM ac.dataset_tables WHERE source_id = '{sid}'").stdout.strip()
    res["table_mb"] = round(int(psql(f"SELECT pg_table_size('{tbl}')").stdout) / 2 ** 20, 1)
    res["indexes_mb"] = round(int(psql(f"SELECT pg_indexes_size('{tbl}')").stdout) / 2 ** 20, 1)
    res["source_id"] = sid
    # a reader with clearance: search by identifier, evidence of a row built by the database, its check by the validator
    import validator as VAL
    r = psql("""DO $$ BEGIN CREATE ROLE ac_rd_measure LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories, granted_at)
SELECT 'ac_rd_measure', 'prj_compliance', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}', '2000-01-01'
WHERE NOT EXISTS (SELECT 1 FROM ac_trust.clearances WHERE role_name = 'ac_rd_measure');""")
    if r.returncode:
        sys.exit("reader setup failed: " + r.stderr)
    k = 200
    rnd = random.Random(1)
    idx = [rnd.randrange(n) for _ in range(k)]
    t0 = time.time()
    r = psql("\n".join(f"SELECT ac.dataset_find('prj_compliance', 'ru.inn', '{_inn10(770_000_000 + i)}');" for i in idx), "ac_rd_measure")
    if r.returncode:
        sys.exit("find failed: " + r.stderr)
    hits = [json.loads(x) for x in r.stdout.splitlines()]
    assert all([x["row"] for x in h["hits"] if x["source_id"] == sid] == [[_ogrn(20_000_000_000 + i * 7)]] for h, i in zip(hits, idx)), "find"
    res["find_by_inn_ms"] = round((time.time() - t0) * 1000 / k, 2)
    t0 = time.time()
    r = psql("\n".join(f"SELECT ac.dataset_evidence('prj_compliance', '{sid}', '[\"{_ogrn(20_000_000_000 + i * 7)}\"]', ARRAY['address']);"
                       for i in idx), "ac_rd_measure")
    if r.returncode:
        sys.exit("evidence failed: " + r.stderr)
    evs = [json.loads(x) for x in r.stdout.splitlines()]
    res["evidence_from_db_ms"] = round((time.time() - t0) * 1000 / k, 2)
    res["evidence_json_bytes"] = len(canon(evs[0]))
    t0 = time.time()
    for ev in evs:
        addr = next(c["value"] for c in ev["cells"] if c["name"] == "address")
        c = {"predicate": "entity.registered_address", "object": {"literal": {"type": "STRING", "value": addr}}}
        why = VAL.row_evidence_error(ev, m, c, c["object"]["literal"], None, None)
        assert why is None, why
    res["validator_check_ms"] = round((time.time() - t0) * 1000 / k, 3)
    return res


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "measure":
        print(json.dumps(measure(int(sys.argv[2]), sys.argv[3] if len(sys.argv) > 3 else f"/tmp/ac_ds_{sys.argv[2]}"), ensure_ascii=False))
    else:
        sys.exit(__doc__)

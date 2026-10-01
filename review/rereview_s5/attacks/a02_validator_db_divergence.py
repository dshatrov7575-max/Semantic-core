#!/usr/bin/env python3
"""A02: the same records, validator vs database (live, ac_loader).
  X1  a rendition whose bytes contain NUL (valid UTF-8): validator computes a text, the database does not
  X2  a rendition with a Unicode 15 combining mark (U+1E4EC NAG MUNDARI SIGN MUHOR) before U+0301: the two NFC differ
For each: validator verdict on world + Source + Publication(validator digest); database verdict on the same Publication,
and on the Publication with the database's own digest.
Usage: PGHOST=... PGDATABASE=review052 python3 a02_validator_db_divergence.py  (reloads the world)
"""
import hashlib
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc, q  # noqa: E402
from s5_tests import source, publication  # noqa: E402

r = subprocess.run([sys.executable, "/home/claude/as/slice/load_s1.py"], capture_output=True, text=True)
assert r.returncode == 0, r.stdout + r.stderr

BASE = "Жители Заречной улицы выступили против застройки, сообщает издание."
CASES = {
    "X1": (BASE + "\x00", "https://nul.example/a"),
    "X2": (BASE + " e" + chr(0x1E4EC) + chr(0x0301), "https://unicode15.example/a"),
}


def val_codes(text, url):
    ds, trust, content = build()
    s = source(text, url, "2026-09-20T10:00:00Z")
    pb = publication(text, url, "2026-09-20T10:05:00Z")
    pb["published_at"] = "2026-09-20T09:00:00Z"
    ds["records"] += [s, pb]
    rep = VAL.validate(ds, trust, content)
    codes = sorted({e[0] if isinstance(e, tuple) else e.get("code", str(e)) for e in rep.errors}) if hasattr(rep, "errors") else rep.codes()
    return pb, codes


for cid, (text, url) in CASES.items():
    b = text.encode("utf-8")
    pb_val, codes = val_codes(text, url)
    pg_td = psql(f"SELECT coalesce(ac.text_digest(decode('{b.hex()}','hex')),'NULL');").stdout.strip()
    time.sleep(1.1)
    s = source(text, url, utc(0))
    rs = psql(ingest_sql([s], {}))
    time.sleep(1.1)
    pb = publication(text, url, utc(0))
    if pb["text_digest"] is None:
        print(f"{cid} ВАЛИДАТОР: текст не сравним (None) -> публикация невозможна; коды при записи с digest=None: {codes}")
        print(f"{cid} БАЗА: источник -> {'принят' if rs.returncode == 0 else rs.stderr[:100]}; text_digest базы = {pg_td}")
        print(f"{cid} DIVERGENCE={'no' if pg_td == 'NULL' else 'YES'}")
        continue
    rp = psql(ingest_sql([pb], {}, commit=False))
    msg_val = "принято" if rp.returncode == 0 else rp.stderr.strip().splitlines()[0][:110]
    alt = "—"
    if pg_td != "NULL":
        pb2 = {**pb, "text_digest": pg_td, "publication_id": VAL.publication_address("tnt_demo", pb["outlet"], pg_td)}
        rp2 = psql(ingest_sql([pb2], {}, commit=False))
        alt = "принято" if rp2.returncode == 0 else rp2.stderr.strip().splitlines()[0][:110]
    pub_err = [c for c in codes if c in ("PUBLICATION_INVALID", "SOURCE_CONTENT_UNAVAILABLE", "SCHEMA_INVALID")]
    print(f"{cid} validator_digest={str(pb_val['text_digest'])[:20]}… db_digest={pg_td[:20]}…")
    print(f"{cid} ВАЛИДАТОР: публикация с его digest -> {'принято' if not pub_err else pub_err} (все коды мира+записей: {codes})")
    print(f"{cid} БАЗА: источник -> {'принят' if rs.returncode == 0 else rs.stderr[:100]}; та же публикация -> {msg_val}")
    print(f"{cid} БАЗА: публикация с digest базы -> {alt}")
    print(f"{cid} DIVERGENCE={'YES' if (not pub_err) != (rp.returncode == 0) else 'no'}")

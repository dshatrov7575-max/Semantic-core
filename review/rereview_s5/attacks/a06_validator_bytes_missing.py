#!/usr/bin/env python3
"""A06: validator vs database on a source of the outlet WITHOUT bytes (an unrelated page of news.example, never cited).
Validator: SOURCE_CONTENT_UNAVAILABLE because a publication of that outlet exists (the world is otherwise valid);
database: the same records are accepted (a source without bytes has no text and is simply not a rendition).
Usage: PGHOST=... PGDATABASE=review052 python3 a06_validator_bytes_missing.py  (reloads the world)
"""
import hashlib
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import psql, utc, q  # noqa: E402
from s5_tests import source  # noqa: E402

r = subprocess.run([sys.executable, "/home/claude/as/slice/load_s1.py"], capture_output=True, text=True)
assert r.returncode == 0

def nobytes(text, uri, at):
    s = source(text, uri, at)
    del s["content_inline"]
    return s

ds, trust, content = build()
base = VAL.validate(ds, trust, content).codes()
ds2, trust2, content2 = build()
ds2["records"].append(nobytes("Совсем другая страница сайта: погода на завтра.", "https://news.example/weather", "2026-09-02T08:00:00Z"))
rep = VAL.validate(ds2, trust2, content2)
ds3, trust3, content3 = build()
ds3["records"].append(nobytes("Страница другого сайта без байтов.", "https://other-site.example/x", "2026-09-02T08:00:00Z"))
rep3 = VAL.validate(ds3, trust3, content3)
print(f"A06 мир: {base}; + источник news.example без байтов: {rep.codes()} ; + такой же источник другого сайта: {rep3.codes()}")
time.sleep(1.1)
s = nobytes("Совсем другая страница сайта: погода на завтра.", "https://news.example/weather", utc(0))
o = s["observations"][0]
rd = psql(f"""SET SESSION AUTHORIZATION ac_loader;
BEGIN;
INSERT INTO ac.sources VALUES ('tnt_demo',{q(s['source_id'])},{s['byte_length']},{q(s['marking'])},{q(s)});
INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES ('tnt_demo',{q(s['source_id'])},now(),{q(o['origin_uri'])},'svc_webmon');
COMMIT;""")
print(f"A06 база: тот же источник без байтов -> {'принят' if rd.returncode == 0 else rd.stderr[:100]}; "
      f"DIVERGENCE={'YES' if rep.codes() != base and rd.returncode == 0 else 'no'}")

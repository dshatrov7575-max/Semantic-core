#!/usr/bin/env python3
"""A05: the marking of the feed vs what it contains.
  M1  a CONFIDENTIAL rendition (later fetch of the article) is listed to a CONFIDENTIAL reader; the feed's own marking
      (lub of publications, claims, entity) does not include it -> the projection is labelled PUBLIC while it carries
      the id, address and time of a CONFIDENTIAL source.
  M2  published_at of a publication record far in the past (valid in the schema too): the mention disappears from a
      date-filtered feed although every rendition was fetched inside the range.
Usage: PGHOST=... PGDATABASE=review052 python3 a05_feed_marking.py  (reloads the world)
"""
import json
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
import s3_tests as S3  # noqa: E402
import s5_tests as S5  # noqa: E402
from s5_tests import source, feed, sql1, mention, publication  # noqa: E402

r = subprocess.run([sys.executable, "/home/claude/as/slice/load_s1.py"], capture_output=True, text=True)
assert r.returncode == 0, r.stdout + r.stderr
sql1(S3.SETUP)
sql1(S5.SETUP)
ds, _, _ = build()
S2 = next(s["content_inline"] for s in ds["records"] if s["kind"] == "Source" and s["title"].startswith("Жители")
          and "\n" not in s["content_inline"] and chr(0x200B) not in s["content_inline"])
CONF = {"level": "CONFIDENTIAL", "categories": []}

time.sleep(1.1)
conf = source(S2.replace(". ", ".\t", 1), "https://amp.news.example/zarechye?src=closed-channel", utc(0), marking=CONF)
psql(ingest_sql([conf], {}))
time.sleep(1.1)
f = feed(user="ac_rd_wm_conf")
inside = conf["source_id"] in json.dumps(f)
print(f"M1 {'FINDING' if inside and f['marking']['level'] == 'PUBLIC' else 'held'} | лента содержит конфиденциальный рендеринг: {inside}; "
      f"маркировка ленты: {f['marking']}")

# M2
time.sleep(1.1)
txt = S2.replace("весной", "зимой")
s = source(txt, "https://region2.example/a", utc(0))
psql(ingest_sql([s], {}))
time.sleep(1.1)
m = mention(s["source_id"], txt, "Жители Заречной улицы выступили против застройки", utc(0))
psql(ingest_sql([m], {}))
time.sleep(1.1)
day = utc(0)[:10]
before = [i.get("source_id") or i.get("publication_id") for i in feed(dfrom=day)["items"]]
p = publication(txt, "https://region2.example/a", utc(0))
p["published_at"] = "1970-01-01T00:00:00Z"
rp = psql(ingest_sql([p], {}))
time.sleep(1.1)
after = feed(dfrom=day)["items"]
print(f"M2 {'FINDING' if rp.returncode == 0 and s['source_id'] not in json.dumps(after) else 'held'} | позиций с {day} до записи публикации: {len(before)}; "
      f"после записи публикации с published_at=1970: {len(after)} (упоминание {'исчезло' if s['source_id'] not in json.dumps(after) else 'осталось'}); "
      f"запись: {'принята' if rp.returncode == 0 else rp.stderr[:90]}")

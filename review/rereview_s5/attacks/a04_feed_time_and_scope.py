#!/usr/bin/env python3
"""A04: the feed ac.wm_feed — time (D16) and scope.
  F1  late bytes: a source of the article observed at news.example is written WITHOUT bytes, bytes arrive later.
      ac.source_texts has no time of its own -> ac.renditions_at(pub, t) for a PAST t changes, the feed as of t changes.
  F2  scope: a source that NO claim of the reader's project cites (fetched for another project — its address carries
      the case parameters), PUBLIC, same text -> listed to the WM reader (PUBLIC, prj_wm_region) as a rendition,
      with its id, raw address and time of fetch.
  F3  a CONFIDENTIAL-only rendition observed later than the publication: hidden from the PUBLIC reader (control).
Usage: PGHOST=... PGDATABASE=review051 python3 a04_feed_time_and_scope.py  (reloads the world)
"""
import json
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc, q, b64  # noqa: E402
import s3_tests as S3  # noqa: E402
import s5_tests as S5  # noqa: E402
from s5_tests import source, feed, sql1  # noqa: E402

r = subprocess.run([sys.executable, "/home/claude/as/slice/load_s1.py"], capture_output=True, text=True)
assert r.returncode == 0, r.stdout + r.stderr
sql1(S3.SETUP)
sql1(S5.SETUP)
ds, _, _ = build()
pub = next(p for p in ds["records"] if p["kind"] == "Publication")
S2 = next(s["content_inline"] for s in ds["records"] if s["kind"] == "Source" and s["title"].startswith("Жители")
          and "\n" not in s["content_inline"] and chr(0x200B) not in s["content_inline"])


def rend(f):
    it = [i for i in f["items"] if i.get("publication_id") == pub["publication_id"]]
    return [(x["source_id"][:18], x["urls"]) for x in it[0]["renditions"]] if it else None


# ---- F1 late bytes
time.sleep(1.1)
late = source(S2.replace(". ", ".   ", 1), "https://news.example/zarechye?page=1", utc(0))
body = {k: v for k, v in late.items() if k != "content_inline"}
o = late["observations"][0]
r1 = psql(f"""SET SESSION AUTHORIZATION ac_loader;
BEGIN;
INSERT INTO ac.sources VALUES ('tnt_demo',{q(late['source_id'])},{late['byte_length']},{q(late['marking'])},{q(body)});
INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES
  ('tnt_demo',{q(late['source_id'])},{q(o['observed_at'])},{q(o['origin_uri'])},'svc_webmon');
COMMIT;""")
print("F1 источник без байтов:", "записан" if r1.returncode == 0 else r1.stderr[:200])
time.sleep(1.1)
t1 = utc(0)
time.sleep(1.1)
f_before = feed(as_of=t1)
time.sleep(1.1)
r2 = psql(f"SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.source_bytes VALUES ('tnt_demo',{q(late['source_id'])},{b64(late['content_inline'].encode())});")
print("F1 байты дописаны позже:", "записаны" if r2.returncode == 0 else r2.stderr[:200])
time.sleep(1.1)
f_after = feed(as_of=t1)
ch = f_before["digest"] != f_after["digest"]
print(f"F1 {'FINDING' if ch else 'held'} | лента на прошедший момент {t1}: рендерингов до={len(rend(f_before))} после={len(rend(f_after))}; "
      f"digest до={f_before['digest'][:24]} после={f_after['digest'][:24]}")
k = sql1(f"SELECT ac.support_key('tnt_demo', {q(late['source_id'])}, {q(t1)}::timestamptz)")
print(f"F1   support_key(поздний источник, {t1}) после дописывания байтов = {k[:30]}… (на тот момент байтов не было)")

# ---- F2 scope: a source no claim of prj_wm_region cites
time.sleep(1.1)
other = source(S2.replace(". ", ". " + chr(0x2003), 1), "https://news.example/zarechye?case=chk_full_1&client=ent_k_developer&analyst=petrova", utc(0),
               title="Материал к Проверке chk_full_1")
r3 = psql(ingest_sql([other], {}))
time.sleep(1.1)
cited = sql1(f"SELECT count(*) FROM ac.claim_evidence e JOIN ac.claims c USING (claim_id) WHERE e.source_id = {q(other['source_id'])}")
fw = json.dumps(feed(), ensure_ascii=False)
leak = other["source_id"] in fw and "case=chk_full_1" in fw
print(f"F2 {'FINDING' if leak else 'held'} | источник не процитирован ни одним утверждением (цитирований: {cited}); читатель ac_rd_wm (PUBLIC, prj_wm_region) "
      f"видит его id: {other['source_id'] in fw}; адрес с параметрами чужой работы: {'case=chk_full_1&client=ent_k_developer&analyst=petrova' in fw}")

# ---- F3 control: a CONFIDENTIAL rendition joined later is hidden from the public reader, shown to the confidential one
time.sleep(1.1)
conf = source(S2.replace(". ", ".\t", 1), "https://amp.news.example/zarechye", utc(0), marking={"level": "CONFIDENTIAL", "categories": []})
psql(ingest_sql([conf], {}))
time.sleep(1.1)
fp, fc = json.dumps(feed(), ensure_ascii=False), json.dumps(feed(user="ac_rd_wm_conf"), ensure_ascii=False)
print(f"F3 {'held' if conf['source_id'] not in fp and conf['source_id'] in fc else 'FINDING'} | конфиденциальный рендеринг: публичному виден={conf['source_id'] in fp}, "
      f"конфиденциальному={conf['source_id'] in fc}")

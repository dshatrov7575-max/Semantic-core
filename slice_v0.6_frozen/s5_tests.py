#!/usr/bin/env python3
"""S5 acceptance in PostgreSQL: publications (O4, D21) and the projection «лента упоминаний».

S5-01 the world: one publication of news.example; its renditions are derived — three sources with different bytes
      (extra line break and no-break space; invisible zero-width space; desktop, AMP path, www with utm, mobile host);
      the aggregator address is not a rendition; database renditions == validator semantics.
S5-02 feed of the developer: ONE item for the article fetched three times; one mention (two claims from two renditions).
S5-03 a live re-fetch with other whitespace and another tracking parameter joins the publication by itself (no new
      publication record): 4 renditions; still one item; the feed as of before the fetch shows 3 renditions.
S5-04 an edited article (one word changed) is another text: its mention is a separate item (by source); after its own
      publication record it is a separate publication item.
S5-05 support keys: all renditions of the article -> the same publication; a source outside outlets -> itself.
S5-06 a CONFIDENTIAL publication is not shown to a PUBLIC reader: no title, address or id of it in the feed; the
      mention stays as a source item.
S5-07 closed Check reports do not change when renditions and publications arrive later (D16).
S5-08 refusal is the same: no clearance, unknown entity, another project.
S5-09 date filter; S5-10 the same as_of gives the same digest.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s5_tests.py
"""
import copy
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from jcs import digest  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
import s3_tests as S3  # noqa: E402

RES = []
SETUP = """
DO $$ BEGIN CREATE ROLE ac_rd_wm LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_wm_conf LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES ('ac_rd_wm', 'prj_wm_region', 'PUBLIC', '{}');
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES ('ac_rd_wm_conf', 'prj_wm_region', 'CONFIDENTIAL', '{}');
RESET ROLE;
"""
PUB = {"level": "PUBLIC", "categories": []}
CONF = {"level": "CONFIDENTIAL", "categories": []}


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<6} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def sql1(s, user=None):
    r = psql((f"SET SESSION AUTHORIZATION {user};\n" if user else "") + s)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout.strip()


def feed(eid="ent_w_developer", user="ac_rd_wm", as_of=None, dfrom=None, proj="prj_wm_region"):
    args = f"'{proj}', '{eid}'" + (f", {as_of!r}::timestamptz" if as_of else ", now()") + (f", {dfrom!r}::date" if dfrom else "")
    return json.loads(sql1(f"SELECT ac.wm_feed({args});", user).splitlines()[-1])


def source(text, uri, observed, marking=PUB, title="Жители Заречной улицы против застройки"):
    b = text.encode("utf-8")
    return {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": "tnt_demo", "source_kind": "MEDIA_ARTICLE",
            "media_type": "text/plain; charset=utf-8", "language": "ru", "title": title, "content_inline": text, "marking": marking,
            "observations": [{"observed_at": observed, "origin_uri": uri, "observed_by": "svc_webmon"}],
            "byte_length": len(b), "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest()}


def mention(sid, text, quote, recorded, subject="ent_w_developer"):
    b = text.encode("utf-8")
    st = b.find(quote.encode("utf-8"))
    c = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": "prj_wm_region", "subject": subject,
         "predicate": "wm.mentioned", "object": {"literal": {"type": "STRING", "value": "Жители Заречной улицы против застройки"}},
         "evidence": [{"source_id": sid, "span": {"start": st, "end": st + len(quote.encode("utf-8"))}, "quote": quote,
                       "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest()}],
         "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": recorded, "marking": PUB,
         "qualifiers": {"sentiment": "NEGATIVE"}}
    c["claim_id"] = "clm:sha256:" + digest(c)
    return c


def publication(text, url, recorded, marking=PUB, title="Жители Заречной улицы против застройки"):
    td = VAL.text_digest_of(text.encode("utf-8"))
    outlet = VAL.url_outlet(url)
    return {"kind": "Publication", "schema_version": "core-ontology/0.2", "tenant_id": "tnt_demo", "outlet": outlet,
            "canonical_url": VAL.url_norm(url), "text_digest": td, "title": title, "marking": marking, "recorded_at": recorded,
            "publication_id": VAL.publication_address("tnt_demo", outlet, td)}


def item_renditions(f):
    return [len(i.get("renditions", [])) for i in f["items"]]


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    sql1(S3.SETUP)
    sql1(SETUP)
    ds, trust, content = build()
    S = {s["source_id"]: s for s in ds["records"] if s["kind"] == "Source"}
    pub = next(p for p in ds["records"] if p["kind"] == "Publication")
    S2 = next(s for s in S.values() if s["title"] == "Жители Заречной улицы против застройки" and "\n" not in s["content_inline"]
              and chr(0x200B) not in s["content_inline"])["content_inline"]

    # S5-01 derived renditions == validator semantics
    py = sorted(sid for sid, s in S.items() if s["tenant_id"] == pub["tenant_id"]
                and VAL.text_digest_of(s["content_inline"].encode()) == pub["text_digest"]
                and any(VAL.url_outlet(o["origin_uri"]) == pub["outlet"] for o in s["observations"]))
    db = sql1(f"SELECT string_agg(source_id || ' ' || array_to_string(urls, ','), ';' ORDER BY source_id) FROM ac.renditions_at('{pub['publication_id']}', now())")
    db_ids = sorted(x.split(" ")[0] for x in db.split(";"))
    urls = sorted(u for x in db.split(";") for u in x.split(" ")[1].split(","))
    check("S5-01", len(py) == 3 and db_ids == py and "https://agg.example/r/123" not in urls and len(urls) == 4,
          "мир: одна публикация, три источника-рендеринга выводятся базой (= валидатор), адрес агрегатора — не рендеринг",
          f"renditions={len(db_ids)} urls={urls}")

    # S5-02 one item
    f = feed()
    it = f["items"]
    check("S5-02", len(it) == 1 and item_renditions(f) == [2] and len(it[0]["mentions"]) == 1 and len(it[0]["mentions"][0]["claims"]) == 2,
          "лента застройщика: статья, полученная трижды, — одна позиция; одно упоминание из двух утверждений; в позиции — только две версии, на которые ссылаются утверждения (S5R-05)",
          f"items={len(it)} renditions={item_renditions(f)}")

    # S5-03 a live re-fetch joins by itself
    time.sleep(1.1)                                     # «before» must be after the load (second precision)
    before = utc(0)
    time.sleep(1.1)
    refetch = source(S2.replace(". ", ".  ", 2), "https://news.example/zarechye?utm_campaign=autumn&ref=feed", utc(0))
    r3 = psql(ingest_sql([refetch], {}))
    time.sleep(1.1)
    n_now = sql1(f"SELECT count(*) FROM ac.renditions_at('{pub['publication_id']}', now())")
    n_before = sql1(f"SELECT count(*) FROM ac.renditions_at('{pub['publication_id']}', {before!r}::timestamptz)")
    m3 = mention(refetch["source_id"], refetch["content_inline"], "Жители Заречной улицы выступили против застройки", utc(0))
    r3b = psql(ingest_sql([m3], {}))
    time.sleep(1.1)
    f3, f3old = feed(), feed(as_of=before)
    npub = sql1("SELECT count(*) FROM ac.publications")
    check("S5-03", r3.returncode == r3b.returncode == 0 and (n_before, n_now) == ("3", "4") and item_renditions(f3) == [3]
          and item_renditions(f3old) == [2] and npub == "1",
          "живой повторный забор с другими пробелами и меткой присоединился сам (рендерингов 3 → 4, записи публикации не нужно); упоминание по нему — та же позиция",
          f"db={'OK' if r3.returncode == 0 else r3.stderr[:80]} derived={n_before}->{n_now} feed now={item_renditions(f3)} before={item_renditions(f3old)} publications={npub}")

    # S5-04 an edited article is another text
    edited_text = S2.replace("выступили против застройки", "выступили против стройки")
    ed = source(edited_text, "https://news.example/zarechye", utc(0))
    r4 = psql(ingest_sql([ed], {}))
    time.sleep(1.1)
    m4 = mention(ed["source_id"], edited_text, "Жители Заречной улицы выступили против стройки", utc(0))
    r4b = psql(ingest_sql([m4], {}))
    time.sleep(1.1)
    f4 = feed()
    kinds4 = sorted("pub" if "publication_id" in i else "src" for i in f4["items"])
    p4 = publication(edited_text, "https://news.example/zarechye", utc(0))
    r4c = psql(ingest_sql([p4], {}))
    time.sleep(1.1)
    f4b = feed()
    kinds4b = sorted("pub" if "publication_id" in i else "src" for i in f4b["items"])
    check("S5-04", r4.returncode == r4b.returncode == r4c.returncode == 0 and kinds4 == ["pub", "src"] and kinds4b == ["pub", "pub"],
          "отредактированная статья — другой текст: сначала отдельная позиция по источнику, после своей записи — отдельная публикация",
          f"before={kinds4} after={kinds4b} {(r4.stderr + r4b.stderr + r4c.stderr)[:120]}")

    # S5-05 support keys
    keys = sql1("SELECT string_agg(DISTINCT ac.support_key(tenant_id, source_id, now()), ',') FROM ac.source_texts st "
                f"WHERE st.text_digest = '{pub['text_digest']}' AND EXISTS (SELECT 1 FROM ac.source_observations o WHERE o.source_id = st.source_id "
                "AND ac.url_outlet(o.origin_uri) = 'news.example')")
    s3id = next(sid for sid, s in S.items() if s["source_kind"] == "SOCIAL_POST")
    k3 = sql1(f"SELECT ac.support_key('tnt_demo', '{s3id}', now())")
    check("S5-05", keys == pub["publication_id"] and k3 == s3id,
          "ключ поддержки: все рендеринги статьи — одна публикация; источник вне изданий — сам источник", f"{keys[:30]}… / {k3[:30]}…")

    # S5-06 a confidential publication is not shown to a public reader
    conf_text = S2.replace("работы начнутся весной", "работы начнутся летом")
    cs = source(conf_text, "https://region.example/news/1", utc(0))
    psql(ingest_sql([cs], {}))
    time.sleep(1.1)
    cm = mention(cs["source_id"], conf_text, "Жители Заречной улицы выступили против застройки", utc(0))
    cp = publication(conf_text, "https://region.example/news/1", utc(0), marking=CONF, title="Секретный заголовок")
    r6 = psql(ingest_sql([cm, cp], {}))
    time.sleep(1.1)
    fp, fc = json.dumps(feed(), ensure_ascii=False), json.dumps(feed(user="ac_rd_wm_conf"), ensure_ascii=False)
    check("S5-06", r6.returncode == 0 and cp["publication_id"] not in fp and "Секретный заголовок" not in fp and "region.example/news/1" not in fp
          and cp["publication_id"] in fc and cs["source_id"] in fp,
          "конфиденциальная публикация не видна публичному читателю (ни заголовка, ни адреса, ни id); упоминание остаётся позицией по источнику",
          f"db={'OK' if r6.returncode == 0 else r6.stderr[:90]}")

    # S5-07 closed Check reports are stable
    after = {k: S3.js(f"SELECT ac.check_report('{k}');")["digest"] for k in sql1("SELECT string_agg(check_id, ' ') FROM ac.checks WHERE status = 'COMPLETED'").split()}
    check("S5-07", after == BEFORE_CHECKS, "отчёты закрытых Проверок не изменились после новых рендерингов и публикаций (D16)",
          ",".join(f"{k}={'=' if after[k] == BEFORE_CHECKS[k] else '≠'}" for k in after))

    # S5-08 refusals
    outs = []
    for user, eid, proj in (("ac_rd_none", "ent_w_developer", "prj_wm_region"), ("ac_rd_wm", "ent_nope", "prj_wm_region"),
                            ("ac_rd_wm", "ent_d_lomov", "prj_dossier")):
        rr = psql(f"SET SESSION AUTHORIZATION {user};\nSELECT ac.wm_feed('{proj}', '{eid}');")
        outs.append(rr.returncode != 0 and "ACCESS_DENIED: нет допуска" in rr.stderr)
    check("S5-08", all(outs), "без допуска, неизвестная сущность, чужой проект — один и тот же отказ", str(outs))

    # S5-09 / S5-10
    fd = feed(dfrom="2026-09-03", as_of=before)
    fixed = utc(0)
    time.sleep(1.1)
    d1, d2 = feed(as_of=fixed)["digest"], feed(as_of=fixed)["digest"]
    check("S5-09", fd["items"] == [], "фильтр по дате: с 03.09.2026 позиций до забора нет")
    check("S5-10", d1 == d2, "одинаковый as_of — одинаковый digest", d1[:24])

    print(f"\ns5_tests={len(RES)} passed={sum(RES)}")
    print("S5_RESULT=" + ("PASS" if all(RES) else "FAIL"))
    return 0 if all(RES) else 1


BEFORE_CHECKS = None

if __name__ == "__main__":
    # the closed Check reports right after the load (S5-07 compares against them)
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    sql1(S3.SETUP)
    BEFORE_CHECKS = {k: S3.js(f"SELECT ac.check_report('{k}');")["digest"] for k in sql1("SELECT string_agg(check_id, ' ') FROM ac.checks WHERE status = 'COMPLETED'").split()}
    sys.exit(main())

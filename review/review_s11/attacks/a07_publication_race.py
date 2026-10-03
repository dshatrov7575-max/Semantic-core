#!/usr/bin/env python3
"""S11R-07: публикация и её рендеринги (страж S5: «маркировка публикации не шире маркировки её рендерингов, полученных
к recorded_at»). Страж блокирует ключи 'source:' только тех источников с этим текстом, которые ВИДИТ; новый
рендеринг (CONFIDENTIAL), записываемый параллельно, им не блокируется.
 (a) два сеанса READ COMMITTED: источник-рендеринг CONFIDENTIAL вставлен и не зафиксирован -> открытая публикация
     фиксируется -> фиксируется источник (его observed_at = now() = начало транзакции, раньше recorded_at публикации).
 (b) то же одной транзакцией: сначала публикация, потом закрытый рендеринг (observed_at = начало транзакции)."""
import copy, json, time
from datetime import datetime, timezone, timedelta
from rv import *
from s5_tests import source, publication
from ingest_s4 import q as Q

fresh(load_rows=False)
ds0, trust, content = build()
PUB = {"level": "PUBLIC", "categories": []}
CONF = {"level": "CONFIDENTIAL", "categories": []}
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def pub_sql(pb):
    return ("INSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
            f"({Q(pb['publication_id'])},{Q(pb['tenant_id'])},{Q(pb['outlet'])},{Q(pb['canonical_url'])},{Q(pb['text_digest'])},{Q(pb['marking'])},{Q(pb)});")


def src_from_db(s):
    obs = json.loads(one("SELECT jsonb_agg(jsonb_build_object('observed_at', to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                         f"'origin_uri', origin_uri, 'observed_by', observed_by)) FROM ac.source_observations WHERE source_id = '{s['source_id']}'"))
    return dict(s, observations=obs)


def run(tag, single):
    text = f"Завод «Ракурс-{tag}» объявил о сокращении. Подробности сообщил источник в дирекции."
    text2 = text.replace(" ", "  ", 1)                 # другой забор той же статьи: тот же нормализованный текст
    s1 = source(text, f"https://race{tag}.example/n", utc(0), marking=PUB, title="Сокращение")
    assert psql(ingest_sql([s1], {})).returncode == 0
    time.sleep(1.2)
    s2 = source(text2, f"https://m.race{tag}.example/n", utc(0), marking=CONF, title="Сокращение")
    if single:
        rec = (datetime.now(timezone.utc) + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pb = publication(text, f"https://race{tag}.example/n", rec, marking=PUB, title="Сокращение")
        r = psql(L + "BEGIN;\nSELECT pg_sleep(2.3);\n" + pub_sql(pb) + "\n" + body_of([s2]) + "\nCOMMIT;")
        ok = r.returncode == 0
        print(f"({tag}) одна транзакция: публикация PUBLIC, затем закрытый рендеринг: {'COMMIT' if ok else first_err(r)[:120]}")
    else:
        th, o1 = bg(L + "BEGIN;\n" + body_of([s2]) + "\nSELECT pg_sleep(3);\nCOMMIT;")
        time.sleep(1.6)
        pb = publication(text, f"https://race{tag}.example/n", utc(0), marking=PUB, title="Сокращение")
        r2 = psql(L + "BEGIN;\n" + pub_sql(pb) + "\nCOMMIT;")
        th.join()
        ok = o1[0].returncode == 0 and r2.returncode == 0
        print(f"({tag}) сеанс 1 (закрытый рендеринг): {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])[:100]}; "
              f"сеанс 2 (публикация PUBLIC): {'COMMIT' if r2.returncode == 0 else first_err(r2)[:100]}")
    if not ok:
        return False, None
    print("    в базе:", one(f"SELECT 'рендеринг CONFIDENTIAL получен ' || min(o.observed_at) || ' <= recorded_at публикации ' || p.recorded_at || ': ' || (min(o.observed_at) <= p.recorded_at) "
                            f"FROM ac.source_observations o, ac.publications p WHERE o.source_id = '{s2['source_id']}' AND p.publication_id = '{pb['publication_id']}' GROUP BY p.recorded_at"))
    ds = copy.deepcopy(ds0)
    ds["records"] += [src_from_db(s1), src_from_db(s2), pb]
    cont = dict(content); cont[s1["source_id"]] = text.encode(); cont[s2["source_id"]] = text2.encode()
    rep = VAL.validate(ds, trust, cont)
    print("    валидатор на мире из базы:", rep.codes(), [e.get("msg", "")[:100] for e in rep.errors][:2])
    time.sleep(1.2)
    seq = psql(L + "BEGIN;\n" + pub_sql(publication(text, f"https://m.race{tag}.example/n", utc(0), marking=PUB, title="Сокращение")) + "\nROLLBACK;")
    print("    контроль (публикация того же текста на издании закрытого рендеринга, последовательно):", first_err(seq)[:120])
    return True, rep.codes()


ok, codes = run("a", single=False)
report("S11R-07a", ok and "MARKING_BROADER_THAN_INPUT" in (codes or []), f"гонка READ COMMITTED: открытая публикация с закрытым рендерингом; валидатор {codes}")
ok, codes = run("b", single=True)
report("S11R-07b", ok and "MARKING_BROADER_THAN_INPUT" in (codes or []), f"одна транзакция, порядок записи: то же; валидатор {codes}")

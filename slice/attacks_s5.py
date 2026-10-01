#!/usr/bin/env python3
"""S5 attacks on publications in the database (ac_loader, live, one transaction each, rolled back), without the
validator in front. Each attack must be refused with the expected text; each legitimate write must pass.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s5.py
"""
import copy
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc, q  # noqa: E402
from s5_tests import source, publication  # noqa: E402

BAD = []
CONF = {"level": "CONFIDENTIAL", "categories": []}


def attack(aid, desc, sql, expect, legit=False):
    r = psql(sql)
    err = r.stderr.strip().splitlines()[0] if r.stderr.strip() else ""
    ok = (r.returncode == 0) if legit else (r.returncode != 0 and any(e in r.stderr for e in expect))
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {'законная: ' if legit else ''}{desc} | {err[:120] or 'принято'}", flush=True)


def pub_sql(pb, tail="ROLLBACK;"):
    """the INSERT the application would send, whatever the record says it is"""
    return ("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nINSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, "
            f"text_digest, marking, body) VALUES ({q(pb['publication_id'])},{q(pb['tenant_id'])},{q(pb['outlet'])},{q(pb['canonical_url'])},"
            f"{q(pb['text_digest'])},{q(pb['marking'])},{q(pb)});\n" + tail)


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    ds, _, _ = build()
    wpub = next(p for p in ds["records"] if p["kind"] == "Publication")
    S2 = next(s["content_inline"] for s in ds["records"] if s["kind"] == "Source"
                          and VAL.text_digest_of(s["content_inline"].encode()) == wpub["text_digest"])
    edited = S2.replace("выступили против застройки", "выступили против стройки")
    secret = S2.replace("работы начнутся весной", "работы начнутся осенью")
    time.sleep(1.1)
    setup = [source(edited, "https://news.example/zarechye", utc(0)), source(secret, "https://news.example/zarechye", utc(0), marking=CONF)]
    if psql(ingest_sql(setup, {})).returncode:
        sys.exit("setup failed")
    time.sleep(1.1)
    now = utc(0)
    good = publication(edited, "https://news.example/zarechye", now)
    P = "PUBLICATION_INVALID"

    attack("L1", "запись публикации отредактированной статьи", pub_sql(good), [], True)
    attack("L2", "публикация строже своих рендерингов (CONFIDENTIAL над PUBLIC)", pub_sql({**good, "marking": CONF}), [], True)

    attack("D501", "подложный адрес публикации", pub_sql({**good, "publication_id": "pub:sha256:" + "1" * 64}), ["publication_address", "columns_match_body"])
    attack("D502", "канонический адрес с меткой utm", pub_sql({**good, "canonical_url": "https://news.example/zarechye?utm_source=x"}), ["publication_url"])
    attack("D503", "канонический адрес другого издания", pub_sql({**good, "canonical_url": "https://agg.example/r/123"}), ["publication_url"])
    td = "sha256:" + "2" * 64
    nob = {**good, "text_digest": td, "publication_id": VAL.publication_address("tnt_demo", "news.example", td)}
    attack("D504", "у текста нет ни одного рендеринга", pub_sql(nob), [P])
    attack("D505", "время записи из будущего", pub_sql({**good, "recorded_at": "2099-01-01T00:00:00Z"}), ["TEMPORAL_ORDER_INVALID"])
    sp = publication(secret, "https://news.example/zarechye", now)
    attack("D506", "публичная публикация над конфиденциальным рендерингом", pub_sql(sp), ["MARKING_BROADER_THAN_INPUT"])
    attack("D507", "дата выхода позже первого получения", pub_sql({**good, "published_at": "2099-01-01T00:00:00Z"}), ["TEMPORAL_ORDER_INVALID"])
    dup = {**copy.deepcopy(wpub), "canonical_url": "https://news.example/amp/zarechye", "recorded_at": now}
    attack("D508", "вторая запись той же публикации с другим адресом", pub_sql(dup), ["publications_pkey"])
    attack("D509", "изменение публикации", f"SET SESSION AUTHORIZATION ac_loader;\nUPDATE ac.publications SET canonical_url = 'https://x.example/' "
           f"WHERE publication_id = {q(wpub['publication_id'])};", ["permission denied", "APPEND_ONLY"])
    attack("D509b", "удаление публикации", f"SET SESSION AUTHORIZATION ac_loader;\nDELETE FROM ac.publications WHERE publication_id = {q(wpub['publication_id'])};",
           ["permission denied", "APPEND_ONLY"])
    attack("D510", "прямая запись текста источника", "SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.source_texts "
           "SELECT tenant_id, source_id, 'sha256:' || repeat('3', 64) FROM ac.source_bytes LIMIT 1;", ["permission denied"])
    bad_cols = pub_sql(good).replace(f",{q(good['canonical_url'])},", f",{q(good['canonical_url'] + '?a=1')},", 1)
    attack("D511", "колонки расходятся с телом публикации", bad_cols, ["columns_match_body", "publication_address", "publication_url"])
    ot = {**good, "tenant_id": "tnt_other", "publication_id": VAL.publication_address("tnt_other", good["outlet"], good["text_digest"])}
    attack("D512", "публикация в tenant, где нет её источников", pub_sql(ot), [P])
    attack("D513", "время поступления задано пишущим", "SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.publications "
           f"(publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body, ingested_at) VALUES ({q(good['publication_id'])},"
           f"'tnt_demo',{q(good['outlet'])},{q(good['canonical_url'])},{q(good['text_digest'])},{q(good['marking'])},{q(good)},'2000-01-01');",
           ["permission denied"])
    attack("D514", "запись другого вида под видом публикации", pub_sql({**good, "kind": "Source"}), ["columns_match_body"])
    attack("D515", "маркировка неизвестного уровня (fail-closed: раньше формы срабатывает доминирование)", pub_sql({**good, "marking": {"level": "SECRETISH", "categories": []}}), ["marking_shape", "MARKING_BROADER_THAN_INPUT"])
    wurl = {**good, "canonical_url": "https://www.news.example/zarechye"}
    attack("D516", "канонический адрес на www. — то же издание news.example", pub_sql(wurl), [], True)
    attack("D517", "хост с завершающей точкой", pub_sql({**good, "canonical_url": "https://news.example./zarechye"}), ["publication_url", "check constraint"])
    print(f"\nattacks={len(BAD)} findings={sum(BAD)}")
    print("S5_ATTACKS=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

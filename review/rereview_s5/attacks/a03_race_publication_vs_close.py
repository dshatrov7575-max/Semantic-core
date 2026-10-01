#!/usr/bin/env python3
"""A03 (D16 / S23-10 class): a publication written in a transaction that is still open while a Check closes.
ac.publications.ingested_at = clock_timestamp() at INSERT, no lock is taken (unlike observations: lock 'source:'),
so after the publication commits it has ingested_at < completed_at and ac.support_key(…, completed_at) changes.

World: in prj_compliance, entity.registered_address (cardinality ONE) of ent_k_developer has two values, all claims ACCEPTED:
  «ул. Вторая, 2» — one claim (source B on other.example), recorded FIRST;
  «ул. Первая, 1» — two claims from two fetches A1 (race.example) and A2 (m.race.example) of one article.
Before the publication: «Первая» has 2 supports > 1 -> main value. With the publication: 1 vs 1 -> tie -> earlier
recorded «Вторая» wins. The Check (FULL) is closed while the publication transaction is open.
Usage: PGHOST=... PGDATABASE=review053 python3 a03_race_publication_vs_close.py
"""
import hashlib
import json
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
import validator as VAL  # noqa: E402
from jcs import digest  # noqa: E402
from ingest_s4 import ingest_sql, utc, q  # noqa: E402
import regression_s22 as R  # noqa: E402
import regression_s23_races as RC  # noqa: E402
from s5_tests import source, publication  # noqa: E402

T = R.T
M = json.loads(R.M_CSPD)
KID = "chk_pubrace"
FULL = RC.FULL


def claim(sid, text, quote, value, recorded):
    b = text.encode()
    st = b.find(quote.encode())
    c = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": "prj_compliance", "subject": "ent_k_developer",
         "predicate": "entity.registered_address", "object": {"literal": {"type": "STRING", "value": value}},
         "evidence": [{"source_id": sid, "span": {"start": st, "end": st + len(quote.encode())}, "quote": quote,
                       "quote_sha256": hashlib.sha256(quote.encode()).hexdigest()}],
         "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": recorded, "marking": M}
    c["claim_id"] = "clm:sha256:" + digest(c)
    return c


def must(sql, what):
    r = T.psql(sql)
    if r.returncode:
        sys.exit(f"{what}: {r.stderr[:400]}")


def main(mode):
    R.reload()
    A = "ООО «Заречье-Девелопмент» сменило адрес: ул. Первая, 1. Об этом сообщила пресс-служба компании."
    A2 = A.replace(" ", "  ", 2)                       # another fetch: other whitespace
    B = "Справка: ООО «Заречье-Девелопмент», адрес: ул. Вторая, 2. Данные справочника."
    time.sleep(1.1)
    sA1, sA2 = source(A, "https://race.example/addr", utc(0)), source(A2, "https://m.race.example/addr", utc(0))
    sB = source(B, "https://other.example/b", utc(0))
    must(ingest_sql([sA1, sA2, sB], {}), "sources")
    time.sleep(1.1)
    cB = claim(sB["source_id"], B, "адрес: ул. Вторая, 2", "ул. Вторая, 2", utc(0))
    must(ingest_sql([cB], {}), "claim B")
    time.sleep(1.1)
    cA1 = claim(sA1["source_id"], A, "ул. Первая, 1", "ул. Первая, 1", utc(0))
    cA2 = claim(sA2["source_id"], A2, "ул. Первая, 1", "ул. Первая, 1", utc(0))
    must(ingest_sql([cA1, cA2], {}), "claims A")
    time.sleep(1.1)
    revs = "".join(f"INSERT INTO ac.claim_reviews VALUES ('rv_{i}', '{c['claim_id']}', 'ACCEPTED', 'usr_y', now(), now());\n"
                   for i, c in enumerate((cB, cA1, cA2)))
    must("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\n" + revs + R.new_check(KID, "FULL") + "\n"
         f"INSERT INTO ac.check_findings VALUES ('{KID}', 'CORPORATE', 'FOUND', 'LOW');\n"
         + "".join(f"INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', '{KID}', 'CORPORATE', '{c['claim_id']}');\n"
                   for c in (cB, cA1, cA2)) + "COMMIT;", "reviews+check")
    time.sleep(1.1)
    pb = publication(A, "https://race.example/addr", utc(0))
    pub_sql = ("BEGIN;\nINSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
               f"({q(pb['publication_id'])},{q(pb['tenant_id'])},{q(pb['outlet'])},{q(pb['canonical_url'])},{q(pb['text_digest'])},"
               f"{q(pb['marking'])},{q(pb)});\nSELECT 'pub inserted at ' || clock_timestamp();\n")
    closing = "BEGIN;\n" + RC.close_sql(KID, None, "CORPORATE", FULL, "LOW", prefilled=True)
    keyA = lambda t: T.psql(f"SELECT ac.support_key('tnt_demo', '{sA1['source_id']}', {t})").stdout.strip()

    def main_text(rep):
        for d in rep.get("dimensions", []):
            if d["dimension"] == "CORPORATE":
                return [f["text"] for f in d.get("facts", [])]

    if mode in ("race", "race2"):
        # race: publication first (open), then the closing; race2: closing first (open), then the publication
        first, second = (pub_sql, closing) if mode == "race" else (closing, pub_sql)
        a = RC.session(first)
        time.sleep(1.5)
        b = RC.session(second)
        time.sleep(2.0)
        waiting = T.psql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity s USING (pid) WHERE NOT l.granted "
                         "AND l.locktype = 'advisory' AND s.datname = current_database()").stdout.strip()
        out_a = RC.finish(a)
        out_b = RC.finish(b)
        rep1 = RC.report(KID)
        time.sleep(1.1)
        rep2 = RC.report(KID)
        times = T.psql(f"SELECT 'completed_at=' || coalesce(completed_at::text, '-') || ' pub.ingested_at=' || coalesce((SELECT ingested_at::text FROM ac.publications "
                       f"WHERE publication_id = '{pb['publication_id']}'), '-') FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        k = T.psql(f"SELECT ac.support_key('tnt_demo', '{sA1['source_id']}', completed_at) FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        print(f"A03-{mode} второй ждал блокировку (pg_locks, не получено): {waiting} | {times} | support_key(A1, completed_at)={k[:24]}")
        print(f"   CORPORATE: {main_text(rep1)} | повторное чтение совпадает: {rep1['digest'] == rep2['digest']} | {(out_a + ' ' + out_b)[-120:]}")
        print(f"A03-{mode} {'held' if waiting != '0' else 'FINDING'}")
    else:                                           # control: publication committed before the closing
        must("SET SESSION AUTHORIZATION ac_loader;\n" + pub_sql + "COMMIT;", "pub")
        time.sleep(1.1)
        must("SET SESSION AUTHORIZATION ac_loader;\n" + closing + "COMMIT;", "close")
        print(f"A03-control (публикация раньше закрытия): CORPORATE = {main_text(RC.report(KID))}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "race")

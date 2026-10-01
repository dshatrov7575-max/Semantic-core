#!/usr/bin/env python3
"""REGRESSION of S5R-01 (reviewer's A03, both orders): a publication written while a Check closes.
Fixed: the publication takes the 'source:' locks of every source with its text and reads its time after the lock, so
the closing (which locks the sources its claims cite) and the publication are serialised; the report of the closed
Check never changes. Invariant checked: digest of the closed report right after closing == after everything commits;
the second transaction really waited (an ungranted advisory lock was seen in pg_locks, S5R-12).

World: in prj_compliance, entity.registered_address (cardinality ONE) of ent_k_developer has two values, all claims ACCEPTED:
  «ул. Вторая, 2» — one claim (source B on other.example), recorded FIRST;
  «ул. Первая, 1» — two claims from two fetches A1 (race.example) and A2 (m.race.example) of one article.
Before the publication: «Первая» has 2 supports > 1 -> main value. With the publication: 1 vs 1 -> tie -> earlier
recorded «Вторая» wins. The Check (FULL) is closed while the publication transaction is open.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/regression_s5_races.py
"""
import hashlib
import json
import subprocess
import sys
import time

from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE))
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

    def blocked():
        return int(T.psql("SELECT count(*) FROM pg_locks WHERE NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").stdout.strip() or 0) > 0

    if mode in ("pub_first", "close_first"):
        first, second = (pub_sql, closing) if mode == "pub_first" else (closing, pub_sql)
        a = RC.session(first)
        time.sleep(1.5)
        b = RC.session(second)
        time.sleep(2.0)
        waited = blocked()
        out_a = RC.finish(a)
        time.sleep(0.5)
        rep_mid = RC.report(KID) if mode == "close_first" else None
        out_b = RC.finish(b)
        rep_end = RC.report(KID)
        rep_later = RC.report(KID)
        st = T.psql(f"SELECT status FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        stable = rep_end["digest"] == rep_later["digest"] and (rep_mid is None or rep_mid["digest"] == rep_end["digest"])
        ok = waited and st == "COMPLETED" and stable
        print(f"S5-RACE-{mode:<11} {'held' if ok else 'FINDING'} | второй ждал: {waited}; Проверка: {st}; отчёт после закрытия "
              f"{'не менялся' if stable else 'ИЗМЕНИЛСЯ'}; CORPORATE = {main_text(rep_end)} | {(out_a + ' ' + out_b)[-90:]}")
        return ok
    if mode == "race":
        a = RC.session(pub_sql)                       # publication transaction: inserted, not committed
        time.sleep(1.5)
        b = RC.session(closing)
        time.sleep(2.0)
        waited = b.poll() is None
        out_b = RC.finish(b)                         # the Check closes first
        rep_mid = RC.report(KID)
        k_mid = T.psql(f"SELECT ac.support_key('tnt_demo', '{sA1['source_id']}', completed_at) FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        out_a = RC.finish(a)                         # then the publication commits
        rep_end = RC.report(KID)
        k_end = T.psql(f"SELECT ac.support_key('tnt_demo', '{sA1['source_id']}', completed_at) FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        times = T.psql(f"SELECT 'completed_at=' || completed_at || ' pub.ingested_at=' || (SELECT ingested_at FROM ac.publications "
                       f"WHERE publication_id = '{pb['publication_id']}') FROM ac.checks WHERE check_id = '{KID}'").stdout.strip()
        changed = rep_mid["digest"] != rep_end["digest"]
        print(f"A03-race {'FINDING' if changed else 'held'} | статус Проверки, прочитанный ДО коммита публикации: {rep_mid.get('status')} (закрытие не ждало) | {times}")
        print(f"   support_key(A1, completed_at): до коммита публикации={k_mid[:28]}… после={k_end[:28]}…")
        print(f"   отчёт закрытой Проверки, CORPORATE, до: {main_text(rep_mid)}")
        print(f"   отчёт закрытой Проверки, CORPORATE, после: {main_text(rep_end)}")
        print(f"   digest до={rep_mid['digest'][:30]} после={rep_end['digest'][:30]} | {out_a[-80:]} | {out_b[-80:]}")
    else:                                           # control: publication committed before the closing
        must("SET SESSION AUTHORIZATION ac_loader;\n" + pub_sql + "COMMIT;", "pub")
        time.sleep(1.1)
        must("SET SESSION AUTHORIZATION ac_loader;\n" + closing + "COMMIT;", "close")
        print(f"A03-control (публикация раньше закрытия): CORPORATE = {main_text(RC.report(KID))}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        res = [main("pub_first"), main("close_first")]
        print(f"\nraces={len(res)} findings={res.count(False)}")
        print("S5_RACES=" + ("PASS" if all(res) else "FAIL"))
        sys.exit(0 if all(res) else 1)

#!/usr/bin/env python3
"""A09 (after the S5R-01 fix): lock order of ac.publications_guard.
The guard locks 'source:' of ALL sources of the tenant with the text, in key order — but a writer that already holds
'source:X' (a new observation of X in the same transaction, the order of ingest_sql: observations before publications)
takes the second key out of global order.
  D1  two loaders, each: new observation of its own fetch of one article (A1 at race.example / A3 at copy.example) and the
      publication of its outlet in the same transaction -> deadlock, PostgreSQL aborts one of them.
  D2  loader: new observation of a CITED source + publication, concurrently with the closing of a Check that cites
      the other fetch -> the closing (or the loader) is aborted with deadlock_detected.
Usage: PGHOST=... PGDATABASE=review053 python3 a09_lock_deadlock.py  (reloads the world)
"""
import subprocess
import sys
import time

sys.path.insert(0, "/home/claude/as/core")
sys.path.insert(0, "/home/claude/as/slice")
from ingest_s4 import ingest_sql, utc, q  # noqa: E402
import regression_s22 as R  # noqa: E402
import regression_s23_races as RC  # noqa: E402
from s5_tests import source, publication  # noqa: E402
import a03_race_publication_vs_close as A3  # noqa: E402

T = R.T


def obs(sid, uri):
    return (f"INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES "
            f"('tnt_demo', {q(sid)}, now(), {q(uri)}, 'svc_webmon');\n")


def pub_ins(pb):
    return ("INSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
            f"({q(pb['publication_id'])},{q(pb['tenant_id'])},{q(pb['outlet'])},{q(pb['canonical_url'])},{q(pb['text_digest'])},"
            f"{q(pb['marking'])},{q(pb)});\n")


def run_pair(first, second, pause_mid):
    """first and second are lists of statements; both start, first does step 0, second step 0, then first step 1, second step 1"""
    a, b = RC.session("BEGIN;\n" + first[0]), None
    time.sleep(1.0)
    b = RC.session("BEGIN;\n" + second[0])
    time.sleep(1.0)
    a.stdin.write(first[1]); a.stdin.flush()
    time.sleep(pause_mid)
    b.stdin.write(second[1]); b.stdin.flush()
    time.sleep(3.0)
    return RC.finish(a), RC.finish(b)


R.reload()
A = "ООО «Заречье-Девелопмент» сменило адрес: ул. Первая, 1. Об этом сообщила пресс-служба компании."
time.sleep(1.1)
sA1, sA3 = source(A, "https://race.example/addr", utc(0)), source(A.replace(" ", "   ", 1), "https://copy.example/addr", utc(0))
assert T.psql(ingest_sql([sA1, sA3], {})).returncode == 0
time.sleep(2.2)
p1, p3 = publication(A, "https://race.example/addr", utc(0)), publication(A, "https://copy.example/addr", utc(0))
oa, ob = run_pair([obs(sA1["source_id"], "https://race.example/addr?r=2"), pub_ins(p1)],
                  [obs(sA3["source_id"], "https://copy.example/addr?r=2"), pub_ins(p3)], 0.5)
dl = "deadlock detected" in (oa + ob)
print(f"D1 {'FINDING' if dl else 'held'} | два загрузчика (наблюдение своего забора + публикация своего издания): "
      f"{'взаимоблокировка, одна транзакция прервана' if dl else 'без взаимоблокировки'} | {(oa + ' || ' + ob).replace(chr(10), ' ')[:260]}")
n = T.psql("SELECT count(*) FROM ac.publications WHERE publication_id IN ('%s','%s')" % (p1["publication_id"], p3["publication_id"])).stdout.strip()
print(f"D1   записано публикаций из двух: {n}")

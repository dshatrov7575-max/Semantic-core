#!/usr/bin/env python3
"""Regression for the S23-10 races (write skew between a Check closing and a concurrent review / merge / search row),
both orders. T_first opens a transaction that touches what the Check rests on and holds it; T_second runs concurrently.
Invariant: the report of a closed Check never changes after it is closed, and a COMPLETED Check never rests on a claim
that was not ACCEPTED at its completion. Serialisation (ac.lock_keys) must make the second transaction wait.
All writes as ac_loader; readers as ac_rd_full.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/regression_s23_races.py
"""
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import regression_s22 as R  # noqa: E402  (reload, verdict, new_check, T)

T = R.T
BAD = []
M = R.M_CSPD


def session(sql):
    p = subprocess.Popen(["psql", "-X", "-q", "-At"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    p.stdin.write("SET SESSION AUTHORIZATION ac_loader;\n" + sql)
    p.stdin.flush()
    return p


def finish(p, tail="COMMIT;\n"):
    p.stdin.write(tail)
    p.stdin.close()
    out = p.stdout.read()
    p.wait()
    return out.strip()


def report(kid):
    try:
        return T.js(f"SELECT ac.check_report('{kid}');")
    except RuntimeError as ex:
        return {"digest": "ERR " + str(ex)[:60], "dimensions": []}


def close_sql(kid, claim, dim, prof_dims, risk, prefilled=False):
    s = "" if prefilled else f"INSERT INTO ac.check_findings VALUES ('{kid}', '{dim}', 'FOUND', '{risk}');\n"
    s += "" if prefilled else f"INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', '{kid}', '{dim}', '{claim}');\n"
    s += f"INSERT INTO ac.check_searches VALUES ('{kid}', '{dim}', 0, now(), 'tnt_demo', NULL, '{{\"query\": \"q\"}}');\n"
    for d in prof_dims:
        if d != dim:
            s += f"INSERT INTO ac.check_findings VALUES ('{kid}', '{d}', 'NOT_FOUND', 'NONE');\n"
            s += f"INSERT INTO ac.check_searches VALUES ('{kid}', '{d}', 0, now(), 'tnt_demo', NULL, '{{\"query\": \"q\"}}');\n"
    s += (f"UPDATE ac.checks SET status = 'COMPLETED', overall_risk = '{risk}', "
          f"body = body || '{{\"status\": \"COMPLETED\", \"overall_risk\": \"{risk}\"}}' WHERE check_id = '{kid}';\n")
    return s


FULL = ["NEGATIVE", "TENDERS", "SOCIAL_MEDIA", "CORPORATE", "PROPERTY", "COURT"]


def race(aid, desc, prep, other_sql, kid, claim, dim, prof, prof_dims, risk, other_first, prefill=False):
    R.reload()
    R.ok("BEGIN;\n" + prep + R.new_check(kid, prof) + "\nCOMMIT;", "ac_loader")
    if prefill:
        R.ok(f"BEGIN; INSERT INTO ac.check_findings VALUES ('{kid}', '{dim}', 'FOUND', '{risk}');"
             f"INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', '{kid}', '{dim}', '{claim}'); COMMIT;", "ac_loader")
    time.sleep(1.1)
    closing = "BEGIN;\n" + close_sql(kid, claim, dim, prof_dims, risk, prefill)
    first, second = (other_sql, closing) if other_first else (closing, other_sql)
    a = session(first)
    time.sleep(1.5)
    b = session(second)
    time.sleep(2.0)
    # the second must be blocked on a lock (S5R-12: «psql has not exited» proves nothing — its stdin is still open)
    waited = int(T.psql("SELECT count(*) FROM pg_locks WHERE NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").stdout.strip() or 0) > 0
    out_a = finish(a)
    rep_mid = report(kid)
    out_b = finish(b)
    rep_end = report(kid)
    st = T.psql(f"SELECT status || ' ' || coalesce(ac.status_at('{claim}', completed_at), '-') FROM ac.checks WHERE check_id = '{kid}'").stdout.strip()
    closed = st.startswith("COMPLETED")
    # the closing committed first -> its report must not change when the other commits; the other committed first ->
    # the closing waited for it, so the first closed rendering (rep_end) must be stable on a later re-read
    changed = closed and ((not other_first and rep_mid["digest"] != rep_end["digest"])
                          or (other_first and report(kid)["digest"] != rep_end["digest"]))
    rests_on_bad = closed and not st.endswith("ACCEPTED")
    finding = changed or rests_on_bad or not waited
    BAD.append(finding)
    print(f"{aid:<10} {'FINDING' if finding else 'held':<7} | {desc} | второй ждал: {waited}; Проверка: {st}; "
          f"отчёт после закрытия {'изменился' if changed else 'не менялся'} | {(out_a + ' ' + out_b)[-110:]}", flush=True)


def main():
    R.reload()
    neg = T.psql("SELECT claim_id FROM ac.claims WHERE predicate = 'media.negative_mention' AND project_id = 'prj_compliance'").stdout.strip()
    own = T.psql("SELECT claim_id FROM ac.claims WHERE predicate = 'prop.owns' AND project_id = 'prj_compliance'").stdout.strip()
    review = f"BEGIN;\nINSERT INTO ac.claim_reviews VALUES ('rev_race', '{neg}', 'REFUTED', 'usr_y', now(), now());\n"
    plot = ("INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name) VALUES "
            "('ent_k_plot_new', 'prj_compliance', 'REAL_ESTATE', '{\"cadastral_number\": \"50:12:0101001:998\"}', 'ACTIVE', now(), "
            "'{\"level\": \"CONFIDENTIAL\", \"categories\": [\"COMMERCIAL_SECRET\"]}', 'НОВОЕ ИМЯ УЧАСТКА');\n")
    merge = "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_plot_new' WHERE entity_id = 'ent_k_land';\n"
    search = "BEGIN;\nINSERT INTO ac.check_searches VALUES ('{kid}', 'NEGATIVE', 1, now(), 'tnt_demo', NULL, '{{\"query\": \"ПОДБРОШЕННЫЙ ПОИСК\"}}');\n"
    for first in (True, False):
        tag = "a" if first else "b"
        race(f"S23-10{tag}.1", ("рецензия REFUTED раньше закрытия" if first else "закрытие раньше рецензии REFUTED"),
             "", review, "chk_race", neg, "NEGATIVE", "EXPRESS_NEGATIVE", ["NEGATIVE"], "MEDIUM", first)
        race(f"S23-10{tag}.2", ("слияние раньше закрытия" if first else "закрытие раньше слияния"),
             plot, merge, "chk_race_m", own, "PROPERTY", "FULL", FULL, "LOW", first)
        race(f"S23-10{tag}.3", ("строка поиска раньше закрытия" if first else "закрытие раньше строки поиска"),
             "", search.format(kid="chk_race_r"), "chk_race_r", neg, "NEGATIVE", "EXPRESS_NEGATIVE", ["NEGATIVE"], "MEDIUM", first, True)
    R.reload()
    print(f"\nraces={len(BAD)} findings={sum(BAD)}")
    print("S23_RACES=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

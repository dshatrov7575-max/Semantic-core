#!/usr/bin/env python3
"""Regression for the S24 hypotheses (closed in v0.2.3b):
 Г-1: a claim added to a Check by a concurrent transaction before the closing must be locked by the closing too
      (the closing reads its lock set AFTER taking the Check lock); a REFUTED review in flight on that claim is serialised.
 Г-2: a source observation written concurrently with the closing of a Check citing the source is serialised with it
      (lock 'source:<id>', ingested_at read after the lock), so first_observed_at in the closed report never changes.
 S24-01: literal identifier schemes, QUANTITY units and check digits are enforced by the database too.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/regression_s24.py
"""
import hashlib
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import regression_s22 as R  # noqa: E402
from regression_s23_races import session, finish, report  # noqa: E402

T = R.T
BAD = []
M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
MC = '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}'
TEXT = "Новая статья: к ООО «Заречье-Девелопмент» предъявлен ещё один иск."
B = TEXT.encode()
SID = "src:sha256:" + hashlib.sha256(B).hexdigest()
QSHA = hashlib.sha256(B).hexdigest()
CID = "clm:sha256:" + "ab" * 32



def verdict(aid, finding, text, detail=""):
    BAD.append(finding)
    print(f"{aid:<8} {'FINDING' if finding else 'held':<7} | {text}{' | ' + detail if detail else ''}", flush=True)


def g1():
    R.reload()
    x = T.psql("SELECT claim_id FROM ac.claims WHERE predicate = 'media.negative_mention' AND project_id = 'prj_compliance'").stdout.strip()
    R.ok("BEGIN;\n" + R.new_check("chk_g1", "EXPRESS_NEGATIVE") + "\nCOMMIT;", "ac_loader")
    time.sleep(1.1)
    add = session(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_g1', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_g1', 'NEGATIVE', '{x}');
INSERT INTO ac.check_searches VALUES ('chk_g1', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "q"}}');
""")
    time.sleep(1.2)
    close = session("""BEGIN;
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', body = body || '{"status": "COMPLETED", "overall_risk": "MEDIUM"}' WHERE check_id = 'chk_g1';
""")
    time.sleep(0.8)
    rev = session(f"BEGIN;\nINSERT INTO ac.claim_reviews VALUES ('rev_g1', '{x}', 'REFUTED', 'usr_y', now(), now());\n")
    time.sleep(1.2)
    o1 = finish(add)
    time.sleep(1.5)
    for s in (close, rev):                       # commit both without waiting: either may be the one holding the claim
        s.stdin.write("COMMIT;\n")
        s.stdin.close()
    o2, o3 = close.stdout.read().strip(), rev.stdout.read().strip()
    close.wait()
    rev.wait()
    st = T.psql(f"SELECT status || ' ' || coalesce(ac.status_at('{x}', completed_at), '-') FROM ac.checks WHERE check_id = 'chk_g1'").stdout.strip()
    r1, r2 = report("chk_g1"), report("chk_g1")
    bad = st.startswith("COMPLETED") and not st.endswith("ACCEPTED")
    verdict("S24-Г1", bad or (st.startswith("COMPLETED") and r1["digest"] != r2["digest"]), "утверждение, добавленное в Проверку другой транзакцией, и рецензия REFUTED в полёте",
            f"Проверка: {st}; {(o1 + ' ' + o2 + ' ' + o3)[-90:]}")


def g2(obs_first):
    R.reload()
    time.sleep(2)
    R.ok(f"""BEGIN;
    INSERT INTO ac.sources VALUES ('tnt_demo', '{SID}', {len(B)}, '{{"level": "PUBLIC", "categories": []}}',
      jsonb_build_object('source_id', '{SID}', 'tenant_id', 'tnt_demo', 'byte_length', {len(B)}, 'title', 'Новая статья', 'source_kind', 'MEDIA',
                         'marking', '{{"level": "PUBLIC", "categories": []}}'::jsonb));
    INSERT INTO ac.source_bytes VALUES ('tnt_demo', '{SID}', convert_to('{TEXT}', 'UTF8'));
    INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES ('tnt_demo', '{SID}', now(), 'https://x/1', 'crawler');
    INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
    SELECT '{CID}', 'prj_compliance', 'tnt_demo', 'ent_k_developer', 'media.negative_mention', NULL, 'HUMAN', now(), '{MC}',
      jsonb_build_object('kind', 'Claim', 'claim_id', '{CID}', 'project_id', 'prj_compliance', 'subject', 'ent_k_developer',
        'predicate', 'media.negative_mention', 'object', jsonb_build_object('literal', jsonb_build_object('type', 'STRING', 'value', 'ещё один иск')),
        'qualifiers', jsonb_build_object('severity', 'MEDIUM'), 'marking', '{MC}'::jsonb, 'produced_by', '{{"kind": "HUMAN", "actor_id": "usr_x"}}'::jsonb,
        'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'evidence', jsonb_build_array(jsonb_build_object('source_id', '{SID}', 'span', jsonb_build_object('start', 0, 'end', {len(B)}),
                                                         'quote_sha256', '{QSHA}')));
    INSERT INTO ac.claim_reviews VALUES ('rev_new_1', '{CID}', 'ACCEPTED', 'usr_x', now(), now());
    INSERT INTO ac.checks VALUES ('chk_obs', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
      (now() AT TIME ZONE 'UTC')::date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_obs', 'project_id', 'prj_compliance',
      'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));
    COMMIT;""", "ac_loader")
    time.sleep(1.1)
    R.ok(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_obs', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_obs', 'NEGATIVE', '{CID}');
INSERT INTO ac.check_searches VALUES ('chk_obs', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН", "search_scope": "СМИ"}}');
COMMIT;""", "ac_loader")
    time.sleep(1.1)
    obs = (f"BEGIN; SET LOCAL ac.historical_import = 'on';\nINSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) "
           f"VALUES ('tnt_demo', '{SID}', (SELECT max(sealed_at) + interval '1 second' FROM ac.history_seals), 'https://x/backdated', 'migrator');\n")
    close = ("BEGIN;\nUPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', "
             "body = body || '{\"status\": \"COMPLETED\", \"overall_risk\": \"MEDIUM\"}' WHERE check_id = 'chk_obs';\n")
    import subprocess
    def sess(sql, role):
        p = subprocess.Popen(["psql", "-X", "-q", "-At"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        p.stdin.write(f"SET SESSION AUTHORIZATION {role};\n" + sql)
        p.stdin.flush()
        return p
    a = sess(obs, "ac_migrator") if obs_first else sess(close, "ac_loader")
    time.sleep(1.2)
    b = sess(close, "ac_loader") if obs_first else sess(obs, "ac_migrator")
    time.sleep(1.5)
    waited = b.poll() is None
    oa = finish(a)
    mid = report("chk_obs")
    ob = finish(b)
    end = report("chk_obs")
    closed_first = not obs_first
    changed = (closed_first and mid["digest"] != end["digest"]) or (not closed_first and report("chk_obs")["digest"] != end["digest"])
    verdict(f"S24-Г2{'a' if obs_first else 'b'}", changed, ("наблюдение раньше закрытия" if obs_first else "закрытие раньше наблюдения")
            + ": first_observed_at в закрытом отчёте не меняется", f"второй ждал: {waited}; {(oa + ' ' + ob)[-80:]}")


def s2401():
    R.reload()
    import attacks_s1
    s = T.psql(attacks_s1.SETUP)
    assert s.returncode == 0, s.stderr
    base = T.psql("SELECT claim_id FROM ac.claims WHERE predicate = 'court.party_to_case' AND project_id = 'prj_compliance'").stdout.strip()
    probes = {
        "схема вне range": """jsonb_build_object('literal', jsonb_build_object('type', 'IDENTIFIER', 'scheme', 'telegram', 'value', 'x'))""",
        "контрольная сумма ИНН": None,
    }
    e1 = T.err(f"""BEGIN; SELECT ac_test.clone('court.party_to_case', 'clm:sha256:{'c1' * 32}', jsonb_build_object('object', {probes['схема вне range']})); COMMIT;""", "ac_loader")
    e2 = T.err(f"""BEGIN; SELECT ac_test.clone('person.sole_proprietor', 'clm:sha256:{'c2' * 32}',
        jsonb_build_object('object', jsonb_build_object('literal', jsonb_build_object('type', 'IDENTIFIER', 'scheme', 'ru.ogrnip', 'value', '326501200004120')))); COMMIT;""", "ac_loader")
    e3 = T.err(f"""BEGIN; SELECT ac_test.clone('ts.has_parameter', 'clm:sha256:{'c3' * 32}',
        jsonb_build_object('object', jsonb_build_object('literal', jsonb_build_object('type', 'QUANTITY', 'unit', 'furlong', 'value', '16')))); COMMIT;""", "ac_loader")
    verdict("S24-01", not ("PREDICATE_RANGE_VIOLATION" in e1 and "IDENTIFIER_CHECKSUM_INVALID" in e2 and "PREDICATE_RANGE_VIOLATION" in e3),
            "схема идентификатора, единица и контрольные цифры литерала проверяются базой", " / ".join(x[:55] for x in (e1, e2, e3)))


def main():
    g1()
    g2(True)
    g2(False)
    s2401()
    R.reload()
    print(f"\nregression_s24={len(BAD)} findings={sum(BAD)}")
    print("S24_REGRESSION=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

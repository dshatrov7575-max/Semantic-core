#!/usr/bin/env python3
"""Regression for the S2.2/S3 re-review findings S22-01…06 (reviewer's attacks, adapted: UTC dates, legal merge for S22-02).
Every write runs as a live role (SET SESSION AUTHORIZATION); the superuser only reloads the world and creates readers.
Prints held/FINDING per attack; exit 1 on any FINDING.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/regression_s22.py
"""
import hashlib
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s3_tests as T  # noqa: E402  (psql, js, err, SETUP)

BAD = []
M_CSPD = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
TODAY = "(now() AT TIME ZONE 'UTC')::date"


def reload():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    s = T.psql(T.SETUP)
    if s.returncode:
        sys.exit("setup failed: " + s.stderr)


def ok(sql, user):
    r = T.psql(sql, user)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def verdict(aid, finding, text, detail=""):
    BAD.append(finding)
    print(f"{aid:<8} {'FINDING' if finding else 'held':<7} | {text}{' | ' + detail if detail else ''}", flush=True)


def new_check(cid, prof, marking=M_CSPD, prev=None):
    return (f"INSERT INTO ac.checks VALUES ('{cid}', 'prj_compliance', 'ent_k_developer', '{prof}', 'IN_PROGRESS', now(), NULL, NULL, "
            f"{TODAY}, NULL, {repr(prev) if prev else 'NULL'}, '{marking}', jsonb_build_object('check_id', '{cid}', 'project_id', "
            f"'prj_compliance', 'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{marking}'::jsonb));")


def main():
    # S22-01: a merge into a broader-marked survivor is refused (names of RESTRICTED entities cannot reach CONFIDENTIAL readers)
    reload()
    e = T.err("""BEGIN;
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name)
VALUES ('ent_k_secret_plot', 'prj_compliance', 'REAL_ESTATE', '{"cadastral_number": "50:12:0101001:999"}', 'ACTIVE', now(),
        '{"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}', 'СЕКРЕТНО');
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_secret_plot' WHERE entity_id = 'ent_k_land';
COMMIT;""", "ac_loader")
    verdict("S22-01", "ENTITY_MERGE_INVALID" not in e, "слияние в сущность с более широкой маркировкой", e[:110])

    # S22-02: a legal merge AFTER a Check closed does not change the Check's report (names as of closing)
    reload()
    before = T.js("SELECT ac.check_report('chk_full_1');")
    ok("""BEGIN;
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name)
VALUES ('ent_k_plot_new', 'prj_compliance', 'REAL_ESTATE', '{"cadastral_number": "50:12:0101001:998"}', 'ACTIVE', now(),
        '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}', 'НОВОЕ ИМЯ УЧАСТКА');
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_plot_new' WHERE entity_id = 'ent_k_land';
COMMIT;""", "ac_loader")
    after = T.js("SELECT ac.check_report('chk_full_1');")
    dos = T.js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');")
    renamed_now = any("НОВОЕ ИМЯ" in f["text"] for s in dos["sections"] for f in s.get("facts", []))
    verdict("S22-02", before["digest"] != after["digest"] or not renamed_now,
            "законное слияние после закрытия: отчёт закрытой Проверки не изменился, досье «сейчас» — с новым именем")

    # S22-03: a Check may not be narrower than its previous Check; the report shows the previous one only to cleared readers
    reload()
    e = T.err("BEGIN;\n" + new_check("chk_cs_only", "TENDERS_ONLY", '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}',
                                     "chk_full_1") + "\nCOMMIT;", "ac_loader")
    verdict("S22-03", "MARKING_BROADER_THAN_INPUT" not in e, "Проверка уже маркировки предыдущей", e[:110])

    # S22-04: no findings into a CANCELLED Check; an open Check's NOT_FOUND without a search is not «Не выявлено.»
    reload()
    ok("BEGIN;\n" + new_check("chk_x", "EXPRESS_NEGATIVE") + "\nCOMMIT;", "ac_loader")
    ok("BEGIN; UPDATE ac.checks SET status = 'CANCELLED', body = jsonb_set(body, '{status}', '\"CANCELLED\"') WHERE check_id = 'chk_x'; COMMIT;",
       "ac_loader")
    before = T.js("SELECT ac.check_report('chk_x');")
    e = T.err("BEGIN; INSERT INTO ac.check_findings VALUES ('chk_x', 'NEGATIVE', 'NOT_FOUND', 'NONE'); COMMIT;", "ac_loader")
    after = T.js("SELECT ac.check_report('chk_x');")
    verdict("S22-04", "CHECK_CLOSED" not in e or before["digest"] != after["digest"], "итог в отменённую Проверку", e[:110])
    ok("BEGIN; INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'TENDERS', 'NOT_FOUND', 'NONE'); COMMIT;", "ac_loader")
    op = T.js("SELECT ac.check_report('chk_tenders_1');")
    d = next(x for x in op["dimensions"] if x["dimension"] == "TENDERS")
    verdict("S22-04b", not (op.get("draft") and d.get("text") == "Поиск по этому направлению не выполнен."),
            "открытая Проверка помечена черновиком; «не выявлено» без поиска так не называется", d.get("text", ""))

    # S22-05: a Check closed live after the seal cannot be rewritten by ac_migrator in historical mode
    reload()
    cid = T.psql("SELECT claim_id FROM ac.claims WHERE predicate = 'media.negative_mention'").stdout.strip()
    ok("BEGIN;\n" + new_check("chk_live", "EXPRESS_NEGATIVE") + "\nCOMMIT;", "ac_loader")
    time.sleep(1.1)
    ok(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_live', 'NEGATIVE', 'FOUND', 'MEDIUM');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_live', 'NEGATIVE', '{cid}');
INSERT INTO ac.check_searches VALUES ('chk_live', 'NEGATIVE', 0, now(), 'tnt_demo', NULL, '{{"query": "ИНН 5012007313", "search_scope": "СМИ"}}');
UPDATE ac.checks SET status = 'COMPLETED', overall_risk = 'MEDIUM', body = body || '{{"status": "COMPLETED", "overall_risk": "MEDIUM"}}'
 WHERE check_id = 'chk_live';
COMMIT;""", "ac_loader")
    before = T.js("SELECT ac.check_report('chk_live');")
    time.sleep(1.1)
    e1 = T.err("""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.check_searches VALUES ('chk_live', 'NEGATIVE', 1, (SELECT completed_at FROM ac.checks WHERE check_id = 'chk_live'),
  'tnt_demo', NULL, '{"query": "подброшенный поиск"}'); COMMIT;""", "ac_migrator")
    e2 = T.err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews VALUES ('rev_back', '{cid}', 'REFUTED', 'usr_x',
  (SELECT completed_at - interval '1 second' FROM ac.checks WHERE check_id = 'chk_live'),
  (SELECT completed_at - interval '1 second' FROM ac.checks WHERE check_id = 'chk_live')); COMMIT;""", "ac_migrator")
    e3 = T.err("BEGIN; INSERT INTO ac.check_findings VALUES ('chk_live', 'COURT', 'NOT_FOUND', 'NONE'); COMMIT;", "ac_loader")
    after = T.js("SELECT ac.check_report('chk_live');")
    verdict("S22-05", not ("CHECK_CLOSED" in e1 and "TEMPORAL_ORDER_INVALID" in e2 and "CHECK_CLOSED" in e3) or before["digest"] != after["digest"],
            "Проверка, закрытая после печати: ни след поиска, ни рецензия задним числом, ни итог", " / ".join(x[:60] for x in (e1, e2, e3)))

    # S22-06: an unknown marking is not a marking (shape CHECK), and dominates() is fail-closed
    reload()
    text = "СЕКРЕТНЫЙ ДОКЛАД".encode()
    sid = "src:sha256:" + hashlib.sha256(text).hexdigest()
    e = T.err(f"""BEGIN;
INSERT INTO ac.sources VALUES ('tnt_demo', '{sid}', {len(text)}, '{{"level": "Restricted", "categories": []}}',
  jsonb_build_object('source_id', '{sid}', 'tenant_id', 'tnt_demo', 'byte_length', {len(text)}, 'title', 'x',
                     'marking', '{{"level": "Restricted", "categories": []}}'::jsonb)); COMMIT;""", "ac_loader")
    dom = T.psql("""SELECT ac.dominates('{"level": "PUBLIC", "categories": []}', '{"level": "Restricted", "categories": []}')::text
       || ac.dominates('{"level": "RESTRICTED", "categories": ["X"]}', '{"level": "PUBLIC", "categories": []}')::text
       || ac.dominates('{"level": "PUBLIC", "categories": [], "extra": 1}', '{"level": "PUBLIC", "categories": []}')::text""").stdout.strip()
    verdict("S22-06", "sources_marking_shape" not in e or dom != "falsefalsefalse",
            "маркировка неизвестной формы отвергается; доминирование с ней — false", f"{e[:70]} / {dom}")

    reload()
    print(f"\nregression_s22={len(BAD)} findings={sum(BAD)}")
    print("S22_REGRESSION=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

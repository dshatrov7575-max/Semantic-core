#!/usr/bin/env python3
"""S3 acceptance: projections «досье», «отчёт Проверки», «провенанс» (proj_s3.sql) on the reference world.

Reloads the world (load_s1.py), creates reader roles with clearances, then checks: every sentence leads to claims
and verified fragments; «Не выявлено» leads to a search trace; the birth-date discrepancy is explained;
a closed Check's report does not change after later reviews; digests are reproducible and independent of the
session time zone; readers see only what their clearance dominates and nothing else (no table access,
no existence oracle, revocation works).

Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s3_tests.py
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = []

SETUP = """
DO $$ BEGIN CREATE ROLE ac_rd_full LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_public LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_cs LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_none LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories, granted_at) VALUES
 ('ac_rd_full', 'prj_dossier', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}', '2000-01-01'),
 ('ac_rd_full', 'prj_compliance', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}', '2000-01-01'),
 ('ac_rd_full', 'prj_wiki_whales', 'PUBLIC', '{}', '2000-01-01'),
 ('ac_rd_public', 'prj_dossier', 'PUBLIC', '{}', '2000-01-01'),
 ('ac_rd_public', 'prj_wiki_whales', 'PUBLIC', '{}', '2000-01-01'),
 ('ac_rd_cs', 'prj_compliance', 'CONFIDENTIAL', '{COMMERCIAL_SECRET}', '2000-01-01');
RESET ROLE;
"""


def psql(sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)


def js(sql, user="ac_rd_full"):
    r = psql(sql, user)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def err(sql, user):
    r = psql(sql, user)
    return r.stderr.strip().splitlines()[0] if r.returncode else "(выполнено)"


def check(tid, ok, desc, detail=""):
    RESULTS.append(ok)
    print(f"{tid} {'PASS' if ok else 'FAIL'} | {desc}{' | ' + detail if detail else ''}")


def facts_of(proj):
    secs = proj.get("sections") or proj.get("dimensions") or []
    return [f for s in secs for f in s.get("facts", [])]


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stderr + r.stdout)
    s = psql(SETUP)
    if s.returncode:
        sys.exit("setup failed: " + s.stderr)

    AS_OF = "'2026-09-30T00:00:00Z'"
    dossier_ids = psql("SELECT entity_id FROM ac.entities WHERE project_id = 'prj_dossier' AND status = 'ACTIVE' "
                       "AND entity_type IN ('PERSON','ORGANIZATION') ORDER BY 1").stdout.split()
    checks = psql("SELECT check_id FROM ac.checks ORDER BY 1").stdout.split()
    dossiers = {e: js(f"SELECT ac.dossier('prj_dossier', '{e}', {AS_OF});") for e in dossier_ids}
    reports = {k: js(f"SELECT ac.check_report('{k}');") for k in checks}

    # 1. every sentence -> claims -> verified fragments
    allf = [f for p in list(dossiers.values()) + list(reports.values()) for f in facts_of(p)]
    ev = [e for f in allf for c in f["claims"] + f.get("other_claims", []) for e in c["evidence"]]
    ok = allf and all(f["claims"] and all(c["evidence"] for c in f["claims"]) for f in allf) and all(e["verified"] for e in ev)
    check("S3-01", bool(ok), "каждое предложение ведёт к утверждению и к фрагменту, сверенному с байтами",
          f"предложений {len(allf)}, фрагментов {len(ev)}")

    # 2. quotes are the bytes of the span (independent re-read as postgres)
    bad = 0
    for e in ev:
        q = psql(f"SELECT convert_from(substring(bytes FROM {e['span'][0]} + 1 FOR {e['span'][1] - e['span'][0]}), 'UTF8') "
                 f"FROM ac.source_bytes WHERE source_id = '{e['source_id']}'").stdout.rstrip("\n")
        bad += q != e["quote"]
    check("S3-02", bad == 0, "цитата проекции = байты источника по span (перечитано независимо)", f"расхождений {bad}")

    # 3. birth-date discrepancy explained
    lom = dossiers["ent_d_lomov"]
    ident = next(s for s in lom["sections"] if s["section"] == "IDENTITY")
    f = ident.get("facts", [])
    ok = (len(f) == 1 and "14.03.1971" in f[0]["text"] and "14.03.1972" in f[0].get("note", "")
          and "Интервью" in f[0].get("note", "") and f[0].get("other_claims"))
    check("S3-03", bool(ok), "расхождение дат рождения выведено одним предложением с пояснением",
          (f[0]["text"] + " / " + f[0].get("note", "")) if f else "нет факта")

    # 4. NOT_FOUND -> «Не выявлено.» + search trace; FOUND -> facts; empty dossier section -> «Сведений нет.»
    dims = [d for k, p in reports.items() for d in p["dimensions"] if p["status"] == "COMPLETED"]
    ok = dims and all((d["result"] == "NOT_FOUND" and d.get("text") == "Не выявлено." and d["searches"] and not d.get("facts"))
                      or (d["result"] == "FOUND" and d.get("facts") and d["searches"]) for d in dims)
    nf = sum(d["result"] == "NOT_FOUND" for d in dims)
    empty = [s for p in dossiers.values() for s in p["sections"] if "facts" not in s]
    ok = ok and nf > 0 and all(s.get("empty") == "Сведений нет." for s in empty)
    check("S3-04", bool(ok), "«Не выявлено» ведёт к следу поиска; найденное — к утверждениям; пустой раздел досье — «Сведений нет.»",
          f"измерений {len(dims)}, из них не выявлено {nf}; пустых разделов досье {len(empty)}")

    # 5. report cites only the Check's own claims; dossier only claims about the entity
    extra = 0
    for k, p in reports.items():
        own = set(psql(f"SELECT claim_id FROM ac.check_finding_claims WHERE check_id = '{k}'").stdout.split())
        extra += len({c["claim_id"] for f in facts_of(p) for c in f["claims"]} - own)
    for e, p in dossiers.items():
        about = set(psql(f"SELECT claim_id FROM ac.claims WHERE ac.resolve(subject) = '{e}' OR ac.resolve(object_entity) = '{e}'").stdout.split())
        extra += len({c["claim_id"] for f in facts_of(p) for c in f["claims"] + f.get("other_claims", [])} - about)
    check("S3-05", extra == 0, "в отчёте только утверждения своей Проверки, в досье — только о своей сущности", f"лишних {extra}")

    # 6. reproducible and independent of the session time zone
    d1 = js("SELECT ac.check_report('chk_full_1');")["digest"]
    d2 = js("SET TimeZone = 'Asia/Vladivostok'; SET lc_numeric = 'C'; SELECT ac.check_report('chk_full_1');")["digest"]
    d3 = js(f"SET TimeZone = 'America/New_York'; SELECT ac.dossier('prj_dossier', 'ent_d_lomov', {AS_OF});")["digest"]
    check("S3-06", d1 == d2 == reports["chk_full_1"]["digest"] and d3 == lom["digest"], "digest воспроизводим и не зависит от часового пояса сессии")

    # 7. non-retroactivity: a later REFUTED review of a claim of a closed Check does not change its report;
    #    the dossier «now» drops the refuted claim
    cid = psql("SELECT claim_id FROM ac.check_finding_claims WHERE check_id = 'chk_full_1' AND dimension = 'COURT'").stdout.strip()
    before = js("SELECT ac.check_report('chk_full_1');")["digest"]
    dos_before = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');")
    w = psql(f"BEGIN; INSERT INTO ac.claim_reviews VALUES ('rev_s3_late', '{cid}', 'REFUTED', 'usr_x', now(), now()); COMMIT;", "ac_loader")
    after = js("SELECT ac.check_report('chk_full_1');")["digest"]
    dos_after = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');")
    in_before = any(c["claim_id"] == cid for f in facts_of(dos_before) for c in f["claims"])
    in_after = any(c["claim_id"] == cid for f in facts_of(dos_after) for c in f["claims"])
    check("S3-07", w.returncode == 0 and before == after and in_before and not in_after,
          "поздняя рецензия REFUTED: отчёт закрытой Проверки не изменился, досье «сейчас» утверждение исключило")

    # 8. merged card resolves to the survivor; the card is listed as «также известен как»
    m = js(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov_media', {AS_OF});")
    check("S3-08", m["digest"] == lom["digest"] and any(a["entity_id"] == "ent_d_lomov_media" for a in lom.get("also_known_as", [])),
          "досье по слитой карточке = досье выжившей сущности; карточка указана как «также известен»")

    # 9. partial clearance: CONFIDENTIAL + COMMERCIAL_SECRET without PERSONAL_DATA sees the company, not the person
    cs = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_cs")
    txt = json.dumps(cs, ensure_ascii=False)
    full = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');")
    ok = "Ломов" not in txt and "PERSONAL_DATA" not in txt and "Ломов" in json.dumps(full, ensure_ascii=False)
    e1 = err("SELECT ac.dossier('prj_compliance', 'ent_k_lomov');", "ac_rd_cs")
    e2 = err("SELECT ac.check_report('chk_full_1');", "ac_rd_cs")
    check("S3-09", ok and "ACCESS_DENIED" in e1 and "ACCESS_DENIED" in e2,
          "допуск без персональных данных: компания видна, физлицо и связи с ним скрыты, Проверка с ПД закрыта")

    # 10. no clearance / wrong project / nonexistent object: the same refusal (no existence oracle)
    e3 = err(f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', {AS_OF});", "ac_rd_public")
    e4 = err(f"SELECT ac.dossier('prj_dossier', 'ent_nonexistent', {AS_OF});", "ac_rd_public")
    e5 = err("SELECT ac.check_report('chk_full_1');", "ac_rd_none")
    e6 = err("SELECT ac.check_report('chk_nope');", "ac_rd_none")
    e7 = err("SELECT ac.dossier('prj_dossier', 'x'' OR 1=1 --');", "ac_rd_full")
    e3b = err("SELECT ac.provenance('clm:sha256:" + "0" * 64 + "');", "ac_rd_public")
    e4b = err("SELECT ac.provenance((SELECT 'x'));", "ac_rd_public")
    same = len({e3, e4, e5, e6, e7, e3b, e4b}) == 1                        # S23-06/16: one and the same refusal text
    check("S3-10", all("ACCESS_DENIED" in e for e in (e3, e4, e5, e6, e7)) and same,
          "нет допуска / чужой проект / несуществующий объект / попытка инъекции — одинаковый отказ")

    # 11. readers have no table access and cannot use helper functions to read data
    probes = ["SELECT count(*) FROM ac.claims;", "SELECT count(*) FROM ac.source_bytes;", "SELECT * FROM ac_trust.clearances;",
              "SELECT ac.evidence_json(claim_id, now()) FROM ac.claims LIMIT 1;", "SELECT ac.status_at('x', now());",
              "SELECT ac.my_clearance('prj_dossier');"]
    outs = [err(p, "ac_rd_full") for p in probes]
    check("S3-11", all("permission denied" in o for o in outs), "у читателя нет доступа к таблицам и к данным через служебные функции",
          "; ".join(o[:60] for o in outs if "permission denied" not in o))

    # 12. clearances: only ac_trust_admin writes them, append-only, system time; revocation works immediately
    e8 = err("INSERT INTO ac_trust.clearances (role_name, project_id, level) VALUES ('ac_rd_public', 'prj_dossier', 'RESTRICTED');", "ac_rd_public")
    e9 = err("INSERT INTO ac_trust.clearances (role_name, project_id, level) VALUES ('ac_rd_public', 'prj_dossier', 'RESTRICTED');", "ac_loader")
    e10 = err("UPDATE ac_trust.clearances SET level = 'RESTRICTED';", "ac_trust_admin")
    ts = psql("SELECT bool_and(granted_at > '2020-01-01') FROM ac_trust.clearances").stdout.strip()
    rv = psql("SET ROLE ac_trust_admin; INSERT INTO ac_trust.clearances (role_name, project_id, level) VALUES ('ac_rd_full', 'prj_wiki_whales', NULL);")
    e11 = err("SELECT ac.dossier('prj_wiki_whales', 'ent_wk_blue');", "ac_rd_full")
    ok_pub = psql("SELECT ac.dossier('prj_wiki_whales', 'ent_wk_blue') IS NOT NULL;", "ac_rd_public").stdout.strip().endswith("t")
    check("S3-12", "permission denied" in e8 and "permission denied" in e9 and ("permission denied" in e10 or "APPEND_ONLY" in e10) and ts == "t"
          and rv.returncode == 0 and "ACCESS_DENIED" in e11 and ok_pub,
          "допуски пишет только ac_trust_admin, только добавлением, время ставит база; отзыв действует сразу")

    # 13. an open Check is reported as a draft evaluated now
    op = reports["chk_tenders_1"]
    check("S3-13", op["status"] == "IN_PROGRESS" and all(d.get("text") == "Проверка по этому направлению не завершена." or d.get("result")
                                                           for d in op["dimensions"]),
          "открытая Проверка: статус IN_PROGRESS, незавершённые направления помечены")

    # 14. provenance: claim -> evidence -> receipt for a PIPELINE claim; clearance enforced
    pc = psql("SELECT claim_id FROM ac.receipt_claims LIMIT 1").stdout.strip()
    r1 = psql("SET ROLE ac_trust_admin; INSERT INTO ac_trust.clearances (role_name, project_id, level) VALUES ('ac_rd_full', 'prj_ts_pumps', 'INTERNAL');")
    pv = js(f"SELECT ac.provenance('{pc}');")
    e12 = err(f"SELECT ac.provenance('{pc}');", "ac_rd_public")
    check("S3-14", r1.returncode == 0 and pv.get("receipt", {}).get("service_id") == "svc_techsense" and pv["evidence"]
          and all(e["verified"] for e in pv["evidence"]) and "ACCESS_DENIED" in e12,
          "провенанс PIPELINE-утверждения: фрагменты и подписанный receipt; без допуска — отказ")

    # 15. every registered predicate has a sentence template; projection functions are owned by a non-superuser
    miss = psql("SELECT count(*) FROM ac.predicates p WHERE NOT EXISTS (SELECT 1 FROM ac.predicate_texts t WHERE t.predicate_id = p.predicate_id)").stdout.strip()
    own = psql("SELECT string_agg(DISTINCT r.rolname || ':' || r.rolsuper, ',') FROM pg_proc f JOIN pg_roles r ON r.oid = f.proowner "
               "WHERE f.proname IN ('dossier','check_report','provenance')").stdout.strip()
    priv = psql("SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'ac_projector' AND privilege_type <> 'SELECT'").stdout.strip()
    check("S3-15", miss == "0" and own == "ac_projector:false" and priv == "0",
          "у каждого предиката есть шаблон; проекции принадлежат ac_projector (не суперпользователь, только SELECT)", f"{miss} / {own} / {priv}")

    # 16. a reader cannot plant objects to hijack name resolution
    e13 = err("CREATE FUNCTION public.dominates(a jsonb, b jsonb) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;", "ac_rd_public")
    e14 = err("CREATE TEMP TABLE entities (x int);", "ac_rd_public")
    check("S3-16", "permission denied" in e13 and "permission denied" in e14, "читатель не может создать объекты для подмены имён")

    print(f"\ns3_tests={len(RESULTS)} passed={sum(RESULTS)}")
    print("S3_RESULT=" + ("PASS" if all(RESULTS) else "FAIL"))
    subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())

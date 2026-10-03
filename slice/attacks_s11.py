#!/usr/bin/env python3
"""S11 attacks (cycle 11): isolation of guarded writes, races of the guards of earlier cycles (found by the independent
review: S11R-04 … S11R-08), the conflict of strong keys of a row, «актуальность строки».
Each attack must be refused («held»); «законная» lines must be accepted.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s11.py
"""
import copy
import hashlib
import json
import threading
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
from fixtures import REGISTRY_ROWS, REGISTRY_COLUMNS, OGRN_DEV, INN_DEV, demo_registry  # noqa: E402
from ingest_s4 import ingest_sql, utc  # noqa: E402
import s3_tests as S3  # noqa: E402
import dataset_s10 as D  # noqa: E402
from s10_tests import claim, copy_file, new_version, first_err, T, PRJ  # noqa: E402
from s11_tests import org, key, CONF_CS, CONF_PD  # noqa: E402

BAD = []
ISO = ["ISOLATION_LEVEL_UNSUPPORTED"]
RI = ["EVIDENCE_ROW_INVALID"]


def held(aid, ok, desc, detail=""):
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def attack(aid, desc, sql, expect, legit=False, user=None):
    r = S3.psql(sql, user)
    ok = (r.returncode == 0) if legit else (r.returncode != 0 and any(x in r.stderr for x in expect))
    held(aid, ok, ("законная: " if legit else "") + desc, first_err(r)[:110] if r.returncode else "принято")


def in_level(level, body, user="ac_loader"):
    return f"SET SESSION AUTHORIZATION {user};\nBEGIN ISOLATION LEVEL {level};\n{body}\nCOMMIT;"


def body_of(records):
    lines = ingest_sql(records, {}).splitlines()
    return "\n".join(ln for ln in lines if not ln.startswith(("SET SESSION", "BEGIN", "COMMIT")))


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    S3.psql(S3.SETUP)
    dv = demo_registry()
    sid = dv.source_id
    _, bad = D.load_rows(T, sid, copy_file(dv), dv.columns)
    assert bad is None, first_err(bad)
    BETA = REGISTRY_ROWS[3]

    # ---- isolation
    e1 = org("ent_a_iso1", "ООО «Изоляция 1»", ogrn=REGISTRY_ROWS[4]["ogrn"])
    for n, lv in enumerate(("REPEATABLE READ", "SERIALIZABLE")):
        attack(f"I0{n + 1}", f"сущность в {lv}", in_level(lv, body_of([e1])), ISO)
    attack("I03", "сущность в READ COMMITTED", in_level("READ COMMITTED", body_of([e1])), [], legit=True)
    time.sleep(1.1)
    ev = dv.evidence([OGRN_DEV], ["address"])
    attack("I04", "утверждение в REPEATABLE READ", in_level("REPEATABLE READ", body_of([claim(ev)])), ISO)
    attack("I05", "уровень изоляции по умолчанию у сеанса", "SET SESSION AUTHORIZATION ac_loader;\nSET default_transaction_isolation = 'repeatable read';\n"
           "BEGIN;\n" + body_of([claim(ev)]) + "\nCOMMIT;", ISO)
    attack("I06", "запись в DO-блоке в SERIALIZABLE", in_level("SERIALIZABLE", "DO $$ BEGIN INSERT INTO ac.claim_reviews SELECT * FROM ac.claim_reviews LIMIT 0; END $$;"), ISO)
    attack("I07", "подтранзакция в REPEATABLE READ", in_level("REPEATABLE READ", "SAVEPOINT a;\n" + body_of([claim(ev)]) + "\nRELEASE a;"), ISO)
    attack("I08", "смена уровня после первого запроса", "SET SESSION AUTHORIZATION ac_loader;\nBEGIN ISOLATION LEVEL REPEATABLE READ;\nSELECT 1;\n"
           "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;\n" + body_of([claim(ev)]) + "\nCOMMIT;", ["must be called before any query"])
    attack("I09", "открытие таблицы строк версии в REPEATABLE READ", in_level("REPEATABLE READ", f"SELECT ac.dataset_open('{T}', '{sid}');"), ISO + ["APPEND_ONLY"])
    v2, r2 = new_version("a-iso")
    attack("I10", "печать версии в SERIALIZABLE", in_level("SERIALIZABLE", f"SELECT ac.dataset_open('{T}', '{v2.source_id}');"), ISO)
    attack("I11", "мигратор: исторический импорт в REPEATABLE READ",
           in_level("REPEATABLE READ", "INSERT INTO ac.history_seals SELECT * FROM ac.history_seals WHERE false;", user="ac_migrator"), ISO)
    attack("I12", "администратор доверия в SERIALIZABLE", in_level("SERIALIZABLE", "INSERT INTO ac_trust.keys SELECT * FROM ac_trust.keys WHERE false;", user="ac_trust_admin"), ISO)
    attack("I13", "суперпользователь в REPEATABLE READ", "BEGIN ISOLATION LEVEL REPEATABLE READ; DELETE FROM ac.claims WHERE false; COMMIT;", ISO)
    tab = lambda s_: S3.psql(f"SELECT table_name FROM ac.dataset_tables WHERE source_id = '{s_}'").stdout.strip() or "none"  # noqa: E731
    attack("I18", "COPY строк версии набора в REPEATABLE READ", "BEGIN ISOLATION LEVEL REPEATABLE READ; "
           f"INSERT INTO acd.{tab(sid)} SELECT * FROM acd.{tab(sid)} WHERE false; COMMIT;", ISO)
    attack("I19", "проекции, которые сами берут блокировку (сохранность, модель, пробелы схемы), в REPEATABLE READ отвергаются — как запись",
           "BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT ac.model('prj_wiki_whales'); COMMIT;", ISO, user="ac_rd_public")
    attack("I14", "чтение досье в REPEATABLE READ (чтение не запрещено)",
           f"BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT ac.dossier('{PRJ}', 'ent_k_developer'); COMMIT;", [], legit=True, user="ac_rd_cs")
    attack("I15", "чтение строки набора в SERIALIZABLE (чтение не запрещено)",
           f"BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT ac.dataset_row('{PRJ}', '{sid}', {key(OGRN_DEV)}); COMMIT;", [], legit=True, user="ac_rd_cs")
    drop = S3.psql("SET SESSION AUTHORIZATION ac_loader; DROP TRIGGER a_isolation_guard ON ac.claims;")
    held("I16", drop.returncode != 0, "загрузчик не может снять стража изоляции с таблицы", first_err(drop)[:70])
    n_guard = S3.psql("SELECT count(*) FROM pg_trigger WHERE tgname = 'a_isolation_guard'").stdout.strip()
    n_tab = S3.psql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN ('ac','ac_trust') AND c.relkind = 'r'").stdout.strip()
    n_guard = S3.psql("SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                      "WHERE g.tgname = 'a_isolation_guard' AND n.nspname IN ('ac','ac_trust')").stdout.strip()
    n_acd = S3.psql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'acd' AND c.relkind = 'r' AND NOT EXISTS "
                    "(SELECT 1 FROM pg_trigger g WHERE g.tgrelid = c.oid AND g.tgname = 'a_isolation_guard')").stdout.strip()
    held("I17", n_guard == n_tab and int(n_tab) > 30 and n_acd == "0", "страж изоляции стоит на каждой таблице ядра и на каждой таблице строк наборов",
         f"таблиц {n_tab}, стражей {n_guard}, таблиц строк без стража {n_acd}")

    # ---- the conflict of strong keys
    a = org("ent_a_beta", "ООО «Бета»", ogrn=BETA["ogrn"])
    b = org("ent_a_beta_inn", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
    assert S3.psql(ingest_sql([a, b], {})).returncode == 0
    time.sleep(1.1)
    ev_inn = dv.evidence([BETA["ogrn"]], ["address", "inn"])
    ev_addr = dv.evidence([BETA["ogrn"]], ["address"])

    def cl(e, subj="ent_a_beta"):
        return claim(e, subj=subj, address=BETA["address"])
    c1 = cl(ev_inn)
    attack("C01", "утверждение цитирует ИНН строки, которым в проекте владеет другая организация: принято, конфликт показан при чтении",
           ingest_sql([c1], {}), [], legit=True)
    flag = lambda c: json.loads(S3.psql(f"SELECT ac.evidence_json('{c['claim_id']}', now());").stdout)[0].get("subject_conflict")  # noqa: E731
    held("C02", flag(c1) is True, "у доказательства такого утверждения стоит subject_conflict", str(flag(c1)))
    c3 = cl(ev_addr)
    attack("C03", "ИНН не процитирован — утверждение об адресе", ingest_sql([c3], {}), [], legit=True)
    held("C04", flag(c3) is None, "без процитированного чужого идентификатора флага нет (конфликт виден в ac.dataset_subject)", str(flag(c3)))
    # the order of writing does not matter any more (S11R-01): the claim first, the other entity later — the flag appears
    g0 = org("ent_a_alfa", "ООО «Альфа-Сервис»", ogrn=REGISTRY_ROWS[2]["ogrn"])
    S3.psql(ingest_sql([g0], {}))
    time.sleep(1.1)
    c9 = claim(dv.evidence([REGISTRY_ROWS[2]["ogrn"]], ["address", "inn"]), subj="ent_a_alfa", address=REGISTRY_ROWS[2]["address"])
    one_tx = S3.psql(ingest_sql([c9, org("ent_a_alfa_inn", "ООО «Альфа» (по ИНН)", inn=REGISTRY_ROWS[2]["inn"])], {}))
    held("C09", one_tx.returncode == 0 and flag(c9) is True,
         "одна транзакция: сначала утверждение, потом сущность с ИНН строки — принято, конфликт показан (порядок записи ничего не обходит)",
         f"{first_err(one_tx)[:50]}; subject_conflict = {flag(c9)}")
    subj = json.loads(S3.psql(f"SELECT ac.dataset_subject('{PRJ}', '{sid}', {key(BETA['ogrn'])});", "ac_rd_cs").stdout)
    held("C05", subj["status"] == "CONFLICT", "проекция «о ком строка» показывает конфликт", f"{subj['status']} {[o['entity_id'] for o in subj['owners']]}")
    attack("C06", "о ком строка — читателю без допуска", f"SELECT ac.dataset_subject('{PRJ}', '{sid}', {key(BETA['ogrn'])});", ["ACCESS_DENIED"], user="ac_rd_none")
    attack("C07", "о ком строка несуществующей версии", f"SELECT ac.dataset_subject('{PRJ}', 'src:sha256:{'1' * 64}', {key(BETA['ogrn'])});", ["ACCESS_DENIED"], user="ac_rd_cs")
    cols = copy.deepcopy(REGISTRY_COLUMNS)
    cols[1]["marking"] = CONF_PD                                         # the INN column (a subject identifier) is personal data
    vk, rk = new_version("a-subj", columns=cols)
    _, b2 = D.load_rows(T, vk.source_id, copy_file(vk), cols)
    assert rk.returncode == 0 and b2 is None
    attack("C08", "о ком строка: идентификатор субъекта — персональные данные, у читателя нет этой категории",
           f"SELECT ac.dataset_subject('{PRJ}', '{vk.source_id}', {key(BETA['ogrn'])});", ["CLEARANCE_INSUFFICIENT"], user="ac_rd_cs")

    # ---- races of the guards of earlier cycles under READ COMMITTED (S11R-04 … S11R-08)
    LD = "SET SESSION AUTHORIZATION ac_loader;\n"

    def bg(sql):
        out = []
        th = threading.Thread(target=lambda: out.append(S3.psql(sql)))
        th.start()
        return th, out

    def both(slow, fast, gap=1.5):
        th, o = bg(slow)
        time.sleep(gap)
        r = S3.psql(fast)
        th.join()
        return o[0], r

    x = org("ent_g_x", "ООО «Гонка Икс»", ogrn=D._ogrn(30_000_000_001))
    y = org("ent_g_y", "ООО «Гонка Игрек»", ogrn=D._ogrn(30_000_000_002))
    a2 = org("ent_g_a", "ООО «Гонка А»", ogrn=D._ogrn(30_000_000_003))
    b3 = org("ent_g_b", "ООО «Гонка Б»", ogrn=D._ogrn(30_000_000_004))
    p1 = org("ent_g_p", "ООО «Гонка П»", inn=D._inn10(770000111))
    q1 = org("ent_g_q", "ООО «Гонка Ку»", inn=D._inn10(770000112))
    assert S3.psql(ingest_sql([x, y, a2, b3, p1, q1], {})).returncode == 0
    time.sleep(1.2)
    merge = lambda a_, b_: LD + f"BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = '{b_}' WHERE entity_id = '{a_}';\nSELECT pg_sleep(3);\nCOMMIT;"  # noqa: E731
    text = "Источник гонки G1 для утверждения о сливаемой сущности."
    src = {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_kind": "DOCUMENT", "media_type": "text/plain; charset=utf-8",
           "language": "ru", "title": "G1", "content_inline": text, "byte_length": len(text.encode()),
           "source_id": "src:sha256:" + hashlib.sha256(text.encode()).hexdigest(), "marking": D.PUB,
           "observations": [{"observed_at": utc(3), "origin_uri": "urn:demo:g1", "observed_by": "svc_webmon"}]}
    assert S3.psql(ingest_sql([src], {})).returncode == 0
    time.sleep(1.2)
    qb = "Источник гонки G1".encode()
    cg = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": PRJ, "subject": "ent_g_x", "predicate": "entity.registered_address",
          "object": {"literal": {"type": "STRING", "value": "адрес"}}, "evidence": [{"source_id": src["source_id"], "span": {"start": 0, "end": len(qb)},
                                                                                  "quote_sha256": hashlib.sha256(qb).hexdigest()}],
          "produced_by": {"kind": "HUMAN", "actor_id": "usr_bank_officer"}, "recorded_at": None, "marking": CONF_CS}

    def late_claim():
        c = dict(cg, recorded_at=utc(0))
        from jcs import digest
        c["claim_id"] = "clm:sha256:" + digest(c)
        return ingest_sql([c], {})
    th, o = bg(merge("ent_g_x", "ent_g_y"))
    time.sleep(1.6)
    r = S3.psql(late_claim())
    th.join()
    held("G1", o[0].returncode == 0 and r.returncode != 0 and "CLAIM_ABOUT_MERGED_ENTITY" in r.stderr,
         "гонка: утверждение о сущности, которую в этот момент сливают, — после слияния отвергнуто (S11R-04)", first_err(r)[:80])
    d = org("ent_g_d", "ООО «Гонка А» (дубль)", inn=D._inn10(770000113))
    d.update(status="MERGED", merged_into="ent_g_a", status_changed_at=utc(0))
    o1, r2 = both(LD + "BEGIN;\n" + body_of([d]) + "\nSELECT pg_sleep(3);\nCOMMIT;",
                  LD + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_g_b' WHERE entity_id = 'ent_g_a';\nCOMMIT;")
    held("G2", (o1.returncode == 0) != (r2.returncode == 0), "гонка: вставка D сразу слитой в A и слияние A в B — проходит одно (S11R-05)",
         f"вставка: {first_err(o1)[:40]}; слияние: {first_err(r2)[:60]}")
    dec = ("INSERT INTO ac.identity_decisions (decision_id, project_id, decision, entity_a, entity_b, decided_at, decided_by, body) "
           "SELECT 'idd_g3', project_id, 'DISTINCT', 'ent_g_p', 'ent_g_q', now(), 'usr_analyst1', "
           "jsonb_build_object('kind','IdentityDecision','decision_id','idd_g3','project_id',project_id,'decision','DISTINCT','entity_ids',jsonb_build_array('ent_g_p','ent_g_q'),"
           "'decided_by','usr_analyst1','decided_at',to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')) FROM ac.entities WHERE entity_id = 'ent_g_p';")
    o1, r2 = both(merge("ent_g_p", "ent_g_q"), LD + "BEGIN;\n" + dec + "\nCOMMIT;")
    pair = S3.psql("SELECT (SELECT status FROM ac.entities WHERE entity_id = 'ent_g_p') || ' ' || (SELECT count(*) FROM ac.identity_decisions "
                   "WHERE decision_id = 'idd_g3')").stdout.strip()
    held("G3", pair != "MERGED 1" and "IDENTITY" in r2.stderr + o1.stderr, "гонка: слияние пары и решение «различны» о ней же — оба не фиксируются (S11R-06)",
         f"состояние: {pair}; решение: {first_err(r2)[:90]}")
    # a public publication and a confidential rendition of its text (S11R-07): a race and one transaction
    from s5_tests import source as wm_source, publication as wm_publication
    from ingest_s4 import q as Q
    CONF = {"level": "CONFIDENTIAL", "categories": []}

    def pub_sql(pb):
        return ("INSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
                f"({Q(pb['publication_id'])},{Q(pb['tenant_id'])},{Q(pb['outlet'])},{Q(pb['canonical_url'])},{Q(pb['text_digest'])},{Q(pb['marking'])},{Q(pb)});")

    def pub_case(tag, single):
        txt = f"Завод «Гонка-{tag}» объявил о сокращении. Подробности сообщил источник в дирекции."
        s1 = wm_source(txt, f"https://g4{tag}.example/n", utc(0), marking=D.PUB, title="Сокращение")
        assert S3.psql(ingest_sql([s1], {})).returncode == 0
        time.sleep(1.2)
        s2 = wm_source(txt.replace(" ", "  ", 1), f"https://m.g4{tag}.example/n", utc(0), marking=CONF, title="Сокращение")
        if single:
            from datetime import datetime, timezone, timedelta
            rec = (datetime.now(timezone.utc) + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            pb = wm_publication(txt, f"https://g4{tag}.example/n", rec, marking=D.PUB, title="Сокращение")
            r_ = S3.psql(LD + "BEGIN;\nSELECT pg_sleep(2.3);\n" + pub_sql(pb) + "\n" + body_of([s2]) + "\nCOMMIT;")
            return r_.returncode != 0, first_err(r_)[:70]
        th_, o_ = bg(LD + "BEGIN;\n" + body_of([s2]) + "\nSELECT pg_sleep(3);\nCOMMIT;")
        time.sleep(1.6)
        pb = wm_publication(txt, f"https://g4{tag}.example/n", utc(0), marking=D.PUB, title="Сокращение")   # recorded_at after the rendition
        r2_ = S3.psql(LD + "BEGIN;\n" + pub_sql(pb) + "\nCOMMIT;")
        th_.join()
        return not (o_[0].returncode == 0 and r2_.returncode == 0), first_err(r2_)[:70]
    ok_a, why_a = pub_case("a", False)
    ok_b, why_b = pub_case("b", True)
    held("G4", ok_a and ok_b, "открытая публикация и закрытый рендеринг её текста, полученный к её recorded_at: гонкой и одной транзакцией — "
         "не фиксируются оба (S11R-07)", f"гонка: {why_a}; одна транзакция: {why_b}")
    # a claim with a tenant predicate and the removal of that predicate in the same second (S11R-08)
    from schema_s9 import write_schema
    from s9_tests import sd, claim as wk_claim, S10 as WK_TEXT
    cur = json.loads(S3.psql("SELECT to_jsonb(k) FROM ac.class_defs k WHERE class_id = 'sdf_whale_species' ORDER BY version DESC LIMIT 1").stdout)
    S3.psql("DO $$ BEGIN CREATE ROLE ac_s11_modeler LOGIN IN ROLE ac_modeler; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
    while time.time() % 1 > 0.15:
        time.sleep(0.01)
    cx = wk_claim("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": "31", "unit": "m"}}, "Длина синего кита достигает 30 метров")
    r_c = S3.psql(ingest_sql([cx], {}))
    body = {k: v for k, v in cur.items() if k in ("root_type", "name", "parent_class_id", "is_abstract") and v is not None}
    r_s = write_schema([sd("ClassDef", "sdf_whale_species", cur["version"] + 1, "REMOVE_ATTRIBUTE", attributes=[], **body)], user="ac_s11_modeler")
    same_second = S3.psql(f"SELECT count(*) FROM ac.class_defs k, ac.claims c WHERE k.class_id = 'sdf_whale_species' AND k.version = {cur['version'] + 1} "
                          f"AND c.claim_id = '{cx['claim_id']}' AND k.recorded_at <= c.recorded_at").stdout.strip()
    held("G5", r_c.returncode == 0 and same_second == "0",
         "утверждение с предикатом tenant и удаление этого предиката из схемы в ту же секунду: версия схемы не встаёт в секунду "
         "утверждения (S11R-08)", f"утверждение: {first_err(r_c)[:30]}; версия схемы: {first_err(r_s)[:80]}")

    # ---- round 2 of the review: neighbours of the same races, deadlocks of legitimate work
    import regression_s22 as R22
    PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}

    def person(eid, sur, bd):
        return {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
                "identity": {"surname": sur, "given_name": "Пётр", "birth_date": bd}, "display_name": sur, "created_at": utc(0), "marking": PD}
    assert S3.psql(ingest_sql([person("ent_g6_p", "Уточнин", "1980-01-01"), person("ent_g6_q", "Выживин", "1981-02-02"),
                               org("ent_g7_x", "ООО «Проверяемое»", inn=D._inn10(782000001)), org("ent_g7_y", "ООО «Выжившее»", inn=D._inn10(782000002)),
                               org("ent_g7_x2", "ООО «П2»", inn=D._inn10(782000011)), org("ent_g7_y2", "ООО «В2»", inn=D._inn10(782000012)),
                               org("ent_g8_main", "ООО «Альфа-Сервис» (G8)", ogrn=D._ogrn(30_000_000_021)),
                               org("ent_g8_d1", "Дубль 1", inn=D._inn10(781000001)), org("ent_g8_d2", "Дубль 2", inn=D._inn10(781000002))], {})).returncode == 0
    time.sleep(1.2)
    dq = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_g6", "project_id": "prj_dossier", "decision": "QUALIFY",
          "entity_id": "ent_g6_p", "disambiguator": "tot-samyj", "decided_by": "usr_analyst1", "decided_at": utc(0)}
    o1, r2 = both(merge("ent_g6_p", "ent_g6_q"), LD + "BEGIN;\nINSERT INTO ac.identity_decisions VALUES ('idd_g6','prj_dossier','QUALIFY','ent_g6_p',NULL,"
                  f"'disambiguator','tot-samyj','usr_analyst1',now(),{Q(dq)});\nCOMMIT;")
    held("G6", o1.returncode == 0 and r2.returncode != 0 and "IDENTITY_DECISION_INVALID" in r2.stderr,
         "гонка: уточнение (QUALIFY) сущности, которую в этот момент сливают, — отвергнуто (S11R2-02)", first_err(r2)[:80])
    mk = lambda kid, e: R22.new_check(kid, "TENDERS_ONLY").replace("ent_k_developer", e)  # noqa: E731
    o1, r2 = both(merge("ent_g7_x", "ent_g7_y"), LD + "BEGIN;\n" + mk("chk_g7", "ent_g7_x") + "\nCOMMIT;")
    r3 = S3.psql(LD + "BEGIN;\n" + mk("chk_g7b", "ent_g7_x2") + "\nCOMMIT;")
    r4 = S3.psql(LD + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_g7_y2' WHERE entity_id = 'ent_g7_x2';")
    r5 = S3.psql(LD + "UPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = 'ent_g7_x2';")
    r6 = S3.psql(LD + "BEGIN;\nUPDATE ac.checks SET status = 'CANCELLED', body = body || jsonb_build_object('status', 'CANCELLED', 'cancelled_at', "
                 "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')) WHERE check_id = 'chk_g7b';\nCOMMIT;")
    time.sleep(1.1)
    r7 = S3.psql(LD + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_g7_y2' WHERE entity_id = 'ent_g7_x2';")
    held("G7", o1.returncode == 0 and "CHECK_SUBJECT_INVALID" in r2.stderr and r3.returncode == 0 and "CHECK_SUBJECT_INVALID" in r4.stderr
         and "CHECK_SUBJECT_INVALID" in r5.stderr and r6.returncode == 0 and r7.returncode == 0,
         "субъект открытой Проверки: гонка «слияние и открытие Проверки» — Проверка отвергнута; слияние и вывод из употребления субъекта "
         "открытой Проверки отвергнуты; после отмены Проверки слияние проходит (S11R2-03)",
         f"гонка: {first_err(r2)[:50]}; слияние: {first_err(r4)[:50]}; вывод: {first_err(r5)[:40]}; отмена: {first_err(r6)[:40]}; после отмены: {first_err(r7)[:30]}")

    def pair(a_, b_):
        ta, oa = bg(a_)
        tb, ob = bg(b_)
        ta.join()
        tb.join()
        return oa[0], ob[0]
    m_row = {"ogrn": D._ogrn(30_000_000_021)}
    g8 = [dict(cg, subject="ent_g8_main", object={"literal": {"type": "STRING", "value": f"адрес {n}"}}) for n in (1, 2)]

    def claim_tx(c0, tail):
        c = dict(c0, recorded_at=utc(0))
        from jcs import digest
        c["claim_id"] = "clm:sha256:" + digest(c)
        return LD + "BEGIN;\n" + body_of([c]) + "\nSELECT pg_sleep(1.5);\n" + tail(c) + "\nCOMMIT;"
    ra, rb = pair(claim_tx(g8[0], lambda c: "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_g8_main' WHERE entity_id = 'ent_g8_d1';"),
                  claim_tx(g8[1], lambda c: "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_g8_main' WHERE entity_id = 'ent_g8_d2';"))
    held("G8", ra.returncode == 0 and rb.returncode == 0,
         "законная: два сеанса пишут по утверждению об одной сущности и в той же транзакции вливают в неё по дублю — оба фиксируются, "
         "взаимной блокировки нет (S11R2-05)", f"A: {first_err(ra)[:50]} | B: {first_err(rb)[:50]}")
    time.sleep(1.1)

    def check_tx(c0, kid):
        return claim_tx(c0, lambda c: R22.new_check(kid, "FULL").replace("ent_k_developer", "ent_g8_main")
                        + f"\nINSERT INTO ac.check_findings VALUES ('{kid}', 'CORPORATE', 'FOUND', 'LOW');\n"
                        f"INSERT INTO ac.check_finding_claims VALUES ('{PRJ}', '{kid}', 'CORPORATE', '{c['claim_id']}');")
    g9 = [dict(x, object={"literal": {"type": "STRING", "value": x["object"]["literal"]["value"] + " (G9)"}}) for x in g8]
    ra, rb = pair(check_tx(g9[0], "chk_g9_a"), check_tx(g9[1], "chk_g9_b"))
    dead = "deadlock" in ra.stderr + rb.stderr
    held("G9", not dead and ra.returncode == 0 and rb.returncode == 0, "законная: два сеанса: утверждение о сущности и строка своей Проверки с ним в одной транзакции — оба фиксируются, взаимной блокировки нет (S11R2-05)",
         f"A: {first_err(ra)[:70]} | B: {first_err(rb)[:70]}")

    # ---- round 3 of the review: two merges into one target (S11R3-01, S11R3-03)
    def person2(eid, inn):
        return {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
                "identity": {"surname": "Тёзкин", "given_name": "Иван", "inn": inn}, "display_name": "Тёзкин", "created_at": utc(0), "marking": PD}
    assert S3.psql(ingest_sql([org("ent_m1_a", "ООО «Цель»", inn=D._inn10(783000001)), org("ent_m1_c", "ООО «Первый»", inn=D._inn10(783000002)),
                               org("ent_m1_d", "ООО «Второй»", inn=D._inn10(783000003))], {})).returncode == 0
    rp = S3.psql(ingest_sql([person2("ent_m2_a", D._inn12(5012000001)), person2("ent_m2_c", D._inn12(5012000002)),
                             person2("ent_m2_d", D._inn12(5012000003))], {}))
    time.sleep(1.2)
    dd = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_m1", "project_id": PRJ, "decision": "DISTINCT",
          "entity_ids": ["ent_m1_c", "ent_m1_d"], "decided_by": "usr_analyst1", "decided_at": utc(0)}
    assert S3.psql(LD + f"BEGIN;\nINSERT INTO ac.identity_decisions VALUES ('idd_m1',{Q(PRJ)},'DISTINCT','ent_m1_c','ent_m1_d',NULL,NULL,"
                   f"'usr_analyst1',{Q(dd['decided_at'])},{Q(dd)});\nCOMMIT;").returncode == 0
    time.sleep(1.2)
    o1, r2 = both(merge("ent_m1_c", "ent_m1_a"), LD + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_m1_a' WHERE entity_id = 'ent_m1_d';")
    held("G10", o1.returncode == 0 and "IDENTITY_DECISION_INVALID" in r2.stderr,
         "гонка: решено «различны» о C и D; C и D параллельно сливают в одну цель — второе слияние отвергнуто (S11R3-01)", first_err(r2)[:80])
    o1, r2 = both(merge("ent_m2_c", "ent_m2_a"), LD + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_m2_a' WHERE entity_id = 'ent_m2_d';")
    held("G11", rp.returncode == 0 and o1.returncode == 0 and r2.returncode == 0,
         "законная: два тёзки (один слабый ключ, разные ИНН) параллельно сливаются в одну цель — оба слияния проходят (S11R3-03)",
         f"мир: {first_err(rp)[:40]}; 1: {first_err(o1)[:40]} | 2: {first_err(r2)[:70]}")

    # ---- currency
    cdev = claim(ev)
    assert S3.psql(ingest_sql([cdev], {})).returncode == 0
    attack("K01", "читатель вызывает ac.row_currency напрямую",
           f"SELECT ac.row_currency('{T}', '{sid}', '{{}}'::jsonb, '{{}}'::jsonb, now());", ["permission denied"], user="ac_rd_cs")
    attack("K02", "читатель вызывает ac.evidence_json напрямую", f"SELECT ac.evidence_json('{cdev['claim_id']}', now());", ["permission denied"], user="ac_rd_cs")
    cur = json.loads(S3.psql(f"SELECT ac.evidence_json('{cdev['claim_id']}', now());").stdout)[0]["currency"]
    held("K03", "value" not in json.dumps(cur) and set(cur) <= {"status", "latest", "changed_columns"}, "в «актуальности строки» нет значений ячеек", json.dumps(cur, ensure_ascii=False)[:120])

    # a version marked above the claim in the middle of the chain (S11R2-06)
    cols0 = dv.columns
    k1, rk1 = new_version("a-h1")
    _, bk1 = D.load_rows(T, k1.source_id, copy_file(k1), cols0)
    time.sleep(1.1)
    ck = claim(k1.evidence([OGRN_DEV], ["address"]))
    assert rk1.returncode == 0 and bk1 is None and S3.psql(ingest_sql([ck], {})).returncode == 0
    from jcs import canon
    k2 = demo_registry(previous=k1.source_id)
    k2.manifest["version_label"] = "a-h2"
    k2.manifest_bytes = canon(k2.manifest).encode("utf-8")
    k2.source_id = "src:sha256:" + hashlib.sha256(k2.manifest_bytes).hexdigest()
    _, rk2 = D.register(k2.manifest_bytes, T, "закрытая версия", marking={"level": "RESTRICTED", "categories": []})
    k3, rk3 = new_version("a-h3", rows=[dict(REGISTRY_ROWS[0], address="г. Москва, ул. Новая, д. 9")] + REGISTRY_ROWS[1:], previous=k2.source_id)
    _, bk3 = D.load_rows(T, k3.source_id, copy_file(k3), cols0)
    assert rk2.returncode == 0 and rk3.returncode == 0 and bk3 is None
    cur = json.loads(S3.psql(f"SELECT ac.evidence_json('{ck['claim_id']}', now());").stdout)[0]["currency"]
    held("K04", cur.get("status") == "CHANGED" and cur["latest"]["version_label"] == "a-h3" and k2.source_id not in json.dumps(cur),
         "закрытая версия в середине цепочки: ответ — по следующей доступной версии, закрытая не названа (S11R2-06)", json.dumps(cur, ensure_ascii=False)[:140])

    print(f"\nattacks={len(BAD)} findings={sum(BAD)}")
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

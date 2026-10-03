#!/usr/bin/env python3
"""S11 acceptance (cycle 11): identity of the row's subject, «актуальность строки», isolation of guarded writes.

S11-01 whom a row is about in a project (ac.dataset_subject): NONE / ONE / CONFLICT / SEVERAL_TYPES — by the owners the
       reader may see; a claim that quotes an identifier owned by another entity of the project is ACCEPTED and its
       evidence is shown with subject_conflict (the validator: warning ROW_SUBJECT_CONFLICT) until the two are merged;
       identifiers of a row are compared in the normal form of entity keys.
S11-02 «актуальность строки»: what became of the row a claim rests on in the latest loaded version of the dataset —
       the versions that follow by «previous»: CURRENT, NOT_LOADED, UNCHANGED, CHANGED (which quoted columns),
       CHANGED_ELSEWHERE, ABSENT, INCOMPARABLE, BRANCHED; time travel; nothing beyond the marking of the claim (a column
       marked higher in the new version is not compared; a higher-marked version does not exist for the projection).
S11-03 every table of the core refuses writes outside READ COMMITTED (the class of S10R-20).
S11-04 the race that DID commit two persons with one name and birth date under REPEATABLE READ before this cycle —
       on every pair of isolation levels at most one is committed.
S11-05 the warning of the validator and the flag of the database agree on every vector of the cycle.
S11-PARITY the vectors of cycle 11 into a fresh database without the validator: refused ⇔ refused.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s11_tests.py [--no-parity]
"""
import copy
import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
from jcs import digest, canon  # noqa: E402
from vectors import build  # noqa: E402
from fixtures import REGISTRY_ROWS, REGISTRY_COLUMNS, OGRN_DEV, demo_registry  # noqa: E402
from ingest_s4 import ingest_sql, utc, q as Q0  # noqa: E402
import s3_tests as S3  # noqa: E402
import dataset_s10 as D  # noqa: E402
import s10_tests as T10  # noqa: E402
from s10_tests import check, sql1, js, err, first_err, copy_file, new_version, claim, T, PRJ, RES  # noqa: E402

CONF_CS = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}
CONF_PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
ALFA, BETA, GAMMA, TRUB = REGISTRY_ROWS[2], REGISTRY_ROWS[3], REGISTRY_ROWS[4], REGISTRY_ROWS[1]


def org(eid, name, marking=CONF_CS, **ids):
    return {"kind": "Entity", "entity_id": eid, "project_id": PRJ, "entity_type": "ORGANIZATION", "status": "ACTIVE",
            "identity": {"name": name, "jurisdiction": "RU", **ids}, "display_name": name, "created_at": utc(0), "marking": marking}


def key(v):
    return "'" + json.dumps([v]) + "'"


def currency(c):
    ev = json.loads(sql1(f"SELECT ac.evidence_json('{c['claim_id']}', now());"))
    return ev[0]["currency"]


def main():
    if "--no-parity" not in sys.argv:
        T10.parity("S", "S11-PARITY", "11")
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    sql1(S3.SETUP)
    ds, _, _ = build()
    c50 = next(x for x in ds["records"] if x["kind"] == "Claim" and x["evidence"][0].get("kind") == "ROW")
    dv = demo_registry()
    sid = dv.source_id
    cols = dv.columns
    not_loaded = currency(c50)

    _, bad = D.load_rows(T, sid, copy_file(dv), cols)
    assert bad is None, first_err(bad)

    # S11-01 the subject of a row in the project
    PD_CS = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}
    a = org("ent_k_beta_a", "ООО «Бета»", ogrn=BETA["ogrn"])
    b = org("ent_k_beta_b", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
    hidden = org("ent_k_trub_pd", "АО «Трубопроводстрой»", marking=PD_CS, ogrn=TRUB["ogrn"])
    g1 = org("ent_k_gamma_a", "ООО «Гамма»", ogrn=GAMMA["ogrn"])
    g2 = org("ent_k_gamma_pd", "ООО «Гамма» (закрытая, по ИНН)", marking=PD_CS, inn=GAMMA["inn"])
    assert S3.psql(ingest_sql([a, b, hidden, g1, g2], {})).returncode == 0
    time.sleep(1.1)
    subj = lambda row, user="ac_rd_cs": js(f"SELECT ac.dataset_subject('{PRJ}', '{sid}', {key(row['ogrn'])});", user)  # noqa: E731
    s_dev, s_none, s_conf = subj(REGISTRY_ROWS[0]), subj(ALFA), subj(BETA)
    s_hid, s_full = subj(TRUB), subj(TRUB, "ac_rd_full")           # the only owner is above the first reader's clearance
    s_half, s_half_full = subj(GAMMA), subj(GAMMA, "ac_rd_full")   # one of the two owners is above it (S11R-10)
    ev_addr = dv.evidence([BETA["ogrn"]], ["address"])
    ev_inn = dv.evidence([BETA["ogrn"]], ["address", "inn"])
    c_conf = claim(ev_inn, subj="ent_k_beta_a", address=BETA["address"])
    w1 = S3.psql(ingest_sql([c_conf], {}))
    flag = lambda c: json.loads(sql1(f"SELECT ac.evidence_json('{c['claim_id']}', now());"))[0].get("subject_conflict")  # noqa: E731
    f_before = flag(c_conf)
    c_g = claim(dv.evidence([GAMMA["ogrn"]], ["name", "inn", "address"]), subj="ent_k_gamma_a", address="x")   # the other owner is above the claim
    c_g["object"] = {"literal": {"type": "STRING", "value": "x"}}
    sql1("SET SESSION AUTHORIZATION ac_loader; UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_beta_a' WHERE entity_id = 'ent_k_beta_b';")
    time.sleep(1.1)
    f_after, s_one = flag(c_conf), subj(BETA)
    check("S11-01", s_dev["status"] == "ONE" and [o["entity_id"] for o in s_dev["owners"]] == ["ent_k_developer"] and s_none["status"] == "NONE"
          and s_conf["status"] == "CONFLICT" and {o["entity_id"] for o in s_conf["owners"]} == {"ent_k_beta_a", "ent_k_beta_b"}
          and s_hid["status"] == "NONE" and s_hid["owners"] == [] and [o["entity_id"] for o in s_full["owners"]] == ["ent_k_trub_pd"]
          and s_half["status"] == "ONE" and [o["entity_id"] for o in s_half["owners"]] == ["ent_k_gamma_a"] and s_half_full["status"] == "CONFLICT"
          and w1.returncode == 0 and f_before is True and f_after is None
          and s_one["status"] == "ONE" and [o["entity_id"] for o in s_one["owners"]] == ["ent_k_beta_a"],
          "о ком строка в проекте: никто / одна сущность / конфликт (ОГРН у одной, ИНН у другой) — по владельцам, видимым читателю "
          "(закрытый второй владелец не превращает ONE в CONFLICT); утверждение с чужим ИНН принято и показано с subject_conflict, "
          "после слияния флаг снят",
          f"девелопер: {s_dev['status']}; Альфа: {s_none['status']}; Бета: {s_conf['status']} -> после слияния {s_one['status']}; "
          f"Гамма читателю без ПД: {s_half['status']}, с ПД: {s_half_full['status']}; флаг до слияния {f_before}, после {f_after}")

    # S11-02 currency of the row
    assert S3.psql(ingest_sql([org("ent_k_alfa2", ALFA["name"] + " (S11)", ogrn=ALFA["ogrn"])], {})).returncode == 0
    time.sleep(1.1)
    c_dev = claim(dv.evidence([OGRN_DEV], ["address"]))
    c_beta = claim(ev_addr, subj="ent_k_beta_a", address=BETA["address"])
    c_alfa = claim(dv.evidence([ALFA["ogrn"]], ["address"]), subj="ent_k_alfa2", address=ALFA["address"])
    c_trub = claim(dv.evidence([TRUB["ogrn"]], ["address"]), subj="ent_k_trub_pd", address=TRUB["address"],
                   marking=PD_CS)
    r1 = S3.psql(ingest_sql([c_dev, c_beta, c_alfa, c_trub], {}))
    assert r1.returncode == 0, first_err(r1)
    cur1 = currency(c_dev)
    before_v2 = sql1("SELECT clock_timestamp()")
    rows2 = [dict(REGISTRY_ROWS[0], address="Московская обл., г. Заречный, ул. Новая, д. 5"), dict(TRUB, director="Новый Директор Иванович"),
             BETA, GAMMA]                                                             # «Альфа-Сервис» исключена из реестра
    v2, r2 = new_version("2026-10-01", rows=rows2, previous=sid)
    assert r2.returncode == 0, first_err(r2)
    still = currency(c_dev)                                                           # v2 registered, its rows are not loaded yet
    _, bad = D.load_rows(T, v2.source_id, copy_file(v2), cols)
    assert bad is None, first_err(bad)
    got = {n: currency(c) for n, c in (("dev", c_dev), ("beta", c_beta), ("alfa", c_alfa), ("trub", c_trub))}
    past = json.loads(sql1(f"SELECT ac.evidence_json('{c_dev['claim_id']}', '{before_v2}');"))[0]["currency"]
    dossier = js(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer');", "ac_rd_cs")
    in_dossier = sorted({e["currency"]["status"] for f in S3.facts_of(dossier) for c in f["claims"] + f.get("other_claims", [])
                         for e in c["evidence"] if e.get("currency")})
    # v3: the address column is now personal data; the address of the developer changed again
    cols3 = copy.deepcopy(REGISTRY_COLUMNS)
    next(c for c in cols3 if c["name"] == "address")["marking"] = CONF_PD
    v3, r3 = new_version("2026-10-02", rows=[dict(rows2[0], address="г. Москва, ул. Третья, д. 3")] + rows2[1:], columns=cols3, previous=v2.source_id)
    _, bad = D.load_rows(T, v3.source_id, copy_file(v3), cols3)
    assert r3.returncode == 0 and bad is None, first_err(r3 if r3.returncode else bad)
    masked = currency(c_dev)
    # v4: a version whose source is marked above the claim
    dv4 = demo_registry(rows=rows2, previous=v3.source_id)
    dv4.manifest["version_label"] = "2026-10-03"
    from jcs import canon
    import hashlib
    dv4.manifest_bytes = canon(dv4.manifest).encode("utf-8")
    dv4.source_id = "src:sha256:" + hashlib.sha256(dv4.manifest_bytes).hexdigest()
    _, r4 = D.register(dv4.manifest_bytes, T, "Реестр, закрытая версия", marking={"level": "RESTRICTED", "categories": []})
    _, bad = D.load_rows(T, dv4.source_id, copy_file(dv4), cols)
    assert r4.returncode == 0 and bad is None, first_err(r4 if r4.returncode else bad)
    restricted = currency(c_dev)
    # two followers of one version: «the latest» is not defined; a follower with another key: incomparable
    va, ra = new_version("ветвь А", rows=rows2, previous=v3.source_id)
    vb, rb = new_version("ветвь Б", rows=rows2[:2], previous=v3.source_id)
    branched = currency(c_dev)
    kcols = copy.deepcopy(REGISTRY_COLUMNS)
    w1v, _ = new_version("K1")
    cw = claim(w1v.evidence([OGRN_DEV], ["address"]))
    w2v, rw2 = new_version("K2", key=("inn",), previous=w1v.source_id)
    _, badw = D.load_rows(T, w2v.source_id, copy_file(w2v), cols)
    time.sleep(1.1)
    cw = claim(w1v.evidence([OGRN_DEV], ["address"]))
    assert S3.psql(ingest_sql([cw], {})).returncode == 0 and rw2.returncode == 0 and badw is None
    incomparable = currency(cw)
    check("S11-02", not_loaded == {"status": "CURRENT"} and cur1["status"] == "CURRENT" and still["status"] == "NOT_LOADED"
          and got["dev"]["status"] == "CHANGED" and got["dev"]["changed_columns"] == ["address"] and got["dev"]["latest"]["version_label"] == "2026-10-01"
          and got["beta"]["status"] == "UNCHANGED" and got["alfa"]["status"] == "ABSENT" and got["trub"]["status"] == "CHANGED_ELSEWHERE"
          and past["status"] == "CURRENT" and "CHANGED" in in_dossier
          and masked["status"] == "CHANGED_ELSEWHERE" and restricted == masked
          and branched == {"status": "BRANCHED"} and incomparable["status"] == "INCOMPARABLE",
          "актуальность строки: нет следующих версий — CURRENT; следующая версия без строк — NOT_LOADED; в новой версии: адрес изменён — CHANGED [address], "
          "строка та же — UNCHANGED, исключена — ABSENT, изменился только скрытый руководитель — CHANGED_ELSEWHERE; на прошлый момент — "
          "CURRENT; колонка, ставшая ПД, по значению не сравнивается; версии выше маркировки утверждения для проекции нет; "
          "две следующие версии у одной — BRANCHED; другой ключ — INCOMPARABLE",
          f"{ {k: v['status'] for k, v in got.items()} }; на прошлый момент {past['status']}; в досье {in_dossier}; "
          f"адрес стал ПД: {masked['status']}; после закрытой версии: {restricted['status']}; ветви: {branched['status']}; другой ключ: {incomparable['status']}")

    # S11-06 the flag of the conflict by the clearance of the READER (S11R2-04); a version marked above the claim in the
    # MIDDLE of the chain (S11R2-06); identifiers of a row in the normal form: the validator == the database (S11R2-01, -09)
    c_gam = claim(dv.evidence([GAMMA["ogrn"]], ["address", "inn"]), subj="ent_k_gamma_a", address=GAMMA["address"])
    rg = S3.psql(ingest_sql([c_gam], {}))
    assert rg.returncode == 0, first_err(rg)

    def dossier_flag(user):
        dz = js(f"SELECT ac.dossier('{PRJ}', 'ent_k_gamma_a');", user)
        return sorted({str(e.get("subject_conflict")) for f in S3.facts_of(dz) for c in f["claims"] + f.get("other_claims", [])
                       for e in c["evidence"] if e.get("row_sha256")})
    fl_cs, fl_full = dossier_flag("ac_rd_cs"), dossier_flag("ac_rd_full")

    def closed_version(label, rows, previous):
        dvx = demo_registry(rows=rows, previous=previous)
        dvx.manifest["version_label"] = label
        dvx.manifest_bytes = canon(dvx.manifest).encode("utf-8")
        dvx.source_id = "src:sha256:" + hashlib.sha256(dvx.manifest_bytes).hexdigest()
        _, rr = D.register(dvx.manifest_bytes, T, "Реестр, закрытая версия " + label, marking={"level": "RESTRICTED", "categories": []})
        _, bb = D.load_rows(T, dvx.source_id, copy_file(dvx), cols)
        assert rr.returncode == 0 and bb is None, first_err(rr if rr.returncode else bb)
        return dvx
    h1, rh1 = new_version("H1")
    _, bh1 = D.load_rows(T, h1.source_id, copy_file(h1), cols)
    time.sleep(1.1)
    ch = claim(h1.evidence([OGRN_DEV], ["address"]))
    assert rh1.returncode == 0 and bh1 is None and S3.psql(ingest_sql([ch], {})).returncode == 0
    h2 = closed_version("H2", rows2, h1.source_id)
    mid_only = currency(ch)                                        # only a closed follower: nothing is said
    h3, rh3 = new_version("H3", rows=rows2, previous=h2.source_id)
    _, bh3 = D.load_rows(T, h3.source_id, copy_file(h3), cols)
    assert rh3.returncode == 0 and bh3 is None
    through = currency(ch)
    import validator as VAL0
    import random
    rnd = random.Random(11)
    alphabet = ["0", "1", "7", "a", "A", "Я", "я", " ", "-", "_", ".", "/", ":", "\u00df", "\uff11", "\U0001E030", "\U0001E08F", "\u0378", "\n", "\u200b", "İ"]
    pairs = [(sch, "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8))))
             for sch in ("lei", "ru.inn", "ru.ogrn", "ru.ogrnip", "vin", "imo", "ru.cadastral", "x.reg") for _ in range(400)]
    pairs += [("lei", "\U0001E030" + "1"), ("lei", "-"), ("lei", ""), ("ru.cadastral", "50:12:0101001:0245\n"), ("ru.cadastral", "050:012:1:2")]
    db_ids = json.loads(sql1("SELECT jsonb_agg(ac.row_id(x->>0, x->>1) ORDER BY o) FROM jsonb_array_elements("
                             + Q0(json.dumps(pairs, ensure_ascii=False)) + "::jsonb) WITH ORDINALITY a(x, o)"))
    val_ids = ["|".join(VAL0.row_id(sch, v)) for sch, v in pairs]
    id_diff = [(p_, a_, b_) for p_, a_, b_ in zip(pairs, val_ids, db_ids) if a_ != b_]
    cn = sql1("SELECT ac.row_id('lei', U&'\\+01E030' || '1') = 'lei|' || U&'\\+01E030' || '1'")
    check("S11-06", fl_cs == ["None"] and fl_full == ["True"]
          and mid_only == {"status": "CURRENT"} and through["status"] == "CHANGED" and through["latest"]["version_label"] == "H3"
          and not id_diff and cn == "t",
          "флаг конфликта — по допуску читателя: читатель без ПД флага не видит, читатель с ПД видит (вторая сущность закрыта ПД); "
          "закрытая версия в середине цепочки проходится без упоминания, ответ — по следующей доступной; идентификатор строки "
          "приводится валидатором и базой одинаково, значение с неназначенным символом Юникода — как записано",
          f"флаг: без ПД {fl_cs}, с ПД {fl_full}; только закрытая следующая: {mid_only['status']}; через закрытую: {through['status']} "
          f"{through.get('latest', {}).get('version_label')}; пар идентификаторов {len(pairs)}, расхождений {len(id_diff)} {id_diff[:2]}")

    # S11-03 every table of the core refuses writes outside READ COMMITTED
    tables = sql1("SELECT string_agg(n.nspname || '.' || c.relname, ' ' ORDER BY 1) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                  "WHERE n.nspname IN ('ac', 'ac_trust') AND c.relkind = 'r'").split()
    bad_tables = []
    for lv in ("REPEATABLE READ", "SERIALIZABLE"):
        out = S3.psql("\n".join(f"BEGIN ISOLATION LEVEL {lv}; DO $$ BEGIN DELETE FROM {t} WHERE false; RAISE NOTICE 'OPEN %', '{t}'; "
                                f"EXCEPTION WHEN check_violation THEN IF SQLERRM NOT LIKE 'ISOLATION_LEVEL_UNSUPPORTED%' THEN RAISE; END IF; END $$; ROLLBACK;"
                                for t in tables))
        bad_tables += [ln for ln in out.stderr.splitlines() if "OPEN" in ln or "ERROR" in ln]
    rc_ok = S3.psql("\n".join(f"BEGIN; DELETE FROM {t} WHERE false; ROLLBACK;" for t in tables))
    check("S11-03", len(tables) > 40 and not bad_tables and rc_ok.returncode == 0,
          "каждая таблица ядра отвергает запись в REPEATABLE READ и SERIALIZABLE; в READ COMMITTED тот же оператор проходит",
          f"таблиц {len(tables)}, открытых {len(bad_tables)} {bad_tables[:3]}; READ COMMITTED: {first_err(rc_ok)}")

    # S11-04 the race of two persons with one name and birth date
    def race(level_a, level_b, tag, pause_a, pause_b, gap):
        out = []

        def run(eid, lv, pause):
            rec = {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
                   "identity": {"surname": "Гонкин" + tag, "given_name": "Пётр", "birth_date": "1980-01-01"}, "display_name": "Гонкин Пётр",
                   "created_at": utc(0), "marking": CONF_PD}
            s = ingest_sql([rec], {}).replace("BEGIN;", f"BEGIN ISOLATION LEVEL {lv};\nSELECT 1;", 1).replace("COMMIT;", f"SELECT pg_sleep({pause});\nCOMMIT;")
            out.append(S3.psql(s).returncode)
        th = [threading.Thread(target=run, args=("ent_race_a" + tag, level_a, pause_a)), threading.Thread(target=run, args=("ent_race_b" + tag, level_b, pause_b))]
        th[0].start()
        time.sleep(gap)
        th[1].start()
        [x.join() for x in th]
        return sql1(f"SELECT count(*) FROM ac.entities WHERE entity_id IN ('ent_race_a{tag}', 'ent_race_b{tag}')")
    L = ("READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE")
    res = {}
    n = 0
    for la in L:
        for lb in L:
            for pa, pb, gap in ((2.0, 0.2, 0.5), (0.2, 0.2, 0.0)):
                n += 1
                res[f"{la[:4]}/{lb[:4]}/{gap}"] = race(la, lb, f"r{n}", pa, pb, gap)
    check("S11-04", all(v in ("0", "1") for v in res.values()) and res["READ/READ/0.5"] == "1",
          "гонка двух физлиц с одним ФИО и датой рождения на всех парах уровней изоляции (18 гонок): зафиксировано не больше одного",
          "зафиксировано: " + " ".join(f"{k}={v}" for k, v in res.items()))

    # S11-05 the warning of the validator == the flag of the database, on every vector of the cycle that both accept
    import validator as VAL
    from vectors import VECTORS
    import load_s1 as L1
    diff, n_warn, n_all = [], 0, 0
    for v in VECTORS:
        if v["id"][1] != "S" or v["expected"]:
            continue
        ds_v, tr_v, ct_v = build(v)
        rep = VAL.validate(ds_v, tr_v, ct_v)
        want = sorted(w["ref"] for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT")
        L1.psql(L1.DDL_ALL)
        L1.register_originals(ds_v, ct_v)
        r = L1.psql(L1.load_sql(ds_v, tr_v, ct_v))
        got = sorted(sql1("SELECT coalesce(string_agg(c.claim_id, ' '), '') FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) "
                          "JOIN ac.datasets d ON d.tenant_id = e.tenant_id AND d.source_id = e.source_id "
                          "WHERE e.kind = 'ROW' AND ac.row_subject_conflict(c, e.row_ev, d.manifest, now())").split())
        if r.returncode and T10.DB_STRICTER.get(v["id"], "-") in first_err(r):
            continue                               # the database refuses this world by a rule only it has (D8)
        n_all += 1
        n_warn += bool(want)
        if r.returncode or got != want:
            diff.append((v["id"], first_err(r)[:60], len(want), len(got)))
    check("S11-05", not diff and n_warn >= 5 and n_all > n_warn,
          "предупреждение валидатора ROW_SUBJECT_CONFLICT и флаг базы subject_conflict совпадают на каждом векторе цикла",
          f"векторов {n_all}, с конфликтом {n_warn}, расхождений {len(diff)} {diff[:3]}")
    L1.psql(L1.DDL_ALL)

    print("ALL PASS" if all(RES) else f"FAILED: {RES.count(False)}")
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())

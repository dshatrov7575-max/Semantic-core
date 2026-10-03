#!/usr/bin/env python3
"""Раунд 2. Дифференциальная проверка: отказ/приём валидатора и базы И предупреждение ROW_SUBJECT_CONFLICT против флага
базы ac.row_subject_conflict(now) на своих мирах (в т. ч. «другая» сущность с маркировкой выше утверждения).
Мир = эталонный мир снимка + случайные правки: какие идентификаторы у субъекта, какие колонки — subject набора, 0–2
«другие» сущности (проект, тип, какие идентификаторы строки несут, статус ACTIVE/RETIRED/MERGED в субъект или в третью
сущность, до/после утверждения, время создания до/в момент/после утверждения), какие колонки цитирует утверждение.
Каждый мир: validator.validate(...) и загрузка в чистую базу без валидатора (как S11-PARITY). Сравнивается отказ/приём.
Возобновляемо: результаты дописываются в out/a20_diff.jsonl, уже посчитанные номера пропускаются.
Usage: PGDATABASE=review11_r2d python3 b20_diff_flag.py [N=300]"""
import copy, json, random, sys
from pathlib import Path
from rv import *
import load_s1 as L
import vectors as V
from fixtures import world, finalize, PUB

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
OUT = Path(__file__).parent / "out" / "b20_diff.jsonl"
done = {json.loads(l)["n"] for l in OUT.read_text().splitlines()} if OUT.exists() else set()
LEI = "549300123456"
T_CLAIM = "2026-09-26T09:00:00Z"
BEFORE, AT, AFTER = "2026-09-05T12:00:00Z", T_CLAIM, "2026-09-27T12:00:00Z"
M_BEFORE, M_AT, M_AFTER = "2026-09-20T10:00:00Z", T_CLAIM, "2026-09-27T13:00:00Z"
BETA = REGISTRY_ROWS[3]


def make(n):
    rnd = random.Random(1100 + n)
    d = {"n": n}
    d["subj_ids"] = rnd.choice([["ogrn"], ["inn"], ["ogrn", "inn"], ["ogrn", "lei"], ["ogrn", "inn", "lei"]])
    d["lei_col"] = rnd.random() < 0.6
    pool = ["ogrn", "inn"] + (["lei"] if d["lei_col"] else [])
    d["subject"] = rnd.choice([[x] for x in pool] + [pool, pool[:2], pool[::-1]])
    d["quote"] = ["address"] + [x for x in ("inn", "lei") if x in pool and rnd.random() < 0.7]
    d["others"] = []
    free = [k for k in ("ogrn", "inn", "lei") if k not in d["subj_ids"]]          # ключи строки, которых у субъекта нет
    rnd.shuffle(free)
    for i in range(rnd.choice([0, 1, 1, 1, 2, 2])):
        own = rnd.random() < 0.8 and bool(free)
        prj = rnd.choice(["prj_compliance"] * 5 + ["prj_dossier"])
        typ = rnd.choice(["ORGANIZATION"] * 5 + ["MOVABLE_PROPERTY"])
        if prj == "prj_dossier" or typ == "MOVABLE_PROPERTY":
            ids = ["lei"] if "lei" in free else ["other_inn"]
            if "lei" in free:
                free.remove("lei")
            if ids == ["other_inn"] and (typ == "MOVABLE_PROPERTY" or any(o["ids"] == ["other_inn"] for o in d["others"])):
                continue
        elif own:
            ids = [free.pop()] + ([free.pop()] if free and rnd.random() < 0.3 else [])
        else:
            if any(o["ids"] == ["other_inn"] for o in d["others"]):
                continue
            ids = ["other_inn"]
        created = rnd.choice([BEFORE, BEFORE, AT, AFTER])
        changed = M_AFTER if created == AFTER else rnd.choice([M_AT, M_AFTER]) if created == AT else rnd.choice([M_BEFORE, M_AT, M_AFTER])
        d["others"].append({"id": f"ent_k_oth{i}", "project": prj, "type": typ, "ids": ids, "created": created, "hidden": rnd.random() < 0.25,
                            "status": rnd.choice(["ACTIVE", "ACTIVE", "RETIRED", "MERGED_SUBJ", "MERGED_SUBJ", "MERGED_THIRD"]), "changed": changed})
    return d


def pre_of(d):
    def f(W):
        dev = W["ent_k_developer"]["identity"]
        for k in ("ogrn", "inn"):
            if k not in d["subj_ids"]:
                dev.pop(k, None)
        if "lei" in d["subj_ids"]:
            dev["foreign_ids"] = [{"scheme": "lei", "value": LEI}]
        cols = V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"}) if d["lei_col"] else copy.deepcopy(REGISTRY_COLUMNS)
        rows = [dict(r, lei=LEI if i == 0 else None) for i, r in enumerate(REGISTRY_ROWS)] if d["lei_col"] else REGISTRY_ROWS
        V.regds(columns=cols, rows=rows, subject=tuple(d["subject"]))(W)
        need_third = any(o["status"] == "MERGED_THIRD" for o in d["others"])
        if need_third:
            V.add_entity("ent_k_third", "prj_compliance", "ORGANIZATION", {"name": "ООО «Третья»", "jurisdiction": "RU", "ogrn": BETA["ogrn"]}, CONF_CS)(W)
        for o in d["others"]:
            if o["type"] == "ORGANIZATION":
                ru = bool({"inn", "other_inn", "ogrn"} & set(o["ids"]))
                ident = {"name": ("ООО «Иная " if ru else "Other Ltd «") + o["id"][-1] + "»", "jurisdiction": "RU" if ru else "CY"}
                if "inn" in o["ids"]:
                    ident["inn"] = INN_DEV
                if "other_inn" in o["ids"]:
                    ident["inn"] = BETA["inn"]
                if "ogrn" in o["ids"]:
                    ident["ogrn"] = OGRN_DEV
                if "lei" in o["ids"]:
                    ident["foreign_ids"] = [{"scheme": "lei", "value": LEI}]
            else:
                ident = {"subtype": "OTHER", "description": "прицеп " + o["id"][-1],
                         "registration": {"scheme": "lei" if "lei" in o["ids"] else "ru.inn", "value": LEI if "lei" in o["ids"] else INN_DEV}}
            marking = ({"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]} if o.get("hidden") else CONF_CS) if o["project"] == "prj_compliance" else {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
            st = o["status"]
            if o["type"] != "ORGANIZATION" or o["project"] != "prj_compliance":
                st = "RETIRED" if st.startswith("MERGED") else st
            kw = {}
            if st == "RETIRED":
                kw = dict(status="RETIRED", changed=o["changed"])
            elif st == "MERGED_SUBJ":
                kw = dict(status="MERGED", merged_into="ent_k_developer", changed=o["changed"])
            elif st == "MERGED_THIRD":
                kw = dict(status="MERGED", merged_into="ent_k_third", changed=o["changed"])
            V.add_entity(o["id"], o["project"], o["type"], ident, marking, **kw)(W)
            W[o["id"]]["created_at"] = o["created"]
        V.rowev([OGRN_DEV], d["quote"])(W)
    return f


def run(d):
    vec = V.V("X", [], "diff", pre=pre_of(d))
    try:
        ds, tr, ct = V.build(vec)
    except Exception as ex:      # noqa: BLE001
        return dict(d, skip=f"build: {type(ex).__name__}: {ex}"[:150])
    rep = VAL.validate(ds, tr, ct)
    codes = rep.codes()
    msgs = [e.get("msg", "")[:70] for e in rep.errors]
    try:
        sql = L.load_sql(ds, tr, ct)
    except Exception as ex:      # noqa: BLE001
        return dict(d, val=codes, skip=f"load_sql: {type(ex).__name__}"[:150])
    assert L.psql(L.DDL_ALL).returncode == 0
    L.register_originals(ds, ct)
    r = L.psql(sql)
    dbmsg = first_err(r)[:160] if r.returncode else ""
    warn = sorted(w["ref"] for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT")
    flags = None
    if r.returncode == 0:
        flags = sorted(S3.psql("SELECT coalesce(string_agg(c.claim_id, ' '), '') FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) "
                               "JOIN ac.datasets d ON d.tenant_id = e.tenant_id AND d.source_id = e.source_id "
                               "WHERE e.kind = 'ROW' AND ac.row_subject_conflict(c, e.row_ev, d.manifest, now())").stdout.split())
    return dict(d, val=codes, val_msg=msgs[:3], db="REFUSED" if r.returncode else "ACCEPTED", db_msg=dbmsg,
                differ=bool(codes) != bool(r.returncode), warn=len(warn), flags=None if flags is None else len(flags),
                flag_differ=flags is not None and not codes and flags != warn)


with OUT.open("a") as fh:
    for n in range(N):
        if n in done:
            continue
        res = run(make(n))
        fh.write(json.dumps(res, ensure_ascii=False) + "\n")
        fh.flush()

rows = [json.loads(l) for l in OUT.read_text().splitlines()]
ok = [r for r in rows if "skip" not in r]
print(f"миров {len(rows)}, сравнено {len(ok)}, пропущено {len(rows) - len(ok)}")
print("валидатор принял / база приняла:", sum(1 for r in ok if not r["val"] and r["db"] == "ACCEPTED"))
print("оба отвергли:", sum(1 for r in ok if r["val"] and r["db"] == "REFUSED"))
diff = [r for r in ok if r["differ"]]
print("РАСХОЖДЕНИЙ отказ/приём:", len(diff))
for r in diff[:10]:
    print("  ", json.dumps({k: r[k] for k in ("n", "subj_ids", "subject", "quote", "others", "val", "val_msg", "db", "db_msg")}, ensure_ascii=False))
acc = [r for r in ok if not r["val"] and r["db"] == "ACCEPTED"]
print("принятых обоими:", len(acc), "| с предупреждением валидатора:", sum(1 for r in acc if r["warn"]), "| с флагом базы:", sum(1 for r in acc if r["flags"]))
fd = [r for r in acc if r["flag_differ"]]
hid = [r for r in fd if any(o.get("hidden") for o in r["others"])]
print("РАСХОЖДЕНИЙ предупреждение/флаг:", len(fd), "| из них в мире есть сущность с маркировкой выше утверждения:", len(hid), "| без такой:", len(fd) - len(hid))
for r in [x for x in fd if x not in hid][:10] + hid[:3]:
    print("  ", json.dumps({k: r[k] for k in ("n", "subj_ids", "subject", "quote", "others", "warn", "flags")}, ensure_ascii=False))

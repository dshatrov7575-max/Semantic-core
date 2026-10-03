#!/usr/bin/env python3
"""S10R: манифест разрешает 512 колонок и строки любой длины — что с этим делает база (широкая таблица, чтение, печать)."""
from common import *
from s10_tests import copy_file
import time, random
stamp = utc(0)
def load(dv):
    r = db_try([source_rec(dv)], commit=True); assert r.returncode == 0, first_err(r)
    return D.load_rows(T, dv.source_id, copy_file(dv), dv.columns)
print("== W1. Наборы шире 100 колонок: печать проходит, а чтение строки и доказательство от базы?")
for n in (100, 101, 512):
    cols = [{"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
            {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}] + \
           [{"name": "c%d" % i, "type": "INTEGER", "marking": PUB} for i in range(n - 2)]
    rows = [dict({"ogrn": OGRN_DEV, "address": REGISTRY_ROWS[0]["address"]}, **{"c%d" % i: i for i in range(n - 2)})]
    dv = DatasetVersion("dst_rev_wide", T, f"rev-a10 {n} колонок {stamp}", cols, ["ogrn"], rows, subject=("ogrn",))
    t, bad = load(dv)
    print(f"   {n} колонок: манифест принят, загрузка и печать:", "ок " + str(t) if bad is None else first_err(bad)[:150])
    r = psql(f"SELECT jsonb_object_keys(ac.dataset_row('{PRJ}', '{dv.source_id}', '[\"{OGRN_DEV}\"]')) LIMIT 1;", "ac_rd_full")
    print(f"      ac.dataset_row      ->", "ок" if r.returncode == 0 else first_err(r)[:140])
    r = psql(f"SELECT length(ac.dataset_evidence('{PRJ}', '{dv.source_id}', '[\"{OGRN_DEV}\"]', ARRAY['address'])::text);", "ac_rd_full")
    print(f"      ac.dataset_evidence ->", "ок, знаков " + r.stdout.strip() if r.returncode == 0 else first_err(r)[:140])
    time.sleep(1.1)
    ev = dv.evidence([OGRN_DEV], ["address"])
    print(f"      утверждение на строке (доказательство производителя, {len(canon(ev))} знаков): валидатор —", py_verdict(validate_with([source_rec(dv), mk_claim(ev)]))[:40],
          "| база —", verdict(db_try([mk_claim(ev)]))[:90])
print("== W2. Длинное значение в колонке ключа / идентификатора (строки не ограничены по длине): печать строит b-tree")
rnd = random.Random(7)
for what, keycol, ln in [("ключ — случайная строка 6000 знаков", "name", 6000), ("идентификатор (не ключ) — случайная строка 6000 знаков", "inn", 6000)]:
    rows = copy.deepcopy(REGISTRY_ROWS); rows[0][keycol] = "".join(rnd.choice("0123456789abcdefghijklmnopqrstuvwxyzАБВГДЕЖЗИКЛМНОП") for _ in range(ln))
    dv = relabel(demo_registry(rows=rows, key=("name",) if keycol == "name" else ("ogrn",), subject=("ogrn",)), f"rev-a10 {what} {stamp}")
    t, bad = load(dv)
    print(f"   {what}: манифест принят; печать ->", "ок" if bad is None else first_err(bad)[:170])
    time.sleep(1.1)
    ev = dv.evidence([rows[0]["name"]] if keycol == "name" else [OGRN_DEV], ["address", "ogrn"])
    print("      а утверждение на эту строку база принимает:", verdict(db_try([mk_claim(ev)]))[:60])

#!/usr/bin/env python3
"""Цена «актуальности строки» в досье на наборе 200 тыс. строк (после `dataset_s10.py measure 200000` в этой базе).
Меряется: время ac.evidence_json на одно доказательство-строку; число вызовов функций на одно досье (track_functions);
то же, когда последняя версия порезана на мелкие файлы (64 строки, вариант (б) исследования о дельтах: большой манифест).
Usage: PGDATABASE=review11_m python3 a43_currency_cost.py <каталог measure>"""
import json, sys, time
from pathlib import Path
from rv import *

out = Path(sys.argv[1])
N = 200000
m1 = json.loads((out / "manifest.json").read_text())
sid1 = "src:sha256:" + __import__("hashlib").sha256((out / "manifest.json").read_bytes()).hexdigest()
assert one(f"SELECT count(*) FROM ac.dataset_tables WHERE source_id = '{sid1}' AND sealed_at IS NOT NULL") == "1"
i = 12345
rows = list(D.synthetic_registry(N))
ogrn, inn = rows[i][0], rows[i][1]
e = org("ent_r_m1", "ООО «Синтетика»", ogrn=ogrn)
r = psql(ingest_sql([e], {}))
assert r.returncode == 0 or "duplicate" in r.stderr, first_err(r)
time.sleep(1.2)
ev = json.loads(one(f"SELECT ac.dataset_evidence('{PRJ}', '{sid1}', '[\"{ogrn}\"]', ARRAY['address']);", "ac_rd_measure"))
c = claim(ev, subj="ent_r_m1", address=rows[i][4])
assert psql(ingest_sql([c], {})).returncode == 0
cid = c["claim_id"]


def timeit(sql, k=100, user=None):
    t0 = time.time()
    r = psql("\n".join([sql + ";"] * k), user)
    assert r.returncode == 0, first_err(r)
    return round((time.time() - t0) * 1000 / k, 2), r.stdout.splitlines()[-1]


def profile(sql, user=None):
    r = psql("SET track_functions = 'all';\nSELECT pg_stat_reset();\n" + sql + ";\nSELECT pg_sleep(0.6);\n"
             "SELECT string_agg(funcname || '×' || calls || ' (' || round(total_time::numeric, 1) || ' мс)', ', ' ORDER BY total_time DESC) "
             "FROM pg_stat_user_functions WHERE schemaname = 'ac' AND funcname IN ('evidence_json','row_currency','dataset_cells','row_evidence_error','dataset_table','group_strong_keys','strong_keys','merkle_root','inclusion_root','dominates','jcs','cell_leaf');")
    return r.stdout.strip().splitlines()[-1] if r.returncode == 0 else first_err(r)


def stage(label):
    ms, last = timeit(f"SELECT ac.evidence_json('{cid}', now())")
    cur = json.loads(last)[0]["currency"]
    msd, _ = timeit(f"SELECT ac.dossier('{PRJ}', 'ent_r_m1')", 30, "ac_rd_measure")
    print(f"[{label}] evidence_json: {ms} мс на вызов; досье сущности (1 утверждение): {msd} мс; currency = {cur['status']}")
    print("    функции на ОДНО досье:", profile(f"SET SESSION AUTHORIZATION ac_rd_measure;\nSELECT ac.dossier('{PRJ}', 'ent_r_m1');\nRESET SESSION AUTHORIZATION"))
    print("    функции на ОДИН evidence_json:", profile(f"SELECT ac.evidence_json('{cid}', now())"))
    return ms, msd


base = stage("одна версия, 49 файлов: CURRENT")


def next_version(label, chunk, sub):
    d = out / sub
    rows2 = [list(x) for x in rows]
    rows2[i][4] = rows2[i][4] + ", корп. 2"
    t0 = time.time()
    key32 = None
    m, b, sid = D.build_stream("dst_egrul_synth", T, label, D.REGISTRY_COLUMNS, ["ogrn"], iter(rows2), d, chunk_rows=chunk, subject=("ogrn", "inn"), previous=sid1)
    src, r = D.register(b, T, f"Синтетический реестр, {label}")
    assert r.returncode == 0, first_err(r)
    t, bad = D.load_rows(T, sid, d / "rows.copy", D.REGISTRY_COLUMNS)
    assert bad is None, first_err(bad)
    print(f"версия {label}: файлов {len(m['files'])}, манифест {len(b)} байт, сборка+загрузка {round(time.time() - t0)} с, {t}")
    return sid


next_version("v2-4096", 4096, "v2")
v2 = stage("две версии, последняя 49 файлов")
next_version("v3-64", 64, "v3")
v3 = stage("три версии, последняя порезана по 64 строки (3125 файлов)")
print(f"\nитог: evidence_json {base[0]} -> {v2[0]} -> {v3[0]} мс; досье {base[1]} -> {v2[1]} -> {v3[1]} мс")

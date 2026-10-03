#!/usr/bin/env python3
"""Позитивные векторы (expected == []) — в базу БЕЗ валидатора (то, чего db_vectors_s1.py не делает: там `if not v["expected"]: continue`).
Запуск из корня копии: PGDATABASE=rev_method python3 findings/14_db_positive_vectors.py
Позитивный вектор, отвергнутый базой = база строже валидатора (или загрузчик не умеет выразить вход)."""
import sys, collections
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "slice")); sys.path.insert(0, str(ROOT / "core"))
import load_s1 as L
import validator as VAL
from vectors import VECTORS, build
covered = lambda vid: (vid[1] == "9" and len(vid) == 4) or vid[1] in ("R", "S")   # эти идут в базу в s9/s10/s11_tests
rows = []
for v in VECTORS:
    if v["expected"]:
        continue
    ds, tr, ct = build(v)
    rep = VAL.validate(ds, tr, ct)
    warns = sorted({w["code"] for w in rep.warnings})
    try:
        sql = L.load_sql(ds, tr, ct); sql.encode("utf-8")
    except Exception as ex:
        rows.append((v["id"], covered(v["id"]), "N/A", type(ex).__name__, warns, v["desc"])); continue
    L.psql(L.DDL_ALL)
    try:
        L.register_originals(ds, ct)
    except Exception as ex:
        pass
    r = L.psql(sql)
    if r.returncode:
        msg = next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr.strip()[:120]).replace("psql:<stdin>:", "")
        rows.append((v["id"], covered(v["id"]), "REJECTED", msg[:150], warns, v["desc"]))
    else:
        rows.append((v["id"], covered(v["id"]), "ACCEPTED", "", warns, v["desc"]))
    print(" | ".join(map(str, rows[-1])), flush=True)
L.psql(L.DDL_ALL)
c = collections.Counter((r[1], r[2]) for r in rows)
print("\nпозитивных:", len(rows), "| (входит в паритет s9/s10/s11, результат):", dict(c))
print("отвергнуто базой, хотя валидатор принимает:")
for r in rows:
    if r[2] != "ACCEPTED": print("  ", " | ".join(map(str, r)))

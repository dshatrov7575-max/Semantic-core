#!/usr/bin/env python3
"""Раунд 3: мутанты валидатора snapshot3. Штатные MS08, MS13…MS23 (перепроверка, в т. ч. исправленного шаблона MS08) и
свои Z01, Z02. Отдельно — проверка заявленной эквивалентности MS23 на своём мире (в векторах автора его нет).
Usage: python3 c50_mutants.py"""
import json, os, sys
from pathlib import Path
sys.dont_write_bytecode = True
SNAP = Path("/tmp/claude-0/s11/r5/core")
sys.path.insert(0, str(SNAP)); sys.path.insert(0, "/tmp/claude-0/s11/r5/slice")
os.chdir(SNAP)
import mutants as MU
import vectors as V
from vectors import VECTORS, build
from fixtures import REGISTRY_ROWS, OGRN_DEV, PUB

OUT = Path("/home/claude/as/review/review_s11/round5/attacks/out/e50_mutants.jsonl")
OFFICIAL = ["MS08"] + [f"MS{i}" for i in range(13, 27)]
CN = 'def _has_unassigned(v: str) -> bool:\n    return any('
EXTRA = [
    ("Z01", "неназначенный символ: только если ВСЕ знаки не назначены (any -> all в _has_unassigned)", CN, CN.replace("any(", "all(")),
    ("Q01", "identity: списки не просматриваются", '    if isinstance(x, list):\n        return any(_identity_has_unassigned(v) for v in x)\n', '    if isinstance(x, list):\n        return False\n'),
    ("Z02", "пустой иностранный идентификатор: проверяется сырая строка, а не нормальная форма", '                if not id_norm(f["value"]):', '                if not f["value"].strip():'),
]
done = {json.loads(l)["id"] for l in OUT.read_text().splitlines()} if OUT.exists() else set()
todo = [m for m in list(MU.M) + EXTRA if m[0] in OFFICIAL + [e[0] for e in EXTRA] and m[0] not in done]


def init():
    vs = sorted(VECTORS, key=lambda v: 0 if v["id"][1] == "S" else 1 if v["id"][1] == "R" else 2)
    MU.CASES = [(None, *build())] + [(v, *build(v)) for v in vs]


def work(m):
    res = MU.run_one(m)
    with OUT.open("a") as fh:
        fh.write(json.dumps({"id": res[0], "result": res[1], "desc": res[2]}, ensure_ascii=False) + "\n")
    return res


if __name__ == "__main__":
    from multiprocessing import Pool
    if todo:
        with Pool(2, initializer=init) as pool:
            list(pool.imap_unordered(work, todo, chunksize=1))
    for l in sorted(OUT.read_text().splitlines()):
        d = json.loads(l)
        print(f"{d['id']:<5} {d['result']:<30} {d['desc'][:110]}")

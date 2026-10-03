#!/usr/bin/env python3
"""Раунд 2 (д): мутанты валидатора snapshot2 на векторах snapshot2/core/vectors.py.
Штатные MS01…MS12 (перепроверка) и свои Y01…Y07 на новых ветках (row_id, row_subject_ids). Векторы S идут первыми.
Результаты дописываются в out/b50_mutants.jsonl (возобновляемо). Usage: python3 b50_mutants.py [ids…]"""
import json, os, sys
from pathlib import Path
sys.dont_write_bytecode = True
SNAP = Path("/tmp/claude-0/s11/r2/core")
sys.path.insert(0, str(SNAP))
os.chdir(SNAP)
import mutants as MU
from vectors import VECTORS, build

OUT = Path("/home/claude/as/review/review_s11/round2/attacks/out/b50_mutants.jsonl")
OFFICIAL = [f"MS{i:02d}" for i in range(1, 13)]
RAW = 'RAW_ID_SCHEMES = {"ru.inn", "ru.ogrn", "ru.ogrnip", "vin", "imo"}'
CAD = '        return scheme, cadastral_norm(value) if _CADASTRAL_RE.fullmatch(value) else value'
EXTRA = [
    ("Y01", "кадастровый: проверяется только начало значения (fullmatch -> match)", CAD, CAD.replace("fullmatch", "match")),
    ("Y02", "vin приводится как прочие (id_norm)", RAW, 'RAW_ID_SCHEMES = {"ru.inn", "ru.ogrn", "ru.ogrnip", "imo"}'),
    ("Y03", "imo приводится как прочие (id_norm)", RAW, 'RAW_ID_SCHEMES = {"ru.inn", "ru.ogrn", "ru.ogrnip", "vin"}'),
    ("Y04", "ru.ogrnip приводится как прочие (id_norm)", RAW, 'RAW_ID_SCHEMES = {"ru.inn", "ru.ogrn", "vin", "imo"}'),
    ("Y05", "ru.ogrn приводится как прочие (id_norm)", RAW, 'RAW_ID_SCHEMES = {"ru.inn", "ru.ogrnip", "vin", "imo"}'),
    ("Y06", "идентификаторы субъекта строки — все процитированные колонки-идентификаторы, а не только subject",
     '    return {row_id(scheme[n], quoted[n]) for n in m.get("subject", ()) if isinstance(quoted.get(n), str)}',
     '    return {row_id(scheme[n], quoted[n]) for n in scheme if scheme[n] and isinstance(quoted.get(n), str)}'),
    ("Y07", "кадастровый не по форме приводится через id_norm, а не «как записан»", CAD, CAD.replace("else value", "else id_norm(value)")),
]
want = sys.argv[1:] or OFFICIAL + [m[0] for m in EXTRA]
done = {json.loads(l)["id"] for l in OUT.read_text().splitlines()} if OUT.exists() else set()
todo = [m for m in list(MU.M) + EXTRA if m[0] in want and m[0] not in done]


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
            for r in pool.imap_unordered(work, todo, chunksize=1):
                print(r, flush=True)
    for l in sorted(OUT.read_text().splitlines()):
        d = json.loads(l)
        print(f"{d['id']:<5} {d['result']:<34} {d['desc']}")

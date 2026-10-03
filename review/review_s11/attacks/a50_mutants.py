#!/usr/bin/env python3
"""Мутанты цикла 11: штатные MS01,02,03,06,07 и задетые MR40…MR47 (из core/mutants.py снимка) + СВОИ мутанты нового
правила (X..), которых у автора нет. Векторы цикла 11 (NS/PS) идут первыми, затем прочие векторы строк (R), затем все
остальные: видно, убит ли мутант «своим» вектором. Результат каждого мутанта дописывается в out/a50_mutants.jsonl
(возобновляемо). Usage: python3 a50_mutants.py [ids…]"""
import json, os, sys
from pathlib import Path
os.environ.setdefault("PGDATABASE", "review11_a")
SNAP = Path("/home/claude/as/review/review_s11/snapshot/core")
sys.path.insert(0, str(SNAP))
os.chdir(SNAP)
import mutants as MU
from vectors import VECTORS, build

OUT = Path("/home/claude/as/review/review_s11/attacks/out/a50_mutants.jsonl")
OFFICIAL = ["MS01", "MS02", "MS03", "MS06", "MS07", "MR40", "MR41", "MR42", "MR43", "MR44", "MR45", "MR46", "MR47"]
A = '        if alien is not None and alien(ids - subj_keys):'
CARR = '    for eid, e in E.items():\n        for k in ent_keys(e["entity_type"], e["identity"]):\n            carriers[(e["project_id"], e["entity_type"], k)].append(e["created_at"])'
EXTRA = [
    ("X01", "конфликт: сущность, созданная РОВНО в момент утверждения, не считается (граница <= -> <)",
     'return lambda keys: {k for k in keys if any(ct <= t for ct in', 'return lambda keys: {k for k in keys if any(ct < t for ct in'),
    ("X02", "конфликт: выведенная из употребления (RETIRED) сущность не считается носителем",
     CARR, CARR.replace('for eid, e in E.items():', 'for eid, e in E.items():\n        if e["status"] == "RETIRED":\n            continue')),
    ("X03", "конфликт: сущность, слитая (когда угодно) в ТРЕТЬЮ сущность, не считается носителем",
     CARR, CARR.replace('for eid, e in E.items():', 'for eid, e in E.items():\n        if e["status"] == "MERGED" and e.get("merged_into") != "ent_k_developer":\n            continue')),
    ("X04", "конфликт: проверяется только первый чужой идентификатор (по сортировке), остальные — нет",
     A, '        if alien is not None and alien(set(sorted(ids - subj_keys)[:1])):'),
    ("X05", "конфликт: носитель с маркировкой выше утверждения не считается",
     CARR, CARR.replace('for eid, e in E.items():', 'for eid, e in E.items():\n        if "PERSONAL_DATA" in e["marking"]["categories"] and e["entity_type"] == "ORGANIZATION":\n            continue')),
    ("X06", "конфликт: момент — время создания носителя против ingested/сейчас: считается только созданная до субъекта",
     'return lambda keys: {k for k in keys if any(ct <= t for ct in', 'return lambda keys: {k for k in keys if any(ct <= e["created_at"] for ct in'),
]
want = [a for a in sys.argv[1:]] or OFFICIAL + [m[0] for m in EXTRA]
done = {json.loads(l)["id"] for l in OUT.read_text().splitlines()} if OUT.exists() else set()
todo = [m for m in list(MU.M) + EXTRA if m[0] in want and m[0] not in done]


def order(v):
    return 0 if v["id"][1] == "S" else 1 if v["id"][1] == "R" else 2


def init():
    vs = sorted(VECTORS, key=order)
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

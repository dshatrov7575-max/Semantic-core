"""Какие взаимодействия правил вообще встречаются в мирах векторов (слияние × Проверка × маркировка × время × доказательства).
Запуск из core/."""
import sys, json, collections, itertools
sys.path.insert(0, ".")
from vectors import VECTORS, build
def feats(ds):
    R = ds["records"] if isinstance(ds, dict) and isinstance(ds.get("records"), list) else []
    R = [r for r in R if isinstance(r, dict)]
    by = collections.defaultdict(list)
    for r in R: by[r.get("kind")].append(r)
    E = {e.get("entity_id"): e for e in by["Entity"]}
    C = {c.get("claim_id"): c for c in by["Claim"]}
    S = {s.get("source_id"): s for s in by["Source"]}
    merged = {k for k, e in E.items() if e.get("status") == "MERGED"}
    retired = {k for k, e in E.items() if e.get("status") == "RETIRED"}
    targets = {E[k].get("merged_into") for k in merged}
    f = set()
    g = lambda d, *p: (g(d.get(p[0], {}), *p[1:]) if len(p) > 1 else d.get(p[0])) if isinstance(d, dict) else None
    if merged: f.add("merge:есть MERGED")
    if len(merged) >= 2: f.add("merge:>=2 MERGED")
    if any(E[k].get("merged_into") in merged for k in merged): f.add("merge:цепочка A→B→C")
    if len(merged) != len(targets) and len(merged) > len(targets): f.add("merge:две сущности слиты в одну")
    if any(g(E[k], "marking") != g(E.get(E[k].get("merged_into"), {}), "marking") for k in merged): f.add("merge:маркировки сливаемой и выжившей разные")
    if any(E.get(E[k].get("merged_into"), {}).get("status") == "RETIRED" for k in merged): f.add("merge:выжившая позже RETIRED")
    if retired: f.add("есть RETIRED")
    cm = [c for c in C.values() if c.get("subject") in merged or g(c, "object", "entity") in merged]
    if cm: f.add("claim:о MERGED сущности (субъект/объект)")
    if any(c.get("subject") in merged and c.get("recorded_at", "") > E[c["subject"]].get("status_changed_at", "9") for c in C.values()): f.add("claim:о MERGED, записано ПОСЛЕ слияния")
    if any(c.get("subject") in targets or g(c, "object", "entity") in targets for c in C.values()): f.add("claim:о выжившей сущности")
    rows = [c for c in C.values() if any(isinstance(ev, dict) and ev.get("kind") == "ROW" for ev in c.get("evidence", []))]
    if rows: f.add("ev:ROW")
    if any(c.get("subject") in merged | targets for c in rows): f.add("ev:ROW × субъект в группе слияния")
    gn = [c for c in C.values() if any(isinstance(ev, dict) and "graph_node" in ev for ev in c.get("evidence", []))]
    if any(c.get("subject") in merged | targets or g(c, "object", "entity") in merged | targets for c in gn): f.add("ev:узел графа × группа слияния")
    if any(len(c.get("evidence", [])) >= 2 for c in C.values()): f.add("ev:>=2 доказательств у утверждения")
    if any(len({ev.get("source_id") for ev in c.get("evidence", []) if isinstance(ev, dict)}) >= 2 for c in C.values()): f.add("ev:доказательства из 2 источников")
    if any(len({ev.get("kind", "SPAN") for ev in c.get("evidence", []) if isinstance(ev, dict)}) >= 2 for c in C.values()): f.add("ev:ROW и фрагмент в одном утверждении")
    rv = collections.Counter(r.get("claim_id") for r in by["ClaimReview"])
    if any(n >= 2 for n in rv.values()): f.add("review:>=2 рецензий на утверждение")
    if any(n >= 3 for n in rv.values()): f.add("review:>=3 рецензий на утверждение")
    for k in by["Check"]:
        st = k.get("status"); sub = k.get("subject_entity_id")
        f.add("check:" + str(st))
        closed = k.get("completed_at") or k.get("cancelled_at")
        if sub in merged: f.add("check × слияние: субъект MERGED")
        if sub in retired: f.add("check × RETIRED субъект")
        if sub in targets: f.add("check × слияние: субъект — выжившая")
        cids = [c for fd in k.get("findings", []) if isinstance(fd, dict) for c in fd.get("claim_ids", [])]
        if any(C.get(c, {}).get("subject") in merged or g(C.get(c, {}), "object", "entity") in merged for c in cids): f.add("check × слияние: утверждение Проверки о MERGED сущности")
        if any(C.get(c, {}).get("subject") != sub and g(C.get(c, {}), "object", "entity") != sub for c in cids if c in C): f.add("check: утверждение касается субъекта только через слияние")
        if "previous_check_id" in k: f.add("check:previous")
        if "previous_check_id" in k and sub in merged | targets: f.add("check:previous × слияние")
        if any(rv.get(c, 0) >= 2 for c in cids): f.add("check × время: утверждение Проверки с >=2 рецензиями")
        if closed and any(r.get("claim_id") in cids and r.get("recorded_at", "") > closed for r in by["ClaimReview"]): f.add("check × время: рецензия ПОСЛЕ закрытия Проверки")
        if any(g(C.get(c, {}), "marking") != k.get("marking") for c in cids if c in C): f.add("check × маркировка: Проверка и её утверждение — разные маркировки")
        if any(any(isinstance(ev, dict) and ev.get("kind") == "ROW" for ev in C.get(c, {}).get("evidence", [])) for c in cids): f.add("check × ROW-доказательство")
        if any(any(isinstance(ev, dict) and "graph_node" in ev for ev in C.get(c, {}).get("evidence", [])) for c in cids): f.add("check × PIPELINE/узел графа")
    if any(g(c, "valid_from") or g(c, "valid_to") for c in C.values()): f.add("time:valid_from/valid_to")
    lv = {g(r, "marking", "level") for r in R if isinstance(r.get("marking"), dict)}
    for l in lv: f.add("marking:уровень " + str(l))
    cats = {c for r in R if isinstance(r.get("marking"), dict) for c in (r["marking"].get("categories") or []) if isinstance(c, str)}
    for c in cats: f.add("marking:категория " + c)
    ten = {r.get("tenant_id") for r in by["Project"]}
    if len(ten) >= 2: f.add("tenant:>=2 tenant с проектами")
    return f
allf = collections.Counter(); cases = {}
for v in [None] + VECTORS:
    try: ds = build(v)[0]
    except Exception: continue
    f = feats(ds); cases[v["id"] if v else "BASE"] = f
    allf.update(f)
base = cases["BASE"]
print("признак | в эталоне | векторов с признаком (из %d)" % len(cases))
names = sorted(set(allf) | {"merge:цепочка A→B→C", "claim:о MERGED, записано ПОСЛЕ слияния", "ev:ROW × субъект в группе слияния", "ev:узел графа × группа слияния",
    "check × слияние: субъект MERGED", "check × RETIRED субъект", "check × слияние: утверждение Проверки о MERGED сущности", "check: утверждение касается субъекта только через слияние",
    "check:previous × слияние", "check × время: рецензия ПОСЛЕ закрытия Проверки", "check × ROW-доказательство", "check × PIPELINE/узел графа", "ev:ROW и фрагмент в одном утверждении",
    "merge:выжившая позже RETIRED", "merge:две сущности слиты в одну", "review:>=3 рецензий на утверждение", "marking:уровень RESTRICTED"})
for n in names:
    print("%-70s | %-3s | %d" % (n, "да" if n in base else "нет", allf.get(n, 0)))
# тройные взаимодействия
def cnt(*ns): return sum(1 for f in cases.values() if all(any(x.startswith(n) for x in f) for n in ns))
print("\nвзаимодействия (число векторов, где все признаки сразу; эталон есть в каждом векторе, поэтому смотрим «редкие»):")
for combo in [("check × слияние: субъект MERGED", "check × время: рецензия ПОСЛЕ"), ("check × слияние: субъект MERGED", "check:previous"),
              ("ev:ROW × субъект в группе", "check × ROW"), ("merge:маркировки сливаемой и выжившей разные", "check × слияние"),
              ("claim:о MERGED, записано ПОСЛЕ слияния",), ("merge:цепочка",), ("check × ROW",), ("check × PIPELINE",), ("check:previous × слияние",)]:
    print("  ", " + ".join(combo), "=>", cnt(*combo))
json.dump({k: sorted(v) for k, v in cases.items()}, open("../findings/interactions.json", "w"), ensure_ascii=False)

"""Качество векторов: (1) из каких мест validator.py на деле приходит ожидаемый код; (2) насколько вектор далёк от эталонного мира.
Запуск из core/ (нужен findings/baseline.json)."""
import sys, json, collections, re
sys.path.insert(0, ".")
from vectors import VECTORS, build
B = json.load(open("../findings/baseline.json"))
neg = [v for v in VECTORS if v["expected"]]
pos = [v for v in VECTORS if not v["expected"]]
# (1) код -> множество (строка, причина) по всем векторам
multi_site = []; by_reason = collections.defaultdict(list)
for v in neg:
    b = B[v["id"]]
    per_code = collections.defaultdict(set)
    for (code, ref, msg), line in zip(b["errors"], b["lines"]):
        reason = re.sub(r"(clm|src|rcp|pub):sha256:[0-9a-f]{64}", "<id>", msg)
        reason = re.sub(r"файл \d+ версии набора: ", "", reason)[:70]
        per_code[code].add((line, reason))
        by_reason[(code, line, reason[:40])].append(v["id"])
    for code, s in per_code.items():
        if len({l for l, _ in s}) > 1 or len(s) > 1:
            multi_site.append((v["id"], code, sorted(s)))
print("негативных векторов:", len(neg))
print("векторов, где ожидаемый код приходит сразу из >=2 разных мест/причин (удаление одного правила вектор не заметит):", len(multi_site))
for x in multi_site[:60]: print("  ", x[0], x[1], [f"L{l}:{r[:45]}" for l, r in x[2]])
print("\nразных (код, место, причина), встреченных в векторах:", len(by_reason))
d = collections.Counter(min(len(v), 6) for v in by_reason.values())
print("распределение числа векторов на одну (код, место, причина) [6 = 6+]:", sorted(d.items()))
# (2) расстояние от эталона: сколько записей мира отличается
base = build()[0]
def key(r):
    for k in ("project_id", "source_id", "entity_id", "claim_id", "review_id", "check_id", "receipt_id", "decision_id", "publication_id", "class_id", "link_id", "idef_id"):
        if k in r and r.get("kind", "").lower().replace("claimreview", "review").replace("artifactreceipt", "receipt").replace("identitydecision", "decision")[:4] in k.replace("_", "")[:8]:
            return (r.get("kind"), r.get(k), r.get("version"))
    return (r.get("kind"), json.dumps(r, sort_keys=True, default=str)[:80])
bj = [json.dumps(r, sort_keys=True, ensure_ascii=False, default=str) for r in base["records"]]
bset = collections.Counter(bj)
dist = collections.Counter(); size = collections.Counter()
far = []
for v in VECTORS:
    try:
        ds = build(v)[0]
        recs = ds["records"] if isinstance(ds, dict) and isinstance(ds.get("records"), list) else []
        vj = collections.Counter(json.dumps(r, sort_keys=True, ensure_ascii=False, default=str) for r in recs)
    except Exception as ex:
        dist["build/serialize error"] += 1; continue
    changed = sum((vj - bset).values()); removed = sum((bset - vj).values())
    n = max(changed, removed)
    dist[min(n, 8)] += 1; size[len(recs)] += 1
    if n >= 8: far.append((v["id"], changed, removed))
print("\nэталонный мир: записей", len(base["records"]))
print("число записей, отличающихся от эталона (max(новых/изменённых, пропавших)); 8 = 8+:", sorted(dist.items(), key=lambda x: str(x[0])))
print("размер мира вектора (записей): min", min(size), "max", max(size))
print("векторы с 8+ отличиями:", len(far), far[:20])

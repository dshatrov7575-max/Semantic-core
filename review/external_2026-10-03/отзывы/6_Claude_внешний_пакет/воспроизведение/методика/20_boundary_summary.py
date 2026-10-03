"""Сводка по ВСЕМ точкам сравнения <, <=, >, >= в validator.py (полный перебор, не выборка): объединение по idx из всех файлов прогонов."""
import sys, json, glob, ast, importlib.util, collections
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("am", "../findings/06_auto_mutator.py"); am = importlib.util.module_from_spec(spec); spec.loader.exec_module(am)
t = ast.parse(am.SRC); am.annotate(t); ss = am.sites(t)
rel = {i for i, (k, n, sub) in enumerate(ss) if k == "CMP" and isinstance(n.ops[sub], (ast.Lt, ast.LtE, ast.Gt, ast.GtE))}
res = {}
for p in glob.glob("../findings/auto_mutants_*.jsonl"):
    for l in open(p, encoding="utf-8"):
        if l.strip():
            r = json.loads(l); res[r["idx"]] = r
done = [res[i] for i in sorted(rel) if i in res]
c = collections.Counter(r["status"] for r in done)
print(f"точек сравнения <,<=,>,>=: {len(rel)}; прогнано: {len(done)}; {dict(c)}; выжило {100 * c['SURVIVED'] / max(1, len(done)):.0f}%")
tot = collections.Counter(r["status"] for r in res.values()); print("все автоматические мутанты (все прогоны, без повторов):", len(res), dict(tot))
kinds = collections.defaultdict(collections.Counter)
for r in res.values(): kinds[r["kind"]][r["status"]] += 1
for k, v in sorted(kinds.items()): print("  ", k, dict(v))
for r in done:
    if r["status"] == "SURVIVED": print(f"  L{r['line']} [{r['func']}] {r['desc'][:120]}")

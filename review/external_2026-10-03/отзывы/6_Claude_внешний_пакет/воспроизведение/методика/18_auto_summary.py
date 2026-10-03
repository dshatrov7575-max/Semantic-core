"""Сводка по автоматическим мутантам. Запуск из core/: python3 ../findings/18_auto_summary.py файл.jsonl [...]"""
import sys, json, collections
NOISE = {"NR13"}     # вывод этого вектора меняется от запуска к запуску (случайный ключ набора), в «строгую разницу» не считается
rows = []
for p in sys.argv[1:]:
    rows += [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
tab = [0x10000]
def scope(r):
    return "таблицы/константы модуля" if r["func"] is None else "логика функций"
print("всего мутантов:", len(rows))
c = collections.Counter((r["status"]) for r in rows); print(dict(c))
for key in ("kind", None):
    t = collections.defaultdict(collections.Counter)
    for r in rows: t[r["kind"] if key else scope(r)][r["status"]] += 1
    for k, v in sorted(t.items()): print("  %-28s убито %3d  выжило %3d  (%.0f%% выжило)" % (k, v["KILLED"], v["SURVIVED"], 100 * v["SURVIVED"] / max(1, sum(v.values()))))
print("\nвыжившие:")
for r in rows:
    if r["status"] == "SURVIVED":
        sd = [x for x in r.get("strict_diff", []) if x not in NOISE]
        print(f"  #{r['idx']} L{r['line']} [{r['func'] or 'модуль'}] {r['kind']}: {r['desc'][:150]}\n      векторов, исполняющих оператор: {r['relevant_vectors']}; полный вывод отличается на: {sd if sd else 'ни одном векторе'}")
by = collections.Counter(r.get("by", "").split("(")[0] for r in rows if r["status"] == "KILLED")
print("\nубиты: BASE", by.get("BASE", 0), "| негативным", sum(v for k, v in by.items() if k[:1] == "N"), "| позитивным", sum(v for k, v in by.items() if k[:1] in "PW"), "| прочее", {k: v for k, v in by.items() if k[:1] not in "NPWB"})

"""Что из validator.py не исполняет НИ ОДИН вектор (и базовый мир); покрытие «причин» отказа. Запуск из core/."""
import json, ast, re, collections
cov = json.load(open("../findings/coverage.json"))
SRC = open("validator.py", encoding="utf-8").read(); L = SRC.split("\n")
mod = set(cov.pop("__module__"))
allv = set().union(*map(set, cov.values()))
tree = ast.parse(SRC)
# исполняемые строки = строки, на которых начинается оператор (stmt) внутри функций, кроме main
stm = {}
def walk(n, func):
    for ch in ast.iter_child_nodes(n):
        f = func
        if isinstance(ch, ast.FunctionDef) and func is None: f = ch.name
        if isinstance(ch, ast.stmt) and f and not isinstance(ch, (ast.FunctionDef,)):
            stm[ch.lineno] = (f, ch)
        walk(ch, f)
walk(tree, None)
exe = {l for l, (f, _) in stm.items() if f != "main"}
unc = sorted(exe - allv)
print("операторов в функциях (кроме main):", len(exe), "исполнено хотя бы одним вектором:", len(exe & allv), "не исполнено:", len(unc))
for l in unc: print("  L%d [%s] %s" % (l, stm[l][0], L[l-1].strip()[:140]))
# сколько векторов исполняет каждую строку с R.err / return "причина"
cnt = collections.Counter(l for v in cov.values() for l in v)
reason = [l for l in sorted(exe) if re.search(r'R\.err\(|return (None, )?f?"', L[l-1]) or 'bad.append(' in L[l-1] or 'terrs.append(' in L[l-1] or 'out.append((path' in L[l-1]]
print("\nточек отказа (R.err / return \"причина\" / bad.append / terrs.append / prescan):", len(reason))
dist = collections.Counter(min(cnt[l], 5) for l in reason)
print("распределение по числу векторов, исполняющих точку отказа (5 = 5 и больше):", sorted(dist.items()))
for k in (0, 1):
    print(f"\nточки отказа, исполняемые ровно {k} вектор(ами):")
    for l in reason:
        if cnt[l] == k: print("  L%d %s" % (l, L[l-1].strip()[:150]))

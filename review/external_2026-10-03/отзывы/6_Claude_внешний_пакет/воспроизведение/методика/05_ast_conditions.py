"""Грубая оценка: сколько условий/булевых операторов/сравнений в validator.py и сколько строк затронуто мутантами. Запуск из core/."""
import ast, sys, collections
sys.path.insert(0, '.')
import mutants
SRC = open('validator.py', encoding='utf-8').read()
tree = ast.parse(SRC)
cnt = collections.Counter()
cond_lines = collections.defaultdict(set)   # line -> kinds
for n in ast.walk(tree):
    k = type(n).__name__
    if isinstance(n, (ast.If, ast.IfExp, ast.While)):
        cnt["if/elif/while/ifexp"] += 1; cond_lines[n.test.lineno].add("if")
    elif isinstance(n, ast.BoolOp):
        cnt["boolop (and/or) operands-1"] += len(n.values) - 1; cnt["boolop nodes"] += 1; cond_lines[n.lineno].add("bool")
    elif isinstance(n, ast.Compare):
        cnt["compare ops"] += len(n.ops); cond_lines[n.lineno].add("cmp")
    elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
        cnt["not"] += 1; cond_lines[n.lineno].add("not")
    elif isinstance(n, ast.comprehension):
        cnt["comprehension ifs"] += len(n.ifs)
        for i in n.ifs: cond_lines[i.lineno].add("compif")
    elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("any", "all"):
        cnt["any/all"] += 1
    elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "err":
        cnt["R.err sites"] += 1
    elif isinstance(n, ast.Return):
        cnt["return"] += 1
    elif isinstance(n, (ast.Continue, ast.Break)):
        cnt["continue/break"] += 1
print(dict(cnt))
decision_points = cnt["if/elif/while/ifexp"] + cnt["boolop (and/or) operands-1"] + cnt["comprehension ifs"]
print("decision points (if/elif/while/ifexp + extra bool operands + comprehension ifs):", decision_points)
print("lines containing a condition:", len(cond_lines))
# map mutants to lines
touched = collections.defaultdict(list)
nomatch = []
for mid, desc, old, new in mutants.M:
    olds = old if isinstance(old, list) else [old]
    for o in olds:
        i = SRC.find(o)
        if i < 0 or SRC.count(o) != 1:
            nomatch.append(mid); continue
        l0 = SRC.count("\n", 0, i) + 1 + (len(o) - len(o.lstrip("\n")))
        l1 = SRC.count("\n", 0, i + len(o.rstrip("\n"))) + 1
        for l in range(l0, l1 + 1):
            touched[l].append(mid)
print("mutants:", len(mutants.M), "pattern not unique:", nomatch)
print("distinct source lines touched by any mutant:", len(touched))
first = collections.Counter()
for mid, desc, old, new in mutants.M:
    o = old[0] if isinstance(old, list) else old
    i = SRC.find(o)
    first[SRC.count("\n", 0, i) + 1 + (len(o) - len(o.lstrip("\n")))] += 1
print("distinct first-lines of mutant patterns:", len(first), "; lines with >=3 mutants:", sum(1 for v in first.values() if v >= 3))
uncovered = sorted(l for l in cond_lines if l not in touched)
print("condition lines without any mutant: %d of %d" % (len(uncovered), len(cond_lines)))
import json
json.dump({"cond_lines": sorted(cond_lines), "touched": {str(k): v for k, v in touched.items()}, "uncovered": uncovered}, open("../findings/ast_conditions.json", "w"))
lines = SRC.split("\n")
for l in uncovered:
    print("%5d  %s" % (l, lines[l-1].strip()[:150]))

"""Автоматический мутатор validator.py (AST, номера строк сохраняются) + прогон случайной выборки против ВСЕХ векторов.

Операторы:
  CMP   <↔<=, >↔>=, ==↔!=, in↔not in, is↔is not
  BOOL  and↔or
  NOT   удаление not
  NEG   отрицание условия if/elif/while/тернарного
  CONST целая константа ±1 (кроме 0/1 в индексах — берём все int, bool не трогаем)
  DEL   R.err(...) → pass;  continue/break → pass
  RET   return X → return None (только если X не None)

Критерий убийства — как у автора (mutants.killed_by): множество кодов != expected, либо (если warn задан) список
предупреждений != warn; базовый мир: нет ошибок и ровно одно предупреждение.
Дополнительно для выживших считаем «строгую» разницу: меняется ли на каком-либо векторе полный вывод
(code, ref, msg ошибок и предупреждений). Если да — мутант НЕ эквивалентен, просто утверждения векторов слабы.

Ускорение: вектор запускается против мутанта, только если он исполняет хотя бы одну строку изменённого оператора
(findings/coverage.json); мутанты уровня модуля — против всех векторов.

Запуск из core/:  python3 ../findings/06_auto_mutator.py list            — число точек мутации по видам
                  python3 ../findings/06_auto_mutator.py run SEED N [J]  — случайная выборка N точек, J процессов
                  python3 ../findings/06_auto_mutator.py lines L1,L2,.. [J] [KINDS] — все точки мутации на этих строках (целевой прогон)
"""
import ast
import copy
import json
import multiprocessing as mp
import random
import sys
import time
import types
from pathlib import Path

sys.path.insert(0, ".")
HERE = Path(".").resolve()
FIND = HERE.parent / "findings"
SRC = (HERE / "validator.py").read_text(encoding="utf-8")
LINES = SRC.split("\n")

CMP_SWAP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
            ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
SKIP_FUNCS = {"main"}          # CLI — вне векторов по построению (проверяется T7), не считаем


def annotate(tree):
    """каждому узлу — охватывающий оператор (stmt) и имя функции верхнего уровня"""
    def walk(node, stmt, func):
        for ch in ast.iter_child_nodes(node):
            s, f = stmt, func
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) and func is None:
                f = ch.name
            if isinstance(ch, ast.stmt):
                s = ch
            ch._stmt, ch._func = s, f
            walk(ch, s, f)
    tree._stmt, tree._func = None, None
    walk(tree, None, None)


def sites(tree):
    """детерминированный список точек мутации: (kind, node, sub)"""
    out = []
    for n in ast.walk(tree):
        f = getattr(n, "_func", None)
        if f in SKIP_FUNCS:
            continue
        st = getattr(n, "_stmt", None)
        if isinstance(st, ast.If) and isinstance(st.test, ast.Compare) and getattr(st.test.left, "id", "") == "__name__":
            continue
        if isinstance(st, ast.Assert) or isinstance(n, ast.Assert):
            continue
        if isinstance(n, ast.Compare):
            for i, op in enumerate(n.ops):
                if type(op) in CMP_SWAP:
                    out.append(("CMP", n, i))
        elif isinstance(n, ast.BoolOp):
            out.append(("BOOL", n, 0))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.append(("NOT", n, 0))
        elif isinstance(n, (ast.If, ast.While, ast.IfExp)):
            out.append(("NEG", n, 0))
        elif isinstance(n, ast.Constant) and type(n.value) is int:
            out.append(("CONST", n, +1))
            out.append(("CONST", n, -1))
        elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) \
                and n.value.func.attr == "err":
            out.append(("DEL", n, 0))
        elif isinstance(n, (ast.Continue, ast.Break)):
            out.append(("DEL", n, 0))
        elif isinstance(n, ast.Return) and n.value is not None and not (isinstance(n.value, ast.Constant) and n.value.value is None):
            out.append(("RET", n, 0))
    return out


def describe(kind, n, sub):
    st = n if isinstance(n, ast.stmt) else n._stmt
    line = n.lineno
    if kind == "CMP":
        d = f"{type(n.ops[sub]).__name__}->{CMP_SWAP[type(n.ops[sub])].__name__} в «{ast.unparse(n)[:110]}»"
    elif kind == "BOOL":
        d = f"{'and->or' if isinstance(n.op, ast.And) else 'or->and'} в «{ast.unparse(n)[:110]}»"
    elif kind == "NOT":
        d = f"удалён not в «{ast.unparse(n)[:110]}»"
    elif kind == "NEG":
        d = f"условие отрицается: «{ast.unparse(n.test)[:110]}»"
    elif kind == "CONST":
        d = f"константа {n.value}->{n.value + sub} в «{LINES[line - 1].strip()[:100]}»"
    elif kind == "DEL":
        d = f"удалён оператор «{ast.unparse(n)[:110]}»"
    else:
        d = f"return None вместо «{ast.unparse(n)[:110]}»"
    return {"kind": kind, "line": line, "func": n._func, "stmt_lines": [st.lineno, st.end_lineno] if st else None, "desc": d}


def apply(kind, n, sub):
    if kind == "CMP":
        n.ops[sub] = CMP_SWAP[type(n.ops[sub])]()
    elif kind == "BOOL":
        n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
    elif kind == "NOT":
        n.op = ast.UAdd()                     # заменим ниже: UAdd неприменим к bool-выражениям не всегда; см. replace
    elif kind == "NEG":
        n.test = ast.copy_location(ast.UnaryOp(op=ast.Not(), operand=n.test), n.test)
    elif kind == "CONST":
        n.value = n.value + sub
    elif kind == "RET":
        n.value = ast.copy_location(ast.Constant(value=None), n.value)


class _Replace(ast.NodeTransformer):
    def __init__(self, target, kind):
        self.target, self.kind = target, kind

    def generic_visit(self, node):
        super().generic_visit(node)
        return node

    def visit(self, node):
        if node is self.target:
            if self.kind == "NOT":
                return node.operand
            if self.kind == "DEL":
                return ast.copy_location(ast.Pass(), node)
        return super().visit(node)


def mutant_code(idx):
    tree = ast.parse(SRC)
    annotate(tree)
    ss = sites(tree)
    kind, n, sub = ss[idx]
    info = describe(kind, n, sub)
    if kind in ("NOT", "DEL"):
        tree = _Replace(n, kind).visit(tree)
    else:
        apply(kind, n, sub)
    ast.fix_missing_locations(tree)
    return compile(tree, "validator_mut", "exec"), info


def load(code):
    mod = types.ModuleType("validator_mut")
    mod.__file__ = str(HERE / "validator.py")
    exec(code, mod.__dict__)
    return mod


CASES = BASELINE = COVER = None


def full(r):
    return ([(e["code"], e["ref"], e["msg"]) for e in r.errors], [(w["code"], w["ref"], w["msg"]) for w in r.warnings])


def author_ok(r, v):
    if v is None:
        return r.errors == [] and [w["code"] for w in r.warnings] == ["CONTRADICTION_SINGLE_VALUED"]
    return r.codes() == v["expected"] and (v["warn"] is None or [w["code"] for w in r.warnings] == v["warn"])


def worker(idx, q):
    t0 = time.time()
    try:
        code, info = mutant_code(idx)
    except Exception as ex:  # noqa: BLE001
        q.put({"idx": idx, "status": "BUILD_ERROR", "err": repr(ex)})
        return
    res = dict(info, idx=idx)
    try:
        mod = load(code)
    except Exception as ex:  # noqa: BLE001
        res.update(status="KILLED", by="(не загружается: %s)" % type(ex).__name__, secs=time.time() - t0)
        q.put(res)
        return
    sl = info["stmt_lines"]
    module_level = info["func"] is None
    rel = []
    for n, (v, ds, tr, ct) in enumerate(CASES):
        vid = v["id"] if v else "BASE"
        if module_level or any(l in COVER[vid] for l in range(sl[0], sl[1] + 1)):
            rel.append(n)
    res["relevant_vectors"] = len(rel)
    strict_diff = []
    for n in rel:
        v, ds, tr, ct = CASES[n]
        vid = v["id"] if v else "BASE"
        try:
            r = mod.validate(ds, tr, ct)
        except BaseException as ex:  # noqa: BLE001
            res.update(status="KILLED", by=f"{vid}(исключение {type(ex).__name__})", secs=time.time() - t0)
            q.put(res)
            return
        if not author_ok(r, v):
            res.update(status="KILLED", by=vid, secs=time.time() - t0)
            q.put(res)
            return
        fr = full(r)
        if [list(map(list, fr[0])), list(map(list, fr[1]))] != BASELINE[vid]:
            strict_diff.append(vid)
    res.update(status="SURVIVED", strict_diff=strict_diff[:12], strict_diff_n=len(strict_diff), secs=time.time() - t0)
    q.put(res)


def main():
    global CASES, BASELINE, COVER
    tree = ast.parse(SRC)
    annotate(tree)
    ss = sites(tree)
    if sys.argv[1] == "list":
        import collections
        print("точек мутации всего:", len(ss))
        print(collections.Counter(k for k, _, _ in ss))
        print("в функциях:", sum(1 for _, n, _ in ss if n._func), "на уровне модуля:", sum(1 for _, n, _ in ss if not n._func))
        print("разных строк с точками мутации:", len({n.lineno for _, n, _ in ss}))
        return
    TIMEOUT = 420
    if sys.argv[1] == "rel":        # все границы: <, <=, >, >= (каждая точка), без выборки
        J = int(sys.argv[2]) if len(sys.argv) > 2 else 2
        sample = [i for i, (k, n, sub) in enumerate(ss) if k == "CMP" and isinstance(n.ops[sub], (ast.Lt, ast.LtE, ast.Gt, ast.GtE))]
        seed, N = "rel", len(sample)
        out_path = FIND / "auto_mutants_rel.jsonl"
    elif sys.argv[1] == "lines":      # целевой прогон: все точки мутации (кроме CONST) на указанных строках
        want = {int(x) for x in sys.argv[2].split(",")}
        J = int(sys.argv[3]) if len(sys.argv) > 3 else 2
        kinds = set(sys.argv[4].split(",")) if len(sys.argv) > 4 else {"CMP", "BOOL", "NOT", "NEG", "DEL", "RET"}
        sample = [i for i, (k, n, sub) in enumerate(ss) if n.lineno in want and k in kinds]
        seed, N = "targeted", len(sample)
        out_path = FIND / "auto_mutants_targeted.jsonl"
    else:
        seed, N = int(sys.argv[2]), int(sys.argv[3])
        J = int(sys.argv[4]) if len(sys.argv) > 4 else 2
        out_path = FIND / f"auto_mutants_seed{seed}.jsonl"
        rng = random.Random(seed)
        pop = list(range(len(ss)))
        if len(sys.argv) > 5:           # только указанные виды мутаций (например, без CONST)
            kinds = set(sys.argv[5].split(","))
            pop = [i for i in pop if ss[i][0] in kinds]
            out_path = FIND / f"auto_mutants_seed{seed}_{'-'.join(sorted(kinds))}.jsonl"
        sample = rng.sample(pop, N)
    done = set()
    if out_path.exists():
        done = {json.loads(x)["idx"] for x in out_path.read_text(encoding="utf-8").splitlines() if x.strip()}
    if sys.argv[1] == "rel":        # уже прогнанные в других файлах точки не повторяем (сводка объединяет по idx)
        for other in FIND.glob("auto_mutants_*.jsonl"):
            done |= {json.loads(x)["idx"] for x in other.read_text(encoding="utf-8").splitlines() if x.strip()}
    todo = [i for i in sample if i not in done]
    print(f"sites={len(ss)} sample={N} todo={len(todo)}", flush=True)
    from vectors import VECTORS, build
    CASES = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
    COVER = {k: set(v) for k, v in json.load(open(FIND / "coverage.json")).items()}
    BASELINE = json.load(open(FIND / "baseline.json"))
    BASELINE = {k: [v["errors"], v["warnings"]] for k, v in BASELINE.items()}
    running = []
    fout = open(out_path, "a", encoding="utf-8")
    ctx = mp.get_context("fork")

    def reap(block):
        nonlocal running
        while True:
            still = []
            for p, q, idx, t0 in running:
                if not q.empty():
                    r = q.get()
                    p.join()
                elif not p.is_alive():
                    try:
                        r = q.get(timeout=2)
                    except Exception:  # noqa: BLE001
                        r = {"idx": idx, "status": "KILLED", "by": "(процесс упал)", **describe(*ss[idx])}
                elif time.time() - t0 > TIMEOUT:
                    p.terminate()
                    r = {"idx": idx, "status": "KILLED", "by": "(таймаут: зацикливание)", **describe(*ss[idx])}
                else:
                    still.append((p, q, idx, t0))
                    continue
                fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                fout.flush()
                print(f"{r['idx']:>5} {r['status']:<9} {r.get('by', '') or ''} L{r.get('line')} {r.get('kind')} {r.get('desc', '')[:120]}"
                      + (f"  [строгая разница на {r['strict_diff_n']} векторах]" if r["status"] == "SURVIVED" else ""), flush=True)
            running = still
            if not block or len(running) < J:
                return
            time.sleep(0.5)

    for idx in todo:
        reap(True)
        q = ctx.Queue()
        p = ctx.Process(target=worker, args=(idx, q))
        p.start()
        running.append((p, q, idx, time.time()))
    while running:
        reap(False)
        time.sleep(0.5)


if __name__ == "__main__":
    main()

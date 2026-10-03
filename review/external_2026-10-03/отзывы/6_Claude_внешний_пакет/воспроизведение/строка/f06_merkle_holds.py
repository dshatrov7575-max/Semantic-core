"""Проверено, держит: структура дерева при ФИКСИРОВАННОМ честном манифесте (подмена узла/листа, позиции, колонки,
дублирование последнего узла, кодирование типов). Прямые вызовы validator.row_evidence_error и полная validate."""
import random, unicodedata
from _h import *
rng = random.Random(7)
rows = [{"ogrn": FX.ogrn("1027%08d" % i), "inn": FX.inn10("7707%05d" % i), "name": f"ООО {i}", "address": f"адрес {i}", "director": None,
         "registered_on": "2020-01-01", "active": True, "employees": i} for i in range(23)]
rows[0].update(REGISTRY_ROWS[0])
dv = demo_registry(rows=rows, chunk_rows=7)          # файлы по 7, 7, 7, 2 строки
m = dv.manifest
C = {"predicate": "entity.registered_address", "object": {"literal": {}}}
def ok(ev, addr):
    return row_evidence_error(ev, m, C, {"type": "STRING", "value": addr}, None, None) is None
keys = [r["ogrn"] for r in rows]
base = {k: dv.evidence([k], ["address"]) for k in keys}
addr = {r["ogrn"]: r["address"] for r in rows}
assert all(ok(base[k], addr[k]) for k in keys)
n_try = n_acc = 0
def t(ev, a):
    global n_try, n_acc
    n_try += 1
    try:
        r = ok(ev, a)
    except Exception:
        r = False
    n_acc += r
# 1) позиция: доказательство строки i как строка j / в другом файле / с лишним, коротким, переставленным путём
for k in keys:
    e0 = base[k]
    for f in range(4):
        for i in range(8):
            if (f, i) != (e0["proof"]["file"], e0["proof"]["index"]):
                e = copy.deepcopy(e0); e["proof"].update(file=f, index=i); t(e, addr[k])
    for mut in (lambda h: h[:-1], lambda h: h + [h[-1]] if h else ["00" * 32], lambda h: h[::-1] if len(set(h)) > 1 else h[:-1], lambda h: h[1:] + h[:1] if len(set(h)) > 1 else h + h):
        e = copy.deepcopy(e0); e["proof"]["hashes"] = mut(e["proof"]["hashes"])
        if e != e0: t(e, addr[k])
# 2) внутренний узел дерева строк как строка; лист строки как row_sha256; узел дерева ячеек как row_sha256
part = [row_leaf(x[3]) for x in dv.rows[:7]]
inner = merkle_root(part[:4])
for fake in (inner, part[0], merkle_root(part[:2])):
    e = copy.deepcopy(base[keys[0]]); e["row_sha256"] = fake.hex(); t(e, addr[keys[0]])
    e["proof"] = {"file": 0, "index": 0, "hashes": [merkle_root(part[4:]).hex()]}; t(e, addr[keys[0]])
# 3) колонка A как колонка B: перестановка ячеек, переименование процитированной, значение одной под именем другой
e0 = dv.evidence([keys[0]], ["address", "name"])
for a, b in ((2, 3), (0, 3), (3, 4)):
    e = copy.deepcopy(e0); e["cells"][a], e["cells"][b] = e["cells"][b], e["cells"][a]; t(e, addr[keys[0]]); t(e, rows[0]["name"])
    e = copy.deepcopy(e0); e["cells"][a]["name"], e["cells"][b]["name"] = e["cells"][b]["name"], e["cells"][a]["name"]; t(e, addr[keys[0]]); t(e, rows[0]["name"])
# 4) чужая строка того же файла с ячейками этой
e = copy.deepcopy(base[keys[1]]); e["cells"] = copy.deepcopy(base[keys[0]]["cells"]); t(e, addr[keys[0]])
e = copy.deepcopy(base[keys[1]]); e["cells"][3]["value"] = addr[keys[0]]; t(e, addr[keys[0]])
print(f"подделок предъявлено {n_try}, принято {n_acc}")
# 5) дублирование последнего узла (CVE-2012-2459): корни n и n+1 листьев с повтором последнего различны для всех n
L = [hashlib.sha256(b"%d" % i).digest() for i in range(70)]
print("корень(n листьев) == корень(n листьев + повтор последнего):", sum(merkle_root(L[:n]) == merkle_root(L[:n] + [L[n - 1]]) for n in range(1, 70)), "из 69")
# 6) кодирование листа: значения разных типов и форм дают разные листья
salt = bytes(32)
vals = ["1", 1, True, None, "", "null", "true", "é", unicodedata.normalize("NFD", "é"), "2021-02-12", " 1", "1 ", "1​"]
leaves = {cell_leaf(salt, "a", v).hex() for v in vals}
print("различных листьев:", len(leaves), "из", len(vals), "| canon:", [canon(["a", v]) for v in vals[:6]])
# 7) соль не 32 байта (сдвиг границы соль/JCS) и ячейка с лишними полями — отказ схемы
for tag, patch in (("соль 31 байт", lambda c: c.__setitem__("salt", c["salt"][:62])), ("соль 33 байта", lambda c: c.__setitem__("salt", c["salt"] + "5b")),
                   ("и leaf, и salt", lambda c: c.__setitem__("leaf", "00" * 32)), ("значение-объект", lambda c: c.__setitem__("value", {"a": 1}))):
    def pre(W, patch=patch):
        W["c50"]["_ev_patch"] = lambda evs: patch(evs[0]["cells"][3])
    R, *_ = run(pre)
    print(f"   {tag}: {R.codes()}")

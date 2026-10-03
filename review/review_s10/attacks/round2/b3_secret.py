#!/usr/bin/env python3
"""S10R раунд 2 / производный секрет строки (dataset.row_secret = HMAC(ключ набора, ключ строки)[:16]): что раскрывается
между версиями и между строками. Ключ набора — СЛУЧАЙНЫЙ (os.urandom), атакующий его не знает."""
from r2common import *
from s10_tests import copy_file
from validator import cell_leaf, cell_salt
import itertools
K = os.urandom(32)
INT = {"level": "INTERNAL", "categories": []}; PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
def ver(label, rows, cols=None):
    return DatasetVersion("dst_rev_secret", T, label, cols or REGISTRY_COLUMNS, ["ogrn"], rows, chunk_rows=4, subject=("ogrn", "inn"), dataset_key=K)
stamp = utc(0)
v1 = ver("v1 " + stamp, REGISTRY_ROWS)
rows2 = copy.deepcopy(REGISTRY_ROWS); rows2[0]["director"] = "Седов Пётр Ильич"; rows2[0]["employees"] = 51          # у девелопера сменился директор и штат
v2 = ver("v2 " + stamp, rows2)
leaf = lambda ev, n: next(c for c in ev["cells"] if c["name"] == n).get("leaf")
print("== 1. Секрет строки зависит только от ключа строки: соли одной строки одинаковы во ВСЕХ версиях")
s1, s2 = v1.rows[v1.where[canon([OGRN_DEV])]][2], v2.rows[v2.where[canon([OGRN_DEV])]][2]
print("   секрет строки девелопера в v1 == в v2:", s1 == s2, "(содержимое строки изменилось: директор и число работников)")
print("== 2. Наблюдатель БЕЗ допуска к колонке видит, изменилась ли скрытая ячейка между версиями (сравнение листьев двух доказательств)")
for key, who in [([OGRN_DEV], "девелопер (директор сменился)"), ([OGRN_TRUB], "Трубопроводстрой (директор тот же)")]:
    a, b = v1.evidence(key, ["address"]), v2.evidence(key, ["address"])
    print(f"   {who}: лист director v1 == v2: {leaf(a, 'director') == leaf(b, 'director')}; лист employees v1 == v2: {leaf(a, 'employees') == leaf(b, 'employees')}")
print("== 3. Читатель, которому колонка была открыта в v1, вскрывает её в v2 после повышения маркировки (соль та же)")
cols2 = copy.deepcopy(REGISTRY_COLUMNS)
for c in cols2:
    if c["name"] == "employees": c["marking"] = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}        # в v2 колонку закрыли
v2c = ver("v2 закрытая колонка " + stamp, rows2, cols2)
for v in (v1, v2c):
    r = db_try([source_rec(v)], commit=True); assert r.returncode == 0, first_err(r)
    t, bad = D.load_rows(T, v.source_id, copy_file(v), v.columns); assert bad is None, first_err(bad)
WHO = "ac_rd_cs"                                                # CONFIDENTIAL + COMMERCIAL_SECRET, без PERSONAL_DATA
key = f"'[\"{OGRN_DEV}\"]'"
e1 = json.loads(psql(f"SELECT ac.dataset_evidence('{PRJ}', '{v1.source_id}', {key}, ARRAY['employees']);", WHO).stdout)
salt = next(c for c in e1["cells"] if c["name"] == "employees")
print("   v1: читателю", WHO, "колонка employees открыта (INTERNAL): значение", salt["value"], ", соль получена из ac.dataset_evidence")
r2 = json.loads(psql(f"SELECT ac.dataset_row('{PRJ}', '{v2c.source_id}', {key});", WHO).stdout)
print("   v2: колонка закрыта (CONFIDENTIAL+PERSONAL_DATA): ac.dataset_row -> withheld =", r2["withheld"])
e2 = json.loads(psql(f"SELECT ac.dataset_evidence('{PRJ}', '{v2c.source_id}', {key}, ARRAY['address']);", WHO).stdout)
target = leaf(e2, "employees")
found = next((n for n in range(0, 100000) if cell_leaf(bytes.fromhex(salt["salt"]), "employees", n).hex() == target), None)
print("   лист employees из доказательства v2 + соль из v1 -> перебор 0…99999: employees в v2 =", found, "| истина:", rows2[0]["employees"])
print("== 4. Между строками: секреты разных строк независимы (HMAC по ключу строки)")
print("   различных секретов на", len(v1.rows), "строк:", len({x[2] for x in v1.rows}), "| соль address строки A годится для строки B:",
      cell_salt(v1.rows[0][2], "address") == cell_salt(v1.rows[1][2], "address"))
print("== 5. Набор без ключа: секрет = HMAC(ключ набора, вся строка) — неизменная строка сохраняет хэш, изменённая получает новый секрет")
n1 = DatasetVersion("dst_rev_nokey", T, "n1", REGISTRY_COLUMNS, [], REGISTRY_ROWS, dataset_key=K); n2 = DatasetVersion("dst_rev_nokey", T, "n2", REGISTRY_COLUMNS, [], rows2, dataset_key=K)
h1 = {x[3] for x in n1.rows}; h2 = {x[3] for x in n2.rows}
print("   общих хэшей строк у двух версий:", len(h1 & h2), "из", len(h1), "(изменилась одна строка)")
print("== 6. Демонстрационный мир: ключ набора — константа fixtures.DEMO_DATASET_KEY; атака раунда 1 с этим ключом")
import fixtures
dv = demo_registry(); row0 = dv.rows[dv.where[canon([OGRN_DEV])]]
cands = [f"{a} {b} {c}" for a, b, c in itertools.product(D._SUR, D._GIV, D._PAT)]
from dataset import row_secret
sec = row_secret(fixtures.DEMO_DATASET_KEY, canon([OGRN_DEV])); tl = leaf(dv.evidence([OGRN_DEV], ["address"]), "director")
print("   с ключом из fixtures.py директор вскрывается:", [c for c in cands if cell_leaf(cell_salt(sec, "director"), "director", c).hex() == tl],
      "| без ключа (секрет по формуле раунда 1) —", [c for c in cands if cell_leaf(cell_salt(hashlib.sha256(('demo-row-secret:' + json.dumps([c if n == 'director' else REGISTRY_ROWS[0][n] for n in dv.names], ensure_ascii=False)).encode()).digest()[:16], 'director'), 'director', c).hex() == tl])

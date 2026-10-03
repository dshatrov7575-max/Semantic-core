#!/usr/bin/env python3
"""S10R / направление 5: восстановление скрытой ячейки (директор, ПД) читателем без категории PERSONAL_DATA.
В демонстрационном мире секрет строки выводится из её содержимого (fixtures.demo_registry: sha256("demo-row-secret:"+json(values))[:16]),
а не случаен, поэтому лист скрытой ячейки и любая процитированная соль — оракул для перебора."""
from common import *
from s10_tests import copy_file
import itertools, time
from validator import cell_leaf
dv = demo_registry()                                   # версия s30 мира
if not psql(f"SELECT 1 FROM ac.dataset_tables WHERE source_id = '{dv.source_id}' AND sealed_at IS NOT NULL").stdout.strip():
    t, bad = D.load_rows(T, dv.source_id, copy_file(dv), dv.columns); assert bad is None, first_err(bad)
WHO = "ac_rd_cs"                                       # допуск CONFIDENTIAL + COMMERCIAL_SECRET, без PERSONAL_DATA
key = f"'[\"{OGRN_DEV}\"]'"
row = json.loads(psql(f"SELECT ac.dataset_row('{PRJ}', '{dv.source_id}', {key});", WHO).stdout)
print("читатель", WHO, "видит ячейки:", json.dumps(row["cells"], ensure_ascii=False)); print("скрыто от него:", row["withheld"])
ev = json.loads(psql(f"SELECT ac.dataset_evidence('{PRJ}', '{dv.source_id}', {key}, ARRAY['address']);", WHO).stdout)
target = next(c for c in ev["cells"] if c["name"] == "director")
print("доказательство от базы: ячейка director =", target)
names = [c["name"] for c in dv.columns]
# словарь: фамилии × имена × отчества (списки синтетического реестра slice/dataset_s10.py) — 480 кандидатов
cands = [f"{a} {b} {c}" for a, b, c in itertools.product(D._SUR, D._GIV, D._PAT)] + [None]
t0 = time.time(); found = None; tried = 0
for cand in cands:
    tried += 1
    vals = [cand if n == "director" else row["cells"][n] for n in names]
    secret = hashlib.sha256(("demo-row-secret:" + json.dumps(vals, ensure_ascii=False)).encode()).digest()[:16]
    if cell_leaf(cell_salt(secret, "director"), "director", cand).hex() == target["leaf"]:
        found = cand; break
print(f"перебор: {tried} кандидатов за {time.time() - t0:.3f} с -> скрытая ячейка director = {found!r}")
truth = REGISTRY_ROWS[0]["director"]
print("истинное значение в реестре:", repr(truth), "| ВОССТАНОВЛЕНО" if found == truth else "| не восстановлено")
# то же по одной лишь процитированной соли (без листа): соль ogrn выдаёт секрет на проверку
salt_ogrn = next(c for c in ev["cells"] if c["name"] == "ogrn")["salt"]
hit = [c for c in cands if cell_salt(hashlib.sha256(("demo-row-secret:" + json.dumps([c if n == "director" else row["cells"][n] for n in names],
       ensure_ascii=False)).encode()).digest()[:16], "ogrn").hex() == salt_ogrn]
print("по процитированной соли колонки ogrn (лист не нужен):", hit)
# контроль: при случайном секрете тот же перебор ничего не даёт
dr = DatasetVersion("dst_registry_demo", T, "rev-a5-random", dv.columns, ["ogrn"], REGISTRY_ROWS, chunk_rows=4, subject=("ogrn", "inn"))
evr = dr.evidence([OGRN_DEV], ["address"]); tl = next(c for c in evr["cells"] if c["name"] == "director")["leaf"]
hitr = [c for c in cands if cell_leaf(cell_salt(hashlib.sha256(("demo-row-secret:" + json.dumps([c if n == "director" else REGISTRY_ROWS[0][n] for n in names],
        ensure_ascii=False)).encode()).digest()[:16], "director"), "director", c).hex() == tl]
print("контроль (секрет os.urandom(16), производитель по умолчанию): найдено", hitr)
# без базы вовсе: доказательство c50 из набора записей + открытые сведения реестра
ds = world()[0]
c50 = next(r for r in ds["records"] if r["kind"] == "Claim" and r["evidence"][0].get("kind") == "ROW")
leaf50 = next(c for c in c50["evidence"][0]["cells"] if c["name"] == "director")["leaf"]
print("лист director в теле утверждения c50 мира совпадает с выданным базой:", leaf50 == target["leaf"])
print("секреты измерительного набора (dataset_s10.measure): sha256('measure-secret:%d' % номер строки)[:16] — выводятся из номера строки")

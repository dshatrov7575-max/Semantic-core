#!/usr/bin/env python3
"""S10R раунд 2 / проверка файлов версии в валидаторе (dataset_file_error) и длины файла в базе.
1) эквивалентность MR84 и MR87 — свидетели; 2) что принимается лишнего: ключ повторяется в ДВУХ файлах, один файл дважды, порядок между файлами;
3) что отвергается зря; 4) набор без ключа, пустой файл; 5) большие файлы — время; 6) база: длина файла и порядок прихода объекта."""
from r2common import *
import mutants as MU
from validator import merkle_root, row_leaf
OBS = "2026-09-05T08:00:00Z"
def version(dv, label, files=None, **patch):
    m = copy.deepcopy(dv.manifest); m["version_label"] = label
    if files is not None: m["files"] = files; m["row_count"] = sum(f["rows"] for f in files)
    m.update(patch)
    class X: pass
    x = X(); x.manifest = m; x.manifest_bytes = canon(m).encode(); x.source_id = "src:sha256:" + hashlib.sha256(x.manifest_bytes).hexdigest(); return x
def val(mod, records, content):
    ds, tr, ct = world(); ds["records"] += copy.deepcopy(records); ct.update(content)
    rep = mod.validate(ds, tr, ct)
    return "ПРИНЯТО" if not rep.errors else "ОТКАЗ " + ",".join(rep.codes()) + ": " + rep.errors[0]["msg"][:90]
def mutant(mid):
    m = next(x for x in MU.M if x[0] == mid); assert MU.SRC.count(m[2]) == 1; return MU.load(MU.SRC.replace(m[2], m[3])), m[1]
def witness(mid, desc, records, content):
    mod, what = mutant(mid); a, b = val(VAL, records, content), val(mod, records, content)
    print(f"{mid} «{what}» — заявлен эквивалентным\n   свидетель: {desc}\n   валидатор: {a}\n   мутант:    {b}\n   => {'НЕ ЭКВИВАЛЕНТЕН' if a.split()[0] != b.split()[0] else 'различия нет'}")
dv = demo_registry(chunk_rows=4096)                      # один файл из 5 строк
addr, data = dv.files[0]
print("== 1. Свидетели эквивалентности")
# MR87: манифест объявляет rows = 6 (и row_count = 6), файл и корень — от 5 строк
f = dict(dv.manifest["files"][0], rows=6)
x = version(dv, "rev-b2 mr87", files=[f])
witness("MR87", "манифест: rows = 6, row_count = 6; файл в хранилище — 5 строк, rows_root — корень этих 5 строк", [source_rec(x, observed=OBS)], {addr: data})
# MR84: адрес в манифесте — не sha256 байтов (опечатка в адресе), хранилище под этим адресом отдаёт верный файл той же длины
bad = "sha256:" + "ab" * 32
x2 = version(dv, "rev-b2 mr84", files=[dict(dv.manifest["files"][0], object=bad)])
witness("MR84", "адрес файла в манифесте не равен sha256 его байтов; хранилище под этим адресом отдаёт сами байты (верные строки, верный корень, та же длина)",
        [source_rec(x2, observed=OBS)], {bad: data})
print("== 2. Что принимается лишнего")
d2 = demo_registry(chunk_rows=3)                          # файлы: 3 строки + 2 строки
(a0, b0), (a1, b1) = d2.files
x3 = version(d2, "rev-b2 один файл дважды", files=[d2.manifest["files"][0], d2.manifest["files"][0]])
print("   один и тот же файл назван в манифесте дважды (каждый ключ — в двух «файлах»): валидатор —", val(VAL, [source_rec(x3, observed=OBS)], {a0: b0})[:110])
x4 = version(d2, "rev-b2 файлы в обратном порядке", files=d2.manifest["files"][::-1])
print("   файлы в обратном порядке ключей (порядок МЕЖДУ файлами): валидатор —", val(VAL, [source_rec(x4, observed=OBS)], dict(d2.files))[:110])
# два разных файла с одним ключом и РАЗНЫМ содержимым строки
alt = demo_registry(chunk_rows=3, rows=[dict(REGISTRY_ROWS[0], address="г. Другой, ул. Вторая, д. 2")] + REGISTRY_ROWS[1:])
k0 = next(i for i, f in enumerate(alt.manifest["files"]) if any(OGRN_DEV in ln for ln in alt.files[i][1].decode().splitlines()))
k1 = next(i for i, f in enumerate(d2.manifest["files"]) if any(OGRN_DEV in ln for ln in d2.files[i][1].decode().splitlines()))
x5 = version(d2, "rev-b2 ключ в двух файлах с разным содержимым", files=[d2.manifest["files"][k1], alt.manifest["files"][k0]])
ct5 = {d2.files[k1][0]: d2.files[k1][1], alt.files[k0][0]: alt.files[k0][1]}
print("   ключ", OGRN_DEV, "в двух файлах версии с РАЗНЫМ адресом в строке: валидатор —", val(VAL, [source_rec(x5, observed=OBS)], ct5)[:110])
e1 = d2.evidence([OGRN_DEV], ["address"]); e1["source_id"] = x5.source_id; e1["proof"]["file"] = 0
e2 = alt.evidence([OGRN_DEV], ["address"]); e2["source_id"] = x5.source_id; e2["proof"]["file"] = 1
c1 = mk_claim(e1, recorded="2026-09-26T09:00:00Z")
c2 = mk_claim(e2, obj={"literal": {"type": "STRING", "value": "г. Другой, ул. Вторая, д. 2"}}, recorded="2026-09-26T09:00:01Z")
print("   два утверждения с одним row_key и разными адресами, оба «доказаны» строкой этой версии: валидатор —", val(VAL, [source_rec(x5, observed=OBS), c1, c2], ct5)[:110])
r = db_try([source_rec(x5)], commit=True); print("   база: регистрация такой версии —", verdict(r)[:60])
time.sleep(1.2)
print("   база: оба утверждения —", verdict(db_try([mk_claim(copy.deepcopy(e1)), mk_claim(copy.deepcopy(e2), obj={"literal": {"type": "STRING", "value": "г. Другой, ул. Вторая, д. 2"}})]))[:60])
print("== 3. Что отвергается зря")
rows_int = [dict(r, employees=n) for r, n in zip(copy.deepcopy(REGISTRY_ROWS), [2, 10, 33, 100, 7])]
di = demo_registry(rows=rows_int, key=("employees",), subject=("ogrn",), chunk_rows=4096)
order = [json.loads(l)["k"][0] for l in di.files[0][1].decode().splitlines()]
print("   ключ — целая колонка: производитель dataset.py кладёт строки в порядке", order, "(порядок строк JCS, не числовой)")
lines = sorted(di.files[0][1].decode().splitlines(), key=lambda l: json.loads(l)["k"][0])
nb = ("\n".join(lines) + "\n").encode(); hs = [bytes.fromhex(json.loads(l)["h"]) for l in lines]
fn = {"object": "sha256:" + hashlib.sha256(nb).hexdigest(), "byte_length": len(nb), "rows": len(lines), "rows_root": merkle_root([row_leaf(h) for h in hs]).hex()}
xn = version(di, "rev-b2 числовой порядок", files=[fn])
print("   тот же файл в ЧИСЛОВОМ порядке ключа", sorted(order), ": валидатор —", val(VAL, [source_rec(xn, observed=OBS)], {fn["object"]: nb})[:120])
r = db_try([source_rec(xn)], commit=True)
from s10_tests import copy_file
class P: pass
p = P(); p.chunk_rows = 4096; p.rows = [(None, json.loads(l)["k"], bytes.fromhex(json.loads(l)["s"]), bytes.fromhex(json.loads(l)["h"]), json.loads(l)["v"]) for l in lines]
t, badl = D.load_rows(T, xn.source_id, copy_file(p), di.columns)
print("   база: та же версия (числовой порядок) зарегистрирована:", verdict(r)[:30], "| загрузка и печать:", "ок" if badl is None else first_err(badl)[:100])
print("== 4. Набор без ключа; пустой файл; часть файлов в хранилище")
dk = demo_registry(key=(), chunk_rows=4096)
print("   набор без ключа, файл в хранилище: валидатор —", val(VAL, [source_rec(version(dk, "rev-b2 без ключа"), observed=OBS)], dict(dk.files))[:60])
xe = version(dv, "rev-b2 пустой файл", files=[dict(dv.manifest["files"][0], object="sha256:" + hashlib.sha256(b"").hexdigest(), byte_length=1)])
print("   адрес файла = sha256 пустых байтов, в хранилище пустой объект: валидатор —", val(VAL, [source_rec(xe, observed=OBS)], {"sha256:" + hashlib.sha256(b"").hexdigest(): b""})[:110])
print("   два файла, в хранилище только второй и он испорчен: валидатор —", val(VAL, [source_rec(version(d2, "rev-b2 часть"), observed=OBS)], {a1: b1[:-2] + b"x\n"})[:110])
print("   два файла, в хранилище нет ни одного: валидатор —", val(VAL, [source_rec(version(d2, "rev-b2 нет файлов"), observed=OBS)], {})[:40])
print("== 5. Большой файл: время проверки валидатором")
big = [dict(REGISTRY_ROWS[0], ogrn="1%012d" % i, inn=None) for i in range(20000)]
t0 = time.time(); db_ = DatasetVersion("dst_rev_big", T, "big", REGISTRY_COLUMNS, ["ogrn"], big, chunk_rows=10 ** 9, subject=("ogrn",)); tb = time.time() - t0
t0 = time.time(); why = VAL.dataset_file_error(db_.manifest, db_.manifest["files"][0], db_.files[0][1]); tv = time.time() - t0
print(f"   20 000 строк × 8 колонок в одном файле ({len(db_.files[0][1]) / 2 ** 20:.1f} МБ): сборка {tb:.1f} с, dataset_file_error {tv:.1f} с ({why}); на 1 млн строк ≈ {tv * 50 / 60:.1f} мин")
print("== 6. База: длина файла в манифесте и порядок прихода объекта в хранилище")
dz = relabel(demo_registry(chunk_rows=4096, rows=[dict(REGISTRY_ROWS[0], employees=4242)] + REGISTRY_ROWS[1:]), "rev-b2 len " + utc(0))
za, zb = dz.files[0]
def reg_obj(tenant, a, n): return psql(f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('{tenant}', '{a}', {n});", "ac_gateway" if False else None)
def as_gateway(sql):
    env = dict(os.environ, PGUSER="ac_gateway"); return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True, env=env)
xw = version(dz, "rev-b2 неверная длина, объект позже " + utc(0), files=[dict(dz.manifest["files"][0], byte_length=len(zb) + 7)])
print("   валидатор (файл в хранилище, длина в манифесте на 7 больше):", val(VAL, [source_rec(xw, observed=OBS)], {za: zb})[:110])
print("   база, порядок 1: манифест с неверной длиной —", verdict(db_try([source_rec(xw)], commit=True))[:40], end="")
r = as_gateway(f"BEGIN; INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('{T}', '{za}', {len(zb)}); INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('{T}', '{za}', 'OK'); COMMIT;")
print("; затем шлюз регистрирует объект с настоящей длиной —", verdict(r)[:60])
print("      в базе:", psql(f"SELECT 'длина в манифесте ' || (manifest->'files'->0->>'byte_length') || ', длина объекта ' || o.byte_length FROM ac.datasets d JOIN ac.objects o ON o.object_address = d.manifest->'files'->0->>'object' WHERE d.source_id = '{xw.source_id}'").stdout.strip())
xw2 = version(dz, "rev-b2 неверная длина, объект раньше " + utc(0), files=[dict(dz.manifest["files"][0], byte_length=len(zb) + 9)])
print("   база, порядок 2: объект уже есть, манифест с неверной длиной —", verdict(db_try([source_rec(xw2)], commit=True))[:150])
r = psql(f"SELECT ac.dataset_info('{PRJ}', '{xw.source_id}')->'files';", "ac_rd_full"); print("   ac.dataset_info о файлах версии с неверной длиной:", (r.stdout.strip() or first_err(r))[:200])

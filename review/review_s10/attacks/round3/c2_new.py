#!/usr/bin/env python3
"""S10R раунд 3 / новое: секрет строки от всех значений; дубликаты у набора без ключа; единственность ключа (валидатор, печать);
LENGTH_MISMATCH; поле proves; время проверки файла."""
import os, sys
os.environ.setdefault("S10_SNAP", "/home/claude/as/review/review_s10/snapshot3"); os.environ.setdefault("PGDATABASE", "review10_3a")
sys.path.insert(0, "/home/claude/as/review/review_s10/attacks/round2")
from r2common import *
from s10_tests import copy_file
from validator import cell_leaf, cell_salt, merkle_root, row_leaf
from dataset import row_secret
K = os.urandom(32); stamp = utc(0); OBS = "2026-09-05T08:00:00Z"
def ver(label, rows, cols=None, key=("ogrn",), did="dst_rev_secret3"):
    return DatasetVersion(did, T, label, cols or REGISTRY_COLUMNS, list(key), rows, chunk_rows=4, subject=("ogrn", "inn"), dataset_key=K)
leaf = lambda ev, n: next(c for c in ev["cells"] if c["name"] == n).get("leaf")
print("== 1. Секрет строки = HMAC(ключ набора, все значения): между версиями")
rows2 = copy.deepcopy(REGISTRY_ROWS); rows2[0]["director"] = "Седов Пётр Ильич"
v1, v2 = ver("v1 " + stamp, REGISTRY_ROWS), ver("v2 " + stamp, rows2)
a, b = v1.evidence([OGRN_DEV], ["address"]), v2.evidence([OGRN_DEV], ["address"])
print("   девелопер (сменился только директор): совпадающих листьев скрытых ячеек v1/v2:", sum(leaf(a, n) == leaf(b, n) for n in v1.names if leaf(a, n)), "из", sum(1 for n in v1.names if leaf(a, n)),
      "| соль процитированной address та же:", a["cells"][3]["salt"] == b["cells"][3]["salt"])
a, b = v1.evidence([OGRN_TRUB], ["address"]), v2.evidence([OGRN_TRUB], ["address"])
print("   Трубопроводстрой (строка не менялась): хэш строки тот же:", a["row_sha256"] == b["row_sha256"])
cols2 = copy.deepcopy(REGISTRY_COLUMNS)
for c in cols2:
    if c["name"] == "employees": c["marking"] = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
rows3 = copy.deepcopy(REGISTRY_ROWS); rows3[0]["employees"] = 51
v3 = ver("v3 закрытая колонка " + stamp, rows3, cols2)
salt_old = next(c for c in v1.evidence([OGRN_DEV], ["employees"])["cells"] if c["name"] == "employees")["salt"]
tgt = leaf(v3.evidence([OGRN_DEV], ["address"]), "employees")
print("   атака раунда 2 (соль employees из v1, лист из v3, где значение 51 и колонка закрыта): найдено", next((n for n in range(100000) if cell_leaf(bytes.fromhex(salt_old), "employees", n).hex() == tgt), None))
print("== 2. Между строками и наборами")
print("   различных секретов на 5 строк:", len({x[2] for x in v1.rows}))
twin = ver("twin", REGISTRY_ROWS, did="dst_rev_other_set")
print("   тот же ключ набора в ДРУГОМ наборе с теми же строками: секреты совпадают:", [x[2] for x in twin.rows] == [x[2] for x in v1.rows], "(идентификатор набора в секрет не входит)")
shuf = [dict(r, name=r["address"], address=r["name"]) for r in REGISTRY_ROWS[:1]]
print("   секрет не зависит от имён колонок: строка с переставленными значениями name/address даёт другой секрет:", row_secret(K, "dst_rev_secret3", [shuf[0].get(n) for n in v1.names]) != v1.rows[v1.where[canon([OGRN_DEV])]][2])
print("== 3. Набор без ключа: строки-дубликаты")
try:
    DatasetVersion("dst_rev_nokey3", T, "dup", REGISTRY_COLUMNS, [], [REGISTRY_ROWS[0], REGISTRY_ROWS[0]], dataset_key=K, subject=("ogrn",)); print("   производитель принял два одинаковых ряда")
except Exception as ex:
    print("   производитель dataset.py: две одинаковые строки —", type(ex).__name__, str(ex)[:50], "(набор без ключа с настоящими дубликатами построить нельзя)")
nk = relabel(DatasetVersion("dst_rev_nokey3", T, "nk", REGISTRY_COLUMNS, [], REGISTRY_ROWS, dataset_key=K, subject=("ogrn",), chunk_rows=4096), "rev-c2 без ключа " + stamp)
# версия без ключа, файл которой содержит одну строку дважды (корень — от этого файла)
lines = nk.files[0][1].decode().splitlines(); dl = lines + [lines[0]]
nb = ("\n".join(dl) + "\n").encode(); hs = [bytes.fromhex(json.loads(l)["h"]) for l in dl]
fn = {"object": "sha256:" + hashlib.sha256(nb).hexdigest(), "byte_length": len(nb), "rows": len(dl), "rows_root": merkle_root([row_leaf(h) for h in hs]).hex()}
m = copy.deepcopy(nk.manifest); m["files"] = [fn]; m["row_count"] = len(dl); m["version_label"] = "rev-c2 без ключа, дубль " + stamp
class X: pass
x = X(); x.manifest = m; x.manifest_bytes = canon(m).encode(); x.source_id = "src:sha256:" + hashlib.sha256(x.manifest_bytes).hexdigest(); x.columns = nk.columns
def val(records, content):
    ds, tr, ct = world(); ds["records"] += copy.deepcopy(records); ct.update(content); rep = VAL.validate(ds, tr, ct)
    return "ПРИНЯТО" if not rep.errors else "ОТКАЗ " + rep.errors[0]["msg"][:90]
print("   валидатор, файл с повторённой строкой в хранилище:", val([source_rec(x, observed=OBS)], {fn["object"]: nb}))
r = db_try([source_rec(x)], commit=True); print("   база: регистрация —", verdict(r)[:20], end="; ")
class P: pass
p = P(); p.chunk_rows = 4096; p.rows = [(None, [], bytes.fromhex(json.loads(l)["s"]), bytes.fromhex(json.loads(l)["h"]), json.loads(l)["v"]) for l in dl]
t, bad = D.load_rows(T, x.source_id, copy_file(p), nk.columns); print("загрузка и печать —", "ПРИНЯТО" if bad is None else first_err(bad)[:110])
print("== 4. Набор с ключом: повтор ключа в таблице (печать) — как было; порядок строк — больше не правило")
d2 = demo_registry(chunk_rows=3); rev = copy.deepcopy(d2.manifest); rev["files"] = rev["files"][::-1]; rev["version_label"] = "rev-c2 обратный порядок файлов " + stamp
y = X(); y.manifest = rev; y.manifest_bytes = canon(rev).encode(); y.source_id = "src:sha256:" + hashlib.sha256(y.manifest_bytes).hexdigest()
print("   файлы версии в обратном порядке, оба в хранилище: валидатор —", val([source_rec(y, observed=OBS)], dict(d2.files)))
print("== 5. LENGTH_MISMATCH")
dz = relabel(demo_registry(chunk_rows=4096, rows=[dict(REGISTRY_ROWS[0], employees=4343)] + REGISTRY_ROWS[1:]), "rev-c2 len " + stamp); za, zb = dz.files[0]
mm = copy.deepcopy(dz.manifest); mm["files"][0]["byte_length"] = len(zb) + 7; mm["version_label"] = "rev-c2 неверная длина " + stamp
z = X(); z.manifest = mm; z.manifest_bytes = canon(mm).encode(); z.source_id = "src:sha256:" + hashlib.sha256(z.manifest_bytes).hexdigest()
print("   манифест с неверной длиной —", verdict(db_try([source_rec(z)], commit=True))[:20], end="; ")
env = dict(os.environ, PGUSER="ac_gateway")
g = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=f"BEGIN; INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('{T}', '{za}', {len(zb)}); INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('{T}', '{za}', 'OK'); COMMIT;", capture_output=True, text=True, env=env)
print("объект позже —", verdict(g)[:20])
print("   ac.dataset_info:", psql(f"SELECT ac.dataset_info('{PRJ}', '{z.source_id}')->'files';", "ac_rd_full").stdout.strip()[:200])
print("   валидатор на том же (файл в хранилище):", val([source_rec(z, observed=OBS)], {za: zb}))
time.sleep(1.2)
ev = dz.evidence([OGRN_DEV], ["address"]); ev["source_id"] = z.source_id
print("   утверждение на строке версии с LENGTH_MISMATCH: база —", verdict(db_try([mk_claim(ev)]))[:40])
print("== 6. Поле proves в проекциях")
dos = psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer');", "ac_rd_full").stdout
evs = [e for s in json.loads(dos).get("sections", []) for f in s.get("facts", []) for c in f.get("claims", []) + f.get("other_claims", []) for e in c["evidence"]]
print("   в досье: доказательств-строк", sum("row_sha256" in e for e in evs), ", у них proves =", {json.dumps(e.get("proves")) for e in evs if "row_sha256" in e}, "| у цитат proves:", {json.dumps(e.get("proves")) for e in evs if "row_sha256" not in e})
print("   в ac.claim_provenance колонка proves:", psql("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'ac' AND table_name = 'claim_provenance' AND column_name = 'proves'").stdout.strip())
print("== 7. Время проверки файла валидатором (20 000 строк)")
big = [dict(REGISTRY_ROWS[0], ogrn="1%012d" % i, inn=None) for i in range(20000)]
db_ = DatasetVersion("dst_rev_big", T, "big", REGISTRY_COLUMNS, ["ogrn"], big, chunk_rows=10 ** 9, subject=("ogrn",))
t0 = time.time(); why = VAL.dataset_file_error(db_.manifest, db_.manifest["files"][0], db_.files[0][1], set()); print(f"   {time.time() - t0:.1f} с, результат {why}")

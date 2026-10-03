#!/usr/bin/env python3
"""S10R / криптография доказательства — попытки, которые НЕ удались (покрытие).
1) inclusion_root: для всех размеров 1..40, всех листьев — чужой номер, укороченный/удлинённый/переставленный путь, внутренний узел вместо листа;
   Python и SQL сверяются между собой.  2) подмены на уровне доказательства (обе стороны должны отвергнуть).  3) длина-расширение соли."""
from common import *
from validator import merkle_root, inclusion_root, row_leaf, cell_leaf
import random, time
rnd = random.Random(5)
leaf = [hashlib.sha256(b"L%d" % i).digest() for i in range(41)]
bad = tot = othersize = 0; sqlcases = []
for n in range(1, 41):
    root = merkle_root(leaf[:n])
    for i in range(n):
        p = audit_path(leaf[:n], i)
        assert inclusion_root(leaf[i], i, n, p) == root
        variants = [(leaf[i], j, n, p) for j in range(n + 3) if j != i]
        variants += [(leaf[i], i, n, p[:-1]), (leaf[i], i, n, p[1:]), (leaf[i], i, n, p + [leaf[0]]), (leaf[i], i, n, p + [root]), (leaf[i], i, n, p[::-1]) if p != p[::-1] else None,
                     (leaf[i], i, n + 1, p), (leaf[i], i, n - 1, p) if n > 1 else None, (leaf[i], i, 2 * n, p), (leaf[i], i, 2 ** 53 - 1, p)]
        if p:                                             # внутренний узел как «лист»: узел над листом i и его сосед
            node = hashlib.sha256(b"\x01" + (p[0] + leaf[i] if i & 1 or (i == n - 1 and False) else leaf[i] + p[0])).digest()
            variants += [(node, i >> 1, (n + 1) >> 1, p[1:]), (node, i, n, p[1:]), (node, i >> 1, n, p[1:])]
        for v in variants:
            if v is None: continue
            tot += 1
            r = inclusion_root(*v)
            if r == root and v[2] != n:
                othersize += 1                           # тот же корень при ДРУГОМ размере дерева (узел вместо листа или тот же путь): размер берётся из манифеста
            elif r == root and not (v[0] == leaf[i] and v[1] == i and v[3] == p):
                bad += 1; print("   совпадение корня:", "n=%d i=%d -> (idx=%d, size=%d, путь %d из %d)" % (n, i, v[1], v[2], len(v[3]), len(p)), "узел вместо листа" if v[0] != leaf[i] else "")
            if rnd.random() < 0.02: sqlcases.append((v, r))
print(f"1) inclusion_root (Python): вариантов {tot}; совпадений с корнем при размере дерева из манифеста и чужих (лист, номер, путь): {bad};")
print(f"   при ДРУГОМ размере дерева тот же корень получается в {othersize} случаях (узел как лист при вдвое меньшем размере; тот же путь при соседнем размере) —")
print("   свойство самой функции; в доказательстве размер берётся из манифеста, а лист строки — sha256(0x02‖хэш строки), узел (0x01) листом не становится (C1)")
arr = lambda xs: "ARRAY[" + ",".join("'\\x" + x.hex() + "'::bytea" for x in xs) + "]::bytea[]"
q = "\n".join(f"SELECT coalesce(encode(ac.inclusion_root('\\x{v[0].hex()}', {v[1]}, {v[2]}, {arr(v[3])}), 'hex'), 'NULL');" for v, _ in sqlcases)
out = psql(q).stdout.split()
print(f"   SQL = Python на выборке {len(sqlcases)}:", out == [(r.hex() if r else "NULL") for _, r in sqlcases])

print("2) подмены на уровне доказательства (версия зарегистрирована; ждём отказ обеих сторон)")
dv = relabel(demo_registry(chunk_rows=4096), "rev-a15 " + utc(0)); src = source_rec(dv)
ev = dv.evidence([OGRN_DEV], ["address"])
def E(fn):
    e = copy.deepcopy(ev); fn(e); return e
leaves = [row_leaf(x[3]) for x in dv.rows]
def as_node(e):                      # «строка» = внутренний узел дерева строк: row_sha256 := узел, путь укорочен
    i = e["proof"]["index"]; e["row_sha256"] = hashlib.sha256(b"\x01" + leaves[i & ~1] + leaves[i | 1]).hexdigest() if (i | 1) < len(leaves) else e["row_sha256"]
    e["proof"]["hashes"] = e["proof"]["hashes"][1:]; e["proof"]["index"] = i >> 1
def cell_node(e):                    # две соседние ячейки-листа заменены «листом» = их узлом, число ячеек меньше на одну
    c = e["cells"]; a, b = c[4], c[5]
    la = bytes.fromhex(a["leaf"]) if "leaf" in a else cell_leaf(bytes.fromhex(a["salt"]), a["name"], a["value"])
    lb = bytes.fromhex(b["leaf"]) if "leaf" in b else cell_leaf(bytes.fromhex(b["salt"]), b["name"], b["value"])
    c[4:6] = [{"name": a["name"], "leaf": hashlib.sha256(b"\x01" + la + lb).hexdigest()}]
other = relabel(demo_registry(chunk_rows=4096, rows=[dict(REGISTRY_ROWS[0], address="г. Иной, ул. Другая, д. 2")] + REGISTRY_ROWS[1:]), "rev-a15b " + utc(0))
tests = [("внутренний узел дерева строк выдан за строку", E(as_node)), ("узел дерева ячеек выдан за лист (ячеек на одну меньше)", E(cell_node)),
         ("лист процитированной ячейки посчитан без имени колонки (соль‖значение)", E(lambda e: e["cells"][3].update(salt=e["cells"][3]["salt"][::-1]))),
         ("контроль (законно): путь включения взят из версии, где изменена только ЭТА строка, — соседи те же, путь тот же", E(lambda e: e.update(proof=other.evidence([OGRN_DEV], ["address"])["proof"]))),
         ("ячейки от другой версии (другой адрес), хэш строки и путь — от этой", E(lambda e: e.update(cells=other.evidence([OGRN_DEV], ["address"])["cells"]))),
         ("хэш строки и ячейки от другой версии, путь — от этой", E(lambda e: e.update(cells=other.evidence([OGRN_DEV], ["address"])["cells"], row_sha256=other.evidence([OGRN_DEV], ["address"])["row_sha256"])))]
for n, (d, e) in enumerate(tests):
    addr = next((c.get("value") for c in e["cells"] if c["name"] == "address" and "salt" in c), REGISTRY_ROWS[0]["address"])
    both(f"C{n + 1}", d, [src, mk_claim(e, obj={"literal": {"type": "STRING", "value": addr}})], expect="accept" if d.startswith("контроль") else "refuse")
print("3) соль = sha256(0x03‖секрет‖имя) вместо HMAC проекта: расширение длины даёт соль только для «имени» с байтами дополнения SHA-256")
pad = b"\x80" + b"\x00" * 10
print("   имя-расширение содержит байт 0x80 и нули; шаблон имени колонки ^[a-z][a-z0-9_]{0,62}$ его не допускает:",
      VAL.parse_manifest(canon(dict(dv.manifest, columns=[dict(dv.manifest["columns"][0], name="ogrn\u0080")] + dv.manifest["columns"][1:])).encode())[1][:70])

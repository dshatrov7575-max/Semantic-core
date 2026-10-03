#!/usr/bin/env python3
"""S10R / направление 7: заявленная эквивалентность мутантов MR01, MR21, MR29.
Для каждого строится мутант (тем же текстом замены, что в core/mutants.py) и вход-свидетель: набор записей, на котором
нормативный валидатор и мутант дают РАЗНЫЕ вердикты. Найден свидетель — мутант не эквивалентен, а правило осталось без вектора."""
from common import *
import mutants as MU
from validator import merkle_root, row_leaf, cell_leaf

def mutant(mid):
    m = next(x for x in MU.M if x[0] == mid)
    assert MU.SRC.count(m[2]) == 1
    return MU.load(MU.SRC.replace(m[2], m[3])), m[1]

def run(mod, records):
    ds, tr, ct = world(); ds["records"] = ds["records"] + copy.deepcopy(records)
    rep = mod.validate(ds, tr, ct)
    return "ПРИНЯТО" if not rep.errors else "ОТКАЗ " + ",".join(rep.codes()) + ": " + rep.errors[0]["msg"][:70]

def show(mid, desc, records):
    mod, what = mutant(mid)
    a, b = run(VAL, records), run(mod, records)
    print(f"{mid} «{what}» — заявлен эквивалентным\n   свидетель: {desc}\n   валидатор: {a}\n   мутант:    {b}\n   => {'НЕ ЭКВИВАЛЕНТЕН' if a.split()[0] != b.split()[0] else 'различия нет'}\n")
    return a.split()[0] != b.split()[0]

# ---------- MR21: порядок ячеек. Производитель посчитал хэш строки по ячейкам в ДРУГОМ порядке, чем колонки манифеста
# (address, ogrn вместо ogrn, address) и в том же порядке привёл ячейки в доказательстве.
cols = [{"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
        {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}]
secret = b"\x11" * 16
vals = {"ogrn": OGRN_DEV, "address": REGISTRY_ROWS[0]["address"]}
order = ["address", "ogrn"]                                   # не порядок манифеста
leaves = [cell_leaf(cell_salt(secret, n), n, vals[n]) for n in order]
h = merkle_root(leaves)
man = {"manifest_format": "ac-dataset-manifest/0.1", "dataset_id": "dst_rev_mr21", "tenant_id": T, "version_label": "rev-mr21", "columns": cols, "key": ["ogrn"],
       "subject": ["ogrn"], "row_count": 1, "files": [{"object": "sha256:" + "0" * 64, "byte_length": 1, "rows": 1, "rows_root": row_leaf(h).hex()}]}
class DV: pass
dv = DV(); dv.manifest = man; dv.manifest_bytes = canon(man).encode(); dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
ev = {"kind": "ROW", "source_id": dv.source_id, "row_key": [OGRN_DEV], "row_sha256": h.hex(),
      "cells": [{"name": n, "value": vals[n], "salt": cell_salt(secret, n).hex()} for n in order], "proof": {"file": 0, "index": 0, "hashes": []}}
src = source_rec(dv, observed="2026-09-05T08:00:00Z")
ok21 = show("MR21", "хэш строки посчитан по ячейкам в порядке (address, ogrn), манифест объявляет (ogrn, address); ячейки доказательства — в порядке производителя",
            [src, mk_claim(ev, recorded="2026-09-26T09:00:00Z")])

# ---------- MR29: лишний хэш пути. Файл на деле из ДВУХ строк, а манифест объявляет rows = 1 и rows_root = корень двух листьев.
# Вторая строка «доказывается» в файле из одной строки: index 0, путь = [лист первой строки].
d2 = demo_registry(rows=REGISTRY_ROWS[:2], chunk_rows=2)
(k0, kv0, s0, h0, v0), (k1, kv1, s1, h1, v1) = d2.rows
man2 = copy.deepcopy(d2.manifest); man2["version_label"] = "rev-mr29"; man2["row_count"] = 1; man2["files"][0]["rows"] = 1
dvb = DV(); dvb.manifest = man2; dvb.manifest_bytes = canon(man2).encode(); dvb.source_id = "src:sha256:" + hashlib.sha256(dvb.manifest_bytes).hexdigest()
which = 1 if kv1 == [OGRN_DEV] else 0                          # нужна строка девелопера как ПРАВЫЙ лист
ev2 = d2.evidence([OGRN_DEV], ["address"]); ev2["source_id"] = dvb.source_id
print("   (строка девелопера — лист №", ev2["proof"]["index"], "из 2; путь производителя:", len(ev2["proof"]["hashes"]), "хэш)")
if ev2["proof"]["index"] == 1:
    ev2["proof"]["index"] = 0                                  # «единственная строка файла», путь из одного (лишнего) хэша
    ok29 = show("MR29", "манифест: rows = 1, rows_root = sha256(0x01‖лист₀‖лист₁) — корень ДВУХ строк; доказательство: index 0, путь [лист₀]",
                [source_rec(dvb, observed="2026-09-05T08:00:00Z"), mk_claim(ev2, recorded="2026-09-26T09:00:00Z")])
else:
    # девелопер оказался левым листом: берём набор, где он правый (ключ с большим ОГРН слева быть не может — переставим строки)
    rows = [dict(REGISTRY_ROWS[1], ogrn=REGISTRY_ROWS[1]["ogrn"]), REGISTRY_ROWS[0]]
    d3 = demo_registry(rows=rows, chunk_rows=2); e3 = d3.evidence([OGRN_DEV], ["address"])
    man3 = copy.deepcopy(d3.manifest); man3["version_label"] = "rev-mr29"; man3["row_count"] = 1; man3["files"][0]["rows"] = 1
    dvc = DV(); dvc.manifest = man3; dvc.manifest_bytes = canon(man3).encode(); dvc.source_id = "src:sha256:" + hashlib.sha256(dvc.manifest_bytes).hexdigest()
    e3["source_id"] = dvc.source_id; print("   лист девелопера №", e3["proof"]["index"]); e3["proof"]["index"] = 0
    ok29 = show("MR29", "манифест: rows = 1, rows_root = корень ДВУХ строк; доказательство: index 0, путь [лист соседней строки]",
                [source_rec(dvc, observed="2026-09-05T08:00:00Z"), mk_claim(e3, recorded="2026-09-26T09:00:00Z")])

# ---------- MR01: повтор ключей. Ищем байты, которые мутант принял бы, а валидатор — нет: любой повтор ключа ломает каноническую форму.
mod, what = mutant("MR01")
base = demo_registry().manifest_bytes.decode()
tries = [base.replace('"row_count":5', '"row_count":5,"row_count":5'), base.replace('"key":["ogrn"]', '"key":["ogrn"],"key":["ogrn"]'),
         base[:-1] + ',"files":' + json.dumps(demo_registry().manifest["files"], separators=(",", ":")) + "}", '{"a":1,"a":1}']
res = [(VAL.parse_manifest(t.encode())[0] is None, mod.parse_manifest(t.encode())[0] is None) for t in tries]
print(f"MR01 «{what}»: {len(tries)} попыток, вердикты (валидатор отверг, мутант отверг) = {res} => {'свидетель не найден — эквивалентность подтверждаю' if all(a == b for a, b in res) else 'НЕ ЭКВИВАЛЕНТЕН'}")
print("\nИТОГ: MR21 не эквивалентен:", ok21, "| MR29 не эквивалентен:", ok29)

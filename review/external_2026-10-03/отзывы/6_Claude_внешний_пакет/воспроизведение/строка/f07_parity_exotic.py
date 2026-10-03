"""Проверено, держит: лист ячейки Python == PostgreSQL на экзотических значениях (а) функцией ac.cell_leaf;
(б) путём широкой таблицы: COPY -> печать -> ac.dataset_evidence == dataset.evidence."""
import random, subprocess
from _h import *
rng = random.Random(11)
exotic = ["", " ", "\t", "\n", "\r\n", "\\", "\\N", "\\.", "\"", "'", "\x01", "\x08", "\x0b", "\x0c", "\x1f", "\x7f", "\x80", "\x85", "\x9f", "\xa0",
          "​", " ", " ", "﻿", "�", "￾", "￿", "\U0001F600", "\U0010FFFF", "\U000E0001", "é", "é", "ﬁ", "İ", "ß",
          "‮" + "abc", "null", "true", "1", "-0", "1e2", "0x10", "[\"a\",1]", "2021-02-12", "а" * 100000, "</script>", "\\u0000", "퟿", ""]
exotic += ["".join(chr(rng.choice([rng.randrange(1, 0x80), rng.randrange(0x80, 0x800), rng.randrange(0xE000, 0x10000), rng.randrange(0x10000, 0x110000)]))
                   for _ in range(rng.randrange(1, 12))) for _ in range(1500)]
ints = [0, 1, -1, 2**53 - 1, -(2**53 - 1), 10**15, -10**15, 2**31, 2**63 - 1 if False else 2**52]
vals = exotic + ints + [True, False, None]
salt = hashlib.sha256(b"s").digest()
import load_s1 as L
_R, _ds, _ix, _content = run()
print("мир в базу:", db_load(_ds, FX.finalize(FX.world())[2], _content) or "ПРИНЯТО")
out = psql("SELECT string_agg(encode(ac.cell_leaf(decode('" + salt.hex() + "','hex'), 'col_a', v), 'hex'), ',' ORDER BY o) FROM "
           f"jsonb_array_elements({L.q(json.dumps(vals, ensure_ascii=False))}::jsonb) WITH ORDINALITY a(v, o)")
db = out.split(",")
py = [cell_leaf(salt, "col_a", v).hex() for v in vals]
print(f"(а) ac.cell_leaf: значений {len(vals)}, расхождений {sum(a != b for a, b in zip(db, py)) if len(db) == len(py) else out[:200]}")

# (б) широкая таблица
cols = [{"name": "k", "type": "INTEGER", "marking": PUB}, {"name": "s", "type": "STRING", "marking": PUB},
        {"name": "d", "type": "DATE", "marking": PUB}, {"name": "i", "type": "INTEGER", "marking": PUB}, {"name": "b", "type": "BOOLEAN", "marking": PUB},
        {"name": "id", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"}]
dates = ["0001-01-01", "9999-12-31", "0999-02-28", "2000-02-29", "1582-10-10", "1900-02-28", None]
rows = [{"k": n, "s": s, "d": dates[n % len(dates)], "i": ints[n % len(ints)] if n % 5 else None, "b": [True, False, None][n % 3], "id": None}
        for n, s in enumerate(exotic[:600])]
dv = DatasetVersion("dst_exotic", T, "v1", cols, ["k"], rows, chunk_rows=97, subject=("id",), dataset_key=os.urandom(32))
import dataset_s10 as D
src, r = D.register(dv.manifest_bytes, T, "exotic")
print("(б) регистрация:", "ПРИНЯТО" if r.returncode == 0 else r.stderr[:200], "| загрузка и печать:", db_load_rows(dv) or "ПРИНЯТО")
bad = 0
# ответ берём в hex: psql в выводе -At молча выбрасывает U+10FFFE и U+10FFFF (артефакт клиента, не базы)
q = "\n".join(f"SELECT encode(convert_to(ac.dataset_evidence('prj_compliance', '{dv.source_id}', '[{n}]', ARRAY['s','d','i','b'])::text, 'UTF8'), 'hex');" for n in range(len(rows)))
res = [bytes.fromhex(x).decode("utf-8") for x in psql(q, "ac_rd_full").split("\n")]
for n, ln in enumerate(res):
    bad += json.loads(ln) != dv.evidence([n], ["s", "d", "i", "b"])
print(f"    доказательств из базы {len(res)}, не равных доказательству производителя: {bad}")
for n, ln in enumerate(res):
    a, b = json.loads(ln), dv.evidence([n], ["s", "d", "i", "b"])
    if a != b:
        print("    расхождение в строке", n, "значение s (repr, первые 40):", repr(rows[n]["s"])[:40], "длина", len(rows[n]["s"]))
        for ca, cb in zip(a["cells"], b["cells"]):
            if ca != cb:
                print("      ячейка", ca["name"], "| база:", repr(ca.get("value"))[:60], "| python:", repr(cb.get("value"))[:60])
        print("      row_sha256 равны:", a["row_sha256"] == b["row_sha256"], "| proof равны:", a["proof"] == b["proof"])

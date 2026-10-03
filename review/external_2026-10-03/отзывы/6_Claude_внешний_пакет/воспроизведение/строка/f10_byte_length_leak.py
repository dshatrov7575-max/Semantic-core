"""F10. Манифест (источник PUBLIC) публикует byte_length файла строк; файл — JSON-строки с ОТКРЫТЫМИ значениями всех
ячеек. Читатель, знающий открытые ячейки строк файла, вычитанием получает суммарную длину скрытых ячеек; для файла из
одной строки (последний файл версии: row_count mod размер файла) — точную длину скрытой ячейки. От качества соли не зависит."""
import itertools
from _h import *
import dataset_s10 as D
_R, ds, ix, content = run()
print("мир в базу:", db_load(ds, FX.finalize(FX.world())[2], content) or "ПРИНЯТО")
dv = DatasetVersion("dst_registry_rnd", T, "2026-09-01", REGISTRY_COLUMNS, ["ogrn"], REGISTRY_ROWS, chunk_rows=4,
                    subject=("ogrn", "inn"), dataset_key=os.urandom(32))                       # честный случайный ключ набора
src, r = D.register(dv.manifest_bytes, T, "Реестр, случайный ключ")
print("версия со случайным ключом набора: регистрация", "ПРИНЯТО" if r.returncode == 0 else r.stderr[:200], "| строки:", db_load_rows(dv) or "ПРИНЯТО")
sid, RD = dv.source_id, "ac_rd_cs"                                                              # читатель без категории ПД
info = json.loads(psql(f"SELECT ac.dataset_info('prj_compliance', '{sid}');", RD))
print("ac.dataset_info читателю", RD, "— файлы:", [(f["rows"], f["byte_length"]) for f in info["files"]])
names = [c["name"] for c in info["columns"]]
known = {}
for k in [r["ogrn"] for r in REGISTRY_ROWS]:                                                    # ключи читатель знает (колонка PUBLIC)
    row = json.loads(psql(f"SELECT ac.dataset_row('prj_compliance', '{sid}', '[\"{k}\"]');", RD))
    ev = json.loads(psql(f"SELECT ac.dataset_evidence('prj_compliance', '{sid}', '[\"{k}\"]', ARRAY['address']);", RD))
    known.setdefault(ev["proof"]["file"], []).append((k, row["cells"], row["withheld"]))
SUR = ["Иванов", "Петров", "Сидоров", "Ломов", "Седов", "Крылов", "Нечаев", "Орлов", "Волков", "Зайцев"]
GIV = ["Иван", "Пётр", "Аркадий", "Олег", "Сергей", "Андрей", "Николай", "Дмитрий"]
PAT = ["Иванович", "Петрович", "Семёнович", "Олегович", "Ильич", "Андреевич"]
cands = [None] + [" ".join(x) for x in itertools.product(SUR, GIV, PAT)]
truth = {r["ogrn"]: r["director"] for r in REGISTRY_ROWS}
for fno, f in enumerate(info["files"]):
    rest = f["byte_length"]
    for k, cells, withheld in known[fno]:
        vals = [cells.get(n) for n in names]                     # скрытая ячейка здесь None -> "null" (4 байта), поправим ниже
        line = canon({"h": "0" * 64, "k": [k], "s": "0" * 32, "v": vals}) + "\n"
        rest -= len(line.encode("utf-8")) - 4 * len(withheld)
    hidden = [truth[k] for k, _, _ in known[fno]]
    print(f"файл {fno}: строк {f['rows']}, скрытых ячеек {sum(len(w) for _, _, w in known[fno])}; суммарная длина их JSON по манифесту = {rest} байт;"
          f" истина = {sum(len(canon(v).encode('utf-8')) for v in hidden)}")
    if f["rows"] == 1:
        fit = [c for c in cands if len(canon(c).encode("utf-8")) == rest]
        print(f"   одна строка в файле: кандидатов директора в словаре {len(cands)}, подходящих по длине {len(fit)};"
              f" пустая ячейка исключена: {None not in fit}; истинное значение среди подходящих: {truth[known[fno][0][0]] in fit}")

# ---- две версии, файл из многих строк: скрытый булев признак одной строки сменился — виден по манифестам
print("\nдве версии набора со скрытой булевой колонкой blacklisted (CONFIDENTIAL + PERSONAL_DATA), один файл на все строки:")
cols = copy.deepcopy(REGISTRY_COLUMNS) + [{"name": "blacklisted", "type": "BOOLEAN", "marking": CONF_PD}]
K = os.urandom(32)
def ver(label, flag_dev, prev=None):
    rows = [dict(r, blacklisted=(flag_dev if r["ogrn"] == OGRN_DEV else False)) for r in REGISTRY_ROWS]
    v = DatasetVersion("dst_flags", T, label, cols, ["ogrn"], rows, subject=("ogrn", "inn"), dataset_key=K, previous=prev)
    s, r = D.register(v.manifest_bytes, T, "флаги " + label)
    assert r.returncode == 0 and db_load_rows(v) is None, r.stderr
    return v
v1 = ver("v1", False); v2 = ver("v2", True, v1.source_id)
out = {}
for v in (v1, v2):
    inf = json.loads(psql(f"SELECT ac.dataset_info('prj_compliance', '{v.source_id}');", RD))
    hashes = {k: json.loads(psql(f"SELECT ac.dataset_row('prj_compliance', '{v.source_id}', '[\"{k}\"]');", RD)) for k in truth}
    out[v.source_id] = (inf["files"][0]["byte_length"], {k: (h["row_sha256"], {n: x for n, x in h["cells"].items()}) for k, h in hashes.items()}, hashes[OGRN_DEV]["withheld"])
(b1, r1, w), (b2, r2, _) = out[v1.source_id], out[v2.source_id]
changed = [k for k in r1 if r1[k][0] != r2[k][0]]
print("   читатель", RD, "— скрыты колонки:", w, "| строк с изменившимся хэшем:", len(changed), "| их открытые ячейки изменились:", any(r1[k][1] != r2[k][1] for k in changed))
print(f"   byte_length файла: v1 = {b1}, v2 = {b2}, разность = {b2 - b1}  (false = 5 байт, true = 4, null = 4; директор не менялся бы без смены длины только при равной длине)")
print("   вывод читателя: у строки", changed, "скрытая ячейка стала короче на 1 байт: blacklisted false -> true (или null) | истина: False -> True")

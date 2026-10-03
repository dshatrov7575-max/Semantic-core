"""F01. Плохой секрет строки (нулевой / одинаковый / выводимый) принимается валидатором (файл строк в хранилище
проверен целиком) — и скрытые ячейки подбираются по листу из ТЕЛА УТВЕРЖДЕНИЯ, без файла и без ключа набора."""
import itertools, time, datetime
from _h import *

SUR = ["Иванов", "Петров", "Сидоров", "Ломов", "Седов", "Крылов", "Нечаев", "Орлов", "Волков", "Зайцев"]
GIV = ["Иван", "Пётр", "Аркадий", "Олег", "Сергей", "Андрей", "Николай", "Дмитрий"]
PAT = ["Иванович", "Петрович", "Семёнович", "Олегович", "Ильич", "Андреевич"]   # словарь из slice/dataset_s10.py

def crack(ev, secret_candidates):
    """ev — доказательство ROW из тела утверждения (процитированы только ogrn и address)"""
    out = {}
    hidden = {c["name"]: bytes.fromhex(c["leaf"]) for c in ev["cells"] if "leaf" in c}
    quoted = {c["name"]: c for c in ev["cells"] if "salt" in c}
    for s in secret_candidates(quoted):
        # секрет подтверждается процитированной солью: salt(ogrn) = sha256(03 || secret || "ogrn")
        if cell_salt(s, "ogrn").hex() != quoted["ogrn"]["salt"]:
            continue
        out["__secret__"] = s.hex()
        dom = {"director": [None] + [" ".join(x) for x in itertools.product(SUR, GIV, PAT)],
               "active": [None, True, False],
               "employees": [None] + list(range(0, 100000)),
               "registered_on": [None] + [(datetime.date(1990, 1, 1) + datetime.timedelta(d)).isoformat() for d in range(14000)],
               "inn": [None] + [FX.inn10("5012%05d" % n) for n in range(100000)]}  # код инспекции 5012 известен из адреса; полный перебор — 10^9
        for name, leaf in hidden.items():
            salt = cell_salt(s, name)
            for v in dom.get(name, []):
                if cell_leaf(salt, name, v) == leaf:
                    out[name] = v
                    break
    return out

for tag, secret_of, cands in [
    ("нулевой секрет", lambda kv, vals: bytes(16), lambda q: [bytes(16)]),
    ("один секрет на весь набор = sha256(dataset_id)[:16]", lambda kv, vals: hashlib.sha256(b"dst_registry_demo").digest()[:16],
     lambda q: [hashlib.sha256(b"dst_registry_demo").digest()[:16]]),
    ("секрет = sha256(ключ строки)[:16] (без ключа набора)", lambda kv, vals: hashlib.sha256(canon(kv).encode()).digest()[:16],
     lambda q: [hashlib.sha256(canon([q["ogrn"]["value"]]).encode()).digest()[:16]]),
    ("честный: HMAC(случайный ключ набора, значения)", None, lambda q: [bytes(16), hashlib.sha256(canon([q["ogrn"]["value"]]).encode()).digest()[:16]]),
]:
    def pre(W, secret_of=secret_of):
        dv = DatasetVersion("dst_registry_demo", T, "2026-09-01", REGISTRY_COLUMNS, ["ogrn"], REGISTRY_ROWS, chunk_rows=4,
                            subject=("ogrn", "inn"), secret_of=secret_of, dataset_key=os.urandom(32))
        set_ds(W, dv)                       # файлы строк лежат в хранилище: валидатор проверяет их целиком
    R, ds, ix, content = run(pre)
    ev = ds["records"][ix["c50"]]["evidence"][0]
    t0 = time.time()
    got = crack(ev, cands)
    print(f"[{tag}] валидатор: {'ПРИНЯТО' if not R.errors else R.codes()}; из тела c50 (маркировка {ds['records'][ix['c50']]['marking']['level']},"
          f" процитированы {[c['name'] for c in ev['cells'] if 'salt' in c]}) восстановлено за {time.time()-t0:.2f} с:")
    print("    ", json.dumps(got, ensure_ascii=False))
print("истина:", json.dumps({k: REGISTRY_ROWS[0][k] for k in ("inn", "director", "registered_on", "active", "employees")}, ensure_ascii=False))

# ---- то же через базу: печать принимает нулевой секрет у всех строк; читатель без категории ПД получает лист и подбирает директора
import dataset_s10 as D
_R, _ds, _ix, _content = run()
print("\nбаза: мир загружен:", db_load(_ds, FX.finalize(FX.world())[2], _content) or "ПРИНЯТО")
dvz = DatasetVersion("dst_registry_zero", T, "z1", REGISTRY_COLUMNS, ["ogrn"], REGISTRY_ROWS, chunk_rows=4, subject=("ogrn", "inn"),
                     secret_of=lambda kv, vals: bytes(16))
src, r = D.register(dvz.manifest_bytes, T, "реестр с нулевым секретом")
print("база: регистрация версии:", "ПРИНЯТО" if r.returncode == 0 else r.stderr[:200], "| загрузка и печать (ac.dataset_seal):", db_load_rows(dvz) or "ПРИНЯТО")
print("база: различных секретов в запечатанной таблице:",
      psql(f"SELECT count(DISTINCT row_secret) || ' на ' || count(*) || ' строк' FROM acd.\"{psql(chr(83)+'ELECT table_name FROM ac.dataset_tables WHERE source_id = ' + chr(39) + dvz.source_id + chr(39))}\""))
row = psql(f"SELECT ac.dataset_row('prj_compliance', '{dvz.source_id}', '[\"{OGRN_DEV}\"]');", "ac_rd_cs")
print("база: ac.dataset_row читателю ac_rd_cs — withheld:", json.loads(row)["withheld"])
evdb = json.loads(psql(f"SELECT ac.dataset_evidence('prj_compliance', '{dvz.source_id}', '[\"{OGRN_DEV}\"]', ARRAY['address']);", "ac_rd_cs"))
print("база: из ac.dataset_evidence тем же читателем подобрано:", json.dumps(crack(evdb, lambda q: [bytes(16)]), ensure_ascii=False))

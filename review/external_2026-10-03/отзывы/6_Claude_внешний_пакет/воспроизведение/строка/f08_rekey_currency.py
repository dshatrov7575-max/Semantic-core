"""F08. Хэш строки зависит от ключа набора, который никто не проверяет и хранение которого не решено. Следующая версия
с ТЕМИ ЖЕ строками, собранная с другим ключом (ключ по умолчанию — os.urandom на каждую сборку; ротация; потеря),
объявляется «актуальностью строки» изменённой: CHANGED_ELSEWHERE, хотя база держит обе таблицы и видит равенство ячеек."""
from _h import *
import dataset_s10 as D
_R, ds, ix, content = run()
print("мир в базу:", db_load(ds, FX.finalize(FX.world())[2], content) or "ПРИНЯТО")
dv1 = demo_registry()
print("v1 (версия мира) — строки:", db_load_rows(dv1) or "ПРИНЯТО")
dv2 = DatasetVersion("dst_registry_demo", T, "2026-10-01", REGISTRY_COLUMNS, ["ogrn"], REGISTRY_ROWS, chunk_rows=4,
                     subject=("ogrn", "inn"), previous=dv1.source_id)          # dataset_key не передан: os.urandom(32)
src, r = D.register(dv2.manifest_bytes, T, "Реестр v2, те же строки")
print("v2: те же", len(REGISTRY_ROWS), "строк, другой ключ набора — регистрация:", "ПРИНЯТО" if r.returncode == 0 else r.stderr[:200],
      "| строки:", db_load_rows(dv2) or "ПРИНЯТО")
same = psql("SELECT count(*) FROM (SELECT c_ogrn, c_inn, c_name, c_address, c_director, c_registered_on, c_active, c_employees FROM acd.\"%s\" "
            "INTERSECT SELECT c_ogrn, c_inn, c_name, c_address, c_director, c_registered_on, c_active, c_employees FROM acd.\"%s\") x" % tuple(
                psql(f"SELECT table_name FROM ac.dataset_tables WHERE source_id = '{d.source_id}'") for d in (dv1, dv2)))
print("строк, равных по всем ячейкам в таблицах v1 и v2:", same, "| равных хэшей строк:", len({x[3] for x in dv1.rows} & {x[3] for x in dv2.rows}))
print("актуальность строки утверждения c50:", json.dumps([e["currency"] for e in dossier_rows()], ensure_ascii=False))

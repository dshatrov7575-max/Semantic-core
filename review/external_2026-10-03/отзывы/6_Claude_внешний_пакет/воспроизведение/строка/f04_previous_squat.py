"""F04. Поле previous: (а) «захват адреса» — версия-пустышка с previous = адрес ещё не полученного документа
навсегда запрещает tenant зарегистрировать этот документ; (б) версия-пустышка с previous = чужая версия
переводит «актуальность строки» всех утверждений на ней в BRANCHED. Ни ключа набора, ни файлов строк не нужно."""
from _h import *
import dataset_s10 as D
from ingest_s4 import ingest_sql, utc
R, ds, ix, content = run()
trust = FX.finalize(FX.world())[2]
print("базовый мир в базу:", db_load(ds, trust, content) or "ПРИНЯТО")

def reg(manifest, title, user="ac_loader"):
    b = canon(manifest).encode("utf-8")
    src, r = D.register(b, T, title, user=user)
    return src, ("ПРИНЯТО" if r.returncode == 0 else next((l for l in r.stderr.splitlines() if "ERROR" in l), r.stderr)[:230])

# ---------- (а) захват адреса будущего источника
doc = "Решение Арбитражного суда Московской области по делу № А41-12345/2026 (текст опубликован на сайте суда).".encode("utf-8")
doc_id = "src:sha256:" + hashlib.sha256(doc).hexdigest()
squat = {"manifest_format": "ac-dataset-manifest/0.1", "dataset_id": "dst_squat", "tenant_id": T, "version_label": "x",
         "columns": [{"name": "a", "type": "STRING", "marking": PUB}], "key": [], "row_count": 0, "files": [], "previous": doc_id}
src_sq, res = reg(squat, "пустышка")
print("(а) версия-пустышка (0 строк, 0 файлов, previous = адрес документа, которого ещё нет):", res)
doc_src = {"kind": "Source", "schema_version": FX.SV, "tenant_id": T, "source_kind": "DOCUMENT", "media_type": "text/plain; charset=utf-8",
           "language": "ru", "title": "Решение суда", "marking": PUB, "byte_length": len(doc), "source_id": doc_id,
           "observations": [{"observed_at": utc(0), "origin_uri": "https://kad.arbitr.example/doc", "observed_by": "svc_webmon"}]}
print("    честный загрузчик регистрирует сам документ:", psql(ingest_sql([doc_src], {doc_id: doc})) or "ПРИНЯТО")
print("    в базе документ есть:", psql(f"SELECT count(*) FROM ac.sources WHERE source_id = '{doc_id}'"),
      "| пустышку убрать:", psql(f"DELETE FROM ac.datasets WHERE source_id = '{src_sq['source_id']}'", "ac_loader")[:90])
# валидатор на том же: мир + пустышка — принято; мир + пустышка + документ — виновата пустышка, но в базе она уже зафиксирована
def with_recs(*recs):
    d2 = copy.deepcopy(ds); d2["records"] = d2["records"] + list(recs)
    c2 = dict(content); c2[src_sq["source_id"]] = canon(squat).encode(); c2[doc_id] = doc
    return validate(d2, trust, c2)
show("    валидатор: мир + пустышка", with_recs(src_sq))
show("    валидатор: мир + пустышка + документ", with_recs(src_sq, doc_src))

# ---------- (б) BRANCHED
dv1 = demo_registry()
print("(б) строки версии v1 мира загружены и запечатаны:", db_load_rows(dv1) or "ПРИНЯТО")
cur = lambda: [e.get("currency") for e in dossier_rows()]
print("    актуальность строки c50 до:", json.dumps(cur(), ensure_ascii=False))
rows2 = copy.deepcopy(REGISTRY_ROWS); rows2[0]["address"] = "г. Москва, ул. Новая, д. 2"
dv2 = demo_registry(rows=rows2, previous=dv1.source_id)
dv2.manifest["version_label"] = "2026-10-01"; dv2.manifest_bytes = canon(dv2.manifest).encode(); dv2.source_id = "src:sha256:" + hashlib.sha256(dv2.manifest_bytes).hexdigest()
print("    честная v2 (previous = v1):", reg(dv2.manifest, "Реестр v2")[1], "| строки:", db_load_rows(dv2) or "ПРИНЯТО")
print("    актуальность строки c50 после честной v2:", json.dumps(cur(), ensure_ascii=False))
spoil = {"manifest_format": "ac-dataset-manifest/0.1", "dataset_id": "dst_registry_demo", "tenant_id": T, "version_label": "мусор",
         "columns": [{"name": "a", "type": "STRING", "marking": PUB}], "key": [], "row_count": 0, "files": [], "previous": dv1.source_id}
print("    пустышка (тот же dataset_id, previous = v1, 0 строк, 0 файлов):", reg(spoil, "мусор")[1])
print("    актуальность строки c50 после пустышки:", json.dumps(cur(), ensure_ascii=False))

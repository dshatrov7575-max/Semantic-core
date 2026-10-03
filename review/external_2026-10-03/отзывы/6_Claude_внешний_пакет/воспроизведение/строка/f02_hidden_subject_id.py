"""F02. «Строка о субъекте»: расходящийся идентификатор субъекта строки можно НЕ ЦИТИРОВАТЬ — правило
«ни один идентификатор строки не расходится с идентификатором субъекта» и предупреждение ROW_SUBJECT_CONFLICT
обходятся выбором процитированных колонок автором утверждения."""
from _h import *
ADDR_TRUB = REGISTRY_ROWS[1]["address"]
COLS = [{"name": "reg_no", "type": "STRING", "marking": PUB}] + copy.deepcopy(REGISTRY_COLUMNS[:4])
# строка реестра: ОГРН и адрес «Трубопроводстроя», ИНН — девелопера (ошибка ввода / намеренно собранная строка)
ROWS = [{"reg_no": "R-1", "ogrn": OGRN_TRUB, "inn": INN_DEV, "name": "АО «Трубопроводстрой»", "address": ADDR_TRUB},
        {"reg_no": "R-2", "ogrn": OGRN_DEV, "inn": INN_TRUB, "name": "x", "address": "y"}]

DV = DatasetVersion("dst_registry_demo", T, "2026-09-01", COLS, ["reg_no"], ROWS, subject=("ogrn", "inn"), dataset_key=os.urandom(32))

def pre(quote):
    def f(W):
        dv = DV
        set_ds(W, dv)
        # в проекте есть и вторая организация с ОГРН «Трубопроводстроя» — по строке это «одна сущность»
        W["ent_k_trub"] = {"kind": "Entity", "schema_version": FX.SV, "entity_id": "ent_k_trub", "project_id": "prj_compliance",
                           "entity_type": "ORGANIZATION", "identity": {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU", "ogrn": OGRN_TRUB},
                           "display_name": "Трубопроводстрой", "status": "ACTIVE", "created_at": "2026-09-05T12:00:00Z", "marking": CONF_CS}
        W["c50"]["object"] = {"literal": {"type": "STRING", "value": ADDR_TRUB}}
        W["c50"]["evidence"] = [{"$row": ["s30", ["R-1"], quote]}]
    return f

print("субъект c50: ent_k_developer (ОГРН", OGRN_DEV, "ИНН", INN_DEV + "); строка R-1: ОГРН", OGRN_TRUB, "ИНН", INN_DEV, "адрес:", ADDR_TRUB)
for quote in (["inn", "address", "ogrn"], ["inn", "address"]):
    R, ds, ix, content = run(pre(quote))
    ev = ds["records"][ix["c50"]]["evidence"][0]
    show(f"валидатор, процитировано {quote}", R)
    if not R.errors:
        tr = FX.finalize(FX.world())[2]
        why = db_load(ds, tr, content)
        print("   база (без валидатора впереди):", why or "ПРИНЯТО")
        if not why:
            for e in dossier_rows():
                print("   досье девелопера (читатель ac_rd_cs):", json.dumps({k: e.get(k) for k in ("cells", "verified", "proves", "subject_conflict")}, ensure_ascii=False))
            # строки версии загружаем и запечатываем; «о ком строка» спрашиваем у самой базы
            print("   загрузка и печать строк:", db_load_rows(DV) or "ПРИНЯТО")
            print("   ac.dataset_subject (читатель ac_rd_full):", psql(f"SELECT ac.dataset_subject('prj_compliance', '{DV.source_id}', '[\"R-1\"]')->>'status', "
                  f"ac.dataset_subject('prj_compliance', '{DV.source_id}', '[\"R-1\"]')->'owners';", "ac_rd_full"))
            for e in dossier_rows(user="ac_rd_full"):
                print("   досье после загрузки (ac_rd_full):", json.dumps({k: e.get(k) for k in ("verified", "subject_conflict")}, ensure_ascii=False))

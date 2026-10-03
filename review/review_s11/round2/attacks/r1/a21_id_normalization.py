#!/usr/bin/env python3
"""S11R-09: правило конфликта (и «строка о субъекте», и ac.dataset_subject) сравнивает идентификатор ИЗ СТРОКИ как есть
с НОРМАЛИЗОВАННЫМ ключом сущности (id_norm: NFKC, регистр, разделители). Если запись идентификатора отличается от его
нормальной формы (регистр, дефисы, пробелы), та же самая строка символов в ячейке и в identity другой организации не
считается совпадением: конфликт не виден ни валидатору, ни базе, ни проекции.
Мир — вектор NS03 автора (чужая организация несёт LEI строки), меняется только запись LEI."""
import json
from rv import *
import load_s1 as L
import vectors as V
from fixtures import PUB

res = {}
for name, lei in (("как у автора (нормальная форма)", "549300123456"), ("с дефисами", "5493-0012-3456"), ("в нижнем регистре букв", "5493ab123456".upper().replace("AB", "ab")),
                  ("в верхнем регистре букв", "5493AB123456")):
    pre = V.seq(V.regds(columns=V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"}),
                        rows=[dict(r, lei=lei if n == 0 else None) for n, r in enumerate(REGISTRY_ROWS)], subject=("ogrn", "inn", "lei")),
                V.add_entity("ent_k_foreign", "prj_compliance", "ORGANIZATION", {"name": "Zarechye Ltd", "jurisdiction": "CY",
                                                                                "foreign_ids": [{"scheme": "lei", "value": lei}]}, CONF_CS),
                V.rowev([OGRN_DEV], ["address", "lei"]))
    ds, tr, ct = V.build(V.V("X", [], name, pre=pre))
    codes = VAL.validate(ds, tr, ct).codes()
    assert L.psql(L.DDL_ALL).returncode == 0
    L.register_originals(ds, ct)
    r = L.psql(L.load_sql(ds, tr, ct))
    dbres = "ОТВЕРГНУТО " + first_err(r)[7:60] if r.returncode else "ПРИНЯТО"
    keyrow = S3.psql("SELECT value FROM ac.entity_keys WHERE owner_entity_id = 'ent_k_foreign' AND scheme = 'lei'").stdout.strip() if r.returncode == 0 else "-"
    sub = "-"
    if r.returncode == 0:
        S3.psql(S3.SETUP)
        dv = next(iter([x for x in ds["records"] if x["kind"] == "Source" and x["source_kind"] == "DATASET_VERSION"]))
        from fixtures import demo_registry
        d2 = demo_registry(columns=V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"}),
                           rows=[dict(r_, lei=lei if n == 0 else None) for n, r_ in enumerate(REGISTRY_ROWS)], subject=("ogrn", "inn", "lei"))
        _, bad = D.load_rows(T, d2.source_id, copy_file(d2), d2.columns)
        s = S3.psql(f"SELECT ac.dataset_subject('{PRJ}', '{d2.source_id}', {key(OGRN_DEV)});", "ac_rd_cs")
        sub = json.loads(s.stdout)["status"] + " " + str([o["entity_id"] for o in json.loads(s.stdout)["owners"]]) if s.returncode == 0 else first_err(s)[:60]
    res[name] = (codes, dbres)
    print(f"LEI в строке и в identity чужой организации = {lei!r:<18} ({name}): валидатор {codes or 'ПРИНЯЛ'}; база: {dbres}; ключ сущности в базе: {keyrow}; dataset_subject: {sub}")
ok = res["как у автора (нормальная форма)"][0] == ["EVIDENCE_ROW_INVALID"] and res["с дефисами"][0] == [] and res["с дефисами"][1] == "ПРИНЯТО"
report("S11R-09", ok, "тот же идентификатор в записи с разделителями/в другом регистре: конфликт не обнаруживается ни валидатором, ни базой, ни проекцией")

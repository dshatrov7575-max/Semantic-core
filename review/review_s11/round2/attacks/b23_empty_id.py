#!/usr/bin/env python3
"""Раунд 2 (г): пустая нормальная форма. id_norm удаляет разделители: значения «-», «./», « » дают пустой ключ.
Проверяется: (1) принимает ли валидатор/база сущность с иностранным идентификатором «-»; (2) считается ли строка
набора с прочерком в колонке-идентификаторе «строкой о» такой сущности и даёт ли конфликт между РАЗНЫМИ строками."""
import json
from rv import *
import load_s1 as L
import vectors as V
from fixtures import PUB

cols = V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"})
out = {}
for name, ent_lei, row_lei in (("у сущности lei «-», в строке «-»", "-", "-"), ("у сущности lei «-», в строке пустая строка", "-", ""),
                               ("у сущности lei «N/A», в строке «n.a»", "N/A", "n.a")):
    pre = V.seq(V.regds(columns=cols, rows=[dict(r, lei=row_lei) for r in REGISTRY_ROWS], subject=("ogrn", "inn", "lei")),
                V.add_entity("ent_k_dash", "prj_compliance", "ORGANIZATION", {"name": "Dash Ltd", "jurisdiction": "CY", "foreign_ids": [{"scheme": "lei", "value": ent_lei}]}, CONF_CS),
                V.rowev([OGRN_DEV], ["address", "lei"]))
    try:
        ds, tr, ct = V.build(V.V("X", [], name, pre=pre))
    except Exception as ex:   # noqa: BLE001
        print(name, "мир не строится:", type(ex).__name__, str(ex)[:80]); continue
    rep = VAL.validate(ds, tr, ct)
    warn = [w for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT"]
    assert L.psql(L.DDL_ALL).returncode == 0
    L.register_originals(ds, ct)
    r = L.psql(L.load_sql(ds, tr, ct))
    flags = S3.psql("SELECT count(*) FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) JOIN ac.datasets d ON d.tenant_id = e.tenant_id AND d.source_id = e.source_id "
                    "WHERE e.kind = 'ROW' AND ac.row_subject_conflict(c, e.row_ev, d.manifest, now())").stdout.strip() if r.returncode == 0 else "-"
    k = S3.psql("SELECT '[' || value || ']' FROM ac.entity_keys WHERE owner_entity_id = 'ent_k_dash'").stdout.strip() if r.returncode == 0 else "-"
    print(f"{name}: валидатор ошибки {rep.codes()} {[e.get('msg', '')[:50] for e in rep.errors][:1]}, конфликтов {len(warn)}; база {'ОТВЕРГЛА ' + first_err(r)[:60] if r.returncode else 'приняла'}, ключ сущности {k}, флагов {flags}")
    out[name] = (rep.codes(), len(warn), r.returncode, flags)
a = out.get("у сущности lei «-», в строке «-»")
report("E1", bool(a) and not a[0] and a[1] > 0, "прочерк в колонке-идентификаторе всех строк набора считается идентификатором сущности с пустым ключом: ложный конфликт")

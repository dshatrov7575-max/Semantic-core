#!/usr/bin/env python3
"""S11R2-01: нормальная форма идентификатора строки расходится у валидатора (Юникод 14.0, Python) и базы (PostgreSQL 16,
Юникод 15): NFKC символов, назначенных в 15.0 (U+1E030…U+1E06D — кириллические модификаторы), база выполняет, валидатор
нет. Сквозной мир: у субъекта ОГРН и иностранный идентификатор lei = «а1» (кириллическая а); в строке набора
lei = U+1E030 + «1». Валидатор: идентификатор строки расходится с идентификатором субъекта (EVIDENCE_ROW_INVALID);
база: тот же идентификатор — принято. Обратный мир (конфликт): чужая организация несёт «а1» — флаг базы есть,
предупреждения валидатора нет."""
import json
from rv import *
import load_s1 as L
import vectors as V
from fixtures import PUB

X = "\U0001E030" + "1"
cols = V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"})
rows = lambda lei: [dict(r, lei=lei if n == 0 else None) for n, r in enumerate(REGISTRY_ROWS)]   # noqa: E731


def run(name, pre):
    ds, tr, ct = V.build(V.V("X", [], name, pre=pre))
    rep = VAL.validate(ds, tr, ct)
    assert L.psql(L.DDL_ALL).returncode == 0
    L.register_originals(ds, ct)
    r = L.psql(L.load_sql(ds, tr, ct))
    flags = "-"
    if r.returncode == 0:
        flags = S3.psql("SELECT count(*) FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) JOIN ac.datasets d ON d.tenant_id = e.tenant_id AND d.source_id = e.source_id "
                        "WHERE e.kind = 'ROW' AND ac.row_subject_conflict(c, e.row_ev, d.manifest, now())").stdout.strip()
    warn = [w["code"] for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT"]
    print(f"{name}: валидатор ошибки {rep.codes()} {[e.get('msg', '')[:60] for e in rep.errors][:1]}, предупреждений о конфликте {len(warn)}; "
          f"база: {'ОТВЕРГНУТО ' + first_err(r)[:70] if r.returncode else 'ПРИНЯТО'}, флагов subject_conflict: {flags}")
    return rep.codes(), r.returncode, len(warn), flags


def own(lei_entity):
    def f(W):
        W["ent_k_developer"]["identity"]["foreign_ids"] = [{"scheme": "lei", "value": lei_entity}]
    return f


a = run("субъект несёт lei «а1», в строке U+1E030+«1»",
        V.seq(V.regds(columns=cols, rows=rows(X), subject=("ogrn", "inn", "lei")), own("а1"), V.rowev([OGRN_DEV], ["address", "lei"])))
ctl = run("контроль: в строке «А-1» (обычная кириллица)",
          V.seq(V.regds(columns=cols, rows=rows("А-1"), subject=("ogrn", "inn", "lei")), own("а1"), V.rowev([OGRN_DEV], ["address", "lei"])))
b = run("чужая организация несёт lei «а1», в строке U+1E030+«1»",
        V.seq(V.regds(columns=cols, rows=rows(X), subject=("ogrn", "inn", "lei")),
              V.add_entity("ent_k_foreign", "prj_compliance", "ORGANIZATION", {"name": "Zarechye Ltd", "jurisdiction": "CY", "foreign_ids": [{"scheme": "lei", "value": "а1"}]}, CONF_CS),
              V.rowev([OGRN_DEV], ["address", "lei"])))
report("S11R2-01", bool(a[0]) and a[1] == 0, f"база принимает мир, который валидатор отвергает {a[0]} (NFKC Юникода 15 против 14)")
report("S11R2-01b", b[1] == 0 and b[2] == 0 and b[3] not in ("0", "-"), "флаг базы subject_conflict есть, предупреждения валидатора нет")

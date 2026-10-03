#!/usr/bin/env python3
"""Раунд 4: запрет неназначенных символов в identity сущности (S11R3-02) покрывает только foreign_ids и registration.
Сильные ключи строятся и из других полей; схема колонки набора может быть любой, в т. ч. «org.informal» (ключ
неформальной организации = norm(name)|disambiguator, norm включает NFKC).
W1  свидетель против «эквивалентности» MS23 и Z01: неформальная организация с названием «Гр»+U+1E030, колонка набора
    со схемой org.informal, в строке «ГР»+U+1E030+«|ddd». Валидатор и мутант дают разные ответы.
W2  паритет: та же сущность, в строке «гра|ddd» (обычная кириллическая «а»). Ключ сущности у валидатора — с U+1E030,
    в базе (NFKC Юникода 15) — «гра|ddd». Валидатор: строка не о субъекте; база: о субъекте.
W3  класс «не назначен»: unicodedata (14.0) против ac.has_unassigned — по всем кодовым точкам.
"""
import json, sys, unicodedata
from rv import *
import load_s1 as L
import vectors as V
import mutants as MU
from fixtures import PUB

X = "\U0001E030"
cols = V.cols_with({"name": "oid", "type": "STRING", "marking": PUB, "identifier_scheme": "org.informal"})


def world(cell):
    rows = [dict(r, oid=cell if n == 0 else None) for n, r in enumerate(REGISTRY_ROWS)]
    def subj(W):
        V.add_entity("ent_k_group", "prj_compliance", "ORGANIZATION", {"name": "Гр" + X, "jurisdiction": "RU", "informal": True, "disambiguator": "ddd"}, CONF_CS)(W)
        W["c50"]["subject"] = "ent_k_group"
    return V.build(V.V("X", [], "w", pre=V.seq(V.regds(columns=cols, rows=rows, subject=("oid",)), subj, V.rowev([OGRN_DEV], ["address", "oid"]))))


def db(ds, tr, ct):
    assert L.psql(L.DDL_ALL).returncode == 0
    L.register_originals(ds, ct)
    r = L.psql(L.load_sql(ds, tr, ct))
    k = S3.psql("SELECT value FROM ac.entity_keys WHERE owner_entity_id = 'ent_k_group' AND strength = 'STRONG'").stdout.strip()
    return r, k


base = MU.load(MU.SRC)
ms23 = next(m for m in MU.M if m[0] == "MS23")
mut = MU.load(MU.SRC.replace(ms23[2], ms23[3]))
z01 = MU.load(MU.SRC.replace("def _has_unassigned(v: str) -> bool:\n    return any(", "def _has_unassigned(v: str) -> bool:\n    return all("))

ds, tr, ct = world("ГР" + X + "|ddd")
a, b, c = base.validate(ds, tr, ct).codes(), mut.validate(ds, tr, ct).codes(), z01.validate(ds, tr, ct).codes()
ent = next(x for x in ds["records"] if x.get("entity_id") == "ent_k_group")
vkey = [k for k in base.entity_identifiers(ent, base.Report(), "-")[0]]
print(f"W1 строка «ГР»+U+1E030+«|ddd»: валидатор {a}; мутант MS23 {b}; мутант Z01 (any -> all) {c}; ключ сущности у валидатора {vkey}")
report("S11R4-W1", a != b, "MS23 не эквивалентен: свидетель — ключ сущности с неназначенным символом из поля name (org.informal)")

ds, tr, ct = world("гра|ddd")
rep = VAL.validate(ds, tr, ct)
r, k = db(ds, tr, ct)
print(f"W2 строка «гра|ddd»: валидатор {rep.codes() or 'ПРИНЯЛ'} {[e.get('msg', '')[:60] for e in rep.errors][:1]}; база {'ОТВЕРГЛА ' + first_err(r)[:80] if r.returncode else 'ПРИНЯЛА'}; "
      f"ключ сущности в базе {k!r} ({[hex(ord(ch)) for ch in k]})")
report("S11R4-W2", bool(rep.codes()) and r.returncode == 0, f"база принимает мир, который валидатор отвергает {rep.codes()}: ключ сущности из названия нормализуется по разным версиям Юникода")
ds, tr, ct = world("гр" + X + "|ddd")
rep = VAL.validate(ds, tr, ct); r, k = db(ds, tr, ct)
print(f"   строка «гр»+U+1E030+«|ddd» (как у сущности): валидатор {rep.codes() or 'ПРИНЯЛ'}; база {'ОТВЕРГЛА ' + first_err(r)[:80] if r.returncode else 'ПРИНЯЛА'}")

# W3
cps = [cp for cp in range(1, 0x110000) if not 0xD800 <= cp <= 0xDFFF]
py = {cp for cp in cps if unicodedata.category(chr(cp)) == "Cn"}
bad = 0
dbset = set()
for i in range(0, len(cps), 60000):
    chunk = cps[i:i + 60000]
    rr = psql("SELECT coalesce(string_agg(cp::text, ','), '') FROM unnest(ARRAY[" + ",".join(map(str, chunk)) + "]) cp WHERE ac.has_unassigned(chr(cp));")
    if rr.returncode:
        sys.exit(first_err(rr))
    dbset |= {int(x) for x in rr.stdout.strip().split(",") if x}
print(f"W3 кодовых точек {len(cps)}: не назначено по Python 14.0 — {len(py)}, по ac.has_unassigned — {len(dbset)}; расхождений {len(py ^ dbset)} {[hex(x) for x in sorted(py ^ dbset)[:6]]}")
report("W3", bool(py ^ dbset), "класс неназначенных символов различается у валидатора и базы")

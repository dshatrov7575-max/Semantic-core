#!/usr/bin/env python3
"""Раунд 3: паритет row_id валидатор/база после исправления S11R2-01.
P1  фазз: 7 схем × (фиксированные + случайные значения), включая символы, назначенные в Юникоде 15.0/15.1, не-символы,
    частное использование, теги, смесь назначенных и неназначенных.
P2  сквозной мир: у СУЩНОСТИ иностранный идентификатор с символом, не назначенным в 14.0 (U+1E030), в строке — та же
    запись. Ключ сущности считают ac.id_norm / id_norm (NFKC по разным версиям Юникода), идентификатор строки — «как
    записан». Сравниваются: ключ сущности у валидатора и в базе; приём утверждения валидатором и базой.
"""
import json, random, sys, unicodedata
from rv import *
import load_s1 as L
import vectors as V
from fixtures import PUB

SCHEMES = ["ru.cadastral", "lei", "ru.inn", "vin", "imo", "x.reg", "ru.ogrn"]
EXOTIC = ["\U0001E030", "\U0001E04D", "\U0001E06D", "ೳ", "\U00011F00", "\U0001DF25", "\U0001E4D0", "\U0001F6DC", "\U0002B739", "\U00031350",
          "￿", "﷐", "", "\U000E0041", "͸", "⿼", "\U0001FAE8", "\U00010EFD", "Ᲊ", "\U0001CC00", "Ɤ", "\U00016D40"]
rnd = random.Random(33)
POOL = list("0123456789:abAB -_./") + EXOTIC + [" ", "０", "Ａ", "ß", "İ", "́", "ǅ", "ﬃ"]
vals = EXOTIC + [a + b for a in ("A", "a-1", "50:012", "") for b in EXOTIC] + ["".join(rnd.choice(POOL) for _ in range(rnd.randint(1, 10))) for _ in range(4000)]
pairs = [(s, v) for s in SCHEMES for v in vals]
r = psql("SELECT jsonb_agg(ac.row_id(x->>0, x->>1) ORDER BY o) FROM jsonb_array_elements($q$" + json.dumps(pairs, ensure_ascii=False) + "$q$::jsonb) WITH ORDINALITY a(x, o);")
if r.returncode:
    sys.exit(first_err(r))
db = json.loads(r.stdout)
bad = [(s, v, "|".join(VAL.row_id(s, v)), d) for (s, v), d in zip(pairs, db) if "|".join(VAL.row_id(s, v)) != d]
print(f"P1 пар: {len(pairs)}; расхождений validator.row_id / ac.row_id: {len(bad)}", [(s, [hex(ord(c)) for c in v], py, d) for s, v, py, d in bad[:4]])
report("P1", bool(bad), "расхождение нормальной формы идентификатора строки")

X = "ab\U0001E030"
cols = V.cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"})
rows = [dict(rw, lei=X if n == 0 else None) for n, rw in enumerate(REGISTRY_ROWS)]
def own(W):
    W["ent_k_developer"]["identity"]["foreign_ids"] = [{"scheme": "lei", "value": X}]
ds, tr, ct = V.build(V.V("X", [], "p2", pre=V.seq(V.regds(columns=cols, rows=rows, subject=("ogrn", "inn", "lei")), own, V.rowev([OGRN_DEV], ["address", "lei"]))))
rep = VAL.validate(ds, tr, ct)
ent = next(x for x in ds["records"] if x.get("entity_id") == "ent_k_developer")
vkeys = sorted(k for k in VAL.entity_identifiers(ent, VAL.Report(), "-")[0] if k[0] == "lei")
assert L.psql(L.DDL_ALL).returncode == 0
L.register_originals(ds, ct)
rr = L.psql(L.load_sql(ds, tr, ct))
dkey = S3.psql("SELECT value FROM ac.entity_keys WHERE owner_entity_id = 'ent_k_developer' AND scheme = 'lei'").stdout.strip() if rr.returncode == 0 else \
       S3.psql("SELECT ac.id_norm($q$" + X + "$q$)").stdout.strip()
print(f"P2 сущность и строка с одной записью lei = 'ab' + U+1E030: валидатор {rep.codes() or 'ПРИНЯЛ'} {[e.get('msg', '')[:70] for e in rep.errors][:1]}; "
      f"база: {'ОТВЕРГЛА ' + first_err(rr)[:90] if rr.returncode else 'ПРИНЯЛА'}")
print(f"   ключ сущности: валидатор {[k[1] for k in vkeys]!r} ({[hex(ord(c)) for c in vkeys[0][1]] if vkeys else ''}); база {dkey!r} ({[hex(ord(c)) for c in dkey]})")
report("P2", bool(rep.codes()) != bool(rr.returncode) or (vkeys and vkeys[0][1] != dkey),
       "ключ СУЩНОСТИ с неназначенным символом расходится у валидатора и базы; приём/отказ: валидатор " + ("отверг" if rep.codes() else "принял") + ", база " + ("отвергла" if rr.returncode else "приняла"))

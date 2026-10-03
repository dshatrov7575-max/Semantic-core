#!/usr/bin/env python3
"""Раунд 5: запрет неназначенных символов в identity — паритет валидатор/база и поиск оставшихся путей.
E1  identity каждой сущности эталонного мира (все 10 типов, какие есть) × каждое строковое поле × вставка символа:
    U+1E030 (не назначен в 14.0, назначен в 15.0), U+0378 (не назначен нигде), U+FFFF (не-символ), U+E000 (частное
    использование, НЕ Cn), U+A7C0 (назначен в 14.0), U+1F600. Сравнивается: отказ/приём и набор ключей
    validator.entity_identifiers против ac.identity_keys.
E2  решение QUALIFY (поле place — свободный текст, становится квалификатором слабого ключа через skel с NFKC):
    место с U+1E030 — вне identity. Принимают ли стороны, и совпадает ли квалификатор.
E3  исторический импорт (мигратор) сущности с неназначенным символом; вставка сразу слитой.
E4  строка набора против ключа сущности после запрета: значение ячейки с U+1E030 при любой схеме не равно ключу.
"""
import copy, json, sys
from rv import *
from ingest_s4 import q as Q

fresh(load_rows=False)
ds0, trust, content = build()
INJ = {"U+1E030": "\U0001E030", "U+0378": "͸", "U+FFFF": "￿", "U+E000": "", "U+A7C0": "Ꟁ", "U+1F600": "\U0001F600"}
ents = [r for r in ds0["records"] if r["kind"] == "Entity"]
types = sorted({e["entity_type"] for e in ents})


def leaves(x, path=()):
    if isinstance(x, str):
        yield path
    elif isinstance(x, dict):
        for k, v in x.items():
            yield from leaves(v, path + (k,))
    elif isinstance(x, list):
        for n, v in enumerate(x):
            yield from leaves(v, path + (n,))


def setp(x, path, fn):
    x = copy.deepcopy(x); node = x
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = fn(node[path[-1]])
    return x


extra = [("ORGANIZATION", {"name": "Zarechye Ltd", "jurisdiction": "CY", "foreign_ids": [{"scheme": "lei", "value": "5493AB"}]}),
         ("MOVABLE_PROPERTY", {"subtype": "OTHER", "description": "прицеп", "registration": {"scheme": "lei", "value": "AB-12"}}),
         ("ORGANIZATION", {"name": "Группа", "jurisdiction": "RU", "informal": True, "disambiguator": "ddd"}),
         ("THING", {"label": "Скелет", "lang": "ru", "namespace": "museum", "disambiguator": "x1"})]
cases = []
seen = set()
for t, ident in [(e["entity_type"], e["identity"]) for e in ents] + extra:
    sig = (t, tuple(sorted(map(str, leaves(ident)))))
    if sig in seen:
        continue
    seen.add(sig)
    cases.append((t, ident, "без вставки"))
    for path in leaves(ident):
        for name, ch in INJ.items():
            for pos in ("конец", "начало"):
                cases.append((t, setp(ident, path, lambda s: s + ch if pos == "конец" else ch + s), f"{'.'.join(map(str, path))} {name} {pos}"))
print(f"E1 типов сущностей: {len({c[0] for c in cases})} {sorted({c[0] for c in cases})}; случаев {len(cases)}")
sql = ("CREATE OR REPLACE FUNCTION pg_temp.try_keys(t text, i jsonb) RETURNS jsonb LANGUAGE plpgsql AS $f$ BEGIN "
       "RETURN (SELECT coalesce(jsonb_agg(jsonb_build_array(scheme, value, strength, qual) ORDER BY scheme, value, strength), '[]') FROM ac.identity_keys(t, i)); "
       "EXCEPTION WHEN others THEN RETURN to_jsonb('ERR ' || split_part(SQLERRM, ':', 1)); END $f$;\n"
       "SELECT jsonb_agg(pg_temp.try_keys(x->>0, x->1) ORDER BY o) FROM jsonb_array_elements($q$" + json.dumps([[t, i] for t, i, _ in cases], ensure_ascii=False) + "$q$::jsonb) WITH ORDINALITY a(x, o);")
r = psql(sql)
if r.returncode:
    sys.exit(first_err(r))
db = json.loads(r.stdout.strip().splitlines()[-1])
diff_refuse, diff_keys, both_ref, both_ok, cn_accepted = [], [], 0, 0, []
for (t, ident, what), d in zip(cases, db):
    rep = VAL.Report()
    try:
        st, wk, sf = VAL.entity_identifiers({"entity_type": t, "identity": ident}, rep, "-")
        codes = sorted({e["code"] for e in rep.errors})
    except Exception as ex:   # noqa: BLE001
        codes = ["EXC " + type(ex).__name__]; st, wk, sf = [], [], []
    v_ref, d_ref = bool(codes), isinstance(d, str)
    if v_ref != d_ref:
        diff_refuse.append((t, what, codes, d if d_ref else "принято"))
        continue
    if v_ref:
        both_ref += 1
        continue
    both_ok += 1
    vk = sorted([[s, v, "STRONG", None] for s, v in st] + [[s, v, "WEAK", ql] for s, v, ql in wk] + [["skel:" + s, v, "SOFT", None] for s, v in sf], key=lambda x: (x[0], x[1], x[2]))
    if vk != sorted(d, key=lambda x: (x[0], x[1], x[2])):
        diff_keys.append((t, what, vk[:2], d[:2]))
    if any(n in what for n in ("U+1E030", "U+0378", "U+FFFF")):
        cn_accepted.append((t, what))
print(f"   оба отвергли {both_ref}, оба приняли {both_ok}; расхождений отказ/приём {len(diff_refuse)} {diff_refuse[:4]}")
print(f"   расхождений наборов ключей у принятых {len(diff_keys)} {diff_keys[:3]}")
print(f"   принято обеими сторонами со вставкой неназначенного символа: {len(cn_accepted)} {cn_accepted[:4]}")
report("E1", bool(diff_refuse or diff_keys or cn_accepted), "паритет запрета и ключей идентичности")

# E2 QUALIFY place with an unassigned code point
L = "SET SESSION AUTHORIZATION ac_loader;\n"
ev1 = {"kind": "Entity", "entity_id": "ent_e2_ev", "project_id": "prj_dossier", "entity_type": "EVENT", "status": "ACTIVE",
       "identity": {"title": "Собрание акционеров", "date": "2026-05-05"}, "display_name": "Собрание", "created_at": utc(0), "marking": CONF_PD}
r0 = psql(ingest_sql([ev1], {}))
import time; time.sleep(1.2)
dec = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_e2", "project_id": "prj_dossier", "decision": "QUALIFY",
       "entity_id": "ent_e2_ev", "place": "Гр\U0001E030", "decided_by": "usr_analyst1", "decided_at": utc(0)}
rd = psql(L + f"INSERT INTO ac.identity_decisions VALUES ('idd_e2','prj_dossier','QUALIFY','ent_e2_ev',NULL,'place',{Q(dec['place'])},'usr_analyst1',{Q(dec['decided_at'])},{Q(dec)});")
ds = copy.deepcopy(ds0); ds["records"] += [dict(ev1, schema_version="core-ontology/0.4"), dec]
codes = VAL.validate(ds, trust, content).codes()
qual = one("SELECT coalesce(string_agg(qual, ','), '-') FROM ac.entity_keys WHERE owner_entity_id = 'ent_e2_ev' AND strength = 'WEAK'") if rd.returncode == 0 else "-"
print(f"E2 событие: {first_err(r0)[:30]}; QUALIFY с местом «Гр»+U+1E030: валидатор {codes or 'ПРИНЯЛ'}; база {first_err(rd)[:80]}; квалификатор в базе {qual!r}; у валидатора {VAL.norm(dec['place'])!r}")
report("E2", (not codes) and rd.returncode == 0 and qual != VAL.norm(dec["place"]), "квалификатор слабого ключа из решения QUALIFY (place) расходится у валидатора и базы: запрет identity решение не покрывает")

# E3 migrator / inserted as MERGED
bad = org("ent_e3_bad", "Гр\U0001E030", inn=D._inn10(787000001))
rm = psql("SET SESSION AUTHORIZATION ac_migrator;\nBEGIN;\nSET LOCAL ac.historical_import = 'on';\n" + body_of([bad], user="ac_migrator") + "\nCOMMIT;")
t = org("ent_e3_t", "Цель", inn=D._inn10(787000002)); assert psql(ingest_sql([t], {})).returncode == 0; time.sleep(1.1)
bad2 = org("ent_e3_bad2", "Гр\U0001E030", inn=D._inn10(787000003)); bad2.update(status="MERGED", merged_into="ent_e3_t", status_changed_at=utc(0))
rm2 = psql(ingest_sql([bad2], {}))
print("E3 мигратор (исторический режим):", first_err(rm)[:70], "| вставка сразу слитой:", first_err(rm2)[:70])
report("E3", rm.returncode == 0 or rm2.returncode == 0, "сущность с неназначенным символом записана в обход")

# E2b: следствие — второе событие с тем же названием и датой и местом «Гра»
ev2 = dict(ev1, entity_id="ent_e2_ev2", identity={"title": "Собрание акционеров", "date": "2026-05-05", "place": "Гра"}, created_at=utc(0))
ds = copy.deepcopy(ds0); ds["records"] += [dict(ev1, schema_version="core-ontology/0.4"), dec, dict(ev2, schema_version="core-ontology/0.4", created_at=dec["decided_at"])]
codes2 = VAL.validate(ds, trust, content).codes()
r2 = psql(ingest_sql([ev2], {}))
print(f"E2b второе событие с местом «Гра»: валидатор {codes2 or 'ПРИНЯЛ'}; база {first_err(r2)[:90]}")
report("E2b", bool(codes2) and r2.returncode == 0, "направление «валидатор отверг, база приняла»")

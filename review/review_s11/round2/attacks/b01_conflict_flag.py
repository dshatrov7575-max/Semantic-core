#!/usr/bin/env python3
"""Раунд 2: правило конфликта как предупреждение (валидатор) и флаг чтения subject_conflict (база).
F1  S11R-01: утверждение, затем сущность с ИНН строки одной транзакцией — принято; флаг и предупреждение есть; verified = true
F2  S11R-02: «обратная датировка» утверждения — флаг есть
F3  S11R-03: исторический импорт сущности — verified остаётся true, появляется флаг
F4  вторая сущность маркирована выше утверждения: предупреждение валидатора есть, флаг базы молчит ДЛЯ ВСЕХ читателей
    (и для читателя с полным допуском); ac.dataset_subject тому же читателю показывает CONFLICT
F5  утечка: читатель без допуска к закрытой сущности флага не видит (контроль)
F6  путешествие во времени: на момент до создания второй сущности флага нет
F7  вторая сущность влита в третью, третья закрыта: флаг молчит, предупреждение есть
"""
import copy, json, time
from datetime import datetime, timezone, timedelta
from rv import *

dv = fresh()
ds0, trust, content = build()
BETA, TRUB, ALFA, GAMMA = REGISTRY_ROWS[3], REGISTRY_ROWS[1], REGISTRY_ROWS[2], REGISTRY_ROWS[4]
CS_PD = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def ent_rec(eid):
    return json.loads(one("SELECT jsonb_strip_nulls(jsonb_build_object('kind','Entity','schema_version','core-ontology/0.4','entity_id',entity_id,'project_id',project_id,"
                          "'entity_type',entity_type,'identity',identity,'status',status,'merged_into',merged_into,"
                          "'status_changed_at',to_char(status_changed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                          "'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'marking',marking,'display_name',display_name)) "
                          f"FROM ac.entities WHERE entity_id = '{eid}'"))


def val(eids, c):
    ds = copy.deepcopy(ds0)
    ds["records"] += [ent_rec(e) for e in eids] + [c]
    rep = VAL.validate(ds, trust, content)
    return rep.codes(), [w["code"] for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT"]


def ev(c, t="now()", user=None):
    return json.loads(one(f"SELECT ac.evidence_json('{c['claim_id']}', {t})"))[0]


def dossier_flags(eid, user):
    d = json.loads(one(f"SELECT ac.dossier('{PRJ}', '{eid}');", user))
    return [e.get("subject_conflict") for f in S3.facts_of(d) for cl in f["claims"] + f.get("other_claims", []) for e in cl["evidence"] if "row_sha256" in e]


# F1
a = org("ent_q1_beta", "ООО «Бета»", ogrn=BETA["ogrn"]); b = org("ent_q1_beta_inn", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(1.2)
c = claim(dv.evidence([BETA["ogrn"]], ["address", "inn"]), subj="ent_q1_beta", address=BETA["address"])
rec = (datetime.now(timezone.utc) + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
c = {k: v for k, v in c.items() if k != "claim_id"}; c["recorded_at"] = rec; c["claim_id"] = "clm:sha256:" + digest(c)
r = psql(L + "BEGIN;\nSELECT pg_sleep(2.3);\n" + body_of([c]) + "\n" + body_of([b]) + "\nCOMMIT;")
e = ev(c); codes, warn = val(["ent_q1_beta", "ent_q1_beta_inn"], c)
print(f"F1 одна транзакция (утверждение, потом сущность): {'ПРИНЯТО' if r.returncode == 0 else first_err(r)}; verified={e['verified']} subject_conflict={e.get('subject_conflict')}; валидатор: ошибки {codes}, предупреждение {warn}")
report("F1", not (r.returncode == 0 and e["verified"] and e.get("subject_conflict") is True and not codes and warn), "S11R-01: база и валидатор расходятся или флаг молчит")
# после слияния флаг снимается
assert psql(L + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_q1_beta' WHERE entity_id = 'ent_q1_beta_inn';").returncode == 0
time.sleep(1.1)
e2 = ev(c); codes, warn = val(["ent_q1_beta", "ent_q1_beta_inn"], c)
print(f"   после слияния: subject_conflict={e2.get('subject_conflict')}; валидатор: {codes} {warn}")

# F2
a = org("ent_q2_trub", "АО «Трубопроводстрой»", ogrn=TRUB["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(2.2); t_between = utc(1); time.sleep(1.2)
assert psql(ingest_sql([org("ent_q2_trub_inn", "АО «Трубопроводстрой» (по ИНН)", inn=TRUB["inn"])], {})).returncode == 0
time.sleep(1.2)
c2 = claim(dv.evidence([TRUB["ogrn"]], ["address", "inn"]), subj="ent_q2_trub", address=TRUB["address"])
c2 = {k: v for k, v in c2.items() if k != "claim_id"}; c2["recorded_at"] = t_between; c2["claim_id"] = "clm:sha256:" + digest(c2)
r = psql(ingest_sql([c2], {})); e = ev(c2); codes, warn = val(["ent_q2_trub", "ent_q2_trub_inn"], c2)
print(f"F2 утверждение датировано до создания второй сущности: {'ПРИНЯТО' if r.returncode == 0 else first_err(r)}; subject_conflict={e.get('subject_conflict')}; валидатор {codes} {warn}")
report("F2", not (e.get("subject_conflict") is True and warn and not codes), "S11R-02: флаг или предупреждение молчит")

# F3 + F6
a = org("ent_q3_alfa", "ООО «Альфа-Сервис»", ogrn=ALFA["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(2.2); t_hist = utc(1); time.sleep(1.2)
c3 = claim(dv.evidence([ALFA["ogrn"]], ["address", "inn"]), subj="ent_q3_alfa", address=ALFA["address"])
assert psql(ingest_sql([c3], {})).returncode == 0
before = ev(c3)
t_mid = one("SELECT clock_timestamp()")
time.sleep(1.2)
b3 = org("ent_q3_alfa_inn", "ООО «Альфа-Сервис» (по ИНН)", inn=ALFA["inn"])
assert psql(ingest_sql([b3], {})).returncode == 0
after = ev(c3); past = ev(c3, f"'{t_mid}'")
print(f"F3/F6 до второй сущности: verified={before['verified']} flag={before.get('subject_conflict')}; после: verified={after['verified']} flag={after.get('subject_conflict')}; "
      f"на прошлый момент: flag={past.get('subject_conflict')}")
report("F3", not (after["verified"] and after.get("subject_conflict") is True and past.get("subject_conflict") is None), "S11R-03 / путешествие во времени")
b4 = org("ent_q3_hist_inn", "ООО (история)", inn=D._inn10(770000555)); b4["created_at"] = t_hist
rh = psql("SET SESSION AUTHORIZATION ac_migrator;\nBEGIN;\nSET LOCAL ac.historical_import = 'on';\n" + body_of([b4], user="ac_migrator") + "\nCOMMIT;")
print("   исторический импорт сущности задним числом:", "принят" if rh.returncode == 0 else first_err(rh)[:80], "| verified:", ev(c3)["verified"])

# F4/F5/F7 the other entity is marked above the claim (own rows: valid made-up numbers)
def row(n, name):
    return {"ogrn": D._ogrn(30_000_000_000 + n), "inn": D._inn10(780_000_000 + n), "name": name, "address": f"г. Тест, ул. {n}", "director": None,
            "registered_on": "2020-01-01", "active": True, "employees": 1}
R4, R7 = row(4, "ООО «Четыре»"), row(7, "ООО «Семь»")
v2, r = new_version("r2-flag", rows=[R4, R7])
assert r.returncode == 0, first_err(r)
_, bad = D.load_rows(T, v2.source_id, copy_file(v2), v2.columns)
assert bad is None, first_err(bad)
a = org("ent_q4_a", R4["name"], ogrn=R4["ogrn"])
h = org("ent_q4_hidden", R4["name"] + " (закрытая карточка, по ИНН)", marking=CS_PD, inn=R4["inn"])
a7 = org("ent_q7_a", R7["name"], ogrn=R7["ogrn"])
b7 = org("ent_q7_b", R7["name"] + " (по ИНН)", inn=R7["inn"])
x7 = org("ent_q7_hidden_survivor", "ООО «Закрытая выжившая»", marking=CS_PD, inn=D._inn10(780_000_099))
assert psql(ingest_sql([a, h, a7, b7, x7], {})).returncode == 0
time.sleep(1.2)
c4 = claim(v2.evidence([R4["ogrn"]], ["address", "inn"]), subj="ent_q4_a", address=R4["address"])
c7 = claim(v2.evidence([R7["ogrn"]], ["address", "inn"]), subj="ent_q7_a", address=R7["address"])
assert psql(ingest_sql([c4, c7], {})).returncode == 0
src = json.loads(one(f"SELECT body || jsonb_build_object('observations', (SELECT jsonb_agg(jsonb_build_object('observed_at', to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), 'origin_uri', origin_uri, 'observed_by', observed_by)) FROM ac.source_observations o WHERE o.source_id = s.source_id)) FROM ac.sources s WHERE source_id = '{v2.source_id}'"))


def val2(eids, c):
    ds = copy.deepcopy(ds0)
    ds["records"] += [src] + [ent_rec(e) for e in eids] + [c]
    cont = dict(content); cont[v2.source_id] = v2.manifest_bytes; cont.update(dict(v2.files))
    rep = VAL.validate(ds, trust, cont)
    return rep.codes(), [w["code"] for w in rep.warnings if w["code"] == "ROW_SUBJECT_CONFLICT"]


codes, warn = val2(["ent_q4_a", "ent_q4_hidden"], c4)
e4 = ev(c4)
subj_full = json.loads(one(f"SELECT ac.dataset_subject('{PRJ}', '{v2.source_id}', {key(R4['ogrn'])});", "ac_rd_full"))
subj_cs = json.loads(one(f"SELECT ac.dataset_subject('{PRJ}', '{v2.source_id}', {key(R4['ogrn'])});", "ac_rd_cs"))
print(f"F4 вторая сущность (ИНН строки) маркирована выше утверждения: валидатор {codes} предупреждение {warn}; флаг базы: {e4.get('subject_conflict')}")
print(f"   досье субъекта, читатель с ПОЛНЫМ допуском: флаги {dossier_flags('ent_q4_a', 'ac_rd_full')}; ac.dataset_subject ему же: {subj_full['status']} {[o['entity_id'] for o in subj_full['owners']]}")
print(f"F5 читатель без ПД: флаги {dossier_flags('ent_q4_a', 'ac_rd_cs')}; ac.dataset_subject: {subj_cs['status']} {[o['entity_id'] for o in subj_cs['owners']]}")
report("F4", bool(warn) and e4.get("subject_conflict") is None and subj_full["status"] == "CONFLICT",
       "конфликт есть (валидатор предупреждает, dataset_subject читателю с полным допуском — CONFLICT), а флаг subject_conflict молчит для всех читателей")
report("F5", any(dossier_flags('ent_q4_a', 'ac_rd_cs')), "читатель без допуска видит флаг о закрытой сущности")
assert psql(L + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_q7_hidden_survivor' WHERE entity_id = 'ent_q7_b';").returncode != 0 or True
st = one("SELECT status FROM ac.entities WHERE entity_id = 'ent_q7_b'")
time.sleep(1.1)
codes, warn = val2(["ent_q7_a", "ent_q7_b", "ent_q7_hidden_survivor"], c7)
print(f"F7 вторая сущность {st} в закрытую третью: валидатор {codes} {warn}; флаг базы: {ev(c7).get('subject_conflict')}; читатель с полным допуском: {dossier_flags('ent_q7_a', 'ac_rd_full')}")

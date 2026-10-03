#!/usr/bin/env python3
"""Раунд 3: правило открытой Проверки, флаг по допуску читателя, цепочка с закрытыми версиями.
O1  сущность и её Проверка в одной транзакции, затем слияние в ней же
O2  Проверка REQUESTED (не IN_PROGRESS) — слияние субъекта
O3  гонка: слияние субъекта (открыто) против открытия Проверки; и наоборот
O4  исторический импорт (мигратор): слияние субъекта открытой Проверки задним числом
O5  после отмены (CANCELLED) слияние проходит; слитая цель (выжившая) с открытой Проверкой — слияние В неё проходит
O6  вставка сущности сразу RETIRED/MERGED и Проверка по ней
F1  флаг: читатель без ПД / с ПД / роль без допуска в проекте / суперпользователь / загрузчик
F2  флаг и вторая сущность, слитая в закрытую для читателя третью
K1  цепочка: v1 -> v2 (закрыта) [-> v3 открыта]: что узнаёт читатель без допуска о закрытой версии
K2  ветвление из закрытой: v1 -> v2 (закрыта) -> {v3a, v3b}; две закрытые ветви и одна открытая за одной из них
"""
import copy, json, time
from rv import *
from a40_helpers import *
import regression_s22 as R22

dv = fresh()
L = "SET SESSION AUTHORIZATION ac_loader;\n"
CS_PD = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}
chk = lambda kid, eid, st="IN_PROGRESS": R22.new_check(kid, "TENDERS_ONLY").replace("ent_k_developer", eid).replace("IN_PROGRESS", st)   # noqa: E731
mrg = lambda a, b: f"UPDATE ac.entities SET status = 'MERGED', merged_into = '{b}' WHERE entity_id = '{a}';"   # noqa: E731
n = [0]
def pair():
    n[0] += 1
    a, b = org(f"ent_o{n[0]}_x", f"П{n[0]}", inn=D._inn10(784000000 + 2 * n[0])), org(f"ent_o{n[0]}_y", f"В{n[0]}", inn=D._inn10(784000001 + 2 * n[0]))
    return a, b

# O1
a, b = pair()
r = psql(L + "BEGIN;\n" + body_of([a, b]) + "\n" + chk("chk_o1", a["entity_id"]) + "\n" + mrg(a["entity_id"], b["entity_id"]) + "\nCOMMIT;")
print("O1 сущность, Проверка и слияние одной транзакцией:", first_err(r)[:90])
bad = [r.returncode == 0]
# O2
a, b = pair(); assert psql(ingest_sql([a, b], {})).returncode == 0; time.sleep(1.1)
r0 = psql(L + chk("chk_o2", a["entity_id"], "REQUESTED")); r = psql(L + mrg(a["entity_id"], b["entity_id"]))
print("O2 Проверка REQUESTED:", first_err(r0)[:40], "| слияние субъекта:", first_err(r)[:80])
bad.append(r0.returncode == 0 and r.returncode == 0)
# O3 races
a, b = pair(); assert psql(ingest_sql([a, b], {})).returncode == 0; time.sleep(1.1)
th, o1 = bg(L + "BEGIN;\n" + chk("chk_o3", a["entity_id"]) + "\nSELECT pg_sleep(3);\nCOMMIT;"); time.sleep(1.5)
r2 = psql(L + mrg(a["entity_id"], b["entity_id"])); th.join()
print("O3 Проверка открывается (не зафиксирована) / слияние субъекта:", first_err(o1[0])[:30], "|", first_err(r2)[:80])
bad.append(o1[0].returncode == 0 and r2.returncode == 0)
a, b = pair(); assert psql(ingest_sql([a, b], {})).returncode == 0; time.sleep(1.1)
th, o1 = bg(L + "BEGIN;\n" + f"UPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = '{a['entity_id']}';" + "\nSELECT pg_sleep(3);\nCOMMIT;"); time.sleep(1.5)
r2 = psql(L + chk("chk_o3b", a["entity_id"])); th.join()
print("   вывод из употребления (не зафиксирован) / открытие Проверки:", first_err(o1[0])[:30], "|", first_err(r2)[:80])
bad.append(o1[0].returncode == 0 and r2.returncode == 0)
# O4 migrator, historical
a, b = pair(); assert psql(ingest_sql([a, b], {})).returncode == 0; time.sleep(2.2); t_hist = utc(1); time.sleep(1.1)
assert psql(L + chk("chk_o4", a["entity_id"])).returncode == 0
r = psql("SET SESSION AUTHORIZATION ac_migrator;\nBEGIN;\nSET LOCAL ac.historical_import = 'on';\n" + mrg(a["entity_id"], b["entity_id"]) + "\nCOMMIT;")
print("O4 мигратор (исторический режим) сливает субъект открытой Проверки:", first_err(r)[:90])
bad.append(r.returncode == 0)
# O5
r1 = psql(L + "UPDATE ac.checks SET status = 'CANCELLED', body = body || '{\"status\": \"CANCELLED\"}' WHERE check_id = 'chk_o4';")
r2 = psql(L + mrg(a["entity_id"], b["entity_id"]))
print("O5 отмена Проверки:", first_err(r1)[:60], "| затем слияние:", first_err(r2)[:60])
a2, b2 = pair(); assert psql(ingest_sql([a2, b2], {})).returncode == 0; time.sleep(1.1)
assert psql(L + chk("chk_o5", b2["entity_id"])).returncode == 0
r3 = psql(L + mrg(a2["entity_id"], b2["entity_id"]))
print("   слияние В субъект открытой Проверки:", first_err(r3)[:60])
# O6
a, b = pair(); a.update(status="RETIRED", status_changed_at=utc(0))
r0 = psql(ingest_sql([a, b], {})); time.sleep(1.1); r = psql(L + chk("chk_o6", a["entity_id"]))
print("O6 сущность вставлена сразу RETIRED:", first_err(r0)[:40], "| Проверка по ней:", first_err(r)[:80])
bad.append(r0.returncode == 0 and r.returncode == 0)
a, b = pair(); a.update(status="RETIRED", status_changed_at=utc(0))
r = psql(L + "BEGIN;\n" + chk("chk_o6b", a["entity_id"]) + "\n" + body_of([a, b]) + "\nCOMMIT;")
print("   Проверка раньше сущности в той же транзакции (сущность сразу RETIRED):", first_err(r)[:90])
bad.append(r.returncode == 0)
open_bad = one("SELECT count(*) FROM ac.checks k JOIN ac.entities e ON e.entity_id = k.subject_entity_id WHERE k.status NOT IN ('COMPLETED','CANCELLED') AND e.status <> 'ACTIVE'")
print("открытых Проверок с не-ACTIVE субъектом в базе:", open_bad)
report("O", any(bad) or open_bad != "0", "обход правила «субъект открытой Проверки — ACTIVE»")

# ---- F flag by the reader's clearance
def row(k, name):
    return {"ogrn": D._ogrn(31_000_000_000 + k), "inn": D._inn10(785_000_000 + k), "name": name, "address": f"г. Тест, ул. {k}", "director": None,
            "registered_on": "2020-01-01", "active": True, "employees": 1}
R4, R7 = row(4, "ООО «Четыре»"), row(7, "ООО «Семь»")
v2, r = new_version("r3-flag", rows=[R4, R7]); assert r.returncode == 0
_, badl = D.load_rows(T, v2.source_id, copy_file(v2), v2.columns); assert badl is None
ents = [org("ent_f_a", R4["name"], ogrn=R4["ogrn"]), org("ent_f_h", R4["name"] + " (закрытая)", marking=CS_PD, inn=R4["inn"]),
        org("ent_f7_a", R7["name"], ogrn=R7["ogrn"]), org("ent_f7_b", R7["name"] + " (по ИНН)", marking=CS_PD, inn=R7["inn"]),
        org("ent_f7_s", "Выжившая открытая", inn=D._inn10(785000099))]
assert psql(ingest_sql(ents, {})).returncode == 0; time.sleep(1.2)
c4 = claim(v2.evidence([R4["ogrn"]], ["address", "inn"]), subj="ent_f_a", address=R4["address"])
c7 = claim(v2.evidence([R7["ogrn"]], ["address", "inn"]), subj="ent_f7_a", address=R7["address"])
assert psql(ingest_sql([c4, c7], {})).returncode == 0
assert psql("DO $$ BEGIN CREATE ROLE ac_rd_r3_other LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;\nSET ROLE ac_trust_admin;\n"
            "INSERT INTO ac_trust.clearances (role_name, project_id, level, categories, granted_at) VALUES ('ac_rd_r3_other', 'prj_dossier', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}', '2000-01-01');").returncode == 0


def flags(eid, user):
    r = psql(f"SELECT ac.dossier('{PRJ}', '{eid}');", user)
    if r.returncode:
        return first_err(r)[:40]
    d = json.loads(r.stdout)
    return [e.get("subject_conflict") for f in S3.facts_of(d) for cl in f["claims"] + f.get("other_claims", []) for e in cl["evidence"] if "row_sha256" in e]


def direct(c, user=None):
    r = psql(f"SELECT ac.evidence_json('{c['claim_id']}', now());", user)
    return json.loads(r.stdout)[0].get("subject_conflict") if r.returncode == 0 else first_err(r)[:40]


res = {u: flags("ent_f_a", u) for u in ("ac_rd_cs", "ac_rd_full", "ac_rd_r3_other", "ac_rd_none")}
print("F1 досье субъекта (вторая сущность с ПД):", res)
print("   прямой вызов evidence_json: суперпользователь", direct(c4), "| загрузчик (без допуска, не суперпользователь):", direct(c4, "ac_loader"), "| читатель без ПД:", direct(c4, "ac_rd_cs"))
prov = psql(f"SELECT ac.provenance('{c4['claim_id']}');", "ac_rd_cs")
pf = [e.get("subject_conflict") for e in json.loads(prov.stdout)["evidence"]] if prov.returncode == 0 else first_err(prov)[:50]
print("   ac.provenance читателю без ПД:", pf)
report("F1", res["ac_rd_cs"] != [None] or res["ac_rd_full"] != [True] or pf not in ([None], ) and not isinstance(pf, str), "флаг по допуску читателя: утечка или молчание")
# F2: the other entity (hidden for the reader) — the flag for the reader without PD
print("F2 вторая сущность с ПД, читатель без ПД:", flags("ent_f7_a", "ac_rd_cs"), "| с ПД:", flags("ent_f7_a", "ac_rd_full"))

# ---- K chain with hidden versions
ADDR = "Московская обл., г. Заречный, ул. Заречная, д. 1"
RESTR = {"level": "RESTRICTED", "categories": []}
rw = lambda addr: [{"code": "A", "ogrn": OGRN_DEV, "address": addr}]   # noqa: E731
time.sleep(1.1)
v1 = ver("dst_k1", "v1", cols(), ["code"], rw(ADDR)); time.sleep(1.1)
c = mk_claim(v1, ["A"], ADDR)
s0 = currency(c)
h = ver("dst_k1", "v2-secret", cols(), ["code"], rw("секрет"), previous=v1.source_id, marking=RESTR)
s1 = currency(c)
v3 = ver("dst_k1", "v3", cols(), ["code"], rw(ADDR), previous=h.source_id)
s2 = currency(c)
info = json.loads(one(f"SELECT ac.dataset_info('{PRJ}', '{v3.source_id}');", "ac_rd_cs"))
print(f"K1 только v1: {s0['status']}; + закрытая v2: {s1['status']}; + открытая v3 за закрытой: {s2['status']} latest={s2.get('latest', {}).get('version_label')}; "
      f"dataset_info(v3).previous для читателя: {info['previous']}")
print("   вывод читателя: v3 названа следующей за v1, но её previous ему не показан (а v1 он видит) => между ними есть версия, закрытая для него")
report("K1", s1 != s0, "появление закрытой версии само меняет ответ читателю без допуска")
report("K1b", s2.get("latest", {}).get("version_label") == "v3" and info["previous"] is None,
       "существование закрытой промежуточной версии выводится из пары ответов currency.latest = v3 и dataset_info(v3).previous = null")
a = ver("dst_k2", "v1", cols(), ["code"], rw(ADDR)); time.sleep(1.1)
c = mk_claim(a, ["A"], ADDR)
hh = ver("dst_k2", "v2-secret", cols(), ["code"], rw("секрет"), previous=a.source_id, marking=RESTR)
ver("dst_k2", "v3a", cols(), ["code"], rw(ADDR), previous=hh.source_id)
k2a = currency(c)["status"]
ver("dst_k2", "v3b", cols(), ["code"], rw("другой"), previous=hh.source_id)
k2b = currency(c)["status"]
b = ver("dst_k3", "v1", cols(), ["code"], rw(ADDR)); time.sleep(1.1)
c3 = mk_claim(b, ["A"], ADDR)
h1 = ver("dst_k3", "s1", cols(), ["code"], rw("с1"), previous=b.source_id, marking=RESTR)
h2 = ver("dst_k3", "s2", cols(), ["code"], rw("с2"), previous=b.source_id, marking=RESTR)
ver("dst_k3", "v3", cols(), ["code"], rw("новый"), previous=h1.source_id)
k3 = currency(c3)
print(f"K2 v1 -> закрытая -> v3a: {k2a}; + v3b от той же закрытой: {k2b}; две закрытые ветви и открытая за одной: {k3['status']}")

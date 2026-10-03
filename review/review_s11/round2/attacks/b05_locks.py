#!/usr/bin/env python3
"""Раунд 2 (б): новые блокировки entity:/text:/shared и соседние гонки.
L1  взаимная блокировка: два сеанса пишут по утверждению об ОДНОЙ сущности (разделяемая entity:, S11R-04) и затем в той
    же транзакции берут исключительную entity: (вливают в неё дубль). До исправления второй просто ждал.
L2  то же с добавлением своего утверждения в Проверку (check_claims_guard берёт исключительную entity: субъекта).
L3  соседняя гонка: решение QUALIFY по сущности, которую в этот момент сливают (страж читает статус без блокировки).
L4  новое правило схемы: при непрерывной записи утверждений схемы tenant конструктор модели не может записать версию.
L5  S11R-08 повторно: утверждение и удаление предиката в одну секунду.
"""
import copy, json, time, threading
from rv import *
from s9_tests import claim as claim9, sd
from schema_s9 import schema_sql

dv = fresh()
ds0, trust, content = build()
L = "SET SESSION AUTHORIZATION ac_loader;\n"
ALFA, TRUB, BETA = REGISTRY_ROWS[2], REGISTRY_ROWS[1], REGISTRY_ROWS[3]


def pair(sql_a, sql_b):
    oa, ob = [], []
    ta = threading.Thread(target=lambda: oa.append(psql(sql_a))); tb = threading.Thread(target=lambda: ob.append(psql(sql_b)))
    t0 = time.time(); ta.start(); tb.start(); ta.join(); tb.join()
    return oa[0], ob[0], round(time.time() - t0, 1)


# ---- L1
ents = [org("ent_l1_main", "ООО «Альфа-Сервис»", ogrn=ALFA["ogrn"]), org("ent_l1_dup1", "Дубль 1", inn=D._inn10(781000001)), org("ent_l1_dup2", "Дубль 2", inn=D._inn10(781000002))]
assert psql(ingest_sql(ents, {})).returncode == 0
time.sleep(1.2)
c1 = claim(dv.evidence([ALFA["ogrn"]], ["address"]), subj="ent_l1_main", address=ALFA["address"])
c2 = claim(dv.evidence([ALFA["ogrn"]], ["address", "name"]), subj="ent_l1_main", address=ALFA["address"])


def tx(c, dup):
    return (L + "BEGIN;\n" + body_of([c]) + "\nSELECT pg_sleep(1.5);\n"
            f"UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_l1_main' WHERE entity_id = '{dup}';\nCOMMIT;")


ra, rb, dt = pair(tx(c1, "ent_l1_dup1"), tx(c2, "ent_l1_dup2"))
print(f"L1 два сеанса: утверждение о сущности + слияние дубля в неё ({dt} с): A: {first_err(ra)[:70]} | B: {first_err(rb)[:70]}")
dead1 = "deadlock" in (ra.stderr + rb.stderr)
report("L1", dead1, "взаимная блокировка на законном сценарии (утверждение о сущности и слияние в неё в одной транзакции, два сеанса)")

# ---- L2 claim + its Check row
import regression_s22 as R22
ents = [org("ent_l2_main", "АО «Трубопроводстрой»", ogrn=TRUB["ogrn"])]
assert psql(ingest_sql(ents, {})).returncode == 0
time.sleep(1.2)
c1 = claim(dv.evidence([TRUB["ogrn"]], ["address"]), subj="ent_l2_main", address=TRUB["address"])
c2 = claim(dv.evidence([TRUB["ogrn"]], ["address", "name"]), subj="ent_l2_main", address=TRUB["address"])
try:
    mk = lambda kid: R22.new_check(kid, "FULL").replace("ent_k_developer", "ent_l2_main")   # noqa: E731
    pre = psql(L + "BEGIN;\n" + mk("chk_l2_a") + "\n" + mk("chk_l2_b") + "\nINSERT INTO ac.check_findings VALUES ('chk_l2_a', 'CORPORATE', 'FOUND', 'LOW');\n"
               "INSERT INTO ac.check_findings VALUES ('chk_l2_b', 'CORPORATE', 'FOUND', 'LOW');\nSET CONSTRAINTS ALL IMMEDIATE;\n" if False else
               L + "SELECT 1;")
    def tx2(c, kid):
        return (L + "BEGIN;\n" + body_of([c]) + "\nSELECT pg_sleep(1.5);\n" + mk(kid) + f"\nINSERT INTO ac.check_findings VALUES ('{kid}', 'CORPORATE', 'FOUND', 'LOW');\n"
                f"INSERT INTO ac.check_finding_claims VALUES ('{PRJ}', '{kid}', 'CORPORATE', '{c['claim_id']}');\nCOMMIT;")
    ra, rb, dt = pair(tx2(c1, "chk_l2_a"), tx2(c2, "chk_l2_b"))
    print(f"L2 два сеанса: утверждение о сущности + своя Проверка с этим утверждением ({dt} с): A: {first_err(ra)[:80]} | B: {first_err(rb)[:80]}")
    report("L2", "deadlock" in (ra.stderr + rb.stderr), "взаимная блокировка: утверждение и строка Проверки о той же сущности в одной транзакции, два сеанса")
except Exception as ex:   # noqa: BLE001
    print("L2 не выполнен:", type(ex).__name__, str(ex)[:100])

# ---- L3 QUALIFY vs merge
def person(eid, sur, bd):
    return {"kind": "Entity", "entity_id": eid, "project_id": "prj_dossier", "entity_type": "PERSON", "status": "ACTIVE",
            "identity": {"surname": sur, "given_name": "Пётр", "birth_date": bd}, "display_name": sur, "created_at": utc(0), "marking": CONF_PD}
assert psql(ingest_sql([person("ent_l3_p", "Уточнин", "1980-01-01"), person("ent_l3_q", "Выживин", "1981-02-02")], {})).returncode == 0
time.sleep(1.2)
from ingest_s4 import q as Q
dec = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_l3", "project_id": "prj_dossier", "decision": "QUALIFY",
       "entity_id": "ent_l3_p", "disambiguator": "tot-samyj", "decided_by": "usr_analyst1", "decided_at": utc(0)}
th, o1 = bg(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_l3_q' WHERE entity_id = 'ent_l3_p';\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.5)
dec["decided_at"] = utc(0)
r2 = psql(L + "BEGIN;\n" + f"INSERT INTO ac.identity_decisions VALUES ('idd_l3','prj_dossier','QUALIFY','ent_l3_p',NULL,'disambiguator','tot-samyj','usr_analyst1',{Q(dec['decided_at'])},{Q(dec)});" + "\nCOMMIT;")
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"L3 слияние P -> Q: {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])[:80]}; QUALIFY по P: {'COMMIT' if r2.returncode == 0 else first_err(r2)[:90]}")
codes = None
if both:
    def ent_rec(eid):
        return json.loads(one("SELECT jsonb_strip_nulls(jsonb_build_object('kind','Entity','schema_version','core-ontology/0.4','entity_id',entity_id,'project_id',project_id,"
                              "'entity_type',entity_type,'identity',identity,'status',status,'merged_into',merged_into,"
                              "'status_changed_at',to_char(status_changed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                              "'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'marking',marking,'display_name',display_name)) "
                              f"FROM ac.entities WHERE entity_id = '{eid}'"))
    ds = copy.deepcopy(ds0); ds["records"] += [ent_rec("ent_l3_p"), ent_rec("ent_l3_q"), dict(dec, decided_at=iso(one("SELECT decided_at FROM ac.identity_decisions WHERE decision_id = 'idd_l3'")))]
    rep = VAL.validate(ds, trust, content); codes = rep.codes()
    print("   валидатор на мире из базы:", codes, [e.get("msg", "")[:100] for e in rep.errors][:2])
    print("   ключи в базе:", one("SELECT string_agg(scheme || ' владелец ' || owner_entity_id || ' qual=' || coalesce(qual, '-'), '; ') FROM ac.entity_keys WHERE owner_entity_id IN ('ent_l3_p', 'ent_l3_q') AND strength = 'WEAK'"))
    seq = psql(L + "BEGIN;\n" + f"INSERT INTO ac.identity_decisions VALUES ('idd_l3b','prj_dossier','QUALIFY','ent_l3_p',NULL,'disambiguator','x','usr_analyst1',now(),{Q(dict(dec, decision_id='idd_l3b', disambiguator='x'))});" + "\nROLLBACK;")
    print("   контроль (последовательно, QUALIFY слитой):", first_err(seq)[:100])
report("L3", both and bool(codes), f"READ COMMITTED: уточнение (QUALIFY) слитой сущности зафиксировано; валидатор: {codes}")

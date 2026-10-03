#!/usr/bin/env python3
"""Раунд 2 (б), соседняя гонка: открытие Проверки по сущности, которую в этот момент сливают. ac.checks_guard для
незакрытой Проверки блокировку entity: не берёт и читает статус субъекта без неё (тот же класс, что S11R-04…06).
Итог: открытая (IN_PROGRESS) Проверка по слитой сущности; валидатор: CHECK_SUBJECT_INVALID."""
import copy, json, time
from rv import *
import regression_s22 as R22

dv = fresh(load_rows=False)
ds0, trust, content = build()
L = "SET SESSION AUTHORIZATION ac_loader;\n"
x = org("ent_c6_x", "ООО «Проверяемое»", inn=D._inn10(782000001)); y = org("ent_c6_y", "ООО «Выжившее»", inn=D._inn10(782000002))
assert psql(ingest_sql([x, y], {})).returncode == 0
time.sleep(1.2)
th, o1 = bg(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_c6_y' WHERE entity_id = 'ent_c6_x';\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.5)
r2 = psql(L + "BEGIN;\n" + R22.new_check("chk_c6", "TENDERS_ONLY").replace("ent_k_developer", "ent_c6_x") + "\nCOMMIT;")
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"слияние X -> Y: {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])[:80]}; открытие Проверки по X: {'COMMIT' if r2.returncode == 0 else first_err(r2)[:90]}")
codes = None
if both:
    print("в базе:", one("SELECT k.check_id || ' ' || k.status || ', запрошена ' || k.requested_at || '; субъект ' || e.entity_id || ' ' || e.status || ' с ' || e.status_changed_at "
                         "FROM ac.checks k JOIN ac.entities e ON e.entity_id = k.subject_entity_id WHERE k.check_id = 'chk_c6'"))
    def ent_rec(eid):
        return json.loads(one("SELECT jsonb_strip_nulls(jsonb_build_object('kind','Entity','schema_version','core-ontology/0.4','entity_id',entity_id,'project_id',project_id,"
                              "'entity_type',entity_type,'identity',identity,'status',status,'merged_into',merged_into,"
                              "'status_changed_at',to_char(status_changed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                              "'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'marking',marking,'display_name',display_name)) "
                              f"FROM ac.entities WHERE entity_id = '{eid}'"))
    tpl = next(r for r in ds0["records"] if r["kind"] == "Check" and r["status"] == "IN_PROGRESS")
    k = dict(copy.deepcopy(tpl), check_id="chk_c6", subject_entity_id="ent_c6_x", requested_at=iso(one("SELECT requested_at FROM ac.checks WHERE check_id = 'chk_c6'")),
             as_of=one("SELECT as_of FROM ac.checks WHERE check_id = 'chk_c6'"), marking=json.loads(one("SELECT marking FROM ac.checks WHERE check_id = 'chk_c6'")))
    k.pop("previous_check_id", None)
    ds = copy.deepcopy(ds0); ds["records"] += [ent_rec("ent_c6_x"), ent_rec("ent_c6_y"), k]
    rep = VAL.validate(ds, trust, content); codes = rep.codes()
    print("валидатор на мире из базы:", codes, [e.get("msg", "")[:100] for e in rep.errors][:2])
    seq = psql(L + "BEGIN;\n" + R22.new_check("chk_c6b", "TENDERS_ONLY").replace("ent_k_developer", "ent_c6_x") + "\nROLLBACK;")
    print("контроль (последовательно):", first_err(seq)[:100])
report("C6", both and "CHECK_SUBJECT_INVALID" in (codes or []), f"READ COMMITTED: открытая Проверка по слитой сущности; валидатор: {codes}")

# то же БЕЗ гонки: Проверка открыта, затем субъект слит — база принимает, валидатор такой мир отвергает
x = org("ent_c7_x", "ООО «П2»", inn=D._inn10(782000011)); y = org("ent_c7_y", "ООО «В2»", inn=D._inn10(782000012))
assert psql(ingest_sql([x, y], {})).returncode == 0
time.sleep(1.2)
r1 = psql(L + "BEGIN;\n" + R22.new_check("chk_c7", "TENDERS_ONLY").replace("ent_k_developer", "ent_c7_x") + "\nCOMMIT;")
r2 = psql(L + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_c7_y' WHERE entity_id = 'ent_c7_x';")
k7 = dict(copy.deepcopy(tpl), check_id="chk_c7", subject_entity_id="ent_c7_x", requested_at=iso(one("SELECT requested_at FROM ac.checks WHERE check_id = 'chk_c7'")),
          as_of=one("SELECT as_of FROM ac.checks WHERE check_id = 'chk_c7'"), marking=json.loads(one("SELECT marking FROM ac.checks WHERE check_id = 'chk_c7'")))
k7.pop("previous_check_id", None)
ds = copy.deepcopy(ds0); ds["records"] += [ent_rec("ent_c7_x"), ent_rec("ent_c7_y"), k7]
codes7 = VAL.validate(ds, trust, content).codes()
print(f"последовательно: открытие Проверки {first_err(r1)}, затем слияние её субъекта {first_err(r2)}; валидатор на мире из базы: {codes7}")
report("C7", r1.returncode == 0 and r2.returncode == 0 and "CHECK_SUBJECT_INVALID" in codes7, "без гонки: субъект открытой Проверки слит; база принимает, валидатор отвергает")

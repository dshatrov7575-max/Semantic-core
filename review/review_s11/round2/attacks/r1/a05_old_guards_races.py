#!/usr/bin/env python3
"""S11R-04..06: стражи прежних циклов, которые гоняются и в READ COMMITTED (запрет уровней изоляции их не лечит):
страж читает БЕЗ блокировки (или блокирует не тот ключ), поэтому не видит незафиксированной записи соседа.
 R1  утверждение о сущности, которую в этот момент сливают (ac.claims_before читает статус без блокировки)
     -> CLAIM_ABOUT_MERGED_ENTITY обойдён.
 R2  цепочка слияний: D вставляется сразу MERGED -> A (без блокировки), одновременно A сливается в B.
 R3  решение «различны» (отложенная проверка при COMMIT) против одновременного слияния той же пары.
Каждая гонка — два сеанса READ COMMITTED; затем то же при смешанных уровнях (второй сеанс REPEATABLE READ отвергается
стражем изоляции — это контроль того, что запрет на месте, а гонка от него не зависит)."""
import copy, json, time
from rv import *

dv = fresh()
ds0, trust, content = build()
ALFA, TRUB, BETA, GAMMA = REGISTRY_ROWS[2], REGISTRY_ROWS[1], REGISTRY_ROWS[3], REGISTRY_ROWS[4]
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def ent_rec(eid):
    r = one("SELECT jsonb_strip_nulls(jsonb_build_object('kind','Entity','schema_version','core-ontology/0.4','entity_id',entity_id,'project_id',project_id,"
            "'entity_type',entity_type,'identity',identity,'status',status,'merged_into',merged_into,"
            "'status_changed_at',to_char(status_changed_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
            "'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'marking',marking,'display_name',display_name)) "
            f"FROM ac.entities WHERE entity_id = '{eid}'")
    return json.loads(r)


def validate_with(*recs):
    ds = copy.deepcopy(ds0)
    ds["records"] += list(recs)
    rep = VAL.validate(ds, trust, content)
    return rep.codes(), [e.get("msg", "")[:110] for e in rep.errors]


# ---------------- R1 claim about an entity being merged
x = org("ent_r5_x", "ООО «Альфа-Сервис»", ogrn=ALFA["ogrn"])
y = org("ent_r5_y", "АО «Трубопроводстрой»", ogrn=TRUB["ogrn"])
assert psql(ingest_sql([x, y], {})).returncode == 0
time.sleep(1.2)
th, o1 = bg(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_r5_y' WHERE entity_id = 'ent_r5_x';\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.6)
c = claim(dv.evidence([ALFA["ogrn"]], ["address"]), subj="ent_r5_x", address=ALFA["address"])
r2 = psql(ingest_sql([c], {}))
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"R1 слияние: {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])}; утверждение о сливаемой: {'COMMIT' if r2.returncode == 0 else first_err(r2)[:100]}")
if both:
    print("   в базе:", one(f"SELECT 'слита ' || e.status_changed_at || ', утверждение записано ' || c.recorded_at || ', после слияния: ' || (c.recorded_at >= e.status_changed_at) "
                           f"FROM ac.entities e, ac.claims c WHERE e.entity_id = 'ent_r5_x' AND c.claim_id = '{c['claim_id']}'"))
    time.sleep(1.2)
    again = psql(ingest_sql([claim(dv.evidence([ALFA["ogrn"]], ["address", "name"]), subj="ent_r5_x", address=ALFA["address"])], {}, commit=False))
    print("   контроль (то же последовательно):", first_err(again)[:110])
    after = bool(one(f"SELECT c.recorded_at >= e.status_changed_at FROM ac.entities e, ac.claims c WHERE e.entity_id = 'ent_r5_x' AND c.claim_id = '{c['claim_id']}'") == "t")
report("S11R-04", both and after, "READ COMMITTED: утверждение о слитой сущности записано после слияния (страж CLAIM_ABOUT_MERGED_ENTITY читает без блокировки)")

# ---------------- R2 a chain of merges
a = org("ent_r5_a", "ООО «Бета»", ogrn=BETA["ogrn"])
b = org("ent_r5_b", "ООО «Гамма»", ogrn=GAMMA["ogrn"])
assert psql(ingest_sql([a, b], {})).returncode == 0
time.sleep(1.2)
d = org("ent_r5_d", "ООО «Бета» (дубль)", inn=BETA["inn"]); d.update(status="MERGED", merged_into="ent_r5_a", status_changed_at=utc(0))
th, o1 = bg(L + "BEGIN;\n" + body_of([d]) + "\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.5)
r2 = psql(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_r5_b' WHERE entity_id = 'ent_r5_a';\nCOMMIT;")
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"R2 вставка D (MERGED -> A): {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])[:100]}; слияние A -> B: {'COMMIT' if r2.returncode == 0 else first_err(r2)[:100]}")
codes = None
if both:
    print("   в базе:", one("SELECT string_agg(entity_id || ':' || status || '->' || coalesce(merged_into, '-'), ', ' ORDER BY entity_id) FROM ac.entities WHERE entity_id LIKE 'ent_r5_%' AND entity_id IN ('ent_r5_a','ent_r5_b','ent_r5_d')"))
    print("   ключи идентичности с владельцем — слитой сущностью:", one("SELECT coalesce(string_agg(k.scheme || '=' || k.value || ' владелец ' || k.owner_entity_id, '; '), 'нет') FROM ac.entity_keys k JOIN ac.entities e ON e.entity_id = k.owner_entity_id WHERE e.status = 'MERGED'"))
    codes, msgs = validate_with(ent_rec("ent_r5_a"), ent_rec("ent_r5_b"), ent_rec("ent_r5_d"))
    print("   валидатор на мире из базы:", codes, msgs[:2])
    seq = psql(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_r5_y' WHERE entity_id = 'ent_r5_b';\nROLLBACK;")
    print("   контроль (последовательно: слить B, в которую уже слита A):", first_err(seq)[:110])
report("S11R-05", both and bool(codes), f"READ COMMITTED: цепочка слияний D->A->B зафиксирована; валидатор: {codes}")

# ---------------- R3 DISTINCT decision vs merge of the same pair
p = org("ent_r5_p", "ООО «Вектор-Один»", inn=D._inn10(770000111))
q_ = org("ent_r5_q", "ООО «Вектор-Два»", inn=D._inn10(770000112))
assert psql(ingest_sql([p, q_], {})).returncode == 0, "ents"
time.sleep(1.2)
dec = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_r5_pq", "project_id": PRJ, "decision": "DISTINCT",
       "entity_ids": ["ent_r5_p", "ent_r5_q"], "decided_by": "usr_analyst1", "decided_at": utc(0)}
from ingest_s4 import q as Q
dec_sql = (f"INSERT INTO ac.identity_decisions VALUES ({Q(dec['decision_id'])},{Q(PRJ)},'DISTINCT','ent_r5_p','ent_r5_q',NULL,NULL,"
           f"{Q(dec['decided_by'])},{Q(dec['decided_at'])},{Q(dec)});")
# слияние открыто (не зафиксировано) -> решение «различны» фиксируется (его отложенная проверка слияния не видит) -> слияние фиксируется
th, o1 = bg(L + "BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_r5_q' WHERE entity_id = 'ent_r5_p';\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.5)
dec["decided_at"] = utc(0)
dec_sql = (f"INSERT INTO ac.identity_decisions VALUES ({Q(dec['decision_id'])},{Q(PRJ)},'DISTINCT','ent_r5_p','ent_r5_q',NULL,NULL,"
           f"{Q(dec['decided_by'])},{Q(dec['decided_at'])},{Q(dec)});")
r2 = psql(L + "BEGIN;\n" + dec_sql + "\nCOMMIT;")
th.join()
both = o1[0].returncode == 0 and r2.returncode == 0
print(f"R3 слияние пары: {'COMMIT' if o1[0].returncode == 0 else first_err(o1[0])[:100]}; решение «различны» о ней же: {'COMMIT' if r2.returncode == 0 else first_err(r2)[:100]}")
codes = None
if both:
    dec_db = dict(dec, decided_at=iso(one("SELECT decided_at FROM ac.identity_decisions WHERE decision_id = 'idd_r5_pq'")))
    codes, msgs = validate_with(ent_rec("ent_r5_p"), ent_rec("ent_r5_q"), dec_db)
    print("   валидатор на мире из базы:", codes, msgs[:2])
    seq = psql(L + "BEGIN;\n" + dec_sql.replace("idd_r5_pq", "idd_r5_pq2") + "\nCOMMIT;")
    print("   контроль (последовательно: «различны» для уже слитых):", first_err(seq)[:110])
report("S11R-06", both and bool(codes), f"READ COMMITTED: пара и слита, и решена «различны»; валидатор: {codes}")

# ---------------- mixed levels: the second session in REPEATABLE READ is refused by the isolation guard
r = psql(L + "BEGIN ISOLATION LEVEL REPEATABLE READ;\nUPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = 'ent_r5_y';\nCOMMIT;")
print("контроль запрета: слияние/вывод в REPEATABLE READ:", first_err(r)[:90])

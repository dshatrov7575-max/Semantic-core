#!/usr/bin/env python3
"""Раунд 4: ключ merge-into:<цель> (берётся раньше entity:).
T1  слияние В цель против слияния САМОЙ цели — оба порядка
T2  слияние В цель против вывода цели из употребления — оба порядка
T3  вставка сущности сразу слитой в цель против слияния цели; против «различны»
T4  взаимная блокировка: два сеанса по два слияния в две цели в противоположном порядке
T5  утверждение о цели + слияние дубля в неё, два сеанса (S11R2-05 не вернулась)
T6  «различны»(C, D): C -> A обычным слиянием, D вставляется сразу слитой в A, параллельно
"""
import copy, json, time, threading
from rv import *
from ingest_s4 import q as Q

dv = fresh()
ds0, trust, content = build()
L = "SET SESSION AUTHORIZATION ac_loader;\n"
k = [0]
def ents(*names):
    out = []
    for nm in names:
        k[0] += 1
        out.append(org(f"ent_t{k[0]}_{nm}", f"Орг {k[0]} {nm}", inn=D._inn10(786000000 + k[0])))
    assert psql(ingest_sql(out, {})).returncode == 0
    time.sleep(1.1)
    return [e["entity_id"] for e in out]
def merge(a, b, pause=0.0):
    return L + f"BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = '{b}' WHERE entity_id = '{a}';\nSELECT pg_sleep({pause});\nCOMMIT;"
def retire(a, pause=0.0):
    return L + f"BEGIN;\nUPDATE ac.entities SET status = 'RETIRED' WHERE entity_id = '{a}';\nSELECT pg_sleep({pause});\nCOMMIT;"
def two(s1, s2, gap=1.5):
    th, o1 = bg(s1); time.sleep(gap); r2 = psql(s2); th.join()
    return o1[0], r2
def state(*ids):
    return one("SELECT string_agg(entity_id || ':' || status || coalesce('->' || merged_into, ''), ', ' ORDER BY 1) FROM ac.entities WHERE entity_id IN (" + ",".join(f"'{i}'" for i in ids) + ")")
def chain_or_dead(*ids):
    """слитая в слитую или в выведенную раньше слияния"""
    return one("SELECT count(*) FROM ac.entities e JOIN ac.entities t ON t.entity_id = e.merged_into WHERE e.entity_id IN (" + ",".join(f"'{i}'" for i in ids) +
               ") AND (t.status = 'MERGED' OR (t.status = 'RETIRED' AND t.status_changed_at <= e.status_changed_at))")
bad = []
a, t, u = ents("a", "t", "u"); r1, r2 = two(merge(a, t, 3), merge(t, u))
print("T1 A->T открыто / T->U:", first_err(r1)[:30], "|", first_err(r2)[:70], "|", state(a, t, u)); bad.append(chain_or_dead(a, t, u))
a, t, u = ents("a", "t", "u"); r1, r2 = two(merge(t, u, 3), merge(a, t))
print("   T->U открыто / A->T:", first_err(r1)[:30], "|", first_err(r2)[:70], "|", state(a, t, u)); bad.append(chain_or_dead(a, t, u))
a, t = ents("a", "t"); r1, r2 = two(merge(a, t, 3), retire(t))
print("T2 A->T открыто / вывод T:", first_err(r1)[:30], "|", first_err(r2)[:70], "|", state(a, t)); bad.append(chain_or_dead(a, t))
a, t = ents("a", "t"); r1, r2 = two(retire(t, 3), merge(a, t))
print("   вывод T открыт / A->T:", first_err(r1)[:30], "|", first_err(r2)[:70], "|", state(a, t)); bad.append(chain_or_dead(a, t))
t, u = ents("t", "u")
d = org("ent_t_ins1", "Вставка слитой", inn=D._inn10(786000900)); d.update(status="MERGED", merged_into=t, status_changed_at=utc(0))
r1, r2 = two(L + "BEGIN;\n" + body_of([d]) + "\nSELECT pg_sleep(3);\nCOMMIT;", merge(t, u))
print("T3 вставка D сразу слитой в T (открыто) / T->U:", first_err(r1)[:30], "|", first_err(r2)[:70]); bad.append(chain_or_dead("ent_t_ins1", t, u))
t, u = ents("t", "u")
d = org("ent_t_ins2", "Вставка слитой 2", inn=D._inn10(786000901)); d.update(status="MERGED", merged_into=t, status_changed_at=utc(0))
r1, r2 = two(merge(t, u, 3), L + "BEGIN;\n" + body_of([d]) + "\nCOMMIT;")
print("   T->U открыто / вставка D сразу слитой в T:", first_err(r1)[:30], "|", first_err(r2)[:70]); bad.append(chain_or_dead("ent_t_ins2", t, u))
print("   нарушений (слита в слитую / в выведенную раньше):", bad)
report("T1-3", any(b != "0" for b in bad), "слияние в цель против слияния/вывода самой цели, вставка сразу слитой")

# T6
c, a = ents("c", "a")
dnew = org("ent_t_ins3", "Различная", inn=D._inn10(786000902))
assert psql(ingest_sql([dnew], {})).returncode == 0; time.sleep(1.1)
dec = {"kind": "IdentityDecision", "schema_version": "core-ontology/0.4", "decision_id": "idd_t6", "project_id": PRJ, "decision": "DISTINCT",
       "entity_ids": [c, "ent_t_ins3"], "decided_by": "usr_analyst1", "decided_at": utc(0)}
assert psql(L + f"INSERT INTO ac.identity_decisions VALUES ('idd_t6',{Q(PRJ)},'DISTINCT',{Q(c)},'ent_t_ins3',NULL,NULL,'usr_analyst1',{Q(dec['decided_at'])},{Q(dec)});").returncode == 0
time.sleep(1.1)
r1, r2 = two(merge(c, a, 3), merge("ent_t_ins3", a))
both = r1.returncode == 0 and r2.returncode == 0
print("T6 «различны»(C, D); C->A открыто / D->A:", first_err(r1)[:30], "|", first_err(r2)[:80])
report("T6", both, "решение «различны» обойдено")

# T4 deadlock: opposite order of two targets
a1, a2, b1, b2, t, u = ents("a1", "a2", "b1", "b2", "t", "u")
def tx(x, y, first, second):
    return L + f"BEGIN;\nUPDATE ac.entities SET status = 'MERGED', merged_into = '{first}' WHERE entity_id = '{x}';\nSELECT pg_sleep(1.5);\nUPDATE ac.entities SET status = 'MERGED', merged_into = '{second}' WHERE entity_id = '{y}';\nCOMMIT;"
oa, ob = [], []
ta = threading.Thread(target=lambda: oa.append(psql(tx(a1, a2, t, u)))); tb = threading.Thread(target=lambda: ob.append(psql(tx(b1, b2, u, t))))
ta.start(); tb.start(); ta.join(); tb.join()
print("T4 два сеанса, по два слияния в цели T, U в противоположном порядке:", first_err(oa[0])[:40], "|", first_err(ob[0])[:40])
# T5
BETA = REGISTRY_ROWS[3]
main = org("ent_t5_main", "ООО «Бета»", ogrn=BETA["ogrn"]); assert psql(ingest_sql([main], {})).returncode == 0
d1, d2 = ents("d1", "d2")
c1 = claim(dv.evidence([BETA["ogrn"]], ["address"]), subj="ent_t5_main", address=BETA["address"])
c2 = claim(dv.evidence([BETA["ogrn"]], ["address", "name"]), subj="ent_t5_main", address=BETA["address"])
def tx5(c, dup):
    return L + "BEGIN;\n" + body_of([c]) + f"\nSELECT pg_sleep(1.5);\nUPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_t5_main' WHERE entity_id = '{dup}';\nCOMMIT;"
oa, ob = [], []
ta = threading.Thread(target=lambda: oa.append(psql(tx5(c1, d1)))); tb = threading.Thread(target=lambda: ob.append(psql(tx5(c2, d2))))
ta.start(); tb.start(); ta.join(); tb.join()
print("T5 утверждение о цели + слияние дубля в неё, два сеанса:", first_err(oa[0])[:40], "|", first_err(ob[0])[:40])
report("T5", "deadlock" in oa[0].stderr + ob[0].stderr, "взаимная блокировка S11R2-05 вернулась")

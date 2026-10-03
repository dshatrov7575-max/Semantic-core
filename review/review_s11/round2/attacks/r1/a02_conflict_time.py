#!/usr/bin/env python3
"""S11R-01 (гонка), S11R-02, S11R-03: конфликт сильных ключей и время.
 (a) гонка двух сеансов READ COMMITTED: сущность с ИНН строки вставлена, но не зафиксирована; утверждение пишется и
     фиксируется; потом фиксируется сущность. Стражи не сериализованы (блокировки по ключу нет вовсе).
 (b) обход через время записи: «другая» сущность уже ЗАФИКСИРОВАНА, утверждение датируется (в пределах 5-минутного
     окна системного времени) моментом до её создания — принимается и базой, и валидатором.
 (c) ретроактивность: мигратор (исторический импорт после печати) создаёт сущность с ИНН строки временем раньше уже
     принятого утверждения — утверждение задним числом становится неверным (verified=false, валидатор отвергает мир)."""
import copy, json, time
from datetime import datetime, timezone, timedelta
from rv import *

dv = fresh()
BETA, GAMMA, ALFA = REGISTRY_ROWS[3], REGISTRY_ROWS[1], REGISTRY_ROWS[2]   # «GAMMA» здесь — строка Трубопроводстроя (адрес не пуст)
ds0, trust, content = build()


def world_check(ents, c):
    ds = copy.deepcopy(ds0)
    for e in ents:
        ca = iso(one(f"SELECT created_at FROM ac.entities WHERE entity_id = '{e['entity_id']}'"))
        ds["records"].append(dict(e, created_at=ca, schema_version="core-ontology/0.4"))
    ds["records"].append(c)
    return VAL.validate(ds, trust, content).codes()


def verified(c):
    return json.loads(one(f"SELECT ac.evidence_json('{c['claim_id']}', now())"))[0]["verified"]


# ---------- (a) race
a = org("ent_r2_beta", "ООО «Бета»", ogrn=BETA["ogrn"])
b = org("ent_r2_beta_inn", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(1.2)
th, out1 = bg("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\n" + body_of([b]) + "\nSELECT pg_sleep(3);\nCOMMIT;")
time.sleep(1.5)
c = claim(dv.evidence([BETA["ogrn"]], ["address", "inn"]), subj="ent_r2_beta", address=BETA["address"])
r2 = psql(ingest_sql([c], {}))
th.join()
ok_a = out1[0].returncode == 0 and r2.returncode == 0
codes = world_check([a, b], c) if ok_a else None
print(f"(a) сеанс 1 (сущность с ИНН, фиксация позже): {'COMMIT' if out1[0].returncode == 0 else first_err(out1[0])}; "
      f"сеанс 2 (утверждение): {'COMMIT' if r2.returncode == 0 else first_err(r2)}")
if ok_a:
    print("    created_at сущности <= recorded_at утверждения:", one(f"SELECT e.created_at || ' <= ' || c.recorded_at || ' : ' || (e.created_at <= c.recorded_at) "
          f"FROM ac.entities e, ac.claims c WHERE e.entity_id = 'ent_r2_beta_inn' AND c.claim_id = '{c['claim_id']}'"))
    print("    валидатор на мире из базы:", codes, "| verified в проекции:", verified(c))
report("S11R-01b", ok_a and "EVIDENCE_ROW_INVALID" in (codes or []), "гонка READ COMMITTED: оба зафиксированы, мир отвергается валидатором")

# ---------- (b) back-dating inside the 5-minute window
a = org("ent_r2_gamma", "ООО «Гамма»", ogrn=GAMMA["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(2.2)
t_between = utc(1)                                    # после создания первой, до создания второй
time.sleep(1.2)
b = org("ent_r2_gamma_inn", "ООО «Гамма» (по ИНН)", inn=GAMMA["inn"])
assert psql(ingest_sql([b], {})).returncode == 0     # «другая» сущность ЗАФИКСИРОВАНА
time.sleep(1.2)
ev = dv.evidence([GAMMA["ogrn"]], ["registered_on", "inn", "name", "address"])
now_claim = claim(ev, subj="ent_r2_gamma", address=GAMMA["address"])
honest = psql(ingest_sql([now_claim], {}, commit=False))
back = {k: v for k, v in now_claim.items() if k != "claim_id"}; back["recorded_at"] = t_between; back["claim_id"] = "clm:sha256:" + digest(back)
r = psql(ingest_sql([back], {}))
print(f"(b) честное время записи: {first_err(honest)[:100]}")
print(f"    то же утверждение, датированное {t_between} (до создания второй сущности, она уже в базе): {'ПРИНЯТО' if r.returncode == 0 else first_err(r)[:120]}")
codes_b = world_check([a, b], back) if r.returncode == 0 else None
print("    валидатор:", codes_b, "| verified:", verified(back) if r.returncode == 0 else None,
      "| dataset_subject сейчас:", json.loads(one(f"SELECT ac.dataset_subject('{PRJ}', '{dv.source_id}', {key(GAMMA['ogrn'])});", "ac_rd_cs"))["status"])
report("S11R-02", honest.returncode != 0 and r.returncode == 0, "конфликт обходится выбором recorded_at в окне системного времени (и база, и валидатор принимают)")

# ---------- (c) retroactive: historical import after the seal
a = org("ent_r2_alfa", "ООО «Альфа-Сервис»", ogrn=ALFA["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(2.2)
t_hist = utc(1)
time.sleep(1.2)
c = claim(dv.evidence([ALFA["ogrn"]], ["address", "inn"]), subj="ent_r2_alfa", address=ALFA["address"])
assert psql(ingest_sql([c], {})).returncode == 0
v_before = verified(c)
b = org("ent_r2_alfa_inn", "ООО «Альфа-Сервис» (по ИНН)", inn=ALFA["inn"]); b["created_at"] = t_hist
r = psql("SET SESSION AUTHORIZATION ac_migrator;\nBEGIN;\nSET LOCAL ac.historical_import = 'on';\n" + body_of([b], user="ac_migrator") + "\nCOMMIT;")
print(f"(c) мигратор создаёт сущность с ИНН строки временем {t_hist} (раньше принятого утверждения): {'ПРИНЯТО' if r.returncode == 0 else first_err(r)[:120]}")
codes_c = world_check([a, b], c) if r.returncode == 0 else None
v_after = verified(c) if r.returncode == 0 else None
print(f"    verified до: {v_before}, после: {v_after}; валидатор на мире из базы: {codes_c}")
report("S11R-03", r.returncode == 0 and v_before and v_after is False, "исторический импорт сущности делает неверным уже принятое утверждение (ретроактивность)")

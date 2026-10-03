#!/usr/bin/env python3
"""S11R-01. Конфликт сильных ключей обходится порядком записи в ОДНОЙ транзакции обычного загрузчика (ac_loader),
READ COMMITTED, без гонок: сначала утверждение (recorded_at = время писателя, T2), потом «другая» сущность с ИНН
строки (created_at = now() = начало транзакции T1 < T2). База принимает; в записанном мире сущность существовала
к моменту утверждения — нормативный валидатор тот же мир отвергает (EVIDENCE_ROW_INVALID), а проекция базы сама
показывает verified=false у принятого утверждения."""
import copy, json, time
from datetime import datetime, timezone, timedelta
from rv import *

dv = fresh()
BETA = REGISTRY_ROWS[3]
a = org("ent_r1_beta", "ООО «Бета»", ogrn=BETA["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
time.sleep(1.2)
b = org("ent_r1_beta_inn", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
ev_inn = dv.evidence([BETA["ogrn"]], ["address", "inn"])
# контроль: в обычном порядке (сущность зафиксирована раньше) правило работает — на откатываемой транзакции
c = claim(ev_inn, subj="ent_r1_beta", address=BETA["address"])
rec = (datetime.now(timezone.utc) + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
c = {k: v for k, v in c.items() if k != "claim_id"}; c["recorded_at"] = rec; c["claim_id"] = "clm:sha256:" + digest(c)
sql = ("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nSELECT now() AS tx_start;\nSELECT pg_sleep(2.3);\n"
       + body_of([c]) + "\n" + body_of([b]) + "\nCOMMIT;")
r = psql(sql)
print("запись (утверждение, затем сущность) в одной транзакции READ COMMITTED:", "ПРИНЯТО" if r.returncode == 0 else first_err(r))
row = one(f"SELECT e.created_at, c.recorded_at, e.created_at <= c.recorded_at FROM ac.entities e, ac.claims c "
          f"WHERE e.entity_id = 'ent_r1_beta_inn' AND c.claim_id = '{c['claim_id']}'")
print("в базе: created_at сущности | recorded_at утверждения | сущность существовала к утверждению:", row)
time.sleep(1.2)
again = psql(ingest_sql([claim(ev_inn, subj="ent_r1_beta", address=BETA["address"])], {}, commit=False))
print("контроль: то же утверждение ещё раз (обычный порядок):", first_err(again)[:120])
evj = json.loads(one(f"SELECT ac.evidence_json('{c['claim_id']}', now())"))[0]
print("проекция базы по принятому утверждению: verified =", evj["verified"])
subj = json.loads(one(f"SELECT ac.dataset_subject('{PRJ}', '{dv.source_id}', {key(BETA['ogrn'])});", "ac_rd_cs"))
print("ac.dataset_subject:", subj["status"], [o["entity_id"] for o in subj["owners"]])

# тот же мир — нормативному валидатору (времена берутся ИЗ БАЗЫ)
ds, trust, content = build()
ca, cb = [iso(one(f"SELECT created_at FROM ac.entities WHERE entity_id = '{x}'")) for x in ("ent_r1_beta", "ent_r1_beta_inn")]
ra, rb = dict(a, created_at=ca, schema_version="core-ontology/0.4"), dict(b, created_at=cb, schema_version="core-ontology/0.4")
ds2 = copy.deepcopy(ds); ds2["records"] += [ra, rb, c]
rep = VAL.validate(ds2, trust, content)
print("валидатор на том же мире:", rep.codes(), [str(e)[:200] for e in rep.errors][:2])
ds3 = copy.deepcopy(ds); ds3["records"] += [ra, c]
print("валидатор без второй сущности (контроль):", VAL.validate(ds3, trust, content).codes())
report("S11R-01", r.returncode == 0 and "EVIDENCE_ROW_INVALID" in rep.codes(),
       f"база приняла мир, который валидатор отвергает {rep.codes()}; verified в проекции = {evj['verified']}")

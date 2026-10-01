"""S4R projection attacks (live, review041 after s4_tests): model section with a CONFIDENTIAL model claim; contested model."""
import sys, json, time, copy, hashlib
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core"); sys.path.insert(0, "/home/claude/as/adapter")
from ingest_s4 import ingest_sql, psql, utc
from jcs import digest
from vectors import build
import s4_tests as T

def sql(s, user=None):
    r = psql((f"SET SESSION AUTHORIZATION {user};\n" if user else "") + s)
    return r.stdout.strip(), r.stderr.strip()

sql("""DO $$ BEGIN CREATE ROLE ac_rv_conf LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES ('ac_rv_conf', 'prj_ts_pumps', 'CONFIDENTIAL', '{COMMERCIAL_SECRET}') ON CONFLICT DO NOTHING;
RESET ROLE;""")
ds, tr, ct = build()
CONF = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}
s1 = next(s for s in ds["records"] if s["kind"] == "Source" and s["title"].startswith("Инструкция по эксплуатации насосной"))
B = s1["content_inline"].encode()
def ev(q):
    qb = q.encode(); st = B.find(qb); assert st >= 0
    return [{"source_id": s1["source_id"], "span": {"start": st, "end": st + len(qb)}, "quote": q, "quote_sha256": hashlib.sha256(qb).hexdigest()}]
def claim(subj, pred, obj, q, marking, quals=None):
    c = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": "prj_ts_pumps", "subject": subj, "predicate": pred,
         "object": obj, "evidence": ev(q), "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": utc(1), "marking": marking}
    if quals: c["qualifiers"] = quals
    c["claim_id"] = "clm:sha256:" + digest(c); return c

# 1. CONFIDENTIAL parameter of the model (secret rating) -- must not reach an INTERNAL reader via «Параметры модели»
c_secret = claim("ent_ts_model", "ts.has_parameter", {"literal": {"type": "QUANTITY", "value": "21", "unit": "bar"}},
                 "Максимальное рабочее давление насоса Н-101 — 16 бар", CONF, {"parameter": "burst_pressure"})
r = psql(ingest_sql([c_secret], {})); print("insert CONF model claim:", "OK" if r.returncode == 0 else r.stderr[:200])
time.sleep(1.2)
for u in ("ac_rd_ts", "ac_rv_conf"):
    out, err = sql("SELECT ac.equipment_card('prj_ts_pumps', 'ent_ts_pump');", u)
    if err and not out: print(u, "ERR", err[:150]); continue
    c = json.loads(out.splitlines()[-1])
    mp = T.texts(c, "MODEL_PARAMETERS")
    print(f"{u}: MODEL_PARAMETERS={mp} marking={c['marking']} leak21={'21' in json.dumps(c, ensure_ascii=False)}")

# 2. a second (contested) model for the pump by an analyst, with its own parameter
m2 = {"kind": "Entity", "schema_version": "core-ontology/0.2", "entity_id": "ent_rv_model2", "project_id": "prj_ts_pumps",
      "entity_type": "EQUIPMENT_MODEL", "identity": {"manufacturer": "Ливгидромаш", "model": "ЦНС 38-44"}, "display_name": "Ливгидромаш ЦНС 38-44",
      "status": "ACTIVE", "created_at": utc(2), "marking": {"level": "INTERNAL", "categories": []}}
INT = {"level": "INTERNAL", "categories": []}
c_m2 = claim("ent_ts_pump", "ts.instance_of", {"entity": "ent_rv_model2"}, "Насос Н-101", INT)
c_m2p = claim("ent_rv_model2", "ts.has_parameter", {"literal": {"type": "QUANTITY", "value": "44", "unit": "bar"}}, "Насос Н-101", INT, {"parameter": "max_working_pressure"})
r = psql(ingest_sql([m2, c_m2, c_m2p], {})); print("insert contested model:", "OK" if r.returncode == 0 else r.stderr[:300])
time.sleep(1.2)
out, err = sql("SELECT ac.equipment_card('prj_ts_pumps', 'ent_ts_pump');", "ac_rd_ts")
c = json.loads(out.splitlines()[-1])
msec = next(x for x in c["sections"] if x["section"] == "MODEL")
print("MODEL section:", json.dumps(msec.get("facts"), ensure_ascii=False)[:600])
print("MODEL_PARAMETERS:", T.texts(c, "MODEL_PARAMETERS"))

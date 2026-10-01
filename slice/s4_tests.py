#!/usr/bin/env python3
"""S4 acceptance in PostgreSQL: the TechSense adapter end to end and the projection «карточка оборудования».

S4-01 the world loads with its artifact: nodes derived by the database, 4 claims of НС-2 rest on nodes n10..n13.
S4-02 live run of the adapter on the valve instruction (ac_loader, one transaction): validator first, then the DB
      accepts source, artifact, new model, 4 claims, receipt; nothing is created for the unmapped relation.
S4-03 card of the valve: model (new), part of НС-2, parameter «номинальное давление — 1.6 МПа», action with its
      condition; every claim of the card leads to receipt -> artifact (stored) -> node, fragment inside the anchor.
S4-04 card of the station НС-2: its components are the pump and the valve (incoming part_of).
S4-05 card of the model НМ 16-100: instances = the pump; a model parameter added by an analyst (HUMAN claim) shows up
      in the pump card in the separate section «Параметры модели».
S4-06 access: no clearance on the project, unknown entity, an entity that is not equipment — the same refusal.
S4-07 reproducible: the same as_of gives the same digest; as_of before the valve run shows no valve facts.
S4-08 a refuted claim leaves the card; the card at a moment before the refutation still shows it.
S4-09 the same run again (same artifact, same claims) is refused: content addresses are unique, nothing is doubled.
S4-10 a disputed model: the section «Модель» names one model with a discrepancy note; model data is of that model.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s4_tests.py
"""
import copy
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "adapter"))
import validator as VAL  # noqa: E402
from fixtures import SEEDS  # noqa: E402
from vectors import build  # noqa: E402
from techsense_umr import adapt  # noqa: E402
import samples as SM  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402

RES = []
SETUP = """
DO $$ BEGIN CREATE ROLE ac_rd_ts LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_full LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES ('ac_rd_ts', 'prj_ts_pumps', 'INTERNAL', '{}');
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES ('ac_rd_ts', 'prj_dossier', 'CONFIDENTIAL', '{PERSONAL_DATA}');
RESET ROLE;
"""


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<6} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def sql1(s, user=None):
    r = psql((f"SET SESSION AUTHORIZATION {user};\n" if user else "") + s)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout.strip()


def card(eid, user="ac_rd_ts", as_of=None):
    a = f", {as_of!r}::timestamptz" if as_of else ""
    return json.loads(sql1(f"SELECT ac.equipment_card('prj_ts_pumps', '{eid}'{a});", user).splitlines()[-1])


def texts(c, section):
    s = next((x for x in c["sections"] if x["section"] == section), None)
    return [f["text"] for f in (s or {}).get("facts", [])]


def reload():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    sql1(SETUP)


def valve_run(ds, content, recorded, issued, observed):
    P = {p["project_id"]: p for p in ds["records"] if p["kind"] == "Project"}
    vs = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, observed)
    srcs = {s["source_id"]: s for s in ds["records"] if s["kind"] == "Source"}
    srcs[vs["source_id"]] = vs
    art = SM.valve_artifact(vs["source_id"])
    ents = [e for e in ds["records"] if e["kind"] == "Entity" and e["project_id"] == "prj_ts_pumps"]
    res = adapt(art, P["prj_ts_pumps"], srcs, content, ents, recorded, issued, "key_ts_1", SEEDS["key_ts_1"])
    return vs, art, res


def analyst_model_claim(ds):
    """a HUMAN claim: the model НМ 16-100 has max working pressure 16 bar (evidence: instruction НС-2)"""
    import hashlib
    from jcs import digest
    s1 = next(s for s in ds["records"] if s["kind"] == "Source" and s["title"].startswith("Инструкция по эксплуатации насосной"))
    q = "Максимальное рабочее давление насоса Н-101 — 16 бар"
    b = s1["content_inline"].encode("utf-8")
    st_, qb = b.find(q.encode("utf-8")), q.encode("utf-8")
    hc = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": "prj_ts_pumps", "subject": "ent_ts_model",
          "predicate": "ts.has_parameter", "object": {"literal": {"type": "QUANTITY", "value": "16", "unit": "bar"}},
          "evidence": [{"source_id": s1["source_id"], "span": {"start": st_, "end": st_ + len(qb)}, "quote": q,
                        "quote_sha256": hashlib.sha256(qb).hexdigest()}],
          "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": utc(1),
          "marking": {"level": "INTERNAL", "categories": []}, "qualifiers": {"parameter": "max_working_pressure"}}
    hc["claim_id"] = "clm:sha256:" + digest(hc)
    return hc


def main():
    reload()
    ds, trust, content = build()
    # S4-01
    n = sql1("SELECT count(*) FROM ac.artifact_nodes")
    rows = sql1("SELECT string_agg(e.graph_node->>'node_id', ',' ORDER BY e.graph_node->>'node_id') FROM ac.claim_evidence e "
                "JOIN ac.claims c USING (claim_id) WHERE c.project_id = 'prj_ts_pumps'")
    check("S4-01", n == "10" and rows == "n10,n11,n12,n13", "мир загружен с артефактом: узлы разобраны базой, 4 утверждения НС-2 на узлах n10..n13",
          f"nodes={n} evidence_nodes={rows}")

    # S4-02 live run: the instruction arrives first (its own transaction), the TechSense run comes later
    t0 = utc(0)
    time.sleep(1.1)
    vs0 = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, utc(0))
    r0 = psql(ingest_sql([vs0], {}))
    time.sleep(1.1)
    obs = sql1(f"SELECT to_char(min(observed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM ac.source_observations WHERE source_id = '{vs0['source_id']}'")
    rec = iss = utc(0)
    vs, art, res = valve_run(ds, content, rec, iss, obs)
    ds2 = copy.deepcopy(ds)
    ds2["records"] += [vs] + res.records
    ct2 = {**content, res.artifact_digest: art}
    rep = VAL.validate(ds2, trust, ct2)
    r = psql(ingest_sql(res.records, ct2, artifacts=[res.artifact_digest]))
    if r0.returncode:
        r = r0
    cnt = sql1("SELECT (SELECT count(*) FROM ac.claims WHERE body->'produced_by'->>'run_id' = 'run_ts_0002') || '/' || "
               "(SELECT count(*) FROM ac.entities WHERE project_id = 'prj_ts_pumps') || '/' || "
               "(SELECT count(*) FROM ac.entities WHERE identity->>'tag' = 'Т-3')")
    check("S4-02", not rep.errors and r.returncode == 0 and cnt == "4/6/0",
          "живой прогон адаптера по инструкции задвижки: валидатор чист, база приняла источник, артефакт, модель, 4 утверждения, receipt; Т-3 не заведён",
          f"validator={rep.codes()} db={'OK' if r.returncode == 0 else r.stderr.strip()[:120]} claims/entities/T-3={cnt}")
    time.sleep(1.1)

    # S4-03 valve card
    c = card("ent_ts_valve_a")
    prod = c.get("production", {})
    path_ok = len(prod) == 4 and all(p["kind"] == "PIPELINE" and p["artifact_stored"] and p["run_id"] == "run_ts_0002"
                                     and p["nodes"] and all(nd["span_in_anchor"] for nd in p["nodes"]) for p in prod.values())
    check("S4-03", texts(c, "MODEL") == ["Задвижка К-1/12: экземпляр модели «АрмаТех ЗКС 80-16»."]
          and texts(c, "PART_OF") == ["Задвижка К-1/12: входит в состав «Насосная станция НС-2»."]
          and texts(c, "PARAMETERS") == ["Задвижка К-1/12: номинальное давление — 1,6 МПа."]
          and texts(c, "ACTIONS") == ["Задвижка К-1/12: при условии «утечка через сальник» требуется закрыть задвижку и вызвать слесаря."]
          and path_ok,
          "карточка задвижки: модель, состав, параметр, действие; путь receipt → артефакт → узел у каждого утверждения",
          f"{texts(c, 'PARAMETERS')} path_ok={path_ok}")

    # S4-04 station components
    st = card("ent_ts_station")
    comp = sorted(texts(st, "COMPONENTS"))
    check("S4-04", comp == ["Задвижка К-1/12: входит в состав «Насосная станция НС-2».", "Насос Н-101: входит в состав «Насосная станция НС-2»."],
          "карточка станции НС-2: состав — насос и задвижка", str(comp))

    # S4-05 model instances + inherited model parameter (HUMAN claim)
    hc = analyst_model_claim(ds)
    r5 = psql(ingest_sql([hc], {}))
    time.sleep(1.1)
    mc = card("ent_ts_model")
    pc = card("ent_ts_pump")
    check("S4-05", r5.returncode == 0 and texts(mc, "INSTANCES") == ["Насос Н-101: экземпляр модели «Насос НМ 16-100»."]
          and texts(pc, "MODEL_PARAMETERS") == ["Насос НМ 16-100: максимальное рабочее давление — 16 бар."]
          and pc["production"][hc["claim_id"]] == {"kind": "HUMAN"},
          "карточка модели: экземпляры; параметр модели (аналитик) виден у насоса отдельным разделом",
          f"db={'OK' if r5.returncode == 0 else r5.stderr[:100]} inst={texts(mc, 'INSTANCES')} model_params={texts(pc, 'MODEL_PARAMETERS')}")

    # S4-06 refusals
    outs = []
    for user, eid, proj in (("ac_rd_full", "ent_ts_pump", "prj_ts_pumps"), ("ac_rd_ts", "ent_nope", "prj_ts_pumps"),
                            ("ac_rd_ts", "ent_d_lomov", "prj_dossier"), ("ac_rd_ts", "ent_ts_pump", "prj_dossier")):
        rr = psql(f"SET SESSION AUTHORIZATION {user};\nSELECT ac.equipment_card('{proj}', '{eid}');")
        outs.append(rr.returncode != 0 and "ACCESS_DENIED: нет допуска" in rr.stderr)
    check("S4-06", all(outs), "без допуска, неизвестная сущность, не оборудование, чужой проект — один и тот же отказ", str(outs))

    # S4-07 reproducible + time travel
    fixed = utc(0)
    time.sleep(1.1)
    d1, d2 = card("ent_ts_valve_a", as_of=fixed)["digest"], card("ent_ts_valve_a", as_of=fixed)["digest"]
    before = card("ent_ts_valve_a", as_of=t0)
    check("S4-07", d1 == d2 and texts(before, "PARAMETERS") == [] and texts(before, "MODEL") == [],
          "одинаковый as_of — одинаковый digest; до прогона у задвижки сведений нет", f"{d1[:20]}… before={texts(before, 'PARAMETERS')}")

    # S4-08 refuted claim leaves the card
    cid = dict(res.report["claims"])["r3"]
    t_before = utc(0)
    time.sleep(1.1)
    r8 = psql(f"SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.claim_reviews VALUES ('rev_s4_refute', '{cid}', 'REFUTED', 'usr_analyst1', now(), now());")
    time.sleep(1.1)
    after, old = card("ent_ts_valve_a"), card("ent_ts_valve_a", as_of=t_before)
    check("S4-08", r8.returncode == 0 and texts(after, "PARAMETERS") == [] and texts(old, "PARAMETERS") != [],
          "опровергнутое утверждение уходит из карточки; на момент до опровержения — видно", r8.stderr.strip()[:100])

    # S4-09 the same run again
    r9 = psql(ingest_sql([r for r in res.records if r["kind"] != "Entity"], ct2, artifacts=[res.artifact_digest]))
    check("S4-09", r9.returncode != 0, "повтор того же прогона отвергнут (адреса уникальны, ничего не удваивается)", r9.stderr.strip()[:110])

    # S4-10 a disputed model: an analyst says the pump is of another model (АрмаТех ЗКС 80-16, from the valve run)
    vsrc = next(x for x in res.records if x["kind"] == "Claim" and x["predicate"] == "ts.instance_of")
    hm = {"kind": "Claim", "schema_version": "core-ontology/0.2", "project_id": "prj_ts_pumps", "subject": "ent_ts_pump",
          "predicate": "ts.instance_of", "object": copy.deepcopy(vsrc["object"]),
          "evidence": [{k: v for k, v in vsrc["evidence"][0].items() if k != "graph_node"}],
          "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": utc(0),
          "marking": {"level": "INTERNAL", "categories": []}}
    from jcs import digest
    hm["claim_id"] = "clm:sha256:" + digest(hm)
    r10 = psql(ingest_sql([hm], {}))
    time.sleep(1.1)
    pc = card("ent_ts_pump")
    msec = next(x for x in pc["sections"] if x["section"] == "MODEL")
    check("S4-10", r10.returncode == 0 and pc.get("model_disputed") is True and len(msec.get("facts", [])) == 1
          and "note" in msec["facts"][0] and texts(pc, "MODEL") == ["Насос Н-101: экземпляр модели «Насос НМ 16-100»."]
          and texts(pc, "MODEL_PARAMETERS") == ["Насос НМ 16-100: максимальное рабочее давление — 16 бар."],
          "спорная модель: раздел «Модель» называет одну модель с пояснением о расхождении, данные — этой модели, флаг расхождения (S4R-12)",
          f"db={'OK' if r10.returncode == 0 else r10.stderr[:90]} disputed={pc.get('model_disputed')} model_params={texts(pc, 'MODEL_PARAMETERS')}")

    print(f"\ns4_tests={len(RES)} passed={sum(RES)}")
    print("S4_RESULT=" + ("PASS" if all(RES) else "FAIL"))
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())

"""S4R adapter attacks: records the adapter emits vs what the validator accepts; silent loss; determinism."""
import sys, json, copy, hashlib, subprocess
sys.path.insert(0, "/home/claude/as/core"); sys.path.insert(0, "/home/claude/as/adapter")
import validator as VAL
from fixtures import SEEDS
from jcs import canon_bytes, canon
from vectors import build, V, add_entity
from techsense_umr import adapt, AdapterError
import samples as SM

INT = {"level": "INTERNAL", "categories": []}
KEY = SEEDS["key_ts_1"]
REC, ISS, OBS = "2026-09-08T09:00:00Z", "2026-09-08T09:00:30Z", "2026-09-08T08:00:00Z"

def world(pre=None):
    ds, tr, ct = build(V("X", [], "w", pre=pre))
    return ds, tr, ct

def go(desc, art_bytes, pre=None, extra_src=None, strict=False):
    ds, tr, ct = world(pre)
    recs = lambda k: [r for r in ds["records"] if r["kind"] == k]
    PRJ = next(p for p in recs("Project") if p["project_id"] == "prj_ts_pumps")
    SRC = {s["source_id"]: s for s in recs("Source")}
    if extra_src:
        SRC[extra_src["source_id"]] = extra_src
    ENT = [e for e in recs("Entity")]
    try:
        res = adapt(art_bytes, PRJ, SRC, ct, ENT, REC, ISS, "key_ts_1", KEY, strict=strict)
    except AdapterError as ex:
        print(f"[{desc}] ADAPTER_ERROR {ex}"); return None
    ds2 = copy.deepcopy(ds)
    if extra_src:
        ds2["records"].append(extra_src)
    ds2["records"] += res.records
    ct2 = dict(ct); ct2[res.artifact_digest] = art_bytes
    rep = VAL.validate(ds2, tr, ct2)
    errs = sorted({(e["code"], e["msg"][:90]) for e in rep.errors})
    print(f"[{desc}] adapter: claims={len(res.report['claims'])} new={res.report['new_entities']} matched={res.report['matched']} "
          f"unmapped={res.report['unmapped']} dup={res.report['possible_duplicates']}")
    print(f"    validator errors={errs or 'NONE'} warnings={sorted({w['code'] for w in rep.warnings})}", flush=True)
    return res, rep

vs = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, OBS)
SID = vs["source_id"]
A = lambda q: SM.anchor(SM.VALVE_TEXT, SID, q)

# 0. reference run
go("эталон: задвижка", SM.valve_artifact(SID), extra_src=vs)

# 1. MERGED: a Latin-«H» duplicate of the pump was merged into ent_ts_pump; TechSense writes the tag in Latin
merged = add_entity("ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101", "description": "насос"},
                    INT, status="MERGED", merged_into="ent_ts_pump", changed="2026-09-05T13:00:00Z")
ds, tr, ct = world(merged)
print("world with merged duplicate:", VAL.validate(ds, tr, ct).codes() or "CLEAN")
rcp = next(r for r in ds["records"] if r["kind"] == "ArtifactReceipt")
a = json.loads(ct[rcp["artifact_digest"]])
a["run_id"] = "run_ts_0009"
a["nodes"][0]["identity"]["tag"] = "H-101"
go("MERGED: узел 'H-101' (лат.) = строгий ключ слитой сущности -> выживший ent_ts_pump", canon_bytes(a), pre=merged)

# 2. two skeleton twins created in ONE artifact (neither exists in the project yet)
def twins(art):
    art["nodes"] += [
        {"id": "x1", "type": "ENTITY", "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "Т-3/1"}},
        {"id": "x2", "type": "ENTITY", "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "Т-31"}},
        {"id": "y1", "type": "RELATION", "role": "part-of", "args": ["x1", "v3"], "anchor": A("напорном трубопроводе Т-3")},
        {"id": "y2", "type": "RELATION", "role": "part-of", "args": ["x2", "v3"], "anchor": A("Задвижка установлена на напорном трубопроводе Т-3")}]
go("двойники по скелету внутри одного артефакта (Т-3/1 и Т-31)", SM.valve_artifact(SID, tweak=twins), extra_src=vs)
go("то же, strict=True", SM.valve_artifact(SID, tweak=twins), extra_src=vs, strict=True)

# 3. unit outside the predicate's unit list / wrong case
go("единица 'psi' (профиль артефакта допускает, предикат нет)", SM.valve_artifact(SID, tweak=lambda a: a["nodes"][3].__setitem__("unit", "psi")), extra_src=vs)
go("единица 'mpa' (регистр)", SM.valve_artifact(SID, tweak=lambda a: a["nodes"][3].__setitem__("unit", "mpa")), extra_src=vs)
# 4. instance-of to an EQUIPMENT (range), part-of from a MODEL (domain)
go("instance-of -> EQUIPMENT (диапазон предиката)", SM.valve_artifact(SID, tweak=lambda a: a["nodes"][7].__setitem__("args", ["v1", "v3"])), extra_src=vs)
go("part-of от модели (домен предиката)", SM.valve_artifact(SID, tweak=lambda a: a["nodes"][8].__setitem__("args", ["v2", "v3"])), extra_src=vs)
# 5. silent loss: an isolated QUANTITY and an ACTION node not used by any relation
go("одинокие узлы QUANTITY/ACTION без отношения", SM.valve_artifact(SID, extra_nodes=(
    {"id": "q9", "type": "QUANTITY", "value": "80", "unit": "mm", "anchor": A("ЗКС 80-16")},)), extra_src=vs)
# 6. RETIRED entity matched by strong key
def retire(W):
    W["ent_ts_valve_a"]["status"] = "RETIRED"; W["ent_ts_valve_a"]["status_changed_at"] = "2026-09-06T12:00:00Z"
ds, tr, ct = world(retire)
print("world with retired valve:", VAL.validate(ds, tr, ct).codes() or "CLEAN")
go("RETIRED: задвижка К-1/12 выведена, адаптер сопоставляет с ней", SM.valve_artifact(SID), pre=retire, extra_src=vs)
# 7. condition text longer than... / parameter not in value_texts
go("parameter 'x_unknown_param' (нет в словаре)", SM.valve_artifact(SID, tweak=lambda a: a["nodes"][9].__setitem__("parameter", "x_unknown_param")), extra_src=vs)

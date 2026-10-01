#!/usr/bin/env python3
"""Acceptance of the TechSense adapter (S4), without a database.

A1 golden: the adapter applied to the stored NS-2 artifact reproduces the hand-written world records c0..c3 and rcp_1
   byte for byte (same claim_id, receipt_id, signature) — two independent constructions agree.
A2 deterministic: two runs give identical canonical bytes.
A3 second instruction (valve К-1/12): 4 claims, 1 new entity (the model), the valve and the station are matched by
   strong key (К-1/12 is not К-11/2), the unmapped relation installed-on is reported and creates nothing;
   the world + new records pass the validator with no errors and no new warnings.
A4 strict mode refuses an artifact with an unmapped relation.
A5 a look-alike tag (Latin «HC-2») is not matched to НС-2: a new entity + report possible_duplicates; strict refuses;
   the validator raises POSSIBLE_DUPLICATE (the loader refuses such a dataset until a person decides).
A6 the adapter refuses: non-canonical bytes, unknown profile, input not among sources, source bytes not matching
   the address, recorded_at after issued_at, anchor beyond the source, malformed mapped relation, no claims at all.
A7 every claim it emits: quote == bytes at the span, graph_node of the same artifact, PIPELINE of the artifact's run.
A8 tampering after the adapter is caught by the validator (value changed and re-addressed -> GRAPH_NODE_INVALID).
A9-A12 (review S4): look-alikes inside one artifact; relations outside the predicate's domain/range/units refused;
   unused nodes and identity differences reported; a node keyed by a merged alias resolves to the survivor.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE))
import validator as VAL  # noqa: E402
from fixtures import SEEDS  # noqa: E402
from jcs import canon_bytes, canon, digest  # noqa: E402
from vectors import build  # noqa: E402
from techsense_umr import adapt, AdapterError  # noqa: E402
import samples as SM  # noqa: E402

RESULTS = []


def check(tid, cond, desc, detail=""):
    RESULTS.append(bool(cond))
    print(f"{tid:<4} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def recs(ds, kind):
    return [r for r in ds["records"] if r["kind"] == kind]


ds, trust, content = build()
P = {p["project_id"]: p for p in recs(ds, "Project")}
PRJ = P["prj_ts_pumps"]
SRC = {s["source_id"]: s for s in recs(ds, "Source")}
ENT = [e for e in recs(ds, "Entity") if e["project_id"] == "prj_ts_pumps"]
RCP = recs(ds, "ArtifactReceipt")[0]
ART = content[RCP["artifact_digest"]]
KEY = SEEDS["key_ts_1"]


def run(art=ART, sources=SRC, recorded="2026-09-06T09:59:00Z", issued="2026-09-06T10:00:00Z", strict=False, entities=ENT):
    return adapt(art, PRJ, sources, content, entities, recorded, issued, "key_ts_1", KEY, strict=strict)


# A1 golden
res = run()
world_claims = {c["claim_id"]: c for c in recs(ds, "Claim")}
mine = [r for r in res.records if r["kind"] == "Claim"]
same_claims = all(world_claims.get(c["claim_id"]) == c for c in mine) and len(mine) == 4
same_rcp = [r for r in res.records if r["kind"] == "ArtifactReceipt"] == [RCP]
check("A1", same_claims and same_rcp and not res.report["new_entities"] and not res.report["unmapped"],
      "адаптер воспроизводит утверждения c0..c3 и receipt мира байт в байт",
      f"claims={len(mine)} receipt={'=' if same_rcp else '≠'} matched={sorted(res.report['matched'].values())}")

# A2 deterministic
res2 = run()
check("A2", canon(res.records) == canon(res2.records), "два прогона дают одинаковые байты")

# A3 valve instruction
NOW_OBS, REC, ISS = "2026-09-08T08:00:00Z", "2026-09-08T09:00:00Z", "2026-09-08T09:00:30Z"
vs = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, NOW_OBS)
src2 = {**SRC, vs["source_id"]: vs}
vart = SM.valve_artifact(vs["source_id"])
r3 = run(vart, src2, REC, ISS)
kinds = [r["kind"] for r in r3.records]
new = [r for r in r3.records if r["kind"] == "Entity"]
ds3 = copy.deepcopy(ds)
ds3["records"] += [vs] + r3.records
ct3 = {**content, r3.artifact_digest: vart}
rep3 = VAL.validate(ds3, trust, ct3)
check("A3", kinds.count("Claim") == 4 and len(new) == 1 and new[0]["entity_type"] == "EQUIPMENT_MODEL"
      and r3.report["matched"] == {"v1": "ent_ts_valve_a", "v3": "ent_ts_station"}
      and r3.report["unmapped"] == [("r5", "installed-on")] and not rep3.errors
      and [w["code"] for w in rep3.warnings] == ["CONTRADICTION_SINGLE_VALUED"],
      "задвижка К-1/12: 4 утверждения, новая модель, К-1/12 ≠ К-11/2, installed-on — в отчёт, Т-3 не заведён; валидатор чист",
      f"new={[e['display_name'] for e in new]} errors={rep3.codes()} unmapped={r3.report['unmapped']}")

# A4 strict
try:
    run(vart, src2, REC, ISS, strict=True)
    check("A4", False, "строгий режим отказывает при неотображённом отношении")
except AdapterError as ex:
    check("A4", "неотображённые" in str(ex), "строгий режим отказывает при неотображённом отношении", str(ex)[:80])

# A5 look-alike station tag (Latin H and C)
lat = "".join(chr(c) for c in (0x48, 0x43)) + "-2"
vart5 = SM.valve_artifact(vs["source_id"], station_tag=lat)
r5 = run(vart5, src2, REC, ISS)
ds5 = copy.deepcopy(ds)
ds5["records"] += [vs] + r5.records
rep5 = VAL.validate(ds5, trust, {**content, r5.artifact_digest: vart5})
try:
    run(vart5, src2, REC, ISS, strict=True)
    strict5 = False
except AdapterError as ex:
    strict5 = "возможные дубли" in str(ex)
check("A5", r5.report["possible_duplicates"] == [("v3", "ent_ts_station")] and "v3" not in r5.report["matched"] and strict5
      and not rep5.errors and "POSSIBLE_DUPLICATE" in [w["code"] for w in rep5.warnings],
      "двойник «HC-2» (латиница) не сопоставлен с НС-2: новая сущность, отчёт о возможном дубле, строгий режим отказывает",
      f"dups={r5.report['possible_duplicates']} warns={[w['code'] for w in rep5.warnings]}")


# A6 refusals
def refuses(tid, desc, fn, needle):
    try:
        fn()
        check(tid, False, desc, "принято")
    except AdapterError as ex:
        check(tid, needle in str(ex), desc, str(ex)[:90])


refuses("A6a", "неканонические байты", lambda: run(ART.replace(b'":', b'": ', 1)), "канонической")


def prof(a):
    a["semantic_profile"] = "ts-semantic/9.9"


refuses("A6b", "неизвестный профиль", lambda: run(SM.valve_artifact(vs["source_id"], tweak=prof), src2, REC, ISS), "профиль")
refuses("A6c", "вход не среди источников", lambda: run(vart, SRC, REC, ISS), "нет такого источника")
bad_src = {**src2, vs["source_id"]: {**vs, "content_inline": SM.VALVE_TEXT.replace("1,6", "2,5")}}
refuses("A6d", "байты входа не совпадают с адресом", lambda: run(vart, bad_src, REC, ISS), "нет проверенных байтов")
refuses("A6e", "recorded_at позже issued_at", lambda: run(vart, src2, ISS, REC), "recorded_at")


def far(a):
    a["nodes"][9]["anchor"]["end"] = 100000


refuses("A6f", "якорь за концом источника", lambda: run(SM.valve_artifact(vs["source_id"], tweak=far), src2, REC, ISS), "якорь")


def wrong_arg(a):
    a["nodes"][9]["args"] = ["v1", "v5"]


refuses("A6g", "has-parameter с действием вместо величины", lambda: run(SM.valve_artifact(vs["source_id"], tweak=wrong_arg), src2, REC, ISS), "не по профилю")


def only_unmapped(a):
    a["nodes"] = [n for n in a["nodes"] if n["type"] != "RELATION" or n["role"] == "installed-on"]


refuses("A6h", "артефакт без отображаемых отношений", lambda: run(SM.valve_artifact(vs["source_id"], tweak=only_unmapped), src2, REC, ISS), "ни одного")

# A7 claims rest on bytes and nodes
ok7 = True
for r in r3.records:
    if r["kind"] != "Claim":
        continue
    ev = r["evidence"][0]
    b = SM.VALVE_TEXT.encode("utf-8")[ev["span"]["start"]:ev["span"]["end"]]
    ok7 &= (b.decode("utf-8") == ev["quote"] and hashlib.sha256(b).hexdigest() == ev["quote_sha256"]
            and ev["graph_node"]["artifact_digest"] == r3.artifact_digest
            and r["produced_by"] == {"kind": "PIPELINE", "service_id": "svc_techsense", "run_id": "run_ts_0002"})
check("A7", ok7, "каждое утверждение: цитата = байты фрагмента, узел того же артефакта, запуск артефакта")

# A8 tampering after the adapter
ds8 = copy.deepcopy(ds3)
c8 = next(r for r in ds8["records"] if r["kind"] == "Claim" and r["predicate"] == "ts.has_parameter" and r["project_id"] == "prj_ts_pumps"
          and r["evidence"][0]["graph_node"]["node_id"] == "r3")
old = c8["claim_id"]
c8["object"]["literal"]["value"] = "2.5"
c8["claim_id"] = "clm:sha256:" + digest({k: v for k, v in c8.items() if k != "claim_id"})
rc8 = next(r for r in ds8["records"] if r["kind"] == "ArtifactReceipt" and r["run_id"] == "run_ts_0002")
rc8["emitted_claim_ids"] = [c8["claim_id"] if x == old else x for x in rc8["emitted_claim_ids"]]
rep8 = VAL.validate(ds8, trust, ct3)
check("A8", "GRAPH_NODE_INVALID" in rep8.codes(), "подмена значения после адаптера (2,5 вместо 1,6) ловится валидатором", ",".join(rep8.codes()))

# ---- review S4: S4R-02, 04, 05, 06
# A9 look-alikes inside one artifact: two new nodes «Т-3/1» and «Т-31» (same skeleton) -> reported, strict refuses
def twins(a):
    a["nodes"].append({"id": "v8", "type": "ENTITY", "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "Т-3/1"}})
    a["nodes"].append({"id": "v9", "type": "ENTITY", "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "Т-31"}})
    an = a["nodes"][8]["anchor"]
    a["nodes"].append({"id": "r8", "type": "RELATION", "role": "part-of", "args": ["v8", "v3"], "anchor": an})
    a["nodes"].append({"id": "r9", "type": "RELATION", "role": "part-of", "args": ["v9", "v3"], "anchor": an})


r9 = run(SM.valve_artifact(vs["source_id"], tweak=twins), src2, REC, ISS)
try:
    run(SM.valve_artifact(vs["source_id"], tweak=twins), src2, REC, ISS, strict=True)
    s9 = False
except AdapterError as ex:
    s9 = "возможные дубли" in str(ex)
check("A9", len(r9.report["possible_duplicates"]) == 1 and r9.report["possible_duplicates"][0][0] == "v9" and s9,
      "двойники по скелету внутри одного артефакта («Т-3/1» и «Т-31») — в отчёт, строгий режим отказывает (S4R-04)",
      str(r9.report["possible_duplicates"]))


# A10 outside the predicate: unit psi, instance-of to equipment, part-of from a model
def psi(a):
    a["nodes"][3]["unit"] = "psi"


def inst_eq(a):
    a["nodes"][7]["args"] = ["v1", "v3"]


def part_model(a):
    a["nodes"][8]["args"] = ["v2", "v3"]


outs = []
for tw in (psi, inst_eq, part_model):
    try:
        run(SM.valve_artifact(vs["source_id"], tweak=tw), src2, REC, ISS)
        outs.append(False)
    except AdapterError as ex:
        outs.append("вне области" in str(ex))
check("A10", all(outs), "единица psi, instance-of на оборудование, part-of от модели — адаптер отказывает, а не выдаёт брак (S4R-05)", str(outs))


# A11 nothing is lost silently: unused nodes and identity differences are reported; strict refuses unused nodes
def extra(a):
    a["nodes"].append({"id": "v10", "type": "QUANTITY", "value": "80", "unit": "mm", "anchor": a["nodes"][3]["anchor"]})
    a["nodes"][0]["identity"]["description"] = "задвижка клиновая"
    a["nodes"] = [n for n in a["nodes"] if n["id"] not in ("r5", "v7")]


r11 = run(SM.valve_artifact(vs["source_id"], tweak=extra), src2, REC, ISS)
try:
    run(SM.valve_artifact(vs["source_id"], tweak=extra), src2, REC, ISS, strict=True)
    s11 = False
except AdapterError as ex:
    s11 = "узлы без" in str(ex)
check("A11", r11.report["unused_nodes"] == [("v10", "QUANTITY")]
      and r11.report["identity_differences"] == [("v1", "ent_ts_valve_a", "description", "задвижка клиновая", "задвижка")] and s11,
      "узел без отношения и расхождение описания — в отчёте; строгий режим отказывает (S4R-06)",
      f"unused={r11.report['unused_nodes']} diff={r11.report['identity_differences']}")

# A12 a node keyed by a merged alias -> the survivor; the validator agrees (S4R-02)
alias = {"kind": "Entity", "schema_version": "core-ontology/0.2", "entity_id": "ent_ts_valve_alias", "project_id": "prj_ts_pumps",
         "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "К-1/12/с"}, "display_name": "Задвижка К-1/12/с",
         "status": "MERGED", "merged_into": "ent_ts_valve_a", "created_at": "2026-09-07T09:00:00Z", "status_changed_at": "2026-09-07T10:00:00Z",
         "marking": {"level": "INTERNAL", "categories": []}}
art12 = SM.valve_artifact(vs["source_id"], tweak=lambda a: a["nodes"][0]["identity"].__setitem__("tag", "К-1/12/с"))
r12 = run(art12, src2, REC, ISS, entities=ENT + [alias])
ds12 = copy.deepcopy(ds)
ds12["records"] += [alias, vs] + r12.records
rep12 = VAL.validate(ds12, trust, {**content, r12.artifact_digest: art12})
check("A12", r12.report["matched"].get("v1") == "ent_ts_valve_a" and not rep12.errors,
      "узел назван ключом слитой сущности: адаптер ставит выжившую, валидатор согласен (S4R-02)",
      f"matched={r12.report['matched'].get('v1')} errors={rep12.codes()}")

print(f"\nadapter_tests={len(RESULTS)} passed={sum(RESULTS)}")
print("ADAPTER_RESULT=" + ("PASS" if all(RESULTS) else "FAIL"))
sys.exit(0 if all(RESULTS) else 1)

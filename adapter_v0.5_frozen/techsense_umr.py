#!/usr/bin/env python3
"""TechSense adapter (S4): a simplified UMR artifact (umr-artifact/0.3, profile ts-semantic/0.2) -> core records.

Inputs
  artifact_bytes  canonical JSON produced by TechSense (its sha256 is the artifact_digest);
  project         the Project record (project_id, tenant_id, default_marking);
  sources         {source_id: Source record} — the artifact's inputs;
  content         object store {source_id: bytes} (Source.content_inline is accepted as well);
  entities        the existing Entity records of the project (for identity matching);
  recorded_at     when the claims are recorded; issued_at — when the receipt is issued (>= recorded_at);
  key_id, private_key  the service key (Ed25519, 32 bytes seed); the public key lives in trust anchors only.

Output  AdapterResult(records, artifact_digest, report)
  records: new Entity records, then Claim records (one per mapped RELATION node, in node order), then one signed
  ArtifactReceipt. report: {"claims": [(node_id, claim_id)], "new_entities": [...], "matched": {node_id: entity_id},
  "unmapped": [(node_id, role)], "possible_duplicates": [(node_id, entity_id)], "unused_nodes": [(node_id, type)],
  "identity_differences": [(node_id, entity_id, field, in_graph, in_entity)]} — nothing of the artifact is lost silently.

Rules
  * the artifact is checked by the validator's own parser first (parse_artifact: UTF-8, no duplicate keys, integer
    profile, schema, canonical bytes); an unknown profile, a broken anchor or a malformed relation stops the adapter;
  * one claim per RELATION node whose role the profile maps (predicates.json -> artifact_formats); relations with
    roles the profile does not map are listed in report["unmapped"] — never dropped silently, never guessed;
  * evidence of a claim = the relation node's anchor: source, byte span, quote re-read from the bytes, sha256 of the
    quote, and graph_node {artifact_digest, node_id};
  * only ENTITY nodes used by mapped relations are resolved; an ENTITY node is matched to an existing entity of the project by the STRONG identity key, computed by the
    validator's entity_identifiers(); a MERGED entity resolves to its survivor; no match -> a new Entity with a
    deterministic id; a soft-key (skeleton) hit without a strong match goes to report["possible_duplicates"] —
    the adapter never merges and never picks the look-alike: a person decides (IdentityDecision or a fix);
  * marking of every produced record = least upper bound of the project default, the input sources and the matched
    entities, so a claim is never broader than what it rests on;
  * deterministic: the same inputs give the same bytes (entity ids, claim_id, receipt_id, signature);
  * a relation outside the domain / range / units of its predicate stops the adapter (it never emits a record the
    validator would refuse);
  * strict=True turns unmapped relations, unused nodes and possible duplicates (with existing entities or between
    new ones of the same artifact) into AdapterError (for unattended runs).
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402
from jcs import digest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
import base64  # noqa: E402

SV = "core-ontology/0.2"
PREDS = {p["id"]: p for p in VAL.PREDICATES["predicates"]}


class AdapterError(Exception):
    pass


class AdapterResult:
    def __init__(self, records, artifact_digest, report):
        self.records, self.artifact_digest, self.report = records, artifact_digest, report


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _join(m, other):
    """least upper bound of two markings; categories keep the order of first appearance (deterministic bytes)"""
    if VAL.dominates(m, other):
        return m
    level = max(m["level"], other["level"], key=VAL.LEVEL.__getitem__)
    cats = list(m["categories"]) + [c for c in other["categories"] if c not in m["categories"]]
    return {"level": level, "categories": cats}


def _strong(etype, identity):
    return set(VAL.entity_identifiers({"entity_type": etype, "identity": identity}, VAL.Report(), "-")[0])


def _soft(etype, identity):
    return set(VAL.entity_identifiers({"entity_type": etype, "identity": identity}, VAL.Report(), "-")[2])


def _display(etype, i):
    if etype == "EQUIPMENT":
        d = i.get("description", "")
        return (d[:1].upper() + d[1:] + " " if d else "") + i["tag"]
    return i["manufacturer"] + " " + i["model"]


def adapt(artifact_bytes, project, sources, content, entities, recorded_at, issued_at, key_id, private_key, strict=False):
    if not recorded_at <= issued_at:
        raise AdapterError("recorded_at позже issued_at")
    dg = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    art, why = VAL.parse_artifact(artifact_bytes)
    if art is None:
        raise AdapterError(why)
    prof = VAL.ARTIFACT_FORMATS[art["artifact_format"]]["profiles"].get(art["semantic_profile"])
    if prof is None:
        raise AdapterError(f"профиль {art['semantic_profile']} не зарегистрирован")
    roles = prof["roles"]
    nodes = {}
    for n in art["nodes"]:
        if n["id"] in nodes:
            raise AdapterError(f"узел {n['id']} повторяется")
        nodes[n["id"]] = n

    # inputs: every input is a known source of the project's tenant with verified bytes
    data = {}
    for sid in art["inputs"]:
        s = sources.get(sid)
        if s is None or s["tenant_id"] != project["tenant_id"]:
            raise AdapterError(f"вход {sid}: нет такого источника в tenant проекта")
        b = s["content_inline"].encode("utf-8") if "content_inline" in s else content.get(sid)
        if b is None or "src:sha256:" + hashlib.sha256(b).hexdigest() != sid:
            raise AdapterError(f"вход {sid}: нет проверенных байтов")
        data[sid] = b

    def anchor_text(n):
        an = n["anchor"]
        b = data.get(an["source_id"])
        if b is None or not an["start"] < an["end"] <= len(b):
            raise AdapterError(f"якорь узла {n['id']} вне байтов входа")
        try:
            return b[an["start"]:an["end"]].decode("utf-8")
        except UnicodeDecodeError:
            raise AdapterError(f"якорь узла {n['id']} режет символ UTF-8") from None

    # marking: project default joined with the inputs
    marking = copy.deepcopy(project["default_marking"])
    for sid in art["inputs"]:
        marking = _join(marking, sources[sid]["marking"])

    # entity resolution by strong key (validator code); soft hits are only reported
    E = {e["entity_id"]: e for e in entities if e["project_id"] == project["project_id"]}
    survivor = lambda eid: E[eid]["merged_into"] if E[eid]["status"] == "MERGED" else eid  # noqa: E731
    strong_idx, soft_idx = {}, {}
    for eid, e in E.items():
        for k in _strong(e["entity_type"], e["identity"]):
            strong_idx.setdefault((e["entity_type"], k), set()).add(survivor(eid))
        for k in _soft(e["entity_type"], e["identity"]):
            soft_idx.setdefault((e["entity_type"], k), set()).add(survivor(eid))
    report = {"claims": [], "new_entities": [], "matched": {}, "unmapped": [], "possible_duplicates": [],
              "unused_nodes": [], "identity_differences": []}
    # only entities that a mapped relation needs are resolved or created (an unmapped relation creates nothing)
    needed = {x for n in art["nodes"] if n["type"] == "RELATION" and n["role"] in roles for x in n["args"]}
    ent_of, new_entities, new_soft = {}, [], {}
    for n in art["nodes"]:
        if n["type"] != "ENTITY" or n["id"] not in needed:
            continue
        t, i = n["entity_type"], n["identity"]
        R = VAL.Report()
        VAL.entity_identifiers({"entity_type": t, "identity": i}, R, n["id"])
        if R.errors:
            raise AdapterError(f"узел {n['id']}: {R.errors[0]['msg']}")
        hits = set().union(*(strong_idx.get((t, k), set()) for k in _strong(t, i)))
        if len(hits) > 1:
            raise AdapterError(f"узел {n['id']}: строгий ключ указывает на несколько сущностей {sorted(hits)}")
        if hits:
            eid = hits.pop()
            ent_of[n["id"]] = eid
            report["matched"][n["id"]] = eid
            marking = _join(marking, E[eid]["marking"])
            for f, v in sorted(i.items()):              # S4R-06: what the graph says differently is not dropped silently
                if E[eid]["identity"].get(f) != v:
                    report["identity_differences"].append((n["id"], eid, f, v, E[eid]["identity"].get(f)))
            continue
        key = sorted(_strong(t, i))[0]
        eid = "ent_ts_" + hashlib.sha256(json.dumps([project["project_id"], t, key], ensure_ascii=False).encode()).hexdigest()[:24]
        if eid in ent_of.values():           # two nodes of the same entity in one artifact
            ent_of[n["id"]] = eid
            continue
        soft_hits = set().union(*(soft_idx.get((t, k), set()) for k in _soft(t, i)))
        for k in _soft(t, i):                           # S4R-04: look-alikes inside one artifact as well
            if new_soft.get((t, k), eid) != eid:
                soft_hits.add(new_soft[(t, k)])
            new_soft[(t, k)] = eid
        for other in sorted(soft_hits):
            report["possible_duplicates"].append((n["id"], other))
        ent_of[n["id"]] = eid
        new_entities.append({"kind": "Entity", "schema_version": SV, "entity_id": eid, "project_id": project["project_id"],
                             "entity_type": t, "identity": copy.deepcopy(i), "display_name": _display(t, i),
                             "status": "ACTIVE", "created_at": recorded_at, "marking": None})
        report["new_entities"].append((n["id"], eid))
    for e in new_entities:
        e["marking"] = marking
    if strict and report["possible_duplicates"]:
        raise AdapterError(f"возможные дубли: {report['possible_duplicates']}")

    # claims: one per mapped RELATION, in node order
    claims = []
    for n in art["nodes"]:
        if n["type"] != "RELATION":
            continue
        spec = roles.get(n["role"])
        if spec is None:
            report["unmapped"].append((n["id"], n["role"]))
            continue
        a0, a1 = nodes[n["args"][0]], nodes[n["args"][1]]
        if a0["type"] != "ENTITY" or a1["type"] != spec["object"]:
            raise AdapterError(f"отношение {n['id']}: аргументы не по профилю")
        pr = PREDS[spec["predicate"]]                     # S4R-05: the ontology of predicates, not only the profile
        rng = pr["range"]
        if (a0["entity_type"] not in pr["domain"]
                or (spec["object"] == "ENTITY" and a1["entity_type"] not in rng.get("entity", []))
                or (spec["object"] == "QUANTITY" and ("QUANTITY" not in rng.get("literal", []) or a1["unit"] not in rng.get("units", [])))
                or (spec["object"] == "ACTION" and "STRING" not in rng.get("literal", []))):
            raise AdapterError(f"отношение {n['id']}: вне области или диапазона предиката {spec['predicate']} (тип или единица)")
        if spec["object"] == "ENTITY":
            obj = {"entity": ent_of[a1["id"]]}
        elif spec["object"] == "QUANTITY":
            obj = {"literal": {"type": "QUANTITY", "value": a1["value"], "unit": a1["unit"]}}
        else:
            obj = {"literal": {"type": "STRING", "value": a1["text"]}}
        quote = anchor_text(n)
        an = n["anchor"]
        c = {"kind": "Claim", "schema_version": SV, "project_id": project["project_id"], "subject": ent_of[a0["id"]],
             "predicate": spec["predicate"], "object": obj,
             "evidence": [{"source_id": an["source_id"], "span": {"start": an["start"], "end": an["end"]}, "quote": quote,
                           "quote_sha256": hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                           "graph_node": {"artifact_digest": dg, "node_id": n["id"]}}],
             "produced_by": {"kind": "PIPELINE", "service_id": art["producer"]["service_id"], "run_id": art["run_id"]},
             "recorded_at": recorded_at, "marking": marking}
        if spec.get("qualifier") == "parameter":
            c["qualifiers"] = {"parameter": n["parameter"]}
        elif spec.get("qualifier") == "condition":
            c["qualifiers"] = {"condition": nodes[n["condition"]]["text"]}
        c["claim_id"] = "clm:sha256:" + digest({k: v for k, v in c.items() if k != "claim_id"})
        claims.append(c)
        report["claims"].append((n["id"], c["claim_id"]))
    used = {x for n in art["nodes"] if n["type"] == "RELATION" and n["role"] in roles
            for x in n["args"] + ([n["condition"]] if "condition" in n else [])}
    report["unused_nodes"] = [(n["id"], n["type"]) for n in art["nodes"] if n["type"] != "RELATION" and n["id"] not in used]
    if strict and report["unmapped"]:
        raise AdapterError(f"неотображённые отношения: {report['unmapped']}")
    if strict and report["unused_nodes"]:
        raise AdapterError(f"узлы без отображаемых отношений: {report['unused_nodes']}")
    if not claims:
        raise AdapterError("артефакт не дал ни одного утверждения")

    r = {"kind": "ArtifactReceipt", "schema_version": SV, "project_id": project["project_id"],
         "producer": copy.deepcopy(art["producer"]), "run_id": art["run_id"], "artifact_digest": dg,
         "artifact_schema_version": art["artifact_format"], "semantic_profile_version": art["semantic_profile"],
         "input_source_ids": list(art["inputs"]), "emitted_claim_ids": [c["claim_id"] for c in claims],
         "issued_at": issued_at, "key_id": key_id}
    r["receipt_id"] = "rcp:sha256:" + digest({k: v for k, v in r.items() if k not in ("receipt_id", "signature")})
    r["signature"] = _b64u(Ed25519PrivateKey.from_private_bytes(private_key).sign(r["receipt_id"].encode()))
    return AdapterResult(new_entities + claims + [r], dg, report)


def main(argv):
    """CLI: techsense_umr.py artifact.json context.json key.seed -> records JSON on stdout.
    context.json: {"project": {...}, "sources": [...], "entities": [...], "recorded_at": ..., "issued_at": ...,
                   "key_id": ..., "content_dir": optional}"""
    art = Path(argv[1]).read_bytes()
    ctx = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    seed = Path(argv[3]).read_bytes()
    content = {}
    if ctx.get("content_dir"):
        for f in Path(ctx["content_dir"]).iterdir():
            content["src:sha256:" + f.name] = f.read_bytes()
    try:
        res = adapt(art, ctx["project"], {s["source_id"]: s for s in ctx["sources"]}, content, ctx["entities"],
                    ctx["recorded_at"], ctx["issued_at"], ctx["key_id"], seed, strict="--strict" in argv)
    except AdapterError as ex:
        print(f"ADAPTER_ERROR {ex}", file=sys.stderr)
        return 1
    print(json.dumps({"records": res.records, "report": res.report}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

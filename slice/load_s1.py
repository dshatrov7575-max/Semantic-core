#!/usr/bin/env python3
"""Srez S1/S2 loader: normative validator first (fail-closed), then ONE transaction into PostgreSQL.

Usage:  PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... python3 slice/load_s1.py
Loads the reference world of core/ (vectors.build()) with its trust anchors and content store.
Identity keys are computed by validator.entity_identifiers() — the same code as the validator (D8).
"""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parent / "core"
STORE = HERE.parent / "store"
sys.path.insert(0, str(CORE))
sys.path.insert(0, str(STORE))
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from object_store import ObjectStore, FsBackend  # noqa: E402
import gateway as GW  # noqa: E402

TAG = "$ac_q$"
DDL_ALL = "\n".join((HERE / f).read_text(encoding="utf-8") for f in ("ddl_s1.sql", "unicode_s1.sql", "keys_s1.sql", "proj_s3.sql",
                                                                          "ddl_s4.sql", "proj_s4.sql", "ddl_s5.sql", "proj_s5.sql", "ddl_s5b.sql"))


def q(v):
    if v is None:
        return "NULL"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    v = str(v)
    assert TAG not in v
    return TAG + v + TAG


def psql(sql, db=None):
    env = dict(os.environ)
    if db:
        env["PGDATABASE"] = db
    return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-At", "-F", " | "], input=sql,
                          capture_output=True, text=True, env=env)


def entity_keys(ds):
    """The key rows the database must hold for a valid dataset, computed by the validator's own functions:
    owners resolved through merges, a QUALIFY decision's qualifier on the owner's unqualified weak keys,
    soft (skeleton) keys under the scheme 'skel:<scheme>'."""
    E = {r["entity_id"]: r for r in ds["records"] if r["kind"] == "Entity"}
    resolve = lambda eid: E[eid]["merged_into"] if E[eid]["status"] == "MERGED" else eid  # noqa: E731
    qual_of = {}
    for d in ds["records"]:
        if d["kind"] == "IdentityDecision" and d["decision"] == "QUALIFY":
            qual_of[d["entity_id"]] = VAL.norm(d["place"]) if "place" in d else d["disambiguator"]
    strong, weak, soft = set(), set(), set()
    for eid, e in E.items():
        st, wk, sf = VAL.entity_identifiers(e, VAL.Report(), eid)
        o = resolve(eid)
        for sch, val in st:
            strong.add((e["project_id"], e["entity_type"], sch, val, o))
        for sch, val, qual in wk:
            weak.add((e["project_id"], e["entity_type"], sch, val, o, qual if qual is not None else qual_of.get(o)))
        for sch, val in sf:
            soft.add((e["project_id"], e["entity_type"], "skel:" + sch, val, o))
    return sorted(strong), sorted(weak, key=lambda x: tuple("" if v is None else v for v in x)), sorted(soft)


def roles_sql():
    """S4 registry: artifact format / semantic profile / role -> predicate (from predicates.json)"""
    out = []
    for fmt, f in VAL.ARTIFACT_FORMATS.items():
        for prof, pr in f["profiles"].items():
            for role, sp in pr["roles"].items():
                out.append(f"INSERT INTO ac.artifact_roles VALUES ({q(fmt)},{q(prof)},{q(role)},{q(sp['predicate'])},{q(sp['object'])},"
                           f"{q(sp.get('qualifier'))});")
    return "\n".join(out)


def artifacts_sql(ds, content):
    """every artifact named by a receipt, under the tenant of the receipt's project"""
    P = {p["project_id"]: p for p in ds["records"] if p["kind"] == "Project"}
    seen, out = set(), []
    for r in ds["records"]:
        if r["kind"] != "ArtifactReceipt":
            continue
        key = (P[r["project_id"]]["tenant_id"], r["artifact_digest"])
        if key in seen or r["artifact_digest"] not in content:
            continue
        seen.add(key)
        out.append(f"INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ({q(key[0])},{q(key[1])},"
                   f"decode({q(base64.b64encode(content[key[1]]).decode())},'base64'));")
    return "\n".join(out)


def load_sql(ds, trust, content):
    R = ds["records"]
    by = lambda k: [r for r in R if r["kind"] == k]  # noqa: E731
    P = {p["project_id"]: p for p in by("Project")}
    out = ["BEGIN;", "SET ROLE ac_trust_admin;"]
    for k in trust["keys"]:
        out.append(f"INSERT INTO ac_trust.keys VALUES ({q(k['tenant_id'])},{q(k['key_id'])},{q(k['service_id'])},{q(k['algorithm'])},"
                   f"{q(k['public_key'])},{q(k['not_before'])},{q(k['not_after'])},{q(k.get('revoked_at'))});")
    out += ["RESET ROLE;"]
    for pr in VAL.PREDICATES["predicates"]:
        out.append(f"INSERT INTO ac.predicates VALUES ({q(pr['id'])},ARRAY[{','.join(q(x) for x in pr['domain'])}]::text[],{q(pr['range'])},"
                   f"ARRAY[{','.join(q(x) for x in pr['dimensions'])}]::text[],{q(pr['cardinality'])},{q(pr.get('qualifiers', {}))});")
    for prof, dims in VAL.PREDICATES["check_profiles"].items():
        out.append(f"INSERT INTO ac.check_profiles VALUES ({q(prof)},ARRAY[{','.join(q(x) for x in dims)}]::text[]);")
    out.append(roles_sql())
    out += ["SET ROLE ac_migrator;", "SET LOCAL ac.historical_import = 'on';"]
    for p in by("Project"):
        out.append(f"INSERT INTO ac.projects VALUES ({q(p['project_id'])},{q(p['tenant_id'])},{q(p['product'])},{q(p['default_marking'])},{q(p)});")
    for s in by("Source"):
        body = {k: v for k, v in s.items() if k != "content_inline"}
        out.append(f"INSERT INTO ac.sources VALUES ({q(s['tenant_id'])},{q(s['source_id'])},{s['byte_length']},{q(s['marking'])},{q(body)});")
        b = content.get(s["source_id"]) or (s["content_inline"].encode("utf-8") if "content_inline" in s else None)
        if b is not None:
            out.append(f"INSERT INTO ac.source_bytes VALUES ({q(s['tenant_id'])},{q(s['source_id'])},decode({q(base64.b64encode(b).decode())},'base64'));")
        for o in s["observations"]:
            og = o.get("original")
            # S6R-07: the loader must not declare an object "stored and verified by reading it back" itself — it was
            # never near a store. Originals are registered for real by the gateway in gateway_register_originals(),
            # in their OWN transaction(s), before this one starts; here we only reference the address already on file.
            out.append("INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by, original_object, "
                       f"original_media_type, original_length) VALUES ({q(s['tenant_id'])},{q(s['source_id'])},{q(o['observed_at'])},"
                       f"{q(o['origin_uri'])},{q(o['observed_by'])},{q(og['object'] if og else None)},{q(og['media_type'] if og else None)},"
                       f"{og['byte_length'] if og else 'NULL'});")
    # S5: publications after the sources whose renditions they name
    for pb in by("Publication"):
        out.append(f"INSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
                   f"({q(pb['publication_id'])},{q(pb['tenant_id'])},{q(pb['outlet'])},{q(pb['canonical_url'])},{q(pb['text_digest'])},"
                   f"{q(pb['marking'])},{q(pb)});")
    # S4: producer artifacts (bytes by digest) before the claims that point at their nodes
    out.append(artifacts_sql(ds, content))
    # entities and identity decisions in time order (a homonym must come after the refinement that separates it);
    # ties: the entity a QUALIFY refines, then decisions, then other entities, merged entities last
    targets = {d["entity_id"] for d in by("IdentityDecision") if d["decision"] == "QUALIFY"}
    events = [(e["created_at"], 0 if e["entity_id"] in targets else 3 if e["status"] == "MERGED" else 2, e["entity_id"], e)
              for e in by("Entity")] + [(d["decided_at"], 1, d["decision_id"], d) for d in by("IdentityDecision")]
    for _, _, _, r in sorted(events, key=lambda x: x[:3]):
        if r["kind"] == "Entity":
            out.append(f"INSERT INTO ac.entities VALUES ({q(r['entity_id'])},{q(r['project_id'])},{q(r['entity_type'])},{q(r['identity'])},"
                       f"{q(r['status'])},{q(r.get('merged_into'))},{q(r.get('status_changed_at'))},{q(r['created_at'])},{q(r['marking'])},"
                       f"{q(r['display_name'])});")
        else:
            ids = r["entity_ids"] if r["decision"] == "DISTINCT" else [r["entity_id"], None]
            field = "place" if "place" in r else "disambiguator" if "disambiguator" in r else None
            out.append(f"INSERT INTO ac.identity_decisions VALUES ({q(r['decision_id'])},{q(r['project_id'])},{q(r['decision'])},"
                       f"{q(ids[0])},{q(ids[1])},{q(field)},{q(r.get(field) if field else None)},{q(r['decided_by'])},"
                       f"{q(r['decided_at'])},{q(r)});")
    # identity keys are derived by the database itself (RS-01); parity with the validator is checked after load
    for c in by("Claim"):
        tenant = P[c["project_id"]]["tenant_id"]
        out.append(f"INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body) VALUES "
                   f"({q(c['claim_id'])},{q(c['project_id'])},{q(tenant)},{q(c['subject'])},{q(c['predicate'])},{q(c['object'].get('entity'))},"
                   f"{q(c['produced_by']['kind'])},{q(c['recorded_at'])},{q(c['marking'])},{q(c)});")
    for r in by("ArtifactReceipt"):
        tenant = P[r["project_id"]]["tenant_id"]
        out.append(f"INSERT INTO ac.artifact_receipts VALUES ({q(r['receipt_id'])},{q(r['project_id'])},{q(tenant)},{q(r['key_id'])},"
                   f"{q(r['producer']['service_id'])},{q(r['issued_at'])},{q(r)});")
        for sid in r["input_source_ids"]:
            out.append(f"INSERT INTO ac.receipt_inputs VALUES ({q(r['receipt_id'])},{q(tenant)},{q(sid)});")
        for cid in r["emitted_claim_ids"]:
            out.append(f"INSERT INTO ac.receipt_claims VALUES ({q(r['receipt_id'])},{q(cid)});")
    for v in by("ClaimReview"):
        out.append(f"INSERT INTO ac.claim_reviews VALUES ({q(v['review_id'])},{q(v['claim_id'])},{q(v['status'])},{q(v['reviewer'])},"
                   f"{q(v['reviewed_at'])},{q(v['recorded_at'])});")
    for k in sorted(by("Check"), key=lambda k: k["as_of"]):
        tenant = P[k["project_id"]]["tenant_id"]
        out.append(f"INSERT INTO ac.checks VALUES ({q(k['check_id'])},{q(k['project_id'])},{q(k['subject_entity_id'])},{q(k['profile'])},"
                   f"{q(k['status'])},{q(k['requested_at'])},{q(k.get('completed_at'))},{q(k.get('cancelled_at'))},{q(k['as_of'])},"
                   f"{q(k.get('overall_risk'))},{q(k.get('previous_check_id'))},{q(k['marking'])},{q(k)});")
        for f in k["findings"]:
            out.append(f"INSERT INTO ac.check_findings VALUES ({q(k['check_id'])},{q(f['dimension'])},{q(f['result'])},{q(f['risk'])});")
        for f in k["findings"]:
            for cid in f["claim_ids"]:
                out.append(f"INSERT INTO ac.check_finding_claims VALUES ({q(k['project_id'])},{q(k['check_id'])},{q(f['dimension'])},{q(cid)});")
            for n, s in enumerate(f["searches"]):
                out.append(f"INSERT INTO ac.check_searches VALUES ({q(k['check_id'])},{q(f['dimension'])},{n},{q(s['performed_at'])},"
                           f"{q(tenant)},{q(s.get('result_source_id'))},{q(s)});")
    out.append("INSERT INTO ac.history_seals DEFAULT VALUES;  -- D13: imported history is sealed")
    out.append("COMMIT;")
    return "\n".join(out)


def register_originals(ds, content):
    """S6R-07: the loader must not declare an object 'stored and verified by reading it back' without ever
    touching a store. Every historical original goes through the same gateway a live write would use — a genuine
    write-verify-read-back cycle against a throwaway local store, each in its OWN short transaction, before the
    main historical-import transaction (which only references the now-really-registered addresses) begins."""
    import tempfile
    by_tenant = {}
    for s in ds["records"]:
        if s["kind"] != "Source":
            continue
        for o in s["observations"]:
            og = o.get("original")
            if og:
                by_tenant.setdefault(s["tenant_id"], {})[og["object"]] = (content[og["object"]], og["media_type"])
    if not by_tenant:
        return
    with tempfile.TemporaryDirectory() as tmp:
        store = ObjectStore(FsBackend(tmp))
        for tenant, objs in by_tenant.items():
            for addr, (data, media_type) in objs.items():
                reg = GW.register(store, tenant, data, media_type)
                assert reg["object"] == addr, f"адрес разошёлся при регистрации: {reg['object']} != {addr}"


def main():
    ds, trust, content = build()
    rep = VAL.validate(ds, trust, content)
    if rep.errors:
        sys.exit("REFUSED by validator: " + ",".join(rep.codes()))
    dups = [w for w in rep.warnings if w["code"] == "POSSIBLE_DUPLICATE"]
    if dups:  # RS-13: a skeleton collision needs an analyst decision (IdentityDecision) before loading
        sys.exit("REFUSED: POSSIBLE_DUPLICATE without an identity decision: " + "; ".join(w["ref"] for w in dups))
    ddl = psql(DDL_ALL)
    if ddl.returncode:
        sys.exit("DDL failed:\n" + ddl.stderr)
    register_originals(ds, content)
    r = psql(load_sql(ds, trust, content))
    if r.returncode:
        sys.exit("LOAD failed:\n" + r.stderr)
    counts = psql("SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (VALUES "
                  "('projects',(SELECT count(*) FROM ac.projects)),('sources',(SELECT count(*) FROM ac.sources)),"
                  "('entities',(SELECT count(*) FROM ac.entities)),('entity_keys',(SELECT count(*) FROM ac.entity_keys)),"
                  "('claims',(SELECT count(*) FROM ac.claims)),('evidence',(SELECT count(*) FROM ac.claim_evidence)),"
                  "('reviews',(SELECT count(*) FROM ac.claim_reviews)),('checks',(SELECT count(*) FROM ac.checks)),"
                  "('decisions',(SELECT count(*) FROM ac.identity_decisions)),('seals',(SELECT count(*) FROM ac.history_seals)),"
                  "('receipts',(SELECT count(*) FROM ac.artifact_receipts)),('artifacts',(SELECT count(*) FROM ac.artifacts)),"
                  "('artifact_nodes',(SELECT count(*) FROM ac.artifact_nodes))) v(t, n);").stdout.strip()
    print("LOAD: OK", counts)
    db = psql("SELECT project_id, entity_type, scheme, value, owner_entity_id, strength, coalesce(qual, '<null>') FROM ac.entity_keys;")
    db_rows = {tuple(ln.split(" | ")) for ln in db.stdout.strip().splitlines()}
    strong, weak, soft = entity_keys(ds)
    py_rows = {(p, t, sc, v, o, "STRONG", "<null>") for (p, t, sc, v, o) in strong} | \
              {(p, t, sc, v, o, "WEAK", "<null>" if ql is None else ql) for (p, t, sc, v, o, ql) in weak} | \
              {(p, t, sc, v, o, "SOFT", "<null>") for (p, t, sc, v, o) in soft}
    same = db_rows == py_rows
    print(f"KEYS PARITY (DB-derived == validator): {'OK' if same else 'MISMATCH'} rows={len(db_rows)}")
    if not same:
        for r in sorted(db_rows - py_rows):
            print("  only in DB:", r)
        for r in sorted(py_rows - db_rows):
            print("  only in validator:", r)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""S4: live ingestion of one TechSense run (as the application role ac_loader, no historical mode).

The order inside ONE transaction: source (+bytes, observation) -> publication (S5) -> artifact (bytes only; the database parses it) ->
new entities -> claims (evidence rows and graph-node checks by triggers) -> receipt (+inputs, +claims).
Deferred checks (receipt completeness, PIPELINE claim has a receipt, possible duplicates) run at COMMIT.
The normative path is: adapter -> validator over (world + new records) -> this SQL. ingest_sql() itself trusts nothing:
the database re-checks what it can (D8).
"""
import base64
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone

TAG = "$ac_q$"


def q(v):
    if v is None:
        return "NULL"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    v = str(v)
    assert TAG not in v
    return TAG + v + TAG


def utc(seconds_ago=0):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64(b):
    return f"decode({q(base64.b64encode(b).decode())},'base64')"


def ingest_sql(records, content, tenant="tnt_demo", artifacts=(), commit=True, user="ac_loader"):
    """records: Source / Entity / Claim / ArtifactReceipt (validator format); content: {address: bytes};
    artifacts: digests to insert (bytes from content)."""
    out = [f"SET SESSION AUTHORIZATION {user};", "BEGIN;"]
    for s in (r for r in records if r["kind"] == "Source"):
        body = {k: v for k, v in s.items() if k != "content_inline"}
        out.append(f"INSERT INTO ac.sources VALUES ({q(s['tenant_id'])},{q(s['source_id'])},{s['byte_length']},{q(s['marking'])},{q(body)});")
        b = content.get(s["source_id"]) or s["content_inline"].encode("utf-8")
        out.append(f"INSERT INTO ac.source_bytes VALUES ({q(s['tenant_id'])},{q(s['source_id'])},{b64(b)});")
        for o in s["observations"]:
            og = o.get("original")               # S5 part 2: the original must already be registered by the storage gateway
            out.append("INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by, original_object, "
                       f"original_media_type, original_length) VALUES ({q(s['tenant_id'])},{q(s['source_id'])},{q(o['observed_at'])},"
                       f"{q(o['origin_uri'])},{q(o['observed_by'])},{q(og['object'] if og else None)},{q(og['media_type'] if og else None)},"
                       f"{og['byte_length'] if og else 'NULL'});")
    for pb in (r for r in records if r["kind"] == "Publication"):
        out.append(f"INSERT INTO ac.publications (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) VALUES "
                   f"({q(pb['publication_id'])},{q(pb['tenant_id'])},{q(pb['outlet'])},{q(pb['canonical_url'])},{q(pb['text_digest'])},"
                   f"{q(pb['marking'])},{q(pb)});")
    for dg in artifacts:
        out.append(f"INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ({q(tenant)},{q(dg)},{b64(content[dg])});")
    for e in (r for r in records if r["kind"] == "Entity"):
        out.append(f"INSERT INTO ac.entities VALUES ({q(e['entity_id'])},{q(e['project_id'])},{q(e['entity_type'])},{q(e['identity'])},"
                   f"{q(e['status'])},{q(e.get('merged_into'))},{q(e.get('status_changed_at'))},{q(e['created_at'])},{q(e['marking'])},"
                   f"{q(e['display_name'])});")
    for c in (r for r in records if r["kind"] == "Claim"):
        out.append(f"INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body) VALUES "
                   f"({q(c['claim_id'])},{q(c['project_id'])},{q(tenant)},{q(c['subject'])},{q(c['predicate'])},{q(c['object'].get('entity'))},"
                   f"{q(c['produced_by']['kind'])},{q(c['recorded_at'])},{q(c['marking'])},{q(c)});")
    for r in (x for x in records if x["kind"] == "ArtifactReceipt"):
        out.append(f"INSERT INTO ac.artifact_receipts VALUES ({q(r['receipt_id'])},{q(r['project_id'])},{q(tenant)},{q(r['key_id'])},"
                   f"{q(r['producer']['service_id'])},{q(r['issued_at'])},{q(r)});")
        for sid in r["input_source_ids"]:
            out.append(f"INSERT INTO ac.receipt_inputs VALUES ({q(r['receipt_id'])},{q(tenant)},{q(sid)});")
        for cid in r["emitted_claim_ids"]:
            out.append(f"INSERT INTO ac.receipt_claims VALUES ({q(r['receipt_id'])},{q(cid)});")
    out.append("COMMIT;" if commit else "ROLLBACK;")
    return "\n".join(out)


def psql(sql):
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True,
                          env=dict(os.environ))

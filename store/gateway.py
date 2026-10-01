#!/usr/bin/env python3
"""Storage gateway (S5 part 2, D26): the only component that writes the registry of originals in the database.

  register(store, tenant, data, media_type)  put with write-verify, then ONE transaction as role ac_storage:
                                             the object row (if new) + a check row 'OK'. Returns the `original`
                                             block for an observation: {object, media_type, byte_length}.
  scrub(store, tenant=None)                  re-reads every registered object and appends the result
                                             (OK / MISSING / CORRUPT) to ac.object_checks, ONE row immediately
                                             after ITS OWN object is read (S6R-08) — not a batch at the end, so
                                             checked_at reflects that object's own read, and a failure partway
                                             through never discards results already recorded. A result that is
                                             not a confirmed absence (store.check raises) ABORTS the run without
                                             recording anything for that object (S6R-05): a store outage must
                                             never be journalled as "the original is lost" — that is irreversible.
                                             Never repairs, never deletes: recovery is an operator's restore from
                                             backup, the next scrub records it.
The gateway connects as the LOGIN role ac_gateway (a member of ac_storage, nothing else) — never as a superuser
session with SET SESSION AUTHORIZATION, which could be undone with a bare RESET from the same channel (S6R-06).
ac_storage itself stays NOLOGIN; ac_gateway is the only way to act as it, and it can do nothing else.
"""
import json
import os
import subprocess

from object_store import ObjectStore, valid_tenant  # noqa: F401  (ObjectStore: type of `store`)

TAG = "$gw$"


def _q(v):
    v = str(v)
    if TAG in v:
        raise ValueError(f"недопустимое значение для SQL-литерала: {v!r}")
    return TAG + v + TAG


def _check_tenant(tenant):
    if not valid_tenant(tenant):
        raise ValueError(f"недопустимый tenant: {tenant!r}")


def _psql(sql):
    env = dict(os.environ)
    env["PGUSER"] = "ac_gateway"                      # a real LOGIN role, member of ac_storage only — no SET SESSION AUTHORIZATION
    r = subprocess.run(["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1"], input=sql,
                       capture_output=True, text=True, env=env)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout


def register(store, tenant, data, media_type):
    _check_tenant(tenant)
    addr = store.put(tenant, data)                       # raises IntegrityError if the read-back differs
    _psql("BEGIN;\n"
          f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ({_q(tenant)}, {_q(addr)}, {len(data)}) "
          "ON CONFLICT (tenant_id, object_address) DO NOTHING;\n"
          f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ({_q(tenant)}, {_q(addr)}, 'OK');\nCOMMIT;")
    return {"object": addr, "media_type": media_type, "byte_length": len(data)}


def _objects_json(tenant=None):
    """One compact JSON object per line (S6R-09): tab-splitting a psql dump breaks the moment a tenant string (or
    anything else) contains a tab or newline — a single bad row then poisons every later scrub of the whole store.
    JSON keeps each row self-delimiting regardless of its content."""
    q = "SELECT json_build_object('tenant_id', tenant_id, 'object_address', object_address, 'byte_length', byte_length)::text " \
        "FROM ac.objects " + (f"WHERE tenant_id = {_q(tenant)} " if tenant else "") + "ORDER BY tenant_id, object_address;"
    return [json.loads(ln) for ln in _psql(q).splitlines() if ln]


def scrub(store, tenant=None):
    if tenant is not None:
        _check_tenant(tenant)
    stats = {"OK": 0, "MISSING": 0, "CORRUPT": 0}
    for row in _objects_json(tenant):
        t, addr, length = row["tenant_id"], row["object_address"], row["byte_length"]
        res = store.check(t, addr, length)                # propagates on anything that is not a confirmed absence
        stats[res] += 1
        _psql(f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ({_q(t)}, {_q(addr)}, '{res}');")
    return stats

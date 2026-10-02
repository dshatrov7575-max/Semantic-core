#!/usr/bin/env python3
"""S9 (cycle 9, D27.1): schema-as-data records (ClassDef / LinkDef / IdentifierDef, validator format) -> SQL.

schema_sql(records)      INSERTs in the order the database needs: by the time of the version, then classes before
                         the links and identifier types of the same second, then by id and version.
write_schema(records)    a live change of the schema through the role of the Model Constructor (ac_modeler):
                         the database stamps the time of each version itself.
The historical import (slice/load_s1.py) inserts the same statements as ac_migrator with ac.historical_import = on.
"""
import json
import os
import subprocess

TAG = "$ac_q$"
KINDS = {"ClassDef": ("ac.class_defs", "class_id"), "LinkDef": ("ac.link_defs", "link_id"),
         "IdentifierDef": ("ac.identifier_defs", "idef_id")}
_ORDER = ["ClassDef", "IdentifierDef", "LinkDef"]


def q(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    v = str(v)
    assert TAG not in v
    return TAG + v + TAG


def one_sql(r):
    """one version of a definition -> one INSERT (columns named: the tables have defaults for absent flags)"""
    table, idf = KINDS[r["kind"]]
    ch = r["change"]
    cols = {"tenant_id": r["tenant_id"], idf: r[idf], "version": r["version"], "name": r["name"],
            "deprecated": bool(r.get("deprecated")), "marking": r["marking"], "change_type": ch["type"],
            "description": ch["description"], "migration_note": ch.get("migration_note"),
            "recorded_at": ch["recorded_at"], "recorded_by": ch["recorded_by"]}
    if r["kind"] == "ClassDef":
        cols.update(root_type=r["root_type"], parent_class_id=r.get("parent_class_id"), is_abstract=bool(r.get("is_abstract")),
                    attributes=r.get("attributes", []))
    elif r["kind"] == "LinkDef":
        cols.update(predicate_id=r["predicate_id"], domain_class_id=r["domain_class_id"], range_class_id=r["range_class_id"],
                    cardinality=r["cardinality"], is_symmetric=bool(r.get("symmetric")))
    else:
        cols.update(scheme=r["scheme"], applies_to_root_type=r["applies_to_root_type"], strength=r["strength"],
                    priority=r["priority"], format=r.get("format"))
    return f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(q(v) for v in cols.values())});"


def schema_records(records):
    rs = [r for r in records if r["kind"] in KINDS]
    return sorted(rs, key=lambda r: (r["change"]["recorded_at"], _ORDER.index(r["kind"]), r[KINDS[r["kind"]][1]], r["version"]))


def schema_sql(records):
    return "\n".join(one_sql(r) for r in schema_records(records))


def write_schema(records, user="ac_modeler", commit=True):
    """live write: each definition version in ONE transaction under the Model Constructor's role"""
    sql = "\n".join([f"SET SESSION AUTHORIZATION {user};", "BEGIN;", schema_sql(records), "COMMIT;" if commit else "ROLLBACK;"])
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True,
                          env=dict(os.environ))

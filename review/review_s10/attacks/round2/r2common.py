import os, sys
os.environ.setdefault("S10_SNAP", "/home/claude/as/review/review_s10/snapshot2")
os.environ.setdefault("PGDATABASE", "review10_2a")
sys.path.insert(0, "/home/claude/as/review/review_s10/attacks")
from common import *
import time
def plain_source(text, kind="DOCUMENT"):
    b = text.encode("utf-8")
    return {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest(),
            "source_kind": kind, "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "рецензент: документ", "content_inline": text,
            "byte_length": len(b), "marking": PUB, "observations": [{"observed_at": utc(2), "origin_uri": "urn:review:s10:doc", "observed_by": "svc_dataset_loader"}]}
def body(records):
    """тело транзакции загрузчика без BEGIN/COMMIT и без SET SESSION AUTHORIZATION"""
    sql = ingest_sql(records, {}, commit=True)
    return "\n".join(l for l in sql.splitlines() if not l.startswith(("SET SESSION", "BEGIN", "COMMIT")))
def run_session(sql, user="ac_loader"):
    return subprocess.Popen(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), f"SET SESSION AUTHORIZATION {user};\n" + sql

"""Общая обвязка атак рецензента S10: работает ТОЛЬКО со снимком и базами review10_*."""
import os, sys, json, copy, hashlib, subprocess, base64
from pathlib import Path
SNAP = Path(os.environ.get("S10_SNAP", "/home/claude/as/review/review_s10/snapshot"))
for p in ("slice", "core", "store"):
    sys.path.insert(0, str(SNAP / p))
os.environ.setdefault("PGHOST", "/home/claude/pg_ac"); os.environ.setdefault("PGPORT", "5436"); os.environ.setdefault("PGUSER", "postgres")
os.environ.setdefault("PGDATABASE", "review10_a")
assert os.environ["PGDATABASE"].startswith("review10_"), "только базы review10_*"
import validator as VAL
from jcs import canon, digest
from vectors import build, VECTORS
from fixtures import REGISTRY_ROWS, REGISTRY_COLUMNS, OGRN_DEV, OGRN_TRUB, INN_DEV, INN_TRUB, demo_registry
from dataset import DatasetVersion, cell_salt, audit_path
from ingest_s4 import ingest_sql, utc
import s3_tests as S3
import dataset_s10 as D

T, PRJ = "tnt_demo", "prj_compliance"
PUB = {"level": "PUBLIC", "categories": []}
CONF_CS = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}

def psql(sql, user=None, db=None):
    env = dict(os.environ)
    if db: env["PGDATABASE"] = db
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True, env=env)

def first_err(r):
    return next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), "(принято)").replace("psql:<stdin>:", "")

def verdict(r):
    return "ПРИНЯТО" if r.returncode == 0 else "ОТКАЗ: " + first_err(r)[:170]

def source_rec(dv, title="рецензент", marking=PUB, observed=None):
    return {"kind": "Source", "schema_version": "core-ontology/0.4", "tenant_id": dv.manifest["tenant_id"], "source_id": dv.source_id,
            "source_kind": "DATASET_VERSION", "media_type": "application/vnd.ac.dataset-manifest+json", "language": "ru", "title": title,
            "byte_length": len(dv.manifest_bytes), "content_inline": dv.manifest_bytes.decode("utf-8"), "marking": marking,
            "observations": [{"observed_at": observed or utc(2), "origin_uri": "urn:review:s10", "observed_by": "svc_dataset_loader"}]}

def relabel(dv, label):
    dv.manifest["version_label"] = label
    dv.manifest_bytes = canon(dv.manifest).encode("utf-8")
    dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
    return dv

def mk_claim(ev, subj="ent_k_developer", predicate="entity.registered_address", obj=None, marking=CONF_CS, recorded=None, **extra):
    c = {"kind": "Claim", "schema_version": "core-ontology/0.4", "project_id": PRJ, "subject": subj, "predicate": predicate,
         "object": obj or {"literal": {"type": "STRING", "value": REGISTRY_ROWS[0]["address"]}},
         "evidence": ev if isinstance(ev, list) else [ev], "produced_by": {"kind": "HUMAN", "actor_id": "usr_bank_officer"},
         "recorded_at": recorded or utc(0), "marking": marking}
    c.update(extra)
    c["claim_id"] = "clm:sha256:" + digest(c)
    return c

_WORLD = None
def world():
    global _WORLD
    if _WORLD is None:
        _WORLD = build()
    ds, tr, ct = _WORLD
    return copy.deepcopy(ds), tr, dict(ct)

def validate_with(records, content=None):
    """валидатор над (мир fixtures + новые записи)"""
    ds, tr, ct = world()
    ds["records"] = ds["records"] + [copy.deepcopy(r) for r in records]
    if content: ct.update(content)
    rep = VAL.validate(ds, tr, ct)
    return rep

def py_verdict(rep):
    return "ПРИНЯТО" if not rep.errors else "ОТКАЗ: " + ",".join(rep.codes()) + " | " + rep.errors[0]["msg"][:110]

def db_try(records, content=None, user="ac_loader", commit=False):
    sql = ingest_sql(records, content or {}, commit=commit, user=user)
    if not commit:
        sql = sql[:sql.rindex("ROLLBACK;")] + "SET CONSTRAINTS ALL IMMEDIATE;\nROLLBACK;"
    return psql(sql)

_REGISTERED = set()
def both(tag, desc, records, content=None, expect=None, quiet=False):
    """Источники (версии наборов) регистрируются загрузчиком и фиксируются (живое время наблюдения ставит база), затем через 1,1 с
    остальные записи идут в базу одной транзакцией с откатом. Валидатор получает мир fixtures + все записи.
    expect: 'accept' | 'refuse' | None; возвращает (py_ok, db_ok)"""
    import time
    srcs = [r for r in records if r["kind"] == "Source"]
    rest = [r for r in records if r["kind"] != "Source"]
    r = None
    fresh = [x for x in srcs if x["source_id"] not in _REGISTERED]
    if fresh:
        r = db_try(fresh, content, commit=True)
        if r.returncode == 0:
            _REGISTERED.update(x["source_id"] for x in fresh)
            time.sleep(1.1)
    if rest and (r is None or r.returncode == 0):
        for c in rest:                       # время записи — «сейчас» (окно системного времени базы)
            if c["kind"] == "Claim":
                c["recorded_at"] = utc(0); c["claim_id"] = "clm:sha256:" + digest({k: v for k, v in c.items() if k != "claim_id"})
        r = db_try(rest, content)
    rep = validate_with(records, content)
    py_ok, db_ok = not rep.errors, r.returncode == 0
    flag = ""
    if py_ok != db_ok: flag = "  <<< РАСХОЖДЕНИЕ валидатор/база"
    elif expect == "refuse" and py_ok: flag = "  <<< ПРИНЯТО ОБОИМИ (ожидался отказ)"
    elif expect == "accept" and not py_ok: flag = "  <<< отвергнуто обоими (ожидалось принятие)"
    if not quiet or flag:
        print(f"{tag:<7}{desc}\n        валидатор: {py_verdict(rep)}\n        база:      {verdict(r)}{flag}", flush=True)
    return py_ok, db_ok

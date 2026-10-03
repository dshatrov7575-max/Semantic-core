"""общая обвязка: мир автора + подмена набора s30 / утверждения c50"""
import sys, os, copy, json, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "core"))
from jcs import canon
import validator as VAL
from validator import validate, cell_leaf, cell_salt, merkle_root, row_leaf, inclusion_root, parse_manifest, row_evidence_error
from dataset import DatasetVersion, row_secret, row_hash, audit_path
import fixtures as FX
from fixtures import world, finalize, demo_registry, REGISTRY_COLUMNS, REGISTRY_ROWS, DEMO_DATASET_KEY, T, PUB, INT, CONF_PD, CONF_CS, OGRN_DEV, INN_DEV, OGRN_TRUB, INN_TRUB

def run(pre=None, post=None):
    W = world()
    if pre: pre(W)
    ds, ix, trust, content = finalize(W)
    if post: post(ds, ix, content)
    R = validate(ds, trust, content)
    return R, ds, ix, content

def show(tag, R):
    errs = [(e["code"], e["msg"][:110]) for e in R.errors]
    warns = [w["code"] for w in R.warnings]
    print(f"{tag}: {'ПРИНЯТО' if not R.errors else 'ОТКАЗ'} errors={errs} warnings={warns}")

def set_ds(W, dv, nofiles=False):
    if nofiles: dv.files = []
    W["__datasets__"]["s30"] = dv
    W["s30"]["content_inline"] = dv.manifest_bytes.decode("utf-8")

# ---------------- PostgreSQL (база rev_row) ----------------
os.environ.setdefault("PGHOST", "/home/claude/pg_ac"); os.environ.setdefault("PGPORT", "5436")
os.environ.setdefault("PGUSER", "postgres"); os.environ["PGDATABASE"] = "rev_row"
sys.path.insert(0, os.path.join(HERE, "..", "slice")); sys.path.insert(0, os.path.join(HERE, "..", "store"))

def db_load(ds, trust, content):
    """свежая схема + мир целиком, БЕЗ валидатора впереди (как S10-PARITY автора) -> None или первая ошибка"""
    import load_s1 as L
    r = L.psql(L.DDL_ALL)
    assert r.returncode == 0, r.stderr[:500]
    L.register_originals(ds, content)
    r = L.psql(L.load_sql(ds, trust, content))
    if r.returncode == 0:
        import s3_tests as S3
        L.psql(S3.SETUP)          # читатели ac_rd_full / ac_rd_cs / ac_rd_public автора
    return None if r.returncode == 0 else next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr.strip())[:260]

def psql(sql, user=None):
    import subprocess
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "ERR " + next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr.strip())[:300]

def dossier_rows(entity="ent_k_developer", user="ac_rd_cs", prj="prj_compliance"):
    out = psql(f"SELECT ac.dossier('{prj}', '{entity}', now());", user)
    if out.startswith("ERR"):
        return out
    d = json.loads(out.splitlines()[-1])
    return [e for sec in (d.get("sections") or d.get("dimensions") or []) for f in sec.get("facts", [])
            for c in f.get("claims", []) + f.get("other_claims", []) for e in c["evidence"] if e.get("source_kind") == "DATASET_VERSION"]

def db_load_rows(dv, tenant=T):
    """загрузчик: open -> COPY -> seal строк версии dv; -> None или ошибка"""
    import dataset_s10 as D, s10_tests as S10
    t, bad = D.load_rows(tenant, dv.source_id, S10.copy_file(dv), dv.columns)
    return None if bad is None else next((ln for ln in bad.stderr.splitlines() if "ERROR" in ln), bad.stderr.strip())[:260]

"""Общая обвязка скриптов рецензента (цикл 11). Работает только со снимком и базами review11_*."""
import json, os, subprocess, sys, time, threading
from pathlib import Path
SNAP = Path("/home/claude/as/review/review_s11/snapshot")
for d in ("slice", "core", "store"):
    sys.path.insert(0, str(SNAP / d))
os.environ.setdefault("PGHOST", "/home/claude/pg_ac"); os.environ.setdefault("PGPORT", "5436"); os.environ.setdefault("PGUSER", "postgres")
assert os.environ.get("PGDATABASE", "").startswith("review11_"), "PGDATABASE должен быть review11_*"
import validator as VAL            # noqa: E402
from vectors import build          # noqa: E402
from fixtures import REGISTRY_ROWS, REGISTRY_COLUMNS, OGRN_DEV, INN_DEV, demo_registry   # noqa: E402
from ingest_s4 import ingest_sql, utc   # noqa: E402
import s3_tests as S3              # noqa: E402
import dataset_s10 as D            # noqa: E402
from s10_tests import claim, copy_file, new_version, first_err, T, PRJ   # noqa: E402
from s11_tests import org, key, CONF_CS, CONF_PD   # noqa: E402
from jcs import canon, digest      # noqa: E402

FOUND = []


def psql(sql, user=None):
    return S3.psql(sql, user)


def one(sql, user=None):
    r = psql(sql, user)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def fresh(load_rows=True):
    """чистый мир снимка в текущей базе + читатели + строки демонстрационного реестра"""
    r = subprocess.run([sys.executable, str(SNAP / "slice" / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    assert psql(S3.SETUP).returncode == 0
    dv = demo_registry()
    if load_rows:
        _, bad = D.load_rows(T, dv.source_id, copy_file(dv), dv.columns)
        assert bad is None, first_err(bad)
    return dv


def report(fid, is_finding, text):
    FOUND.append(is_finding)
    print(f"{fid:<8} {'НАХОДКА' if is_finding else 'устояло'} | {text}", flush=True)


def body_of(records, **kw):
    lines = ingest_sql(records, {}, **kw).splitlines()
    return "\n".join(ln for ln in lines if not ln.startswith(("SET SESSION", "BEGIN", "COMMIT", "ROLLBACK")))


def bg(sql, user=None, out=None):
    """оператор в отдельном сеансе (поток); результат psql кладётся в out[0]"""
    out = out if out is not None else []
    th = threading.Thread(target=lambda: out.append(psql(sql, user)))
    th.start()
    return th, out


def iso(ts):
    """timestamptz базы (текст) -> запись времени онтологии, секунды вверх не округляются"""
    return one(f"SELECT to_char('{ts}'::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")

"""Common harness for the S2.2/S3 re-review attacks.
Env: PGDATABASE (empty scratch db), SLICE (path to the slice dir under review; core/ must be its sibling),
PGHOST/PGPORT/PGUSER (defaults: /home/claude/pg_ac, 5436, postgres).
The superuser is used ONLY to (re)load the reference world and to create reader roles/clearances the way
slice/s3_tests.py does; every attack statement runs under SET SESSION AUTHORIZATION <live role>.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("PGHOST", "/home/claude/pg_ac")
os.environ.setdefault("PGPORT", "5436")
os.environ.setdefault("PGUSER", "postgres")
SLICE = Path(os.environ.get("SLICE", "/home/claude/s23/slice")).resolve()
CORE = SLICE.parent / "core"
if "PGDATABASE" not in os.environ:
    sys.exit("set PGDATABASE to an empty scratch database")

READERS = """
DO $$ BEGIN CREATE ROLE ac_rd_full LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_public LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_cs LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_rd_none LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories) VALUES
 ('ac_rd_full', 'prj_dossier', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}'),
 ('ac_rd_full', 'prj_compliance', 'CONFIDENTIAL', '{PERSONAL_DATA,COMMERCIAL_SECRET}'),
 ('ac_rd_full', 'prj_wiki_whales', 'PUBLIC', '{}'),
 ('ac_rd_public', 'prj_dossier', 'PUBLIC', '{}'),
 ('ac_rd_public', 'prj_wiki_whales', 'PUBLIC', '{}'),
 ('ac_rd_cs', 'prj_compliance', 'CONFIDENTIAL', '{COMMERCIAL_SECRET}');
RESET ROLE;
"""


def psql(sql, user=None, db=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    env = dict(os.environ)
    if db:
        env["PGDATABASE"] = db
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql,
                          capture_output=True, text=True, env=env)


def ok(sql, user=None):
    r = psql(sql, user)
    if r.returncode:
        raise RuntimeError(f"[{user}] {r.stderr.strip()}")
    return r.stdout.strip()


def err(sql, user=None):
    r = psql(sql, user)
    return (r.stderr.strip().splitlines() or ["?"])[0] if r.returncode else "(выполнено)"


def js(sql, user):
    return json.loads(ok(sql, user).splitlines()[-1])


def reload(readers=True):
    r = subprocess.run([sys.executable, str(SLICE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    if readers:
        ok(READERS)


def verdict(aid, finding, text):
    print(f"{aid}: {'FINDING' if finding else 'held'} | {text}", flush=True)
    return finding

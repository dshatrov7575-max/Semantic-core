#!/usr/bin/env python3
"""S6 review, part 2: more attacks on the registry (savepoints / SET CONSTRAINTS, loader visibility, SET ROLE audit).
Usage: PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=review06x python3 db_attacks2.py"""
import hashlib, os, subprocess
assert os.environ.get("PGDATABASE", "").startswith("review06")
def psql(sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)
def show(name, r):
    print(f"  {name}: rc={r.returncode} out={r.stdout.strip()[:120]!r} err={(r.stderr.strip().splitlines() or [''])[0][:110]}")
A = lambda t: "sha256:" + hashlib.sha256(t.encode()).hexdigest()
O = lambda a, n=5: f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('tnt_demo','{a}',{n});\n"
K = lambda a, r="OK": f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo','{a}','{r}');\n"

print("== C1: object registered WITHOUT a surviving OK check: fire the deferred trigger early, then roll the check back")
a = A("c1")
show("savepoint + SET CONSTRAINTS IMMEDIATE + ROLLBACK TO", psql("\\set ON_ERROR_STOP 1\nBEGIN;\n" + O(a) + "SAVEPOINT s;\n" + K(a) +
     "SET CONSTRAINTS ALL IMMEDIATE;\nROLLBACK TO s;\nCOMMIT;\n" +
     f"SELECT 'objects=' || (SELECT count(*) FROM ac.objects WHERE object_address='{a}') || ' checks=' || (SELECT count(*) FROM ac.object_checks WHERE object_address='{a}');", "ac_storage"))
a = A("c1b")
show("SET CONSTRAINTS IMMEDIATE inside savepoint, release, no rollback of object", psql("BEGIN;\nSAVEPOINT s0;\n" + O(a) + "SAVEPOINT s;\n" + K(a) +
     "SET CONSTRAINTS ac.object_verified IMMEDIATE;\nSET CONSTRAINTS ac.object_verified DEFERRED;\nROLLBACK TO s;\nRELEASE s0;\nCOMMIT;\n" +
     f"SELECT 'objects=' || (SELECT count(*) FROM ac.objects WHERE object_address='{a}') || ' checks=' || (SELECT count(*) FROM ac.object_checks WHERE object_address='{a}');", "ac_storage"))
a = A("c1c")
show("OK then CORRUPT in the registering transaction (latest is CORRUPT)", psql("BEGIN;\n" + O(a) + K(a) + K(a, "CORRUPT") + "COMMIT;\n" +
     f"SELECT ac.object_status_at('tnt_demo','{a}',clock_timestamp());", "ac_storage"))

print("== C2: who is recorded as the actor (session_user) under SET ROLE vs SET SESSION AUTHORIZATION")
a = A("c2")
show("SET ROLE ac_storage by postgres", psql("SET ROLE ac_storage;\nBEGIN;\n" + O(a) + K(a) + "COMMIT;\n" + f"SELECT stored_by FROM ac.objects WHERE object_address='{a}';"))
print("== C3: what the application role can read from the registry (all tenants)")
show("ac_loader reads registry of every tenant", psql("SELECT count(*), count(DISTINCT tenant_id) FROM ac.objects;", "ac_loader"))
show("ac_loader tries SET ROLE ac_storage", psql("SET ROLE ac_storage;", "ac_loader"))
show("ac_migrator tries SET ROLE ac_storage", psql("SET ROLE ac_storage;", "ac_migrator"))
show("ac_loader observation UPDATE original", psql("UPDATE ac.source_observations SET original_object = NULL;", "ac_loader"))
show("ac_migrator historical: observation with original, observed in 2026-09 but object stored today",
     psql("BEGIN;\nSET LOCAL ac.historical_import='on';\nSELECT 1;\nROLLBACK;", "ac_migrator"))
print("== C4: observation naming an object with wrong length 0 / NULL parts")
src = psql("SELECT source_id FROM ac.sources LIMIT 1").stdout.strip()
obj = psql("SELECT object_address FROM ac.objects WHERE tenant_id='tnt_demo' ORDER BY stored_at LIMIT 1").stdout.strip()
for name, cols in (("object without length", f"'{obj}','text/html',NULL"), ("length without object", "NULL,NULL,679"),
                   ("type only", "NULL,'text/html',NULL"), ("negative length", f"'{obj}','text/html',-1")):
    show(name, psql("BEGIN;\nINSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by, original_object, original_media_type, original_length) "
                    f"VALUES ('tnt_demo','{src}', now(), 'https://c4.example/{name.replace(' ', '_')}', 'svc_x', {cols});\nROLLBACK;", "ac_loader"))

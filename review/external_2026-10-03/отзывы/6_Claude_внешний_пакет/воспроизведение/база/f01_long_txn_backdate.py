#!/usr/bin/env python3
"""F01: «окно 5 минут» отсчитывается от НАЧАЛА транзакции (now()), а не от фиксации.
Транзакция ac_app, открытая дольше 5 минут, фиксирует утверждение с recorded_at в прошлом,
и НЕ предварительный ответ ac.dossier(as_of) на прошлый момент меняется (digest другой).
Usage: python3 f01_long_txn_backdate.py [wait_seconds=310]"""
import subprocess, sys, time, json, os
WAIT = int(sys.argv[1]) if len(sys.argv) > 1 else 310
ENV = dict(os.environ)
CID = "clm:sha256:" + ("%064x" % int(time.time()))

def psql(sql, user):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-U", user, "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True, env=ENV)
    return (r.stdout + r.stderr).strip()

a = subprocess.Popen(["psql", "-X", "-q", "-At", "-U", "ac_app"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV)
a.stdin.write("BEGIN;\nSELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), current_setting('transaction_isolation');\n"); a.stdin.flush()
t0 = a.stdout.readline().strip().split("|")[0]
print("A (ac_app): BEGIN, now() =", t0)
print(f"... транзакция A открыта и простаивает {WAIT} c")
time.sleep(WAIT)
Q = f"SELECT ac.dossier('prj_dossier', 'ent_d_lomov', '{t0}'::timestamptz);"
def show(tag):
    j = json.loads(psql(Q, "ac_rd_full"))
    ident = [f["text"] for s in j["sections"] if s["section"] == "IDENTITY" for f in s.get("facts", [])]
    notes = [f.get("note") for s in j["sections"] if s["section"] == "IDENTITY" for f in s.get("facts", [])]
    print(f"{tag}: as_of={j['as_of']} provisional={j.get('provisional')} digest={j['digest'][:23]}… IDENTITY={ident} note={notes}")
    return j
print("clock:", psql("SELECT clock_timestamp()", "ac_rd_full"))
j1 = show("R1 (до фиксации A)   ")
a.stdin.write(f"""
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT c.b->>'claim_id', c.project_id, c.tenant_id, c.subject, c.predicate, c.object_entity, c.produced_kind, (c.b->>'recorded_at')::timestamptz, c.marking, c.b
FROM (SELECT c0.*, jsonb_set(c0.body || jsonb_build_object('claim_id', '{CID}', 'recorded_at',
        to_char((now() - interval '4 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')), '{{object,literal,value}}', '"1999-09-09"') AS b
      FROM ac.claims c0 WHERE predicate='person.birth_date' AND subject='ent_d_lomov' ORDER BY claim_id LIMIT 1) c;
COMMIT;
SELECT 'A: зафиксировано; recorded_at=' || recorded_at || ' ingested_at=' || ingested_at || ' commit≈' || clock_timestamp()
       || ' (recorded_at раньше фиксации на ' || (clock_timestamp() - recorded_at) || ')' FROM ac.claims WHERE claim_id = '{CID}';
""")
a.stdin.close(); print(a.stdout.read().strip()); a.wait()
j2 = show("R2 (после фиксации A)")
ok = j1["digest"] != j2["digest"] and j1.get("provisional") is None and j2.get("provisional") is None
print("ИТОГ:", "ВОСПРОИЗВЕДЕНО — не предварительный ответ на прошлый момент изменился" if ok else
      ("ответ изменился, но был помечен provisional (ожидание короче 5 минут)" if j1["digest"] != j2["digest"] else "не воспроизведено"))

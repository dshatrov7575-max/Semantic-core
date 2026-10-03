#!/usr/bin/env python3
"""F03: массовая запись одной транзакцией. Каждая сущность/утверждение берёт advisory-блокировки уровня транзакции,
они копятся до COMMIT в общей таблице блокировок (max_locks_per_transaction=64 * max_connections=100).
Запускать ТОЛЬКО на отдельном кластере (исчерпание таблицы блокировок бьёт по всем базам кластера).
Usage: PGHOST=/home/claude/rev_pg PGPORT=5438 PGDATABASE=rev2 python3 f03_bulk_lock_exhaustion.py N [N ...]"""
import subprocess, sys, os, time, re
ENV = dict(os.environ)
def psql(sql, user="ac_app"):
    t = time.time()
    r = subprocess.run(["psql", "-X", "-q", "-At", "-U", user], input=sql, capture_output=True, text=True, env=ENV)
    return (r.stdout + r.stderr).strip(), time.time() - t
print("настройки:", psql("SELECT 'max_locks_per_transaction=' || current_setting('max_locks_per_transaction') || ' max_connections=' || current_setting('max_connections') || ' max_prepared_transactions=' || current_setting('max_prepared_transactions')")[0])
for n in [int(x) for x in sys.argv[1:]] or [1000]:
    tag = "b%d_%d" % (n, int(time.time()) % 100000)
    sql = f"""
\\timing on
BEGIN;
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name)
SELECT 'ent_{tag}_' || g, 'prj_wiki_whales', 'CONCEPT', jsonb_build_object('lang', 'ru', 'label', 'bulk {tag} item ' || g, 'namespace', 'bulk'),
       'ACTIVE', now(), '{{"level": "PUBLIC", "categories": []}}', 'bulk ' || g FROM generate_series(1, {n}) g;
SELECT 'locks after entities: ' || count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid();
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT b->>'claim_id', c.project_id, c.tenant_id, b->>'subject', c.predicate, NULL, c.produced_kind, (b->>'recorded_at')::timestamptz, c.marking, b
FROM (SELECT * FROM ac.claims WHERE predicate = 'wiki.property' ORDER BY claim_id LIMIT 1) c, generate_series(1, {n}) g,
     LATERAL (SELECT c.body || jsonb_build_object('claim_id', 'clm:sha256:' || encode(sha256(convert_to('{tag}' || g, 'UTF8')), 'hex'),
                     'subject', 'ent_{tag}_' || g, 'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS b) x;
SELECT 'locks after claims: ' || count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid();
COMMIT;
SELECT 'committed entities: ' || count(*) FROM ac.entities WHERE entity_id LIKE 'ent_{tag}_%';
SELECT 'committed claims: ' || count(*) FROM ac.claims WHERE subject LIKE 'ent_{tag}_%';
"""
    out, dt = psql(sql)
    lines = [l for l in out.splitlines() if l.strip()]
    print(f"\n=== N = {n} (одна транзакция ac_app: {n} сущностей + {n} утверждений), всего {dt:.1f} c")
    for l in lines:
        print("  ", l[:300])
    times = [float(m) for m in re.findall(r"Time: ([0-9.]+) ms", out)]
    if len(times) >= 4 and "committed claims: %d" % n in out:
        print(f"   => на 1 сущность {times[1]/n:.2f} мс, на 1 утверждение {times[3]/n:.2f} мс")

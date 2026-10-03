#!/usr/bin/env python3
"""S10R раунд 2 / отложенные проверки ac.dataset_refs_check: гонки двух транзакций (READ COMMITTED и REPEATABLE READ), SET CONSTRAINTS,
порядок внутри транзакции, исторический импорт, предикаты колонок."""
from r2common import *
import threading
stamp = utc(0)
def state(v, doc):
    return psql(f"SELECT 'версия в каталоге: ' || (SELECT count(*) FROM ac.datasets WHERE source_id = '{v.source_id}') || ', её previous — источник вида ' || "
                f"coalesce((SELECT body->>'source_kind' FROM ac.sources WHERE source_id = '{doc['source_id']}'), '(нет)') || ', версий-набора с этим адресом: ' || "
                f"(SELECT count(*) FROM ac.datasets WHERE source_id = '{doc['source_id']}')").stdout.strip()
def race(tag, iso, first):
    """две транзакции: A пишет версию (previous = P), B пишет документ P. first — кто начинает и держит транзакцию 3 с."""
    doc = plain_source(f"Документ-гонка {tag} {stamp}")
    v = relabel(demo_registry(previous=doc["source_id"]), f"rev-b1 {tag} {stamp}")
    A, B = body([source_rec(v)]), body([doc])
    slow, fast = (A, B) if first == "A" else (B, A)
    begin = f"BEGIN ISOLATION LEVEL {iso};\n"
    res = {}
    def go(name, sql):
        r = psql(sql, "ac_loader"); res[name] = verdict(r)[:110]
    t1 = threading.Thread(target=go, args=("медленная", begin + slow + "\nSELECT pg_sleep(3);\nCOMMIT;"))
    t2 = threading.Thread(target=go, args=("быстрая", begin + fast + "\nCOMMIT;"))
    t1.start(); time.sleep(1); t2.start(); t1.join(); t2.join()
    both_in = psql(f"SELECT (SELECT count(*) FROM ac.datasets WHERE source_id = '{v.source_id}') + (SELECT count(*) FROM ac.sources WHERE source_id = '{doc['source_id']}')").stdout.strip() == "2"
    print(f"{tag}: {iso}; первой начала и 3 с держит транзакцию {'версия' if first == 'A' else 'документ'}\n     медленная: {res['медленная']}\n     быстрая:   {res['быстрая']}\n     итог: {state(v, doc)}"
          f"{'   <<< ОБЕ ЗАФИКСИРОВАНЫ: в базе состояние, которое валидатор отвергает' if both_in else ''}")
    if both_in:
        print("     валидатор на том же наборе записей:", py_verdict(validate_with([doc, source_rec(v)]))[:120])
    return both_in
print("== 1. Гонка двух транзакций")
out = [race("G1", "READ COMMITTED", "A"), race("G2", "READ COMMITTED", "B"), race("G3", "REPEATABLE READ", "A"), race("G4", "REPEATABLE READ", "B"),
       race("G5", "SERIALIZABLE", "A"), race("G6", "SERIALIZABLE", "B")]
print("   прошло гонок с несогласованным итогом:", sum(out), "из", len(out))

print("== 2. SET CONSTRAINTS внутри одной транзакции")
for tag, order in [("S1", "версия, затем документ"), ("S2", "документ, затем версия")]:
    doc = plain_source(f"Документ {tag} {stamp}"); v = relabel(demo_registry(previous=doc["source_id"]), f"rev-b1 {tag} {stamp}")
    parts = [body([source_rec(v)]), body([doc])] if tag == "S1" else [body([doc]), body([source_rec(v)])]
    for mode in ("SET CONSTRAINTS ALL IMMEDIATE;", "SET CONSTRAINTS ALL DEFERRED;", ""):
        sql = "BEGIN;\n" + mode + "\n" + parts[0] + "\n" + ("SET CONSTRAINTS ALL IMMEDIATE;\nSET CONSTRAINTS ALL DEFERRED;\n" if mode == "" else "") + parts[1] + "\nCOMMIT;"
        print(f"   {tag} ({order}), режим «{mode or 'IMMEDIATE→DEFERRED между записями'}»:", verdict(psql(sql, "ac_loader"))[:110])
print("== 3. Точка сохранения: проверка в отменённой подтранзакции не «съедает» отложенную")
doc = plain_source(f"Документ SP {stamp}"); v = relabel(demo_registry(previous=doc["source_id"]), f"rev-b1 SP {stamp}")
sql = "BEGIN;\n" + body([source_rec(v)]) + "\nSAVEPOINT a;\nSET CONSTRAINTS ALL IMMEDIATE;\nROLLBACK TO a;\n" + body([doc]) + "\nCOMMIT;"
print("   ", verdict(psql(sql, "ac_loader"))[:110])
print("== 4. Предикат колонки: схема tenant, объявленная ПОЗЖЕ получения версии (живой путь) и вовсе не объявленная")
for pid, why in [("x.max_length", "объявлен в схеме tenant 2026-09-02, версия получена сейчас"), ("x.never_declared", "нигде не объявлен"), ("entity.registered_address", "реестр ядра")]:
    cols = copy.deepcopy(REGISTRY_COLUMNS); cols[2]["predicate"] = pid
    v = relabel(demo_registry(columns=cols), f"rev-b1 P {pid} {stamp}")
    r = db_try([source_rec(v)], commit=False)
    print(f"   {pid} ({why}): валидатор — {py_verdict(validate_with([source_rec(v)]))[:60]} | база — {verdict(r)[:100]}")
print("== 5. Версия без наблюдения в той же транзакции (наблюдение — отдельной транзакцией позже): предикат схемы tenant")
cols = copy.deepcopy(REGISTRY_COLUMNS); cols[2]["predicate"] = "x.max_length"
v = relabel(demo_registry(columns=cols), f"rev-b1 noobs {stamp}")
sql = "BEGIN;\n" + "\n".join(l for l in body([source_rec(v)]).splitlines() if "source_observations" not in l) + "\nCOMMIT;"
print("   источник + манифест без наблюдения:", verdict(psql(sql, "ac_loader"))[:140])
cols[2]["predicate"] = "entity.registered_address"; v = relabel(demo_registry(columns=cols), f"rev-b1 noobs2 {stamp}")
sql = "BEGIN;\n" + "\n".join(l for l in body([source_rec(v)]).splitlines() if "source_observations" not in l) + "\nCOMMIT;"
print("   то же с предикатом реестра:", verdict(psql(sql, "ac_loader"))[:140], "| валидатор требует наблюдение (minItems 1):",
      py_verdict(validate_with([dict(source_rec(v), observations=[])]))[:60])

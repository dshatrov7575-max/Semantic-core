#!/usr/bin/env python3
"""S10R / направление 4: маркировки и допуск — оракулы «есть/нет», тексты ошибок, прямой доступ."""
from common import *
from s10_tests import copy_file
import time
stamp = utc(0)
CONF_PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
dv = relabel(demo_registry(), "rev-a4 " + stamp)
r = db_try([source_rec(dv, marking=CONF_PD)], commit=True); assert r.returncode == 0, first_err(r)
t, bad = D.load_rows(T, dv.source_id, copy_file(dv), dv.columns); assert bad is None, first_err(bad)
ghost = "src:sha256:" + "ab" * 32
key = f"'[\"{OGRN_DEV}\"]'"
print("== M1. Оракул существования версии набора (маркировка источника CONFIDENTIAL+PERSONAL_DATA)")
print("   образец проекта (досье): читатель без допуска, сущность есть / сущности нет:")
for eid in ("ent_k_developer", "ent_no_such_entity"):
    print(f"      ac.dossier({eid}) ->", first_err(psql(f"SELECT ac.dossier('{PRJ}', '{eid}');", "ac_rd_none"))[:80])
for who, why in [("ac_rd_none", "нет допуска в проекте"), ("ac_rd_cs", "допуск CONFIDENTIAL/COMMERCIAL_SECRET, без PERSONAL_DATA")]:
    for fn, call in [("dataset_row", "ac.dataset_row('{p}', '{sid}', {k})"), ("dataset_evidence", "ac.dataset_evidence('{p}', '{sid}', {k}, ARRAY['address'])")]:
        a = first_err(psql("SELECT " + call.format(p=PRJ, sid=dv.source_id, k=key) + ";", who))
        b = first_err(psql("SELECT " + call.format(p=PRJ, sid=ghost, k=key) + ";", who))
        print(f"   {who} ({why}), {fn}:\n      версия есть -> {a[:90]}\n      версии нет  -> {b[:90]}\n      {'<<< ОРАКУЛ: ответы различимы' if a != b else 'ответы одинаковы'}")
print("== M2. Оракул «загружена ли и запечатана ли версия» для читателя с допуском к источнику, но без допуска к ключу — нет: ключ проверяется раньше")
print("== M3. Поиск по идентификатору: читатель без PERSONAL_DATA и версия с маркировкой источника PD")
r = psql(f"SELECT ac.dataset_find('{PRJ}', 'ru.inn', '{INN_DEV}');", "ac_rd_cs")
hits = json.loads(r.stdout)["hits"] if r.returncode == 0 else first_err(r)
print("   попаданий в версии rev-a4 (должно быть 0):", sum(1 for h in hits if h["source_id"] == dv.source_id) if isinstance(hits, list) else hits)
print("== M4. Прямой доступ читателя")
for what, q in [("ac.datasets", "SELECT count(*) FROM ac.datasets;"), ("ac.dataset_tables", "SELECT count(*) FROM ac.dataset_tables;"),
                ("ac.dataset_cells()", f"SELECT * FROM ac.dataset_cells('{T}', '{dv.source_id}', {key}::jsonb);"),
                ("ac.dataset_table()", f"SELECT ac.dataset_table('{T}', '{dv.source_id}');"),
                ("ac.claim_evidence (соли и листья в row_ev)", "SELECT row_ev FROM ac.claim_evidence WHERE kind = 'ROW' LIMIT 1;"),
                ("ac.claims.body", "SELECT body FROM ac.claims LIMIT 1;"),
                ("ac.dataset_open", f"SELECT ac.dataset_open('{T}', '{dv.source_id}');"), ("ac.dataset_seal", f"SELECT ac.dataset_seal('{T}', '{dv.source_id}');")]:
    print(f"   ac_rd_full: {what} ->", verdict(psql(q, "ac_rd_full"))[:110])
print("== M5. Досье: что видит читатель без PERSONAL_DATA в доказательстве-строке c50 (директор — скрытый лист)")
r = psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer');", "ac_rd_cs")
if r.returncode == 0:
    txt = r.stdout
    evs = [e for s in json.loads(txt).get("sections", []) for f in s.get("facts", []) for c in f.get("claims", []) for e in c.get("evidence", []) if "row_sha256" in e]
    print("   доказательств-строк в досье:", len(evs), "| поля:", sorted(evs[0]) if evs else "-", "| ячейки:", evs[0].get("cells") if evs else "-")
    print("   «Ломов» (директор, ПД) встречается в ячейках доказательства-строки:", any("Ломов" in json.dumps(e.get("cells"), ensure_ascii=False) for e in evs),
          "| слова salt/leaf в досье:", "salt" in txt, "leaf" in txt)
else:
    print("   ", first_err(r))

#!/usr/bin/env python3
"""F02: отказ проекции «нет записи» и «нельзя» различим по полю CONTEXT ошибки (стек PL/pgSQL):
текст сообщения одинаков, а место RAISE разное. Читатель БЕЗ единого допуска (ac_rd_none) перебирает
идентификаторы сущностей / Проверок / утверждений / проектов и узнаёт, какие существуют."""
import subprocess, os
def err(sql, user="ac_rd_none"):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-U", user], input=sql, capture_output=True, text=True, env=dict(os.environ))
    return " / ".join(l.strip() for l in (r.stdout + r.stderr).strip().splitlines())
CLM = "clm:sha256:7e74ccbb2608da776b95bd520ecb3636a85a115889601dca7d36a0ead9dc9bfc"
PAIRS = [
 ("dossier",        "SELECT ac.dossier('prj_dossier','ent_d_lomov');",            "SELECT ac.dossier('prj_dossier','ent_d_nobody');"),
 ("check_report",   "SELECT ac.check_report('chk_full_1');",                      "SELECT ac.check_report('chk_nope');"),
 ("provenance",     f"SELECT ac.provenance('{CLM}');",                            "SELECT ac.provenance('clm:sha256:" + "0"*64 + "');"),
 ("custody",        f"SELECT ac.custody('{CLM}');",                               "SELECT ac.custody('clm:sha256:" + "0"*64 + "');"),
 ("equipment_card", "SELECT ac.equipment_card('prj_ts_pumps','ent_ts_pump');",    "SELECT ac.equipment_card('prj_ts_pumps','ent_ts_nothing');"),
 ("wm_feed",        "SELECT ac.wm_feed('prj_wm_region','ent_w_developer');",      "SELECT ac.wm_feed('prj_wm_region','ent_w_nothing');"),
 ("model",          "SELECT ac.model('prj_ts_pumps');",                           "SELECT ac.model('prj_nothing');"),
 ("schema_gaps",    "SELECT ac.schema_gaps('prj_ts_pumps');",                     "SELECT ac.schema_gaps('prj_nothing');"),
]
n = 0
print("session_user = ac_rd_none; допусков:", err("SELECT count(*) FROM ac_trust.clearances", "postgres"), "строк всего, у ac_rd_none — 0")
for name, exists, missing in PAIRS:
    e1, e2 = err(exists), err(missing)
    diff = e1 != e2
    n += diff
    print(f"\n[{name}] {'РАЗЛИЧИМО' if diff else 'неразличимо'}\n  есть, нельзя: {e1}\n  нет записи : {e2}")
print(f"\nИТОГ: различимо у {n} проекций из {len(PAIRS)}")
# перебор: какие из кандидатов существуют
cands = ["ent_d_lomov", "ent_d_ivanov", "ent_d_trub", "ent_d_petrov", "ent_d_car", "ent_d_zzz"]
found = [c for c in cands if "require_clearance" in err(f"SELECT ac.dossier('prj_dossier','{c}');")]
print("перебор под ac_rd_none, существуют в prj_dossier:", found)

#!/usr/bin/env python3
"""Рецензия цикла 9: добивающие проверки (после db_attacks_s9.py — использует review09e)."""
import sys, types, subprocess, os
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot" / "core"
sys.path.insert(0, str(SNAP))
import vectors as VX
SRC = (SNAP / "validator.py").read_text(encoding="utf-8")
old = 'if lit is None or lit.get("type") != "CLASS_REF":\n            R.err("PREDICATE_RANGE_VIOLATION", cid, "schema.is_a: объект должен быть литералом CLASS_REF")\n            continue'
new = 'if lit is None or lit.get("type") != "CLASS_REF":\n            continue'
assert SRC.count(old) == 1
m = types.ModuleType("vm"); m.__file__ = str(SNAP / "validator.py"); exec(compile(SRC.replace(old, new), m.__file__, "exec"), m.__dict__)
killers = [v["id"] for v in VX.VECTORS if m.validate(*VX.build(v)).codes() != v["expected"]]
print("мутант «особое правило is_a не выдаёт PREDICATE_RANGE_VIOLATION (ошибка удалена, continue оставлен)»:", "KILLED " + str(killers) if killers else "SURVIVED (N831 проходит за счёт общего правила range)")
def sql(t):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=t, capture_output=True, text=True, env={**os.environ, "PGDATABASE": "review09e"})
    print("  [review09e]", " ".join(t.split())[:200], "\n      =>", (r.stdout.strip() + " " + r.stderr.strip().split("\n")[0]).strip() or "OK (принято)")
print("имя класса из одних пробелов и пустой label_ru (схема: NonEmpty = minLength 1 + шаблон \\S):")
sql("INSERT INTO ac.class_defs VALUES ('sdf_blank','tnt_demo','PERSON','   ','',NULL,NULL,1,now(),'usr_rev','{\"level\":\"PUBLIC\",\"categories\":[]}');")
sql("INSERT INTO ac.class_defs VALUES ('sdf_notenant','tnt_no_such_tenant_anywhere','PERSON','x',NULL,NULL,NULL,1,now(),'usr_rev','{\"level\":\"PUBLIC\",\"categories\":[]}'); SELECT count(*) FROM ac.projects WHERE tenant_id='tnt_no_such_tenant_anywhere';")

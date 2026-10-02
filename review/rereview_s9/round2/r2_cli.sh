#!/bin/bash
# Раунд 2: CLI «Конструктор модели» (снимок 2). bash r2_cli.sh > r2_cli.out 2>&1
MC="python3 ../snapshot2/core/model_constructor.py"
W=$(mktemp -d); F=$W/m.json
run() { echo; echo "\$ ${*/$W/TMP}"; "$@" 2>&1 | tail -4; echo "(exit ${PIPESTATUS[0]})"; }
C="--tenant tnt_demo --by usr_modeler1 --description тест"
run $MC init $F
run $MC add-class $F sdf_org_sub $C --root-type ORGANIZATION --name "Дочерние" --at 2026-10-01T10:00:00Z
run $MC validate $F
echo "== отказы =="
run $MC add-class $F sdf_child $C --root-type PERSON --name "x" --parent sdf_no_such_parent
run $MC add-class $F sdf_child2 $C --root-type PERSON --name "" 
run $MC add-class $F sdf_secret $C --root-type PERSON --name S --marking RESTRICTED:COMMERCIAL_SECRET --at 2026-10-01T10:01:00Z
run $MC add-class $F sdf_pubkid $C --root-type PERSON --name K --parent sdf_secret --marking PUBLIC --at 2026-10-01T10:02:00Z
echo "== атрибуты, версии =="
run $MC add-attribute $F sdf_org_sub $C --predicate x.crm_id --name "номер CRM" --type STRING --required --at 2026-10-01T10:03:00Z
run $MC add-attribute $F sdf_org_sub $C --predicate x.crm_id --name "повтор" --type STRING --at 2026-10-01T10:04:00Z
run $MC add-identifier $F sdf_id_bad $C --scheme x.badfmt --root-type ORGANIZATION --name B --strength WEAK --priority 3 --format "DIGIT:9-1"
run $MC add-identifier $F sdf_id_inn $C --scheme ru.inn --root-type ORGANIZATION --name ИНН --strength WEAK --priority 1
run $MC rename $F sdf_org_sub $C --name "Новое имя" --at 2026-10-01T10:02:30Z
run $MC rename $F sdf_org_sub $C --name "Новое имя" --at 2026-10-01T10:05:00Z
run $MC deprecate $F sdf_org_sub $C --at 2026-10-01T10:06:00Z
run $MC rename $F sdf_org_sub $C --name "После вывода" --at 2026-10-01T10:07:00Z
run $MC add-class $F sdf_future $C --root-type PERSON --name F --at 2099-01-01T00:00:00Z
run $MC journal $F --tenant tnt_demo
run $MC validate $F
python3 - $F <<'P'
import json,sys
d=json.load(open(sys.argv[1])); print("записей в файле:", len(d["records"]), [ (r.get("class_id") or r.get("idef_id"), r["version"], r["change"]["type"]) for r in d["records"]])
P
rm -rf $W

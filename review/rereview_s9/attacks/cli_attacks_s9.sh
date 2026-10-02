#!/bin/bash
# Рецензия цикла 9: CLI «Конструктор модели». Запуск: bash cli_attacks_s9.sh > cli_attacks_s9.out 2>&1
MC="python3 ../snapshot/core/model_constructor.py"
VAL="python3 ../snapshot/core/validator.py"
W=$(mktemp -d)
run() { echo; echo "\$ $*"; "$@" 2>&1 | tail -6; echo "(exit ${PIPESTATUS[0]})"; }
echo "== 1. add-class + набор из одной записи -> validate-schema =="
$MC add-class sdf_org_sub --root-type ORGANIZATION --name "Дочерние" --tenant-id tnt_demo --out $W/c1.json
python3 - $W <<'P'
import json,sys
w=sys.argv[1]; c=json.load(open(w+'/c1.json'))
json.dump({"records":[c]}, open(w+'/ds.json','w'), ensure_ascii=False)
json.dump([c], open(w+'/list.json','w'), ensure_ascii=False)
P
run $MC validate-schema $W/ds.json
run $MC validate-schema $W/list.json
echo; echo "== 2. тот же набор через нормативный валидатор (контроль: запись сама по себе валидна?) =="
run $VAL $W/ds.json
echo; echo "== 3. add-* заявлено «проверяет созданную запись через validator»: наследник несуществующего родителя, version=0, пустое имя =="
run $MC add-class sdf_child --root-type PERSON --name "" --parent sdf_no_such_parent --version 0 --tenant-id tnt_demo --out $W/c2.json
python3 - $W <<'P'
import json,sys
w=sys.argv[1]; json.dump({"records":[json.load(open(w+'/c2.json'))]}, open(w+'/ds2.json','w'), ensure_ascii=False)
P
run $VAL $W/ds2.json
echo; echo "== 4. маркировка: RESTRICTED и категории задать нельзя =="
run $MC add-class sdf_secret --root-type PERSON --name S --tenant-id tnt_demo --marking-level RESTRICTED
echo; echo "== 5. атрибуты класса: есть ли параметр? =="
$MC add-class --help | grep -ci "attr"
echo; echo "== 6. add-iddef: невалидное регулярное выражение принимается =="
run $MC add-iddef sdf_id_bad --scheme ru.inn --applies-to ORGANIZATION --strength WEAK --val-regex "([" --tenant-id tnt_demo
echo; echo "== 7. add-link: незарегистрированный предикат; created-at из будущего =="
run $MC add-link sdf_lnk_x --predicate-id no.such_thing --domain-class-id sdf_a1 --range-class-id sdf_b1 --cardinality ONE --tenant-id tnt_demo --created-at 2099-01-01T00:00:00Z
rm -rf $W

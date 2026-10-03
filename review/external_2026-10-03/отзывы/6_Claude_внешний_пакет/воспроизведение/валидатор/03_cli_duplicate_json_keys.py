"""ОШИБКА, P1. CLI валидатора читает набор и реестр доверия обычным json.loads: повторяющийся ключ объекта молча
заменяется последним. Артефакты, манифесты и файлы строк тот же валидатор читает строго (object_pairs_hook=_no_dup).
Итог: файл, в котором одна запись несёт ДВА значения «marking» (или весь набор — два массива «records»), проходит с
exit 0; читатель, берущий первое значение, видит другое содержание, чем проверил валидатор."""
import json, os, shutil, subprocess, sys, tempfile
from _h import *

d = tempfile.mkdtemp(prefix="dupkeys_", dir=os.path.dirname(os.path.abspath(__file__)))
os.mkdir(d + "/content")
ds, ix, trust, content = finalize(world())
for k, b in content.items():
    open(d + "/content/" + k.split(":")[-1], "wb").write(b)
json.dump(trust, open(d + "/trust.json", "w"))
txt = json.dumps(ds, ensure_ascii=False)
V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "validator.py")

def cli(name, text):
    open(f"{d}/{name}", "w", encoding="utf-8").write(text)
    p = subprocess.run([sys.executable, V, f"{d}/{name}", "--trust", d + "/trust.json", "--content-dir", d + "/content"],
                       capture_output=True, text=True)
    print(f"{name:22} exit={p.returncode}  {p.stdout.strip().splitlines()[-1]}")

cli("ok.json", txt)
one = json.dumps(ds["records"][ix["ent_d_lomov"]], ensure_ascii=False)
assert one in txt
cli("dup_marking.json", txt.replace(one, '{"marking":{"level":"PUBLIC","categories":[]},' + one[1:]))
cli("dup_records.json", '{"dataset_format":"core-dataset/0.3","ontology_version":"core-ontology/0.4",'
                        '"records":[{"kind":"Entity","чужая запись":true}],' + txt[txt.index('"records"'):])
tr = json.dumps(trust)
open(d + "/trust.json", "w").write(tr.replace('"keys"', '"keys":[],"keys"', 1))
cli("dup_trust_keys.json", txt)
print("контроль — тот же приём в артефакте:", VAL.parse_artifact(b'{"run_id":"run_a","run_id":"run_b"}')[1])
shutil.rmtree(d)

"""T4 (3000 «случайных повреждений»): сколько случаев вообще доходит до семантической фазы и сколько РАЗНЫХ значений в T6.
Воспроизводит генератор tests.py (тот же seed). Запуск из core/."""
import sys, copy, random, json, collections, hashlib
sys.path.insert(0, ".")
from validator import validate
import validator
from vectors import VECTORS, build
base, trust, content = build()
calls = [0]
orig = validator._semantic
def spy(*a, **k):
    calls[0] += 1
    return orig(*a, **k)
validator._semantic = spy
rng = random.Random(20260930)
JUNK = [None, True, 0, -1, 2**40, "", " ", "x", "ent_x", "2026-13-01", [], {}, [1], {"a": 1}, "src:sha256:" + "0" * 64]
def paths(node, p=()):
    yield p
    if isinstance(node, dict):
        for k, v in node.items(): yield from paths(v, p + (k,))
    elif isinstance(node, list):
        for n, v in enumerate(node): yield from paths(v, p + (n,))
all_paths = [p for p in paths(base) if p]
out = collections.Counter(); sem_codes = collections.Counter(); clean = 0
for i in range(3000):
    d = copy.deepcopy(base)
    for _ in range(rng.randint(1, 3)):
        p = rng.choice(all_paths); node = d
        try:
            for k in p[:-1]: node = node[k]
            if rng.random() < 0.3 and isinstance(node, dict): node.pop(p[-1], None)
            else: node[p[-1]] = rng.choice(JUNK)
        except (KeyError, IndexError, TypeError): pass
    before = calls[0]
    r = validate(d, trust, content)
    reached = calls[0] > before
    out["дошло до семантики" if reached else "остановлено фазой 0/1 (SCHEMA_INVALID)"] += 1
    if reached:
        for c in r.codes(): sem_codes[c] += 1
        if not r.errors: clean += 1
print(dict(out)); print("из дошедших — без ошибок (повреждение принято):", clean); print("коды семантики:", sem_codes.most_common())
validator._semantic = orig
# T6: сколько разных значений среди «N values»
seen = set(); total = 0
for v in [None] + VECTORS:
    d, tr, ct = build(v)
    if v is not None and "SCHEMA_INVALID" in validate(d, tr, ct).codes(): continue
    for r in d["records"]:
        total += 1
        try: seen.add(hashlib.sha256(json.dumps(r, sort_keys=True, ensure_ascii=False).encode("utf-8", "surrogatepass")).digest())
        except Exception: pass
print("T6: записей всего", total, "разных", len(seen))

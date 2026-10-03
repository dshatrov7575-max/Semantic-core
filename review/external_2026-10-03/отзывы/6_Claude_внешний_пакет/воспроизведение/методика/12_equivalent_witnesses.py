"""Попытка опровергнуть «эквивалентных» мутантов свидетелями. Запуск из core/.
Для каждого свидетеля: коды немутированного валидатора и коды мутанта; разные => мутант НЕ эквивалентен."""
import sys, types, copy
sys.path.insert(0, ".")
from pathlib import Path
import mutants
from vectors import build, V, seq, setk, add_entity, _nest, INT, CONF_PD
SRC = Path("validator.py").read_text(encoding="utf-8")
M = {m[0]: m for m in mutants.M}

def load(mid=None):
    src = SRC
    if mid:
        _, _, old, new = M[mid]
        olds, news = (old, new) if isinstance(old, list) else ([old], [new])
        for o, n in zip(olds, news):
            assert src.count(o) == 1
            src = src.replace(o, n)
    mod = types.ModuleType("validator_mut"); mod.__file__ = str(Path("validator.py").resolve())
    exec(compile(src, "validator_mut", "exec"), mod.__dict__)
    return mod

ORIG = load()
def run(mid, name, vec):
    ds, tr, ct = build(vec)
    out = []
    for mod in (ORIG, load(mid)):
        try:
            r = mod.validate(ds, tr, ct)
            out.append((r.codes(), [e["msg"][:90] for e in r.errors][:3]))
        except BaseException as ex:
            out.append((["<исключение %s>" % type(ex).__name__], []))
    verdict = "ОПРОВЕРГНУТ (коды разные)" if out[0][0] != out[1][0] else "не опровергнут"
    print(f"{mid} [{name}]: {verdict}\n   оригинал: {out[0]}\n   мутант:   {out[1]}")

# --- M616: путь адреса может начинаться не с «/»
def m616a(W):
    W["s2c"]["marking"] = CONF_PD
    W["s2c"]["observations"][0]["origin_uri"] = "https://m.news.example:x/zarechye"
run("M616", "наблюдение https://m.news.example:x/zarechye с более узкой маркировкой", V("W616a", [], "", pre=m616a))
def m616b(W):
    for s in ("s2", "s2b", "s2c"):
        for o in W[s]["observations"]:
            o["origin_uri"] = o["origin_uri"].replace("news.example/", "news.example:x/")
run("M616", "все наблюдения издания — с «:x» после хоста", V("W616b", [], "", pre=m616b))

# --- M317: без предела глубины
def m317(d, ix, e):
    e["trust"]["keys"] = _nest(5000)
run("M317", "реестр доверия: keys = список вложенности 5000", V("W317", [], "", post=m317))
def m317b(d, ix, e):
    e["trust"]["keys"][0]["not_before"] = _nest(5000)
run("M317", "реестр доверия: not_before = список вложенности 5000", V("W317b", [], "", post=m317b))

# --- M536: тип сущности узла
def m536(W):
    add_entity("ent_ts_model_x", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "Икс", "model": "Игрек-1"}, INT,
               status="MERGED", merged_into="ent_ts_station", changed="2026-09-05T13:00:00Z")(W)
    n3 = W["__artifacts__"]["umr_ns2"]["nodes"][2]
    n3["entity_type"] = "EQUIPMENT_MODEL"; n3["identity"] = {"manufacturer": "Икс", "model": "Игрек-1"}
run("M536", "узел EQUIPMENT_MODEL вместо EQUIPMENT; модель (неправомерно) слита в станцию", V("W536", [], "", pre=m536))

# --- M318
def m318(d, ix, e):
    e["trust"]["keys"] = _nest(5000)
run("M318", "реестр доверия: keys = список вложенности 5000", V("W318", [], "", post=m318))

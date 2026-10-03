#!/usr/bin/env python3
"""S10R / направление 2: свой дифференциальный фаззер ДОКАЗАТЕЛЬСТВА-СТРОКИ.
Не мутации одной строки c50, а СЛУЧАЙНЫЕ НАБОРЫ: случайные колонки всех типов (до 512), случайные ключи (в т.ч. из булевых, целых колонок
и дат), subject, колонки-идентификаторы, колонки предикатов; значения — Юникод (все виды пробелов, управляющие, вне BMP, кавычки, \\u2028),
границы целых ±(2^53−1), даты-границы, null; затем мутации доказательства и утверждения (другой субъект, предикат, объект, литерал,
row_key с подменой типа true↔1, числа, ячейки, путь). Валидатор — целиком (мир + версия + утверждение); база — страж
ac.row_evidence_guard над той же записью (версия зарегистрирована в базе обычным путём, утверждение — как составная запись ac.claims).
Запуск: PGDATABASE=review10_f python3 a9_fuzz_row.py [N] [seed]"""
from common import *
import random, re, time
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 2002)
UNI = [" ", " ", " ", " ", "　", "\u0085", "​", "﻿", "\u0080", "\u007f", "\t", "\n", "\r", "\x1f", "\x01", "\x08", "\x0c", "\x0b",
       "\U0001f600", "\U00010000", "\U0010ffff", "￿", "﷐", "", "é", "é", "ё", "\"", "\\", "/", "'", "<", "&", "‮", "a", "Я", "0", "$", "|", "%", "{", "}"]
INTS = [0, 1, -1, 2, 48, 2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 31, -2 ** 31, 2 ** 32, 10 ** 15]
DATES = ["0001-01-01", "9999-12-31", "2024-02-29", "2021-02-12", "1970-01-01", "2000-12-31", "1900-02-28"]
PUBM = {"level": "PUBLIC", "categories": []}
MARKS = [PUBM, PUBM, PUBM, {"level": "INTERNAL", "categories": []}, {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}, {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}]
PREDS = ["entity.registered_address", "court.party_to_case", "competitor.competes_with", "media.negative_mention", "corp.founder_of", "x.note"]
SCHEMES = ["ru.ogrn", "ru.inn", "ru.arbitr", "x.code"]
ORGS = {"ent_k_developer": {"ru.ogrn": OGRN_DEV, "ru.inn": INN_DEV}}
W = world()[0]
ENT = {r["entity_id"]: r for r in W["records"] if r["kind"] == "Entity"}
OTHER = [e for e in ENT.values() if e["project_id"] == PRJ and e["entity_id"] != "ent_k_developer"]
def keys_of(e): return VAL.entity_identifiers(e, VAL.Report(), "-")[0]

def sval(): return "".join(rnd.choice(UNI) for _ in range(rnd.choice([0, 1, 1, 2, 3, 6])))
def val(t, i):
    if rnd.random() < .12: return None
    if t == "STRING": return sval() + (str(i) if rnd.random() < .5 else "")
    if t == "INTEGER": return rnd.choice(INTS)
    if t == "BOOLEAN": return rnd.random() < .5
    return rnd.choice(DATES)

def make_dataset(tag):
    n = rnd.choice([1, 2, 3, 4, 5, 6, 8, 12, 12, 40, 512])
    cols = []
    for i in range(n):
        c = {"name": "c%d" % i, "type": rnd.choice(["STRING", "STRING", "INTEGER", "BOOLEAN", "DATE"]), "marking": rnd.choice(MARKS)}
        if c["type"] == "STRING" and rnd.random() < .45: c["identifier_scheme"] = rnd.choice(SCHEMES)
        if rnd.random() < .45: c["predicate"] = rnd.choice(PREDS)
        cols.append(c)
    idc = [c["name"] for c in cols if "identifier_scheme" in c]
    subject = rnd.sample(idc, min(len(idc), rnd.choice([0, 1, 1, 2, 3]))) if idc else []
    nrows = rnd.choice([1, 2, 3, 5, 9, 17])
    keyc = rnd.sample([c["name"] for c in cols], min(n, rnd.choice([0, 1, 1, 2, 3])))
    rows = []
    for r in range(nrows):
        row = {}
        for c in cols:
            v = val(c["type"], r)
            if "identifier_scheme" in c and rnd.random() < .7:
                me = ORGS["ent_k_developer"].get(c["identifier_scheme"])
                oth = [v2 for e in OTHER for s2, v2 in keys_of(e) if s2 == c["identifier_scheme"]]
                v = rnd.choice(([me] if me else []) * 3 + oth + [OGRN_TRUB, INN_TRUB, None, "А41-12345/2026"]) if r == 0 or rnd.random() < .3 else v
            row[c["name"]] = v
        for k in keyc:                                   # ключ: непустой и уникальный
            t = next(c["type"] for c in cols if c["name"] == k)
            if row[k] is None or t in ("BOOLEAN",) or True:
                row[k] = {"STRING": "k%d%s" % (r, sval()), "INTEGER": r if rnd.random() < .7 else 2 ** 53 - 1 - r, "BOOLEAN": r % 2 == 0, "DATE": "20%02d-01-0%d" % (r % 90 + 10, r % 9 + 1)}[t] \
                    if not (t == "STRING" and next(c for c in cols if c["name"] == k).get("identifier_scheme") and row[k]) else row[k]
        rows.append(row)
    # булев ключ уникален только на ≤2 строках; составной ключ — по набору
    seen, uniq = set(), []
    for row in rows:
        kv = canon([row[k] for k in keyc])
        if keyc and kv in seen: continue
        seen.add(kv); uniq.append(row)
    try:
        dv = DatasetVersion("dst_rev_fuzz", T, tag, cols, keyc, uniq, chunk_rows=rnd.choice([1, 2, 3, 4, 8, 4096]), subject=subject, check=False)
    except Exception as ex:
        return None
    return dv

def base_claim(dv, ridx):
    """утверждение, которое строка (как правило) говорит: предикат и объект — по случайной колонке предиката"""
    _, kv, secret, h, values = dv.rows[ridx]
    names = dv.names
    pc = [c for c in dv.columns if "predicate" in c]
    quote = set(rnd.sample(names, rnd.randrange(0, min(len(names), 6) + 1))) | set(dv.manifest.get("subject", []) if rnd.random() < .8 else [])
    pred, obj = rnd.choice(PREDS), {"literal": {"type": "STRING", "value": "нечто"}}
    if pc and rnd.random() < .9:
        c = rnd.choice(pc); v = values[names.index(c["name"])]; pred = c["predicate"]; quote.add(c["name"])
        if "identifier_scheme" in c and rnd.random() < .4:
            cand = [e["entity_id"] for e in ENT.values() if e["project_id"] == PRJ and (c["identifier_scheme"], v) in keys_of(e)]
            obj = {"entity": rnd.choice(cand)} if cand else {"entity": rnd.choice(list(ENT.values()))["entity_id"]} if rnd.random() < .3 else \
                  {"literal": {"type": "IDENTIFIER", "scheme": c["identifier_scheme"], "value": v if isinstance(v, str) and v.strip() else "x"}}
        elif "identifier_scheme" in c:
            obj = {"literal": {"type": "IDENTIFIER", "scheme": rnd.choice([c["identifier_scheme"]] * 4 + SCHEMES), "value": v if isinstance(v, str) and v.strip() and len(v) <= 2000 else "x"}}
        elif c["type"] == "STRING": obj = {"literal": {"type": "STRING", "value": v if isinstance(v, str) and v.strip() and len(v) <= 2000 else "x"}}
        elif c["type"] == "INTEGER": obj = {"literal": {"type": "INTEGER", "value": v if v is not None else 0}}
        elif c["type"] == "BOOLEAN": obj = {"literal": {"type": "BOOLEAN", "value": bool(v)}}
        else: obj = {"literal": {"type": rnd.choice(["DATE", "DATE", "STRING"]), "value": v or "2020-01-01"}}
    key = [values[names.index(k)] for k in dv.key] if dv.key else h.hex()
    ev = dv.evidence(key, quote)
    return ev, pred, obj

def mutate_ev(ev, dv):
    op = rnd.randrange(30)
    cells = ev["cells"]; q = [c for c in cells if "salt" in c]; hid = [c for c in cells if "leaf" in c]
    if op == 0 and "row_key" in ev:                       # подмена типа в row_key: true<->1, false<->0, "1"<->1
        i = rnd.randrange(len(ev["row_key"])); v = ev["row_key"][i]
        ev["row_key"][i] = {True: 1, False: 0}.get(v, v) if isinstance(v, bool) else (v == 1 if v in (0, 1) else str(v)) if isinstance(v, int) else (int(v) if v.isdigit() and len(v) < 16 else v + " ") if isinstance(v, str) else v
    elif op == 1 and q:                                   # подмена типа в ячейке
        c = rnd.choice(q); v = c["value"]
        c["value"] = {True: 1, False: 0}.get(v) if isinstance(v, bool) else (v == 1 if v in (0, 1) else str(v)) if isinstance(v, int) else (None if v is not None else "")
    elif op == 2 and q: rnd.choice(q)["value"] = rnd.choice([None, "", " ", 0, 1, True, False, "2021-02-30", "0000-01-01", "20210212", "2021-2-12", "10000-01-01", "2021-02-12 ", "２０２１-02-12", 2 ** 53 - 1, -(2 ** 53 - 1), " ", "a\u0000b"])
    elif op == 3 and hid:                                 # скрытую ячейку — раскрыть неверно; или процитированную — скрыть
        c = rnd.choice(hid); leaf = c.pop("leaf"); c["value"] = rnd.choice([None, "x", 1, True]); c["salt"] = leaf
    elif op == 4 and q:
        c = rnd.choice(q); leaf = VAL.cell_leaf(bytes.fromhex(c["salt"]), c["name"], c["value"]).hex(); c.clear(); c.update(name=c.get("name", ""), leaf=leaf)
        c["name"] = [x["name"] for x in dv.columns][cells.index(c)]
    elif op == 5 and len(cells) > 1:
        i, j = rnd.sample(range(len(cells)), 2); cells[i], cells[j] = cells[j], cells[i]
    elif op == 6: ev["proof"]["index"] = rnd.choice([0, 1, ev["proof"]["index"] + 1, ev["proof"]["index"] ^ 1, 2 ** 53 - 1, 4096])
    elif op == 7: ev["proof"]["file"] = rnd.choice([0, 1, ev["proof"]["file"] + 1, 2 ** 53 - 1, 2 ** 31, 2 ** 31 - 1, 2 ** 32])
    elif op == 8: ev["proof"]["hashes"] = rnd.choice([[], ev["proof"]["hashes"][:-1], ev["proof"]["hashes"] + ["0" * 64], ev["proof"]["hashes"][::-1], ev["proof"]["hashes"] * 2, ["0" * 64] * 64, ["0" * 64] * 65])
    elif op == 9 and "row_key" in ev: ev["row_key"] = rnd.choice([[], ev["row_key"][::-1], ev["row_key"] + ev["row_key"], ev["row_key"][:-1], [None], ev["row_key"] * 9])
    elif op == 10: ev.pop("row_key", None) if "row_key" in ev else ev.__setitem__("row_key", rnd.choice([[ev["row_sha256"]], ["x"], [0]]))
    elif op == 11: ev["row_sha256"] = rnd.choice([ev["row_sha256"].upper(), "0" * 64, ev["row_sha256"][:-1], ev["row_sha256"][::-1]])
    elif op == 12 and q: rnd.choice(q)["salt"] = rnd.choice(["0" * 64, "F" * 64, "0" * 62])
    elif op == 13 and q:                                  # пара ячеек с одинаковыми именами / чужое имя
        rnd.choice(cells)["name"] = rnd.choice([c["name"] for c in cells] + ["zz", "C0", ""])
    elif op == 14: cells.append(copy.deepcopy(rnd.choice(cells))) if rnd.random() < .5 else cells.pop(rnd.randrange(len(cells)))
    elif op == 15 and q:
        c = rnd.choice(q); c[rnd.choice(["leaf", "note", "type"])] = "0" * 64
    elif op == 16: ev[rnd.choice(["span", "quote", "graph_node", "note", "kind"])] = rnd.choice([{"start": 0, "end": 1}, "x", "ROW", "row", None])
    elif op == 17 and q and isinstance(rnd.choice(q)["value"], str):
        c = rnd.choice([x for x in q if isinstance(x["value"], str)]); c["value"] = c["value"] + rnd.choice(["", " ", "́", "​"])
    return ev

def text_mut(txt):
    """запись чисел в тексте JSON утверждения (идёт в базу как текст)"""
    nums = list(re.finditer(r'(?<=: )(-?\d+)(?=[,}\]])', txt))
    if not nums: return txt, False
    mm = rnd.choice(nums); n = int(mm.group(1))
    alt = rnd.choice([f"{n}.0", f"{n}e0", f"{n}E0", f"{n}.00", f"{n}0e-1" if n >= 0 else f"{n}.0", "-0" if n == 0 else f"{n}e+0", "1e2" if n == 100 else f"{n}e0"])
    return txt[:mm.start()] + alt + txt[mm.end():], True

# ---- наборы
dss, t0 = [], time.time()
stamp = utc(0)
while len(dss) < 60:
    dv = make_dataset(f"rev-a9 {stamp} #{len(dss)} {rnd.random()}")
    if dv is None or not dv.rows: continue
    src = source_rec(dv, marking=PUBM)
    if VAL.parse_manifest(dv.manifest_bytes)[0] is None: continue
    r = db_try([src], commit=True)
    if r.returncode: print("регистрация версии отвергнута базой, а валидатором принята:", first_err(r)[:200], dv.manifest_bytes[:200]); continue
    dss.append((dv, src))
time.sleep(1.2)
print(f"наборов: {len(dss)} (колонок от {min(len(d.columns) for d, _ in dss)} до {max(len(d.columns) for d, _ in dss)}; ключи из типов: "
      f"{sorted({next(c['type'] for c in d.columns if c['name'] == k) for d, _ in dss for k in d.key})})")

cases = []
while len(cases) < N:
    dv, src = rnd.choice(dss)
    try:
        ev, pred, obj = base_claim(dv, rnd.randrange(len(dv.rows)))
    except Exception as ex:
        continue
    subj = "ent_k_developer" if rnd.random() < .8 else rnd.choice(OTHER)["entity_id"]
    mut = rnd.random()
    if mut < .55:
        ev = mutate_ev(ev, dv)
    marking = rnd.choice([{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}] * 3 + [CONF_CS])
    c = {"kind": "Claim", "schema_version": "core-ontology/0.4", "project_id": PRJ, "subject": subj, "predicate": pred, "object": obj, "evidence": [ev],
         "produced_by": {"kind": "HUMAN", "actor_id": "usr_bank_officer"}, "recorded_at": utc(0), "marking": marking}
    try:
        c["claim_id"] = "clm:sha256:" + digest(c)
    except Exception:
        c["claim_id"] = "clm:sha256:" + "0" * 64
    try:
        txt = json.dumps(c, ensure_ascii=False, sort_keys=True)
    except Exception:
        continue
    tm = False
    if rnd.random() < .08: txt, tm = text_mut(txt)
    if "\\u0000" in txt or "$fz$" in txt: 
        if rnd.random() < .9: continue
    cases.append((dv, src, c, txt, tm))

setup = """
CREATE FUNCTION pg_temp.row_verdict(txt text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE c ac.claims; src ac.sources; b jsonb; ev jsonb;
BEGIN
  BEGIN
    b := txt::jsonb; ev := b->'evidence'->0;
    SELECT * INTO src FROM ac.sources WHERE tenant_id = 'tnt_demo' AND source_id = ev->>'source_id';
    IF src.source_id IS NULL THEN RETURN 'REF_UNRESOLVED'; END IF;
    c.claim_id := b->>'claim_id'; c.project_id := b->>'project_id'; c.tenant_id := 'tnt_demo'; c.subject := b->>'subject'; c.predicate := b->>'predicate';
    c.object_entity := b->'object'->>'entity'; c.recorded_at := (b->>'recorded_at')::timestamptz; c.marking := b->'marking'; c.body := b;
    PERFORM ac.row_evidence_guard(c, src, ev);
    RETURN 'FUZZ_ACCEPTED';
  EXCEPTION WHEN others THEN
    RETURN replace(replace(SQLERRM, E'\\n', ' '), E'\\r', ' ');
  END;
END $f$;"""
out = []
for st in range(0, len(cases), 200):
    r = psql(setup + "\n" + "\n".join(f"SELECT pg_temp.row_verdict($fz${x[3]}$fz$);" for x in cases[st:st + 200]))
    if r.returncode: sys.exit("harness: " + r.stderr[:1500])
    out += r.stdout.splitlines()
assert len(out) == len(cases), (len(out), len(cases))
ROWCODES = {"EVIDENCE_ROW_INVALID", "SCHEMA_INVALID", "MARKING_BROADER_THAN_INPUT"}
diff, acc, rej = [], 0, 0
for (dv, src, c, txt, tm), v in zip(cases, out):
    try:
        obj = json.loads(txt)
    except Exception:
        obj = c
    rep = validate_with([src, obj])
    # вердикт валидатора по доказательству-строке: коды стража строки; маркировка — только сообщение о колонке
    errs = [e for e in rep.errors if e["code"] in ("EVIDENCE_ROW_INVALID", "SCHEMA_INVALID") or (e["code"] == "MARKING_BROADER_THAN_INPUT" and "колонки" in e["msg"])
            or e["code"] == "VALIDATOR_INTERNAL_ERROR"]
    py_ok, db_ok = not errs, v.startswith("FUZZ_ACCEPTED")
    acc += py_ok and db_ok; rej += (not py_ok) and (not db_ok)
    if py_ok != db_ok:
        diff.append(("валидатор ПРИНЯЛ, база отвергла" if py_ok else "база ПРИНЯЛА, валидатор отверг", errs[:1], v[:150], txt, tm))
print(f"доказательство-строка: случаев {len(cases)}, принято обоими {acc}, отвергнуто обоими {rej}, РАСХОЖДЕНИЙ {len(diff)}")
kinds = {}
for d in diff:
    msg = (d[1][0]["code"] + ": " + d[1][0]["msg"][:70]) if d[1] else "-"
    kinds.setdefault((d[0], re.sub(r"c\d+", "cN", msg), re.sub(r"c\d+", "cN", d[2])[:90], d[4]), []).append(d)
for (k, m1, m2, tm), lst in sorted(kinds.items(), key=lambda x: -len(x[1])):
    print(f"\n[{len(lst)}×] {k}{' (число в тексте JSON переписано: 1 -> 1.0 / 1e0)' if tm else ''}\n    валидатор: {m1}\n    база:      {m2}")
    ex = json.loads(lst[0][3]) if not tm else None
    if ex:
        e0 = ex["evidence"][0]
        print("    пример: row_key =", json.dumps(e0.get("row_key"), ensure_ascii=False)[:120], "| процитировано:", json.dumps([(x["name"], x["value"]) for x in e0.get("cells", []) if isinstance(x, dict) and "salt" in x][:6], ensure_ascii=False)[:300])
        print("            предикат:", ex["predicate"], "| объект:", json.dumps(ex["object"], ensure_ascii=False)[:150], "| субъект:", ex["subject"])
    else:
        print("    пример (фрагмент текста):", re.findall(r'"(?:index|file|value)": [-0-9.eE+]+', lst[0][3])[:6])
json.dump([{"kind": d[0], "py": d[1], "db": d[2], "claim_text": d[3]} for d in diff[:200]], open("out/a9_divergences.json", "w"), ensure_ascii=False, indent=1)

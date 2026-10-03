#!/usr/bin/env python3
"""S10R / направление 2: свой дифференциальный фаззер МАНИФЕСТА (валидатор parse_manifest + правила tenant/previous ↔ триггер базы).
Мутации иные, чем в slice/attacks_s10.py: запись чисел (1e2, 1.0, -0, +5, 05), экранирование \\uXXXX, суррогаты, невалидный UTF-8, BOM,
Юникод в version_label (все виды пробелов, C1, нулевая ширина, вне BMP, длины 2000/2001), границы 512 колонок / 8 ключей / 63 символа имени,
маркировки, большие файлы-списки, повтор ключей, перестановка ключей, null и вложенные структуры.
Запуск: PGDATABASE=review10_f python3 a8_fuzz_manifest.py [N] [seed]   (база — свежая, после load_s1.py)"""
from r2common import *
import random, re
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1002)
BASE = demo_registry().manifest
DS, TR, CT = build()
S = {s["source_id"]: s for s in DS["records"] if s["kind"] == "Source"}
DOC = next(k for k, s in S.items() if s["source_kind"] != "DATASET_VERSION" and s["tenant_id"] == T)
VER = demo_registry().source_id
UNI = [" ", " ", " ", " ", " ", " ", " ", " ", " ", "　", "\u0085", "​", "‍", "﻿", "\u0080", "\u009f",
       "\u007f", "\t", "\n", "\r", "\x1c", "\x1f", "\x01", "᠎", "⁠", "\U0001f600", "\U00010000", "\U0010ffff", "￿", "￾", "﷐", "",
       "é", "é", "ё", "Ω", "\"", "\\", "/", "'", "<", "؜", "‮", "a", "Я", "0", "̀", "\x00"]
PUBM = {"level": "PUBLIC", "categories": []}
MARK = [PUBM, {"level": "INTERNAL", "categories": []}, {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]},
        {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}, {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]},
        {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "PERSONAL_DATA"]}, {"level": "RESTRICTED", "categories": []}, {"level": "SECRET", "categories": []},
        {"level": "PUBLIC"}, {"level": "PUBLIC", "categories": None}, {"level": "PUBLIC", "categories": ["NO_SUCH"]}, {"level": "public", "categories": []},
        {"level": "PUBLIC", "categories": [], "x": 1}, {"level": "PUBLIC", "categories": [1]}, None, [], "PUBLIC", {"categories": []}, {"level": None, "categories": []}]
NAMES = ["a", "a" * 63, "a" * 64, "A", "a-b", "1a", "_a", "a_", "ogrn", "inn", "", "a b", "я", "a\n", "a0_9", "c_x", "row_secret", "version_no"]
SCH = ["ru.inn", "a", "ab", "a.", "a" * 41, "a" * 42, "A.b", "ru.inn\n", "1a", "ru_inn", "x.y.z", "", None, 5, "ru.ogrn"]
PRED = ["entity.registered_address", "x.max_length", "x.itis_tsn", "x.belongs_to", "court.party_to_case", "person.birth_date", "x.note", "a.b", "a.", ".b", "a.b.c", "a.B", "a1.b", "a.b_c", "a_b.c", "a.b\n", "", None, 7, "ab"]

def col(i):
    return {"name": "c%d" % i, "type": rnd.choice(["STRING", "INTEGER", "BOOLEAN", "DATE"]), "marking": PUBM}

def structural(m):
    op = rnd.randrange(34)
    if op == 0: m["version_label"] = "".join(rnd.choice(UNI) for _ in range(rnd.choice([1, 1, 2, 3, 5])))
    elif op == 1: m["version_label"] = rnd.choice(UNI[:20] + ["a", "я", "\U0001f600"]) * rnd.choice([1999, 2000, 2001])
    elif op == 2: m["version_label"] = rnd.choice(["x" + rnd.choice(UNI), rnd.choice(UNI) + "x", rnd.choice(UNI) + rnd.choice(UNI)])
    elif op == 3:
        n = rnd.choice([1, 2, 511, 512, 513]); m["columns"] = [col(i) for i in range(n)]; m["key"] = ["c0"] if rnd.random() < .5 else []; m.pop("subject", None)
    elif op == 4: rnd.choice(m["columns"])["name"] = rnd.choice(NAMES)
    elif op == 5: rnd.choice(m["columns"])["marking"] = copy.deepcopy(rnd.choice(MARK))
    elif op == 6: rnd.choice(m["columns"])["identifier_scheme"] = rnd.choice(SCH)
    elif op == 7: rnd.choice(m["columns"])["predicate"] = rnd.choice(PRED)
    elif op == 8: rnd.choice(m["columns"])["type"] = rnd.choice(["STRING", "INTEGER", "BOOLEAN", "DATE", "string", "TEXT", "", None, 1, ["STRING"], "QUANTITY", "IDENTIFIER"])
    elif op == 9: m["key"] = rnd.choice([[], ["ogrn", "ogrn"], ["ogrn", "inn"], ["inn", "ogrn"], [c["name"] for c in m["columns"]][:8], [c["name"] for c in m["columns"]] + ["ogrn"],
                                          ["employees"], ["active"], ["registered_on"], [1], [None], "ogrn", None, {"0": "ogrn"}, ["Ogrn"], ["ogrn "], [["ogrn"]]])
    elif op == 10: m["subject"] = rnd.choice([[], ["ogrn"], ["inn", "ogrn"], ["ogrn", "ogrn"], ["name"], ["employees"], ["zz"], [1], None, "ogrn", ["ogrn", "inn", "name"], [True]])
    elif op == 11: m["row_count"] = rnd.choice([0, 5, 6, 4, -1, -5, 2 ** 53 - 1, 2 ** 53, True, False, None, "5", [5], 5.0, 5.5, 1e2, -0.0, 10 ** 30])
    elif op == 12:
        f = rnd.choice(m["files"]); k = rnd.choice(["rows", "byte_length"])
        f[k] = rnd.choice([0, 1, -1, 2 ** 53 - 1, 2 ** 53, True, None, "1", 1.0, 1.5, 4, 5])
        if rnd.random() < .6 and isinstance(f[k], int) and not isinstance(f[k], bool): m["row_count"] = sum(x["rows"] for x in m["files"] if isinstance(x["rows"], int))
    elif op == 13: m["files"] = rnd.choice([[], [m["files"][0]], m["files"] * 2, m["files"][::-1], None, {}, [None], [[]], m["files"] + [{}]]); 
    elif op == 14:
        if m["files"] and isinstance(m["files"], list): m["row_count"] = sum(x["rows"] for x in m["files"])
        f = rnd.choice(m["files"]) if m["files"] else {}; k = rnd.choice(["object", "rows_root"])
        f[k] = rnd.choice(["sha256:" + "0" * 64, "0" * 64, "sha256:" + "A" * 64, "A" * 64, "0" * 63, "0" * 65, "sha256:" + "0" * 63, "", None, 5, "sha1:" + "0" * 40, "g" * 64, "0" * 64 + "\n"])
    elif op == 15: m["previous"] = rnd.choice([VER, DOC, "src:sha256:" + "0" * 64, "src:sha256:" + "0" * 63, "src:sha256:" + "F" * 64, "sha256:" + "0" * 64, "", None, 5, [VER], VER + " ", VER.upper()])
    elif op == 16: m["dataset_id"] = rnd.choice(["dst_ab", "dst_a", "dst_" + "a" * 64, "dst_" + "a" * 65, "DST_ab", "dst_AB", "dst-ab", "dst_ab\n", "dst_я", "", None, 5, "dst_registry_demo", "dst_other", "ent_ab"])
    elif op == 17: m["tenant_id"] = rnd.choice(["tnt_demo", "tnt_other", "tnt_d", "tnt_" + "a" * 64, "tnt_" + "a" * 65, "TNT_demo", "", None, 5, "tnt_demo\n", " tnt_demo"])
    elif op == 18: m["manifest_format"] = rnd.choice(["ac-dataset-manifest/0.1", "ac-dataset-manifest/0.2", "AC-DATASET-MANIFEST/0.1", "ac-dataset-manifest/0.1 ", None, 1, ""])
    elif op == 19: m[rnd.choice(["owner", "deleted_keys", "Columns", "", "a\u0000b", "я", "manifest_format ", "x" * 300])] = rnd.choice([None, 1, "x", [], {}])
    elif op == 20: del m[rnd.choice(list(m))]
    elif op == 21:
        c = rnd.choice(m["columns"]); c[rnd.choice(["note", "nullable", "Name", "unit", ""])] = rnd.choice([None, True, "x"])
    elif op == 22:
        c = rnd.choice(m["columns"]); c.pop(rnd.choice(list(c)))
    elif op == 23:
        n = rnd.choice([1, 50, 2000]); f0 = m["files"][0]
        m["files"] = [dict(f0, rows=1) for _ in range(n)]; m["row_count"] = n
    elif op == 24:
        d = x = {}
        for _ in range(rnd.choice([3, 63, 64, 65, 200])): x["a"] = {}; x = x["a"]
        tgt = rnd.choice(["deep", "version_label", "columns", "files", "key"]); m[tgt] = d
    elif op == 25: m["columns"] = rnd.choice([[], None, {}, "x", [None], [[]], [1], m["columns"] + [m["columns"][0]], m["columns"][::-1]])
    elif op == 26:
        c = rnd.choice(m["columns"]); c["type"] = rnd.choice(["INTEGER", "BOOLEAN", "DATE"])           # идентификатор у нестроковой
    elif op == 27: m["subject"] = [c["name"] for c in m["columns"] if "identifier_scheme" in c][:rnd.choice([1, 2, 8, 9])]
    elif op == 28:
        m["columns"] = [dict(col(i), identifier_scheme="ru.inn") if True else 0 for i in range(rnd.choice([8, 9, 10]))]
        for c in m["columns"]: c["type"] = "STRING"
        m["key"] = [c["name"] for c in m["columns"]][:rnd.choice([8, 9])]; m["subject"] = [c["name"] for c in m["columns"]][:rnd.choice([8, 9])]
    elif op == 29: m["version_label"] = rnd.choice([None, 5, True, [], {}, ["x"], "", " ", "　", "x"])
    elif op == 30: rnd.choice(m["columns"])["name"] = rnd.choice([c["name"] for c in m["columns"]])
    elif op == 31:
        m["files"] = []; m["row_count"] = rnd.choice([0, 0, 1])
    elif op == 32:
        c = rnd.choice(m["columns"]); c["marking"] = {"level": rnd.choice(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
                                                     "categories": rnd.sample(["PERSONAL_DATA", "COMMERCIAL_SECRET", "STATE_SECRET", "BANK_SECRET", "MEDICAL"], rnd.randrange(3))}
    else: pass
    return m

NUMF = [lambda n: f"{n}.0", lambda n: f"{n}e0", lambda n: f"{n}E0", lambda n: f"{n}e+0", lambda n: f"0{n}", lambda n: f"+{n}", lambda n: f"-{n}", lambda n: f"{n}.00",
        lambda n: f"{n}0e-1", lambda n: f"0.{n}e1", lambda n: "-0" if n == 0 else f"{n}e-0", lambda n: f" {n}", lambda n: f"0x{n:x}", lambda n: "NaN", lambda n: "Infinity",
        lambda n: f"{n}e0000", lambda n: f"\"{n}\"", lambda n: f"{n}." , lambda n: f"{n}e400", lambda n: "1e2" if n == 100 else f"{n}"]
def textual(b):
    """мутация на уровне байтов"""
    op = rnd.randrange(22)
    t = b.decode("utf-8", "surrogatepass") if op < 16 else None
    if op in (0, 1, 2):
        nums = list(re.finditer(r'(?<=:)(\d+)(?=[,}\]])', t))
        if nums:
            mm = rnd.choice(nums); n = int(mm.group(1)); return (t[:mm.start()] + rnd.choice(NUMF)(n) + t[mm.end():]).encode("utf-8", "surrogatepass")
    if op in (3, 4):                                          # символ строки -> \uXXXX
        idx = [i for i, ch in enumerate(t) if ch.isalnum() or ord(ch) > 127]
        if idx:
            i = rnd.choice(idx); cp = ord(t[i])
            if cp > 0xFFFF:
                cp -= 0x10000; esc = "\\u%04x\\u%04x" % (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF))
            else:
                esc = ("\\u%04x" if rnd.random() < .5 else "\\u%04X") % cp
            return (t[:i] + esc + t[i + 1:]).encode("utf-8", "surrogatepass")
    if op == 5: return t.replace('"version_label":"', '"version_label":"' + rnd.choice(["\\ud800", "\\udc00", "\\ud800\\ud800", "\\udc00\\ud800", "\\u0000", "\\u001f", "\\u007f", "\\/", "\\u0020", "\\x41", "\\'", "\\u00e9", "\\uD83D\\uDE00"]), 1).encode()
    if op == 6: return json.dumps(json.loads(t), ensure_ascii=rnd.random() < .5, separators=rnd.choice([(",", ":"), (", ", ": "), (",", ": ")]), sort_keys=rnd.random() < .7).encode()
    if op == 7:
        i = t.find(",\"");  return (t[:i] + "," + t[1:i] + t[i:]).encode() if i > 0 else b       # повтор первого ключа
    if op == 8: return rnd.choice([b"\xef\xbb\xbf", b" ", b"\n", b"\t"]) + b
    if op == 9: return b + rnd.choice([b" ", b"\n", b"\x00", b"}", b"{}", b"\r\n", b"//x"])
    if op == 10: return t.encode(rnd.choice(["utf-16", "utf-16-le", "utf-32", "cp1251"]), "replace")
    if op == 11: return t.replace("true", rnd.choice(["True", "TRUE", "1", "\"true\""])).replace("null", rnd.choice(["None", "NULL", "nil"])).encode()
    if op == 12: return t.replace('"key":[', '"key" :[', 1).encode() if rnd.random() < .5 else t.replace(",", ", ", 1).encode()
    if op == 13: return ("[" + t + "]").encode() if rnd.random() < .5 else json.dumps(t).encode()
    if op == 14: return t.replace("{", "{\"\":1,", 1).encode() if rnd.random() < .5 else t[:-1].encode()
    if op == 15: return t.replace('"row_count":', '"row_count":' + rnd.choice(["", "-", "--", "0", "1"]), 1).encode()
    if op == 16:
        i = rnd.randrange(len(b)); return b[:i] + rnd.choice([b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\x80", b"\xe2\x28\xa1", b"\x00", b"\x7f", b"\x1f"]) + b[i + 1:]
    if op == 17: return b.replace(b'"version_label":"', b'"version_label":"' + rnd.choice([b"\xed\xa0\x80", b"\xc3\x28", b"\x00", b"\x7f", b"\xc2\x80", b"\xef\xbf\xbf", b"\xf0\x9f\x98\x80", b"\xe2\x80\x8b"]), 1)
    return b

cases, seen = [], {canon(BASE).encode()}
while len(cases) < N:
    m = copy.deepcopy(BASE)
    k = rnd.choice([0, 1, 1, 1, 2])
    try:
        for _ in range(k): m = structural(m)
    except Exception:
        continue
    try:
        b = canon(m).encode("utf-8")
    except Exception:
        try: b = json.dumps(m, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8", "surrogatepass")
        except Exception: continue
    if k == 0 or rnd.random() < .25: b = textual(b)
    if b in seen or len(b) > 3_000_000: continue
    seen.add(b); cases.append(b)

setup = """
CREATE FUNCTION pg_temp.manifest_verdict(b64 text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE b bytea := decode(b64, 'base64'); sid text; pub jsonb := '{"level":"PUBLIC","categories":[]}';
BEGIN
  sid := 'src:sha256:' || encode(sha256(b), 'hex');
  BEGIN
    INSERT INTO ac.sources VALUES ('tnt_demo', sid, length(b), pub, jsonb_build_object('kind', 'Source', 'schema_version', 'core-ontology/0.4',
      'tenant_id', 'tnt_demo', 'source_kind', 'DATASET_VERSION', 'media_type', 'application/vnd.ac.dataset-manifest+json',
      'language', 'ru', 'title', 'fuzz', 'marking', pub, 'byte_length', length(b), 'source_id', sid));
    INSERT INTO ac.source_bytes VALUES ('tnt_demo', sid, b);
    INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) VALUES ('tnt_demo', sid, '2026-09-05T08:00:00Z', 'urn:fuzz', 'svc_dataset_loader');
    SET CONSTRAINTS ALL IMMEDIATE;
    RAISE EXCEPTION 'FUZZ_ACCEPTED';
  EXCEPTION WHEN others THEN
    RETURN replace(replace(SQLERRM, E'\\n', ' '), E'\\r', ' ');
  END;
END $f$;"""
out = []
for st in range(0, len(cases), 400):
    r = psql(setup + "\n" + "\n".join(f"SELECT pg_temp.manifest_verdict('{base64.b64encode(b).decode()}');" for b in cases[st:st + 400]))
    if r.returncode: sys.exit("harness: " + r.stderr[:1500])
    out += r.stdout.splitlines()
assert len(out) == len(cases), (len(out), len(cases))
diff, acc = [], 0
CT0 = {k: v for k, v in CT.items() if v[:5] != b'{"h":'}          # файлы строк база не читает: валидатору их не даём
recs = DS["records"]; si = next(i for i, x in enumerate(recs) if x["kind"] == "Source" and x["source_kind"] == "DATASET_VERSION")
for b, v in zip(cases, out):
    why = None
    try:
        text = b.decode("utf-8")
        extra = dict(recs[si], content_inline=text, byte_length=len(b), source_id="src:sha256:" + hashlib.sha256(b).hexdigest(), title="fuzz")
        rep = VAL.validate(dict(DS, records=recs + [extra]), TR, dict(CT0, **{extra["source_id"]: b}))
        py_ok, why = not rep.errors, (rep.errors[0]["code"] + ": " + rep.errors[0]["msg"][:80]) if rep.errors else None
    except UnicodeDecodeError:
        py_ok = False
    db_ok = v.startswith("FUZZ_ACCEPTED")
    acc += py_ok and db_ok
    if py_ok != db_ok:
        diff.append(("валидатор ПРИНЯЛ, база отвергла" if py_ok else "база ПРИНЯЛА, валидатор отверг", b[:260], why, v[:140]))
print(f"манифест: случаев {len(cases)}, принято обоими {acc}, отвергнуто обоими {len(cases) - acc - len(diff)}, РАСХОЖДЕНИЙ {len(diff)}")
kinds = {}
for d in diff:
    key = (d[0], re.sub(r"[0-9a-f]{16,}", "…", str(d[2] or "") + " || " + d[3])[:150])
    kinds.setdefault(key, []).append(d)
for (k, sig), lst in sorted(kinds.items(), key=lambda x: -len(x[1])):
    print(f"\n[{len(lst)}×] {k}\n    причины: {sig}\n    пример байтов: {lst[0][1]!r}")

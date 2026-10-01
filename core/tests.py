"""Acceptance suite for core-ontology/0.2 (fast; the mutation run is separate: mutants.py).

T1 valid world: 0 errors, exactly the expected warning.
T2 every vector through the real validator yields EXACTLY its expected error-code set (positives: none).
T3 rule coverage: every error code (except the internal safety net) has a negative vector.
T4 fail-closed fuzz: 3000 seeded random corruptions of the valid world - the validator always returns a
   report (never raises) and never reports VALIDATOR_INTERNAL_ERROR.
T5 JCS: RFC 8785 key-order example, escaping, Cyrillic; rejects float / 2^53 / lone surrogates (values and keys).
T6 JCS parity Python == Node on every record of every schema-valid dataset + tricky strings/keys.
T8 the validator refuses to run on a Unicode version other than the one the database tables were generated for.
T7 CLI: world + trust + content-dir -> exit 0; float input, 100 000-deep nesting -> exit 1 without traceback;
   a sub-directory inside --content-dir is ignored.
"""
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from jcs import canon, digest, CanonicalizationError
from validator import ERROR_CODES, validate
from vectors import VECTORS, build

HERE = Path(__file__).resolve().parent
fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# T1
base, trust, content = build()
R = validate(base, trust, content)
check(R.errors == [], f"T1 errors: {R.codes()}")
check([w["code"] for w in R.warnings] == ["CONTRADICTION_SINGLE_VALUED"], f"T1 warnings: {R.warnings}")

# T2
schema_valid = [base]
for v in VECTORS:
    d, tr, ct = build(v)
    rr = validate(d, tr, ct)
    got = rr.codes()
    check(got == v["expected"], f"T2 {v['id']}: expected {v['expected']} got {got}")
    if v["warn"] is not None:
        check([w["code"] for w in rr.warnings] == v["warn"], f"T2 {v['id']}: warnings {[w['code'] for w in rr.warnings]}")
    if "SCHEMA_INVALID" not in got:
        schema_valid.append(d)

# T3
covered = {c for v in VECTORS for c in v["expected"]}
need = set(ERROR_CODES) - {"VALIDATOR_INTERNAL_ERROR"}
check(need <= covered, f"T3 codes without vector: {sorted(need - covered)}")

# T4 fuzz
rng = random.Random(20260930)
JUNK = [None, True, 0, -1, 2**40, "", " ", "x", "ent_x", "2026-13-01", [], {}, [1], {"a": 1}, "src:sha256:" + "0" * 64]


def paths(node, p=()):
    yield p
    if isinstance(node, dict):
        for k, v in node.items():
            yield from paths(v, p + (k,))
    elif isinstance(node, list):
        for n, v in enumerate(node):
            yield from paths(v, p + (n,))


all_paths = [p for p in paths(base) if p]
crashes = internal = 0
for i in range(3000):
    d = copy.deepcopy(base)
    for _ in range(rng.randint(1, 3)):
        p = rng.choice(all_paths)
        node = d
        try:
            for k in p[:-1]:
                node = node[k]
            if rng.random() < 0.3 and isinstance(node, dict):
                node.pop(p[-1], None)
            else:
                node[p[-1]] = rng.choice(JUNK)
        except (KeyError, IndexError, TypeError):
            pass
    try:
        r = validate(d, trust, content)
        internal += "VALIDATOR_INTERNAL_ERROR" in r.codes()
    except Exception as ex:  # noqa: BLE001
        crashes += 1
        if crashes <= 3:
            fails.append(f"T4 crash on fuzz case {i}: {type(ex).__name__}: {ex}")
check(crashes == 0 and internal == 0, f"T4 fuzz: crashes={crashes} internal_errors={internal}")

# T5
rfc = {"€": "Euro Sign", "\r": "Carriage Return", "\uFB33": "Hebrew Letter Dalet With Dagesh", "1": "One",
       "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
check(list(json.loads(canon(rfc))) == ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "\uFB33"], "T5 RFC 8785 key order")
check(canon({"b": "ТЕНАНТ-01", "a": [1, True, None]}) == '{"a":[1,true,null],"b":"ТЕНАНТ-01"}', "T5 cyrillic")
check(canon("\u0001\n\"\\/\u007f\u2028") == '"\\u0001\\n\\"\\\\/\u007f\u2028"', "T5 escaping")
for bad in (1.5, 1.0, 2**53, "\ud800", {"\ud800": 1}):
    try:
        canon(bad)
        fails.append(f"T5 accepted {bad!r}")
    except CanonicalizationError:
        pass

# T6
tricky = [rfc, {"\uE000": 1, "\U0001F600": 2}, {"\u0080": 1, "\u007f": 2, "\uFFFF": 3, "\U00010000": 4},
          "\u2028\u2029", "\u0000\u001f\u007f", {"__proto__": 1, "a": 2}, {"é": 1, "e\u0301": 2}, -0]
recs = [r for d in schema_valid for r in d["records"]] + tricky
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
    json.dump(recs, f, ensure_ascii=False)
out = subprocess.run(["node", str(HERE / "jcs.mjs"), f.name], capture_output=True, text=True, check=True).stdout.split("\n")
node = [line.split("\t")[1] for line in out if line]
py = [digest(r) for r in recs]
check(len(node) == len(py) and py == node, f"T6 node/python differ on {sum(a != b for a, b in zip(py, node))} of {len(py)}")

# T7
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / "ds.json").write_text(json.dumps(base, ensure_ascii=False), encoding="utf-8")
    (tmp / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
    (tmp / "c").mkdir()
    for sid, b in content.items():
        (tmp / "c" / sid.split(":")[-1]).write_bytes(b)
    stripped = copy.deepcopy(base)
    for r in stripped["records"]:
        r.pop("content_inline", None)
    (tmp / "prod.json").write_text(json.dumps(stripped, ensure_ascii=False), encoding="utf-8")
    bad = copy.deepcopy(base)
    bad["records"][0]["x"] = 1.0
    (tmp / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    run = lambda *a: subprocess.run([sys.executable, str(HERE / "validator.py"), *a], capture_output=True, text=True)
    r1 = run(str(tmp / "prod.json"), "--trust", str(tmp / "trust.json"), "--content-dir", str(tmp / "c"))
    r2 = run(str(tmp / "bad.json"), "--trust", str(tmp / "trust.json"))
    r3 = run(str(tmp / "prod.json"))
    check(r1.returncode == 0, f"T7 prod-shape CLI exit {r1.returncode}: {r1.stdout[-300:]}")
    check(r2.returncode == 1 and "Traceback" not in r2.stderr and "SCHEMA_INVALID" in r2.stdout, "T7 float CLI")
    check(r3.returncode == 1 and "SOURCE_CONTENT_UNAVAILABLE" in r3.stdout and "RECEIPT_KEY_INVALID" in r3.stdout,
          "T7 no trust/no content must fail closed")
    # RR-05: pathological nesting and a directory inside --content-dir must not produce a traceback
    (tmp / "deep.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    (tmp / "c" / "subdir").mkdir()
    r4 = run(str(tmp / "deep.json"))
    r5 = run(str(tmp / "prod.json"), "--trust", str(tmp / "trust.json"), "--content-dir", str(tmp / "c"))
    check(r4.returncode == 1 and "Traceback" not in r4.stderr and "SCHEMA_INVALID" in r4.stdout, f"T7 deep nesting CLI: {r4.stderr[-200:]}")
    check(r5.returncode == 0 and "Traceback" not in r5.stderr, f"T7 subdirectory in content-dir: {r5.stderr[-200:]}")

# T8 pinned Unicode (S5R-13): with another Unicode version the validator refuses instead of computing other keys/digests
import validator as _V  # noqa: E402
_saved = _V.UNICODE_VERSION
_V.UNICODE_VERSION = "0.0.0"
_r8 = validate(base, trust, content)
_V.UNICODE_VERSION = _saved
check(_r8.codes() == ["VALIDATOR_INTERNAL_ERROR"], f"T8 unicode pin: {_r8.codes()}")

neg = sum(1 for v in VECTORS if v["expected"])
print(f"T1 valid world: records={len(base['records'])} errors={len(R.errors)} warnings={len(R.warnings)}")
print(f"T2 vectors: {len(VECTORS)} ({neg} negative, {len(VECTORS) - neg} positive)")
print(f"T3 error codes covered: {len(covered & need)}/{len(need)}")
print(f"T4 fuzz: 3000 cases, crashes={crashes}, internal={internal}")
print(f"T6 JCS parity py/node: {len(py)} values")
print(f"T8 Unicode pinned to {_saved}: another version -> {_r8.codes()}")
print("FAILURES:" if fails else "ALL PASS", *fails, sep="\n  ")
sys.exit(1 if fails else 0)

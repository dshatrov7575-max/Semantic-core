"""Acceptance suite for core-ontology/0.3 (fast; the mutation run is separate: mutants.py).

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
T9 Model Constructor CLI (D27.1): each command adds one version through the validator; refusals leave the file intact.
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

# T9 Model Constructor CLI (D27.1): every command = one new version through the validator; a refusal leaves the file intact
with tempfile.TemporaryDirectory() as tmp:
    f9 = str(Path(tmp) / "schema.json")
    mc = lambda *a: subprocess.run([sys.executable, str(HERE / "model_constructor.py"), *a], capture_output=True, text=True)  # noqa: E731
    by = ["--tenant", "tnt_demo", "--by", "usr_modeler1", "--description", "тест T9"]
    ok_steps = [
        ("init", f9),
        ("add-class", f9, "sdf_animal", *by, "--root-type", "THING", "--name", "Животное", "--abstract", "--at", "2026-10-01T10:00:00Z"),
        ("add-class", f9, "sdf_shark", *by, "--root-type", "THING", "--name", "Акула", "--parent", "sdf_animal", "--at", "2026-10-01T10:01:00Z"),
        ("add-attribute", f9, "sdf_animal", *by, "--predicate", "x.max_depth", "--name", "глубина погружения", "--type", "QUANTITY",
         "--unit", "m", "--required", "--at", "2026-10-01T10:02:00Z"),
        ("add-identifier", f9, "sdf_tag", *by, "--scheme", "x.tag", "--root-type", "THING", "--name", "Метка", "--strength", "WEAK",
         "--priority", "1", "--format", "UPPER:2,lit:-,DIGIT:4", "--at", "2026-10-01T10:03:00Z"),
        ("add-attribute", f9, "sdf_shark", *by, "--predicate", "x.tag_no", "--name", "номер метки", "--type", "IDENTIFIER",
         "--scheme", "x.tag", "--at", "2026-10-01T10:04:00Z"),
        ("add-link", f9, "sdf_eats", *by, "--predicate", "x.eats", "--name", "питается", "--domain", "sdf_shark", "--range", "sdf_animal",
         "--at", "2026-10-01T10:05:00Z"),
        ("change-attribute", f9, "sdf_animal", *by, "--predicate", "x.max_depth", "--optional", "--at", "2026-10-01T10:06:00Z"),
        ("rename", f9, "sdf_shark", *by, "--name", "Акулы"),                      # no --at: the clock (and the wait for the next second)
        ("add-class", f9, "sdf_secret", *by, "--root-type", "THING", "--name", "Закрытый класс", "--marking", "RESTRICTED:COMMERCIAL_SECRET"),
        ("validate", f9)]
    for st in ok_steps:
        r9 = mc(*st)
        check(r9.returncode == 0, f"T9 {st[0]} {st[2] if len(st) > 2 else ''}: exit {r9.returncode}: {r9.stderr[-200:]}")
    before9 = Path(f9).read_bytes()
    bad_steps = [
        ("add-class", f9, "sdf_x1", *by, "--root-type", "THING", "--name", "Класс", "--parent", "sdf_no_such_parent"),
        ("add-class", f9, "sdf_x2", *by, "--root-type", "THING", "--name", "   "),
        ("add-class", f9, "sdf_x3", *by, "--root-type", "CONCEPT", "--name", "Класс", "--parent", "sdf_animal"),
        ("add-attribute", f9, "sdf_shark", *by, "--predicate", "x.max_depth", "--name", "повтор", "--type", "STRING"),
        ("add-attribute", f9, "sdf_shark", *by, "--predicate", "x.other", "--name", "без единицы", "--type", "QUANTITY"),
        ("change-attribute", f9, "sdf_shark", *by, "--predicate", "x.max_depth", "--many"),
        ("add-identifier", f9, "sdf_re", *by, "--scheme", "x.re", "--root-type", "THING", "--name", "Регулярка", "--strength", "WEAK",
         "--priority", "2", "--format", "(a+)+$"),
        ("add-identifier", f9, "sdf_inn", *by, "--scheme", "ru.inn", "--root-type", "ORGANIZATION", "--name", "ИНН", "--strength", "WEAK",
         "--priority", "1"),
        ("rename", f9, "sdf_animal", *by, "--name", "Животные", "--marking", "PUBLIC"),
        ("rename", f9, "sdf_animal", *by, "--name", "Животные", "--at", "2026-09-01T00:00:00Z"),
        ("rename", f9, "sdf_animal", *by, "--name", "Животные", "--at", "2099-01-01T00:00:00Z"),
        ("add-link", f9, "sdf_l2", *by, "--predicate", "x.eats", "--name", "повтор", "--domain", "sdf_shark", "--range", "sdf_shark")]
    for st in bad_steps:
        r9 = mc(*st)
        check(r9.returncode == 1 and "Traceback" not in r9.stderr and Path(f9).read_bytes() == before9,
              f"T9 refusal {st[0]} {st[2]}: exit {r9.returncode}, file changed={Path(f9).read_bytes() != before9}: {r9.stderr[-200:]}")
    sh9 = mc("show", f9, "--tenant", "tnt_demo")
    check(sh9.returncode == 0 and "x.max_depth «глубина погружения»: QUANTITY m, ONE (от sdf_animal)" in sh9.stdout
          and "sdf_shark v3 «Акулы»" in sh9.stdout and "x.eats" in sh9.stdout and "RESTRICTED" in sh9.stdout,
          f"T9 show: {sh9.stdout[-400:]} {sh9.stderr[-200:]}")
    sh9b = mc("show", f9, "--tenant", "tnt_demo", "--at", "2026-10-01T10:01:30Z")
    check(sh9b.returncode == 0 and "x.max_depth" not in sh9b.stdout and "классов 2" in sh9b.stdout, f"T9 show --at: {sh9b.stdout[-300:]}")
    jr9 = mc("journal", f9, "--tenant", "tnt_demo")
    check(jr9.returncode == 0 and len(jr9.stdout.strip().splitlines()) == 9 and "CHANGE_ATTRIBUTE ClassDef sdf_animal v3" in jr9.stdout,
          f"T9 journal: {jr9.stdout[-300:]}")
    ds9 = json.loads(Path(f9).read_text(encoding="utf-8"))
    schema_valid.append(ds9)

neg = sum(1 for v in VECTORS if v["expected"])
print(f"T1 valid world: records={len(base['records'])} errors={len(R.errors)} warnings={len(R.warnings)}")
print(f"T2 vectors: {len(VECTORS)} ({neg} negative, {len(VECTORS) - neg} positive)")
print(f"T3 error codes covered: {len(covered & need)}/{len(need)}")
print(f"T4 fuzz: 3000 cases, crashes={crashes}, internal={internal}")
print(f"T6 JCS parity py/node: {len(py)} values")
print(f"T8 Unicode pinned to {_saved}: another version -> {_r8.codes()}")
print(f"T9 Model Constructor CLI: {len(ok_steps)} commands accepted, {len(bad_steps)} refused with the file intact, show/journal checked")
print("FAILURES:" if fails else "ALL PASS", *fails, sep="\n  ")
sys.exit(1 if fails else 0)

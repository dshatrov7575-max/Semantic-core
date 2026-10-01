"""Executable acceptance suite for core-ontology/0.1.

T1  valid world: 0 errors, exactly the expected warnings.
T2  every vector (built by fixtures.py and run through the real validator)
    yields EXACTLY its expected error-code set (isolation: no collateral codes).
T3  mutation/necessity: with the vector's rule(s) disabled the same dataset is
    clean -> each rule is the only thing standing between the vector and acceptance.
T4  rule coverage: every error code of the validator has >= 1 negative vector.
T5  JCS: RFC 8785 key-ordering example + Cyrillic/control-char vectors (py == expected bytes).
T6  JCS parity Python vs Node over every record of every dataset (incl. Cyrillic).
Prints a summary; exit code 1 on any failure.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from fixtures import VECTORS, build
from jcs import canon, digest
from validator import ERROR_CODES, validate

HERE = Path(__file__).resolve().parent
fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# T1
base = build()
R = validate(base)
check(R.errors == [], f"T1 valid world has errors: {R.codes()}")
check([w["code"] for w in R.warnings] == ["CONTRADICTION_SINGLE_VALUED"], f"T1 warnings: {R.warnings}")

# T2 + T3
datasets = [base]
for v in VECTORS:
    d = build(v)
    datasets.append(d)
    got = validate(d).codes()
    check(got == sorted(v["expected"]), f"T2 {v['id']}: expected {v['expected']} got {got}")
    if v["expected"]:
        again = validate(d, disabled=set(v["expected"]))
        check(again.errors == [], f"T3 {v['id']}: with rule disabled still errors {again.codes()}")

# T4
covered = {c for v in VECTORS for c in v["expected"]}
check(set(ERROR_CODES) <= covered, f"T4 codes without vector: {sorted(set(ERROR_CODES) - covered)}")

# T5  RFC 8785 §3.2.3 sorting example, plus escaping
rfc = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
       "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
order = [k for k in json.loads(canon(rfc))]
check(order == ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"], f"T5 RFC8785 key order {order!r}")
check(canon({"b": "ТЕНАНТ-01", "a": [1, True, None]}) == '{"a":[1,true,null],"b":"ТЕНАНТ-01"}', "T5 cyrillic literal")
check(canon("\u0001\n\"\\/\u007f") == '"\\u0001\\n\\"\\\\/\u007f"', "T5 escaping")
for bad in (1.5, 2**53, "\ud800"):
    try:
        canon(bad)
        fails.append(f"T5 accepted {bad!r}")
    except ValueError:
        pass

# T6  Node parity
recs = [r for d in datasets if isinstance(d.get("records"), list) for r in d["records"]
        if "confidence" not in r]  # N01 carries a float on purpose (outside JCS profile)
recs.append(rfc)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
    json.dump(recs, f, ensure_ascii=False)
out = subprocess.run(["node", str(HERE / "jcs.mjs"), f.name], capture_output=True, text=True, check=True).stdout.split("\n")
node = [l.split("\t")[1] for l in out if l]
py = [digest(r) for r in recs]
mism = sum(a != b for a, b in zip(py, node))
check(len(node) == len(py) and mism == 0, f"T6 node/python digests differ: {mism} of {len(py)}")

neg = sum(1 for v in VECTORS if v["expected"])
print(f"T1 valid world: records={len(base['records'])} errors={len(R.errors)} warnings={len(R.warnings)}")
print(f"T2 vectors: {len(VECTORS)} ({neg} negative, {len(VECTORS) - neg} positive boundary)")
print(f"T3 necessity runs: {neg}")
print(f"T4 error codes covered: {len(covered & set(ERROR_CODES))}/{len(ERROR_CODES)}")
print(f"T6 JCS parity py/node: {len(py)} records")
print("FAILURES:" if fails else "ALL PASS", *fails, sep="\n  ")
sys.exit(1 if fails else 0)

#!/usr/bin/env python3
"""S5R-02 regression: ac.text_digest == validator.text_digest_of for EVERY code point (except surrogates), each placed
between a letter and a combining acute, next to a space and twice — so NFC, ignorable dropping, whitespace folding and
the «unassigned in the validator's Unicode version» rule are all exercised. Inputs travel as hex (bytea), so NUL and
noncharacters are compared too. Usage: PGHOST=... PGDATABASE=<db with ddl_s5> python3 slice/parity_s5_exhaustive.py
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402

CHUNK = 40000


def main():
    cps = [cp for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF]
    bad = total = 0
    for i in range(0, len(cps), CHUNK):
        part = cps[i:i + CHUNK]
        hexes = [("a" + chr(cp) + chr(0x301) + " " + chr(0x20) + chr(cp) + "b").encode("utf-8").hex() for cp in part]
        r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"],
                           input=f"SELECT json_agg(ac.text_digest(decode(h, 'hex')) ORDER BY n) FROM jsonb_array_elements_text($j${json.dumps(hexes)}$j$::jsonb) "
                                 "WITH ORDINALITY a(h, n);", capture_output=True, text=True)
        if r.returncode:
            sys.exit(r.stderr[:400])
        db = json.loads(r.stdout.strip())
        for cp, h, d in zip(part, hexes, db):
            total += 1
            if d != VAL.text_digest_of(bytes.fromhex(h)):
                bad += 1
                if bad <= 10:
                    print(f"  U+{cp:04X}: db={d} validator={VAL.text_digest_of(bytes.fromhex(h))}")
    print(f"code_points={total} mismatches={bad}")
    print("S5_EXHAUSTIVE=" + ("PASS" if bad == 0 else "FAIL"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

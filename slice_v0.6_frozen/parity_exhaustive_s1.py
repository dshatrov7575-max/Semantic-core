#!/usr/bin/env python3
"""Exhaustive single-code-point parity of the SQL key functions with the validator: for EVERY code point cp the
word 'x' + cp + '1' is normalised by PostgreSQL and by Python and the UTF-8 bytes are compared.
Code points unassigned in Python's Unicode database (category Cn) are reported separately: PostgreSQL 16 carries
Unicode 15.0, Python 3.11 carries 14.0, so newer characters (e.g. U+1E030.. Cyrillic modifier letters) get more
folding in the database; the database is the stricter side there. About 10 minutes per function.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<db with the slice> python3 slice/parity_exhaustive_s1.py [fn ...]
"""
import os
import subprocess
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402

FNS = {"base_key": ("ac.base_key(w)", VAL.base_key), "skel": ("ac.skel(w)", VAL.norm),
       "skel_nokc": ("ac.skel(w, false)", lambda s: VAL.norm(s, nfkc=False)),
       "tag_norm": ("ac.tag_norm(w)", VAL.tag_norm), "id_norm": ("ac.id_norm(w)", VAL.id_norm)}


def main():
    names = sys.argv[1:] or list(FNS)
    total_bad = 0
    for name in names:
        sqlexpr, fn = FNS[name]
        r = subprocess.run(["psql", "-XAt", "-c", f"SELECT cp, coalesce(encode(convert_to({sqlexpr}, 'UTF8'), 'hex'), '<null>') FROM "
                            "(SELECT cp, 'x' || chr(cp) || '1' AS w FROM generate_series(1, 1114111) cp WHERE cp < 55296 OR cp > 57343) v ORDER BY cp"],
                           capture_output=True, text=True, env=os.environ)
        if r.returncode:
            sys.exit(r.stderr[:500])
        bad, newer = [], []
        for line in r.stdout.split("\n"):
            if not line:
                continue
            cp_s, _, got = line.partition("|")
            cp = int(cp_s)
            exp = fn("x" + chr(cp) + "1").encode("utf-8").hex()
            if got != exp:
                (newer if unicodedata.category(chr(cp)) == "Cn" else bad).append(hex(cp))
        total_bad += len(bad)
        print(f"{name}: mismatches={len(bad)} {bad[:12]} | unassigned-in-Python (Unicode {unicodedata.unidata_version}) folded by PostgreSQL: {len(newer)} {newer[:4]}")
    print("EXHAUSTIVE_PARITY_RESULT=" + ("PASS" if total_bad == 0 else "FAIL"))
    return 1 if total_bad else 0


if __name__ == "__main__":
    sys.exit(main())

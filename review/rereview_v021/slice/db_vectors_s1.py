#!/usr/bin/env python3
"""Honest DB coverage: every NEGATIVE vector of core/vectors.py is loaded into a fresh schema WITHOUT the validator
gate. Reports which error codes the database enforces on its own and which stay validator-only.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=... python3 slice/db_vectors_s1.py
"""
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import load_s1 as L  # noqa: E402
from vectors import VECTORS, build  # noqa: E402

DDL = (HERE / "ddl_s1.sql").read_text(encoding="utf-8")


def main():
    by_code = defaultdict(lambda: [0, 0, 0])  # rejected, accepted, not representable
    rows = []
    for v in VECTORS:
        if not v["expected"]:
            continue
        try:
            ds, tr, ct = build(v)
            sql = L.load_sql(ds, tr, ct)
            sql.encode("utf-8")
        except Exception as ex:  # noqa: BLE001 - input the SQL loader / UTF-8 wire cannot even express
            res, msg = "N/A", f"{type(ex).__name__}"
        else:
            L.psql(DDL)
            r = L.psql(sql)
            if r.returncode:
                res = "REJECTED"
                msg = next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr.strip()[:120])
            else:
                res, msg = "ACCEPTED", ""
        for c in v["expected"]:
            by_code[c][{"REJECTED": 0, "ACCEPTED": 1, "N/A": 2}[res]] += 1
        rows.append((v["id"], ",".join(v["expected"]), res, msg.replace("psql:<stdin>:", "")[:140]))
    for r in rows:
        print(" | ".join(r))
    print("\nкод ошибки | отвергнуто БД | принято БД | не представимо в SQL")
    for c in sorted(by_code):
        a, b, n = by_code[c]
        print(f"{c} | {a} | {b} | {n}")
    tot = [sum(x[i] for x in by_code.values()) for i in range(3)]
    rej = sum(1 for r in rows if r[2] == "REJECTED")
    acc = sum(1 for r in rows if r[2] == "ACCEPTED")
    na = sum(1 for r in rows if r[2] == "N/A")
    print(f"\nnegative_vectors={len(rows)} rejected_by_db={rej} accepted_by_db={acc} not_representable={na}")
    L.psql(DDL)
    return 0


if __name__ == "__main__":
    sys.exit(main())

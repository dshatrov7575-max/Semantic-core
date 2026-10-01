"""Parity harness: the same mutated world -> validator codes and DB (fresh DDL in PGDATABASE, no validator gate)."""
import os, sys, copy, json, hashlib, time
from pathlib import Path
AS = Path("/home/claude/as")
sys.path.insert(0, str(AS / "core")); sys.path.insert(0, str(AS / "slice")); sys.path.insert(0, str(AS / "adapter"))
import validator as VAL
from vectors import build, V
import load_s1 as L

def run(desc, pre=None, post=None, db=True):
    ds, tr, ct = build(V("X", [], desc, pre=pre, post=post))
    rep = VAL.validate(ds, tr, ct)
    vcodes = rep.codes()
    dbres = "-"
    if db:
        L.psql(L.DDL_ALL)
        r = L.psql(L.load_sql(ds, tr, ct))
        dbres = "ACCEPTED" if r.returncode == 0 else "REJECTED: " + next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), r.stderr[:150]).replace("psql:<stdin>:", "")[:160]
    print(f"[{desc}] validator={vcodes or 'CLEAN'} warn={sorted({w['code'] for w in rep.warnings})} | db={dbres}", flush=True)
    return vcodes, dbres, rep

def art(fn):
    return lambda W: fn(W["__artifacts__"]["umr_ns2"])

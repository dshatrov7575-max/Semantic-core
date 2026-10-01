#!/usr/bin/env python3
"""S21 parity fuzz: SQL identity normalisation (keys_s1.sql) vs Python validator (validator.py).
Finds inputs where ac.base_key/skel/id_norm/tag_norm diverge from the Python normative code.
A divergence is exploitable: DB derives keys with SQL norm; validator with Python norm, so a string
that Python folds to an existing key but SQL does not => duplicate identity accepted by DB (RS-01),
or vice versa => validator-legal world the DB falsely rejects/merges.
Usage: PGHOST=.. PGPORT=.. PGUSER=postgres PGDATABASE=.. SLICE=<slice dir> python3 parity_fuzz.py
"""
import os, subprocess, sys, unicodedata
from pathlib import Path
SLICE = Path(os.environ.get("SLICE", "/home/claude/s21/slice"))
sys.path.insert(0, str(SLICE)); sys.path.insert(0, str(SLICE.parent / "core"))
import validator as VAL

def psql_rows(pairs):
    # pairs: list of (tag, s). Build one query returning tag|fn|py-unused; we compute SQL side.
    vals = ",".join("(%s,%s)" % (lit(t), lit(s)) for t, s in pairs)
    sql = f"""
WITH v(tag,s) AS (VALUES {vals})
SELECT tag, ac.base_key(s), ac.skel(s), ac.id_norm(s), ac.tag_norm(s) FROM v;"""
    r = subprocess.run(["psql","-X","-q","-v","ON_ERROR_STOP=1","-At","-F","\t"],
                       input=sql, capture_output=True, text=True)
    if r.returncode:
        sys.exit("SQL error: " + r.stderr[:400])
    out = {}
    for ln in r.stdout.splitlines():
        parts = ln.split("\t")
        out[parts[0]] = parts[1:]
    return out

def lit(s):
    return "'" + s.replace("'", "''") + "'"

def gen():
    cases = []
    # 1) all Cf category code points
    for cp in range(1, 0x110000):
        if 0xD800 <= cp <= 0xDFFF: continue
        try:
            if unicodedata.category(chr(cp)) == "Cf":
                cases.append(("cf_%X" % cp, "a" + chr(cp) + "b"))
        except Exception: pass
    # 2) wide/narrow decomposition code points
    for cp in range(1, 0x110000):
        if 0xD800 <= cp <= 0xDFFF: continue
        d = unicodedata.decomposition(chr(cp))
        if d.startswith(("<wide>", "<narrow>")):
            cases.append(("wn_%X" % cp, "a" + chr(cp) + "b"))
    # 3) dash category Pd + minus
    for cp in range(1, 0x30000):
        if 0xD800 <= cp <= 0xDFFF: continue
        if unicodedata.category(chr(cp)) == "Pd":
            cases.append(("pd_%X" % cp, "a" + chr(cp) + "b"))
    # 4) Pi/Pf punctuation
    for cp in range(1, 0x30000):
        if 0xD800 <= cp <= 0xDFFF: continue
        if unicodedata.category(chr(cp)) in ("Pi","Pf"):
            cases.append(("pif_%X" % cp, "a" + chr(cp) + "b"))
    # 5) whitespace-ish
    for cp in list(range(0x9,0xE))+[0x1C,0x1D,0x1E,0x1F,0x20,0x85,0xA0,0x1680]+list(range(0x2000,0x200B))+[0x2028,0x2029,0x202F,0x205F,0x3000]:
        cases.append(("ws_%X" % cp, "a" + chr(cp) + "b"))
    return cases

def main():
    cases = gen()
    # chunk to avoid huge queries
    div = []
    CH = 400
    for i in range(0, len(cases), CH):
        chunk = cases[i:i+CH]
        sqlres = psql_rows(chunk)
        for tag, s in chunk:
            py = [VAL.base_key(s), VAL.norm(s), VAL.id_norm(s), VAL.tag_norm(s)]
            sq = sqlres.get(tag)
            if sq is None:
                div.append((tag, s, "NO-SQL-ROW", py, None)); continue
            if py != sq:
                div.append((tag, s, "DIFF", py, sq))
    print("cases=%d divergences=%d" % (len(cases), len(div)))
    for tag, s, kind, py, sq in div[:80]:
        cps = " ".join("U+%04X" % ord(c) for c in s)
        print(f"{tag} [{cps}] {kind}\n   PY base={py[0]!r} skel={py[1]!r} id={py[2]!r} tag={py[3]!r}")
        if sq: print(f"   SQL base={sq[0]!r} skel={sq[1]!r} id={sq[2]!r} tag={sq[3]!r}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

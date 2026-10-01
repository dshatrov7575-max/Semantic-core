#!/usr/bin/env python3
"""Parity of identity keys: SQL port (keys_s1.sql) vs the normative validator (validator.py).
  1) every entity of every vector world: ac.identity_keys(type, identity) vs validator.entity_identifiers();
  2) a corpus of hostile strings: ac.base_key / ac.skel / ac.id_norm / ac.tag_norm vs Python.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<db with ddl_s1+keys_s1 applied> python3 slice/keys_parity_s1.py
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import load_s1 as L  # noqa: E402
import validator as VAL  # noqa: E402
from vectors import VECTORS, build  # noqa: E402

HELPER = """
CREATE SCHEMA IF NOT EXISTS ac_test;
CREATE OR REPLACE FUNCTION ac_test.keys_or_err(t text, i jsonb) RETURNS text LANGUAGE plpgsql AS $$
DECLARE r text;
BEGIN
  SELECT coalesce(jsonb_agg(jsonb_build_array(scheme, value, strength, qual) ORDER BY scheme, value, strength, qual)::text, '[]')
    INTO r FROM ac.identity_keys(t, i);
  RETURN r;
EXCEPTION WHEN others THEN
  RETURN 'ERR:' || split_part(SQLERRM, ':', 1);
END $$;
"""


def py_keys(t, i):
    R = VAL.Report()
    try:
        st, wk, sf = VAL.entity_identifiers({"entity_type": t, "identity": i}, R, "x")
    except Exception as ex:  # noqa: BLE001
        return None, {f"PYEXC:{type(ex).__name__}"}
    rows = [[a, b, "STRONG", None] for a, b in st] + [[a, b, "WEAK", q] for a, b, q in wk] + \
           [["skel:" + a, b, "SOFT", None] for a, b in sf]
    rows.sort(key=lambda r: tuple("" if x is None else x for x in r))
    return rows, set(R.codes())


def sql_rows(pairs):
    vals = ",".join(f"({L.q(t)},{L.q(json.dumps(i, ensure_ascii=False))}::jsonb)" for t, i in pairs)
    r = L.psql(f"SELECT ac_test.keys_or_err(t, i) FROM (VALUES {vals}) v(t, i);")
    if r.returncode:
        raise SystemExit(r.stderr)
    return r.stdout.rstrip("\n").split("\n")


def main():
    L.psql(HELPER)
    seen, pairs = set(), []
    for v in [None] + VECTORS:
        try:
            ds, _, _ = build(v)
        except Exception:  # noqa: BLE001
            continue
        for rec in ds["records"]:
            if rec.get("kind") == "Entity" and isinstance(rec.get("identity"), dict):
                k = (rec["entity_type"], json.dumps(rec["identity"], sort_keys=True, ensure_ascii=False))
                if k not in seen and "\ud800" not in k[1]:
                    seen.add(k)
                    pairs.append((rec["entity_type"], rec["identity"]))
    out = sql_rows(pairs)
    mism = 0
    for (t, i), s in zip(pairs, out):
        rows, codes = py_keys(t, i)
        if s.startswith("ERR:"):
            ok = s[4:] in codes
        else:
            ok = not (codes & {"IDENTIFIER_CHECKSUM_INVALID", "ENTITY_IDENTITY_INSUFFICIENT"}) and json.loads(s) == rows
        if not ok:
            mism += 1
            if mism <= 15:
                print("ENTITY MISMATCH", t, json.dumps(i, ensure_ascii=False)[:120], "| sql:", s[:160], "| py:", rows, sorted(codes))
    print(f"entities compared={len(pairs)} mismatches={mism}")

    # string corpus
    rnd = random.Random(20260930)
    alphabet = list("АаВЕКМНОРСТХУаеокрстхуЁёАБВГДЕЖЗИЙЛПФЦЧШЩЪЫЬЭЮЯабвгджзийлпфцчшщъыьэюя"
                    "AaBbCcEeHKkMOoPpTXxYyΑΒΕΖΗΙΚΜΝΟΡΤΥΧαειοκρτυχνΣσςßẞİıĲǅ"
                    "0123456789 -_./:\"'«»„“”‚‘’‹›`–—‑−⸺―\u00A0\u2009\u3000\t"
                    "\u00AD\u034F\u200B\u200D\u2060\uFEFF\uFE0F\u3164\u180E\U000e0041\u0301\u0308"
                    "\uFF11\uFF12\uFF21\uFF41\uFF0D\uFF0F\uFF4B²½ﬁ℃Ⅱ№ǆ㎏") + [chr(c) for c in (  # v0.2.2 / S21-01: half-width kana and hangul, fullwidth macron, accents,
        0xFF71, 0xFF76, 0xFF9E, 0xFF9F, 0xFFA1, 0xFFC2, 0xFFE3, 0xFFE8, 0x30A2, 0x0300, 0x0301, 0x0306, 0x0308, 0x0327, 0x20D7,
        0x1DC4, 0x13AA, 0xAB7A, 0x13A2, 0x1D0F, 0x1D00, 0x0299, 0x0585, 0x0555, 0x03F9, 0x03F2, 0x2800, 0x00EB, 0x00CB,
        0x0439, 0x0419, 0x0451, 0x0401)] + ["Ломов", "Заречье", "НМ 16-100", "PT-101", "РТ-101"]
    words = ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 10))) for _ in range(3000)]
    fns = [("base_key", lambda s: VAL.base_key(s)), ("skel", VAL.norm), ("skel_nokc", lambda s: VAL.norm(s, nfkc=False)),
           ("id_norm", VAL.id_norm), ("tag_norm", VAL.tag_norm), ("tag_compact", VAL.tag_compact)]
    sqlf = {"skel_nokc": "ac.skel(w, false)"}
    smis = 0
    for name, fn in fns:
        vals = ",".join(f"({L.q(w)})" for w in words)
        r = L.psql(f"SELECT coalesce({sqlf.get(name, f'ac.{name}(w)')}, '<null>') FROM (VALUES {vals}) v(w);")
        got = r.stdout.rstrip("\n").split("\n") if r.returncode == 0 else ["<psql error>"] * len(words)
        bad = [(w, g, fn(w)) for w, g in zip(words, got) if g != fn(w)]
        smis += len(bad)
        print(f"{name}: {len(words) - len(bad)}/{len(words)} equal")
        for w, g, e in bad[:6]:
            print(f"   {name} MISMATCH {w!r}: sql={g!r} py={e!r}")
    print(f"PARITY_RESULT={'PASS' if mism == 0 and smis == 0 else 'FAIL'}")
    return 0 if mism == 0 and smis == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

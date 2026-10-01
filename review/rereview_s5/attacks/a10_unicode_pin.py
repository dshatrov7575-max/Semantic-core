#!/usr/bin/env python3
"""A10 (final check of S5R-13): the Unicode pin of the validator under another interpreter.
  P1  validate() on the valid world: Python 3.11 -> no errors; 3.12/3.13 -> VALIDATOR_INTERNAL_ERROR (fail-closed)
  P2  the module-level helpers (text_digest_of, pub_norm, norm) are NOT guarded: under 3.12/3.13 they still return
      values different from the database — callers that use them directly (fixtures, adapters, tests helpers) are not stopped.
Run: python3.11 a10_unicode_pin.py; PYTHONPATH=stubs python3.12 a10_unicode_pin.py; PYTHONPATH=stubs python3.13 a10_unicode_pin.py
(stubs: jsonschema/cryptography without network; schema/signature checks are not reached when the pin refuses)
"""
import subprocess, sys, unicodedata
sys.path.insert(0, "/home/claude/as/core")
import validator as VAL
import pickle
W = "/home/claude/as/review/rereview_s5/attacks/a10_world.pkl"
if unicodedata.unidata_version == "14.0.0":          # the world is built (and signed) under the pinned interpreter only
    from vectors import build
    pickle.dump(build(), open(W, "wb"))
ds, trust, content = pickle.load(open(W, "rb"))
codes = VAL.validate(ds, trust, content).codes()
t = "Жители в шоке " + chr(0x1FAE8)
r = subprocess.run(["psql", "-X", "-q", "-At"], input=f"SELECT coalesce(ac.text_digest(decode('{t.encode().hex()}','hex')),'NULL');", capture_output=True, text=True)
print(f"A10 python {sys.version.split()[0]} unicode {unicodedata.unidata_version} | validate(мир) -> {codes} | "
      f"text_digest_of(эмодзи U+1FAE8) = {str(VAL.text_digest_of(t.encode()))[:22]} db={r.stdout.strip()[:22]}")

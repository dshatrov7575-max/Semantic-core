#!/usr/bin/env python3
"""A08 (after the S5R-02 fix): the «Cn in the validator's Unicode version» rule.
  V1  the validator's text_digest_of uses the RUNTIME unicodedata; the database class is frozen at generation (Unicode 14).
      The same core/validator.py run under python3.12 (Unicode 15.0) / python3.13 (15.1) gives a digest where the database
      gives NULL — the publication address depends on the interpreter again (only the direction of the divergence changed).
      Run: for py in python3.11 python3.12 python3.13; do uv run -q -p $py --with jsonschema --with cryptography python a08_unicode_version.py; done
  V2  ordinary modern texts: emoji of Unicode 15/15.1 (🫨 U+1FAE8, 🩷 U+1FA77, 🪿 U+1FABF) make a text «not comparable»:
      such articles are never deduplicated (every fetch is its own item and its own support).
"""
import subprocess
import sys
import unicodedata

sys.path.insert(0, "/home/claude/as/core")
import validator as VAL  # noqa: E402

CASES = {"e+U+1E4EC+U+0301": "e" + chr(0x1E4EC) + chr(0x301), "emoji U+1FAE8": "Жители в шоке " + chr(0x1FAE8),
         "emoji U+1FA77": "Любим район " + chr(0x1FA77), "emoji U+1FABF": "Гуси " + chr(0x1FABF)}
for name, t in CASES.items():
    b = t.encode()
    py = VAL.text_digest_of(b)
    r = subprocess.run(["psql", "-X", "-q", "-At"], input=f"SELECT coalesce(ac.text_digest(decode('{b.hex()}','hex')),'NULL');",
                       capture_output=True, text=True)
    pg = r.stdout.strip()
    print(f"A08 python {sys.version.split()[0]} unicode {unicodedata.unidata_version} | {name:<18} validator={str(py)[:22]:<24} db={pg[:22]:<24} "
          f"equal={(py or 'NULL') == pg}")

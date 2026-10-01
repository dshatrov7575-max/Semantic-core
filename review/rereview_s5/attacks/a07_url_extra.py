#!/usr/bin/env python3
"""A07: extra URL parity (IDN Unicode host, punycode, backslash, empty params, '+' scheme) — validator vs database."""
import json, subprocess, sys
sys.path.insert(0, "/home/claude/as/core")
import validator as VAL
BS = chr(92)
U = ["https://пример.рф/a", "https://xn--e1afmkfd.xn--p1ai/a", "https://news.example" + BS + "zarechye", "https://news.example/?&&a=1&&",
     "https://news.example/a?utm_source", "https://news.example/a?=1", "HTTP://NEWS.EXAMPLE:80", "https://news.example:443/", "git+https://news.example/a",
     "https://news.example/a?b=2&a=1&a=0", "https://news.example/" + chr(0x0301), "https://news.example/a?Ä=1&a=1&ä=2"]
payload = json.dumps(U)
r = subprocess.run(["psql", "-X", "-q", "-At"], input=f"SELECT json_agg(json_build_array(ac.url_norm(s), ac.url_outlet(s)) ORDER BY n) FROM jsonb_array_elements_text($j${payload}$j$::jsonb) WITH ORDINALITY a(s,n);", capture_output=True, text=True)
db = json.loads(r.stdout.strip())
bad = 0
for u, d in zip(U, db):
    py = [VAL.url_norm(u), VAL.url_outlet(u)]
    bad += py != d
    print(f"{'OK ' if py == d else 'DIFF'} {u!r:<45} py={py} db={d}")
print("A07 mismatches", bad)

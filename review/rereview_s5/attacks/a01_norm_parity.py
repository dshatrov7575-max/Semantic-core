#!/usr/bin/env python3
"""A01: parity and semantics of the S5 normalizers (validator <-> database) on hostile inputs.
  a) NFC across Unicode versions: Python unicodedata (validator) vs PostgreSQL normalize() — brute force over all code points
     in the strings  e + X + U+0301  and  X + U+0301  (new combining classes / compositions)
  b) bytes with NUL: text_digest_of vs ac.text_digest
  c) URL semantics: what host do url_norm / url_outlet attribute (userinfo, chars outside the host class, port glued to path)
  d) idempotency: url_outlet(u) == url_outlet(url_norm(u)), pub_norm(pub_norm(x)) == pub_norm(x)
Usage: PGHOST=... PGDATABASE=review051 python3 a01_norm_parity.py
"""
import json
import subprocess
import sys
import unicodedata

sys.path.insert(0, "/home/claude/as/core")
import validator as VAL  # noqa: E402

BS = chr(92)


def psql(sql):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr[:800])
    return r.stdout


print("python", sys.version.split()[0], "unicodedata", unicodedata.unidata_version)
print("pg", psql("SHOW server_version;").strip())

# ---------------- a) NFC brute force, done in the database in one pass; Python recomputes the same strings
ACUTE = 0x0301
q = f"""
SELECT string_agg(c::text || ':' || encode(convert_to(ac.pub_norm(chr(101) || chr(c) || chr({ACUTE})), 'UTF8'), 'hex')
                  || ':' || encode(convert_to(ac.pub_norm(chr(c) || chr({ACUTE})), 'UTF8'), 'hex'), ',')
FROM generate_series(1, 1114111) c WHERE c NOT BETWEEN 55296 AND 57343;
"""
db = psql(q).strip().split(",")
bad = []
for row in db:
    c, h1, h2 = row.split(":")
    c = int(c)
    p1 = VAL.pub_norm("e" + chr(c) + chr(ACUTE)).encode("utf-8").hex()
    p2 = VAL.pub_norm(chr(c) + chr(ACUTE)).encode("utf-8").hex()
    if p1 != h1 or p2 != h2:
        bad.append((hex(c), unicodedata.name(chr(c), "?"), h1, p1, h2, p2))
print(f"A01a NFC brute force: code points={len(db)} mismatches={len(bad)}")
for b in bad[:8]:
    print("   ", b)
if bad:
    c = int(bad[0][0], 16)
    s = "e" + chr(c) + chr(ACUTE)
    py = VAL.text_digest_of(s.encode())
    pg = psql(f"SELECT ac.text_digest(decode('{s.encode().hex()}', 'hex'));").strip()
    for b0 in bad:
        c = int(b0[0], 16)
        s = "e" + chr(c) + chr(ACUTE)
        py = VAL.text_digest_of(s.encode())
        pg = psql(f"SELECT coalesce(ac.text_digest(decode('{s.encode().hex()}', 'hex')), 'NULL');").strip()
        print(f"A01a text_digest for e+{hex(c)}+U+0301: validator={str(py)[:20]} db={pg[:20]} equal={(py or 'NULL') == pg}")

# ---------------- b) NUL inside UTF-8 bytes
for b in (b"abc\x00def", b"\x00", "Заречная\x00".encode()):
    py = VAL.text_digest_of(b)
    pg = psql(f"SELECT coalesce(ac.text_digest(decode('{b.hex()}', 'hex')), 'NULL');").strip()
    print(f"A01b bytes={b!r:<28} validator={(py or 'None')[:24]:<26} db={pg[:24]}  equal={py == pg or (py is None and pg == 'NULL')}")

# ---------------- c) URL host attribution vs RFC 3986 / WHATWG host
URLS = [
    ("https://news.example@evil.example/zarechye", "evil.example"),
    ("https://news.example:443@evil.example/zarechye", "evil.example"),
    ("https://news.example_x.attacker.com/zarechye", "news.example_x.attacker.com"),
    ("https://news.example~attacker.com/zarechye", "?"),
    ("http://news.example:80evil.com/zarechye", "?"),
    ("https://news.example%2eattacker.com/zarechye", "?"),
    ("https://news.example" + BS + "@evil.example/", "news.example (whatwg)"),
    ("https://www.co.uk/a", "www.co.uk"), ("https://m.co.uk/a", "m.co.uk"), ("https://amp.co.uk/a", "amp.co.uk"),
    ("https://news.example:8443/a", "news.example:8443"),
    ("https://NEWS.example./a?b=&a=1&utm_x=1#f", "news.example"),
    ("https://news.example/a?A=1&a=1", "news.example"),
]
for u, real in URLS:
    n, o = VAL.url_norm(u), VAL.url_outlet(u)
    payload = json.dumps(u)
    pg = psql(f"SELECT coalesce(ac.url_norm(s), 'NULL') || ' | ' || coalesce(ac.url_outlet(s), 'NULL') FROM (SELECT $j${payload}$j$::jsonb->>0 s) x;").strip()
    o2 = VAL.url_outlet(n) if n else None
    print(f"A01c {u!r:<52} real host={real:<28} outlet={o!s:<14} norm={n!s:<48} db=[{pg}]  outlet(norm(u))={o2}  idempotent={o == o2}")

# ---------------- d) pub_norm idempotency over every code point (with surrounding spaces)
nonid = []
for c in range(1, 0x110000):
    if 0xD800 <= c <= 0xDFFF:
        continue
    s = " " + chr(c) + " " + chr(ACUTE)
    a = VAL.pub_norm(s)
    if VAL.pub_norm(a) != a:
        nonid.append(hex(c))
print(f"A01d pub_norm idempotent: non-idempotent code points={len(nonid)} {nonid[:10]}")

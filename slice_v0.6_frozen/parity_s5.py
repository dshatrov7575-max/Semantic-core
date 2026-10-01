#!/usr/bin/env python3
"""S5 parity: the database normalizers equal the validator's on hostile inputs.
  ac.pub_norm / ac.text_digest  == validator.pub_norm / text_digest_of   (text of a rendition)
  ac.url_norm / ac.url_outlet   == validator.url_norm / url_outlet      (canonical address, outlet)
  ac.publication_address        == validator.publication_address
Inputs: every source of the world, seeded random strings mixing whitespace of the class and around it, invisible and
combining characters, letters, and random URLs (case, ports, dots, prefixes www./m./amp., tracking and other parameters,
fragments, non-http schemes). Usage: PGHOST=... PGDATABASE=<db with ddl_s5> python3 slice/parity_s5.py [N]
"""
import json
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
rng = random.Random(20261001)
WS = sorted(VAL._PUB_WS)
NEAR_WS = [chr(c) for c in (0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x1C, 0x1D, 0x1E, 0x1F, 0x200E, 0x0301, 0x0308,
                            0x0306, 0x00E9, 0x0065, 0x0418, 0x0439, 0x0438, 0x0306, 0x212B, 0x00C5, 0x1E9B, 0x0323, 0xFB01, 0x3000)]
LETTERS = list("абвгдеёжзийклмнопрстуфхцчшщъыьэюяABCabc012 .,«»—-") + ["\U0001F600", "İ", "ı"]


def rand_text():
    parts = []
    for _ in range(rng.randint(0, 25)):
        r = rng.random()
        parts.append(rng.choice(WS) if r < 0.35 else rng.choice(NEAR_WS) if r < 0.6 else rng.choice(LETTERS))
    return "".join(parts)


HOSTS = ["news.example", "NEWS.Example.", "www.news.example", "m.news.example", "amp.news.example", "www.www.a.b", "m.b",
         "WWW.M.X.Y", "a..b", "-x.y", "xn--80ak6aa92e.example", "1.2.3.4", "localhost", ""]
PARAMS = ["utm_source=tg", "UTM_Medium=x", "fbclid=1", "gclid=2", "yclid=", "_openstat=a", "a=1", "b=2", "A=3", "b=1", "x",
          "=y", "id=10", "id=9", "mc_cid=z", "q=%D0%B0", "utm=1", "utm_=2"]


def rand_url():
    scheme = rng.choice(["http", "https", "HTTPS", "Http", "ftp", "urn:demo", "mailto"])
    host = rng.choice(HOSTS)
    port = rng.choice(["", "", ":80", ":443", ":8080", ":0443", ":99999"])
    path = rng.choice(["", "/", "/a", "/A/b/", "/a?", "//x", "/путь", "/a b", "/%20"])
    q = "&".join(rng.choice(PARAMS) for _ in range(rng.randint(0, 4)))
    frag = rng.choice(["", "", "#f", "#a?b=1", "#", "#a" + chr(10) + "b", "#" + chr(13)])
    sep = "?" if q or rng.random() < 0.2 else ""
    if scheme in ("urn:demo", "mailto"):
        return f"{scheme}:{host}{path}"
    return f"{scheme}://{host}{port}{path}{sep}{q}{frag}"


def ok_pg(s):
    return "\x00" not in s and not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def psql(sql):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr[:500])
    return r.stdout


def run(kind, items, sql_expr, py):
    items = [x for x in items if ok_pg(x)]
    payload = json.dumps(items, ensure_ascii=True)
    assert "$j$" not in payload
    out = psql(f"SELECT coalesce(json_agg({sql_expr} ORDER BY n), '[]') FROM jsonb_array_elements_text($j${payload}$j$::jsonb) WITH ORDINALITY a(s, n);")
    db = json.loads(out.strip().splitlines()[-1])
    bad = [(x, d, py(x)) for x, d in zip(items, db) if d != py(x)]
    print(f"{kind:<22} inputs={len(items):<6} mismatches={len(bad)}")
    for b in bad[:5]:
        print("   ", ascii(b)[:240])
    return len(bad)


def main():
    ds, _, content = build()
    texts = [s["content_inline"] for s in ds["records"] if s["kind"] == "Source" and "content_inline" in s]
    texts += [rand_text() for _ in range(N)]
    urls = [o["origin_uri"] for s in ds["records"] if s["kind"] == "Source" for o in s["observations"]]
    urls += [p["canonical_url"] for p in ds["records"] if p["kind"] == "Publication"] + [rand_url() for _ in range(N)]
    bad = 0
    bad += run("pub_norm", texts, "ac.pub_norm(s)", VAL.pub_norm)
    bad += run("text_digest", texts, "ac.text_digest(convert_to(s, 'UTF8'))", lambda s: VAL.text_digest_of(s.encode("utf-8")))
    bad += run("url_norm", urls, "ac.url_norm(s)", VAL.url_norm)
    bad += run("url_outlet", urls, "ac.url_outlet(s)", VAL.url_outlet)
    raw = [bytes(rng.choice([0x00, 0x20, 0x41, 0xC3, 0xA9, 0xD0, 0x96, 0xE2, 0x80, 0x8B, 0xFF, 0xED, 0xA0, 0xF4, 0x90, 0x0A])
                 for _ in range(rng.randint(0, 12))).hex() for _ in range(N // 3)]
    bad += run("text_digest(bytes)", raw, "ac.text_digest(decode(s, 'hex'))", lambda h: VAL.text_digest_of(bytes.fromhex(h)))
    triples = [json.dumps([rng.choice(["tnt_demo", "tnt_other", "tnt_x1"]), rng.choice(["news.example", "a.b", "xn--80ak6aa92e.example"]),
                           "sha256:" + "".join(rng.choice("0123456789abcdef") for _ in range(64))]) for _ in range(500)]
    bad += run("publication_address", triples, "ac.publication_address(s::jsonb->>0, s::jsonb->>1, s::jsonb->>2)",
               lambda t: VAL.publication_address(*json.loads(t)))
    print("S5_PARITY=" + ("PASS" if bad == 0 else "FAIL"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

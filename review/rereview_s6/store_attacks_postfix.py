#!/usr/bin/env python3
"""S6 review: attacks on object_store.py / s3_emulator.py / gateway.py.
Usage: PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=review06x python3 store_attacks.py
(fresh load of slice/load_s1.py). Starts its own emulator processes on free ports and stops them by PID."""
import datetime, hashlib, hmac, http.client, json, os, socket, subprocess, sys, tempfile, time, urllib.parse
from pathlib import Path
sys.path.insert(0, "/home/claude/as/slice"); sys.path.insert(0, "/home/claude/as/core"); sys.path.insert(0, "/home/claude/as/store")
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
import requests
import object_store as OS
from object_store import ObjectStore, S3Backend, FsBackend, sigv4_signature, object_key
import gateway as GW
import s3_tests as S3, s5_tests as S5
from ingest_s4 import ingest_sql, utc

assert os.environ.get("PGDATABASE", "").startswith("review06")
EMU = "/home/claude/as/store/s3_emulator.py"

def psql(sql, user=None):
    pre = f"SET SESSION AUTHORIZATION {user};\n" if user else ""
    return subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=pre + sql, capture_output=True, text=True)
def one(sql, user=None):
    r = psql(sql, user)
    if r.returncode: raise RuntimeError(r.stderr.strip()[:400])
    return r.stdout.strip()
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
def emulator(root, port):
    srv = subprocess.Popen([sys.executable, EMU, str(root), str(port), "AKTEST", "sekret"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ))
    for _ in range(100):
        try: requests.get(f"http://127.0.0.1:{port}/x", timeout=1); break
        except requests.RequestException: time.sleep(0.2)
    return srv
for _s in (S3.SETUP, S5.SETUP):
    try: one(_s)
    except RuntimeError: pass

tmp = Path(tempfile.mkdtemp(prefix="s6rev_"))
port = free_port(); srv = emulator(tmp, port); ep = f"http://127.0.0.1:{port}"
good = ObjectStore(S3Backend(ep, "originals", "AKTEST", "sekret"))
try:
    print("== B1: any backend failure is journalled as MISSING (immutable) — wrong/expired credentials, 5xx")
    raw = b"<html>original page for review S6 B1</html>"
    og = GW.register(good, "tnt_demo", raw, "text/html")
    time.sleep(0.3)
    bad = ObjectStore(S3Backend(ep, "originals", "AKTEST", "expired-secret"))
    # POST-FIX ADAPTATION (S6R-05 closed): scrub() now RAISES on a rejected signature instead of returning a
    # {'OK':.., 'MISSING':.., 'CORRUPT':..} stats dict (the original finding was that it silently counted this
    # as MISSING). The original script asserted the stats dict unconditionally; wrapped here so B2-B9 still run.
    try:
        st = GW.scrub(bad, "tnt_demo")
    except Exception as e:
        st = f"RAISED {type(e).__name__}: {str(e)[:140]}"
    print("  the object is intact on disk:", (tmp / "originals" / object_key("tnt_demo", og["object"])).read_bytes() == raw)
    print("  scrub with a rejected signature (HTTP 403 for every GET) returned:", st)
    print("  journal:", one(f"SELECT string_agg(result, ',' ORDER BY checked_at) FROM ac.object_checks WHERE object_address='{og['object']}'"))
    s = S5.source("Текст страницы B1, рецензия S6.", "https://news.example/b1", utc(0)); s["observations"][0]["original"] = og
    r = psql(ingest_sql([s], {}))
    print("  consequence: observation naming the intact original:", "accepted" if r.returncode == 0 else r.stderr.strip().splitlines()[0][:110])
    try: chk = bad.check("tnt_demo", og["object"])
    except Exception as e: chk = f"RAISES {type(e).__name__}"
    print("  store.check on a 403:", chk, "| store.get on a 403 raises:", end=" ")
    try: bad.get("tnt_demo", og["object"]); print("nothing")
    except Exception as e: print(type(e).__name__, str(e)[:60])

    print("\n== B2: client signs Host with an explicit default port, the HTTP library sends it without -> every request 403")
    canon = S3Backend("http://s3.example.com:80", "b", "k", "s")
    pr = requests.Request("GET", "http://s3.example.com:80/b/k").prepare()
    import http.client as hc
    class Rec(hc.HTTPConnection):
        def connect(self): raise OSError("stop")
    c = hc.HTTPConnection("s3.example.com", 80); buf = []
    c.send = lambda d: buf.append(d); c.connect = lambda: None; c.sock = object()
    c.putrequest("GET", "/b/k"); c.endheaders()
    print("  signed host:", canon.host, "| Host header actually sent by http.client/urllib3:", [l for l in b"".join(buf).split(b"\r\n") if l.lower().startswith(b"host")])

    print("\n== B3: the gateway's database session is a SUPERUSER session (SET SESSION AUTHORIZATION), not role ac_storage")
    try:
        b3 = GW._psql("RESET SESSION AUTHORIZATION;\nSELECT 'now ' || current_user || ', superuser=' || current_setting('is_superuser') || "
                       "', source_bytes rows readable=' || (SELECT count(*) FROM ac.source_bytes) || ', claims=' || (SELECT count(*) FROM ac.claims);").strip()
    except Exception as e:
        b3 = f"RAISES {type(e).__name__}: {str(e)[:120]}"
    print("  through gateway._psql:", b3)
    print("  login roles that are members of ac_storage:", one("SELECT count(*) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid WHERE r.rolname='ac_storage'"))
    inj = ("import sys; sys.path.insert(0,'/home/claude/as/store'); import gateway as GW\n"
           "class St:\n    def check(self,*a): return 'OK'\n"
           "t = 'x' + GW.TAG + '; RESET SESSION AUTHORIZATION; CREATE TABLE IF NOT EXISTS public.s6_pwned AS SELECT current_user AS who, (SELECT count(*) FROM ac.claims) AS claims; --'\n"
           "try:\n    print(GW.scrub(St(), t))\nexcept Exception as e:\n    print(type(e).__name__, str(e)[:80])\n")
    for flag in ([], ["-O"]):
        psql("DROP TABLE IF EXISTS public.s6_pwned")
        r = subprocess.run([sys.executable] + flag + ["-c", inj], capture_output=True, text=True)
        print(f"  scrub(tenant=<payload>) under python3 {' '.join(flag) or '(default)'}: {r.stdout.strip()[:90]} | injected table exists:",
              one("SELECT coalesce((SELECT who || '/' || claims FROM public.s6_pwned), 'no')") if one("SELECT to_regclass('public.s6_pwned') IS NOT NULL") == "t" else "no")
    psql("DROP TABLE IF EXISTS public.s6_pwned")

    print("\n== B4: scrub stamps results at the END of the run (database clock at insert), not when the object was read")
    a1 = GW.register(good, "tnt_demo", b"object one, review S6 B4", "text/plain")
    a2 = GW.register(good, "tnt_demo", b"object two, review S6 B4", "text/plain")
    first, second = sorted([a1["object"], a2["object"]])
    class Slow(ObjectStore):
        def check(self, tenant, addr, n=None):
            res = super().check(tenant, addr, n)
            if addr == first:      # damage it right after it was read; the run continues for a while (large store)
                (tmp / "originals" / object_key(tenant, addr)).write_bytes(b"DAMAGED")
                self.damaged_at = one("SELECT clock_timestamp()"); time.sleep(3)
            return res
    slow = Slow(S3Backend(ep, "originals", "AKTEST", "sekret"))
    try: st = GW.scrub(slow, "tnt_demo")
    except Exception as e: st = repr(e)
    row = one(f"SELECT result || ' checked_at=' || checked_at FROM ac.object_checks WHERE object_address='{first}' ORDER BY checked_at DESC LIMIT 1")
    print("  object damaged at", slow.damaged_at, "| journal says:", row, "| really now:", good.check("tnt_demo", first))

    print("\n== B5: one registry row with an odd tenant stops every later scrub (rows are immutable)")
    h = "sha256:" + hashlib.sha256(b"tab").hexdigest()
    try:
        one(f"BEGIN;\nINSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES (E'tnt\\tx','{h}',1);\n"
            f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES (E'tnt\\tx','{h}','OK');\nCOMMIT;", "ac_storage")
        poisoned = False
    except RuntimeError as e:
        # POST-FIX (S6R-09 closed): ac.objects now has CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'), so the poisoned
        # row this attack relies on can no longer be inserted at all -- there is nothing left for scrub() to choke on.
        print("  poisoned row refused at insert:", str(e).strip().splitlines()[0][:100])
        poisoned = True
    if not poisoned:
        try: print("  scrub of everything:", GW.scrub(good))
        except Exception as e: print("  scrub of everything raises:", type(e).__name__, str(e)[:80])
        try: print("  scrub of tnt_demo only:", GW.scrub(good, "tnt_demo"))
        except Exception as e: print("  scrub of tnt_demo raises:", type(e).__name__, str(e)[:80])

    print("\n== B6: tenant isolation by prefix — listing")
    # POST-FIX adaptation: the original example tenants 'tnt_a'/'tnt_ab' no longer both pass valid_tenant() /
    # object_key() now that S6R-09's own recommended pattern (^tnt_[a-z0-9_]{2,64}$, >=2 chars after 'tnt_') is
    # enforced -- 'tnt_a' has only 1. Same collision, both names now schema-valid: 'tnt_ab' is still a string
    # prefix of 'tnt_abc'.
    fs = ObjectStore(FsBackend(tmp / "fs"))
    fs.put("tnt_ab", b"alpha"); fs.put("tnt_abc", b"beta")
    good.put("tnt_ab", b"alpha"); good.put("tnt_abc", b"beta")
    print("  FsBackend.keys('tnt_ab') ->", [k.split('/')[0] for k in fs.b.keys("tnt_ab")], "| S3Backend.keys('tnt_ab') ->", [k.split('/')[0] for k in good.b.keys("tnt_ab")])
    print("  tenant-safe ObjectStore.keys('tnt_ab') ->", [k.split('/')[0] for k in fs.keys("tnt_ab")], "/", [k.split('/')[0] for k in good.keys("tnt_ab")])
    accepted = []
    for t in ("sha256", "_", "0"):
        try: object_key(t, "sha256:" + "0" * 64); accepted.append(t)
        except OS.ObjectStoreError: pass
    print("  object_key accepts tenants the schema forbids (^tnt_[a-z0-9_]{2,64}$):", accepted, "(S6R-09 fix: object_key now validates too)")
    for t in ("tnt/x", "..", "tnt_x/..", "TNT_X", "tnt-x", "tnt_x\n", ""):
        try: object_key(t, "sha256:" + "0" * 64); print(f"  tenant {t!r}: ACCEPTED")
        except OS.ObjectStoreError: pass
    print("  tenants with '/', '..', upper case, '-', newline, empty: refused by object_key")

    print("\n== B7: SigV4 — independent implementation vs object_store.sigv4_signature")
    def ref(method, host, path, query, headers, ph, secret, region, amz):
        enc = lambda s_, safe="": urllib.parse.quote(s_, safe=safe + "-_.~")
        cq = "&".join(sorted(f"{enc(k)}={enc(v)}" for k, v in query.items()))
        hs = dict({k.lower(): " ".join(v.split()) for k, v in headers.items()}, host=host)
        ch = "".join(f"{k}:{hs[k]}\n" for k in sorted(hs))
        cr = "\n".join([method, enc(path, "/"), cq, ch, ";".join(sorted(hs)), ph])
        scope = f"{amz[:8]}/{region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(cr.encode()).hexdigest()])
        k = ("AWS4" + secret).encode()
        for p_ in (amz[:8], region, "s3", "aws4_request"): k = hmac.new(k, p_.encode(), hashlib.sha256).digest()
        return hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    amz = "20260102T030405Z"; e = hashlib.sha256(b"").hexdigest(); H = {"x-amz-date": amz, "x-amz-content-sha256": e}
    cases = {"put object": ("PUT", "/originals/tnt_demo/sha256/ab/" + "ab" * 32, {}),
             "list prefix+token (+/= space)": ("GET", "/originals", {"list-type": "2", "prefix": "tnt_demo/", "continuation-token": "1a+b/c= d~*"}),
             "query names whose raw and encoded order differ": ("GET", "/originals", {"a~": "1", "a" + chr(0xe9): "2"}),
             "key with space, '+', '%', unicode": ("GET", "/originals/a b+c%25/" + chr(0x44f), {})}
    for name, (m, p_, q_) in cases.items():
        mine = ref(m, "h:9000", p_, q_, H, e, "s", "us-east-1", amz); his = sigv4_signature(m, "h:9000", p_, q_, H, e, "s", "us-east-1", amz)[0]
        print(f"  {name:<46}", "same" if mine == his else "DIFFERENT")

    print("\n== B8: what the emulator does NOT check (real S3/MinIO do) — so the suite cannot see these client faults")
    def raw_call(region="us-east-1", amz=None, method="GET", path="/originals/" + object_key("tnt_demo", og["object"]), send_path=None):
        amz = amz or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        hh = {"x-amz-date": amz, "x-amz-content-sha256": e}
        sig, signed, scope = sigv4_signature(method, f"127.0.0.1:{port}", path, {}, hh, e, "sekret", region, amz)
        hh["Authorization"] = f"AWS4-HMAC-SHA256 Credential=AKTEST/{scope}, SignedHeaders={signed}, Signature={sig}"
        c_ = http.client.HTTPConnection("127.0.0.1", port, timeout=10); c_.request(method, send_path or path, headers=hh); r_ = c_.getresponse(); b_ = r_.read(); c_.close()
        return r_.status, b_
    print("  region 'zz-nowhere-9' in the credential scope: HTTP", raw_call(region="zz-nowhere-9")[0], "(real: 400 AuthorizationHeaderMalformed)")
    print("  x-amz-date 20000101T000000Z (26 years old, replay): HTTP", raw_call(amz="20000101T000000Z")[0], "(real: 403 RequestTimeTooSkewed)")
    (tmp / "originals2").mkdir(exist_ok=True); (tmp / "originals2" / "secret.txt").write_bytes(b"other bucket")
    st_, body_ = raw_call(path="/originals/../originals2/secret.txt")
    print("  GET /originals/../originals2/secret.txt (bucket escape, fpath() compares string prefixes): HTTP", st_, body_[:20])
    print("  the emulator verifies signatures with the client's own sigv4_signature (s3_emulator.py imports it): a shared canonicalisation fault is invisible")
finally:
    srv.terminate()

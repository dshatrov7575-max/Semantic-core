#!/usr/bin/env python3
"""S5 part 2 acceptance: originals in the object store (through the S3 protocol, emulator) + the registry in PostgreSQL.

S6-01 the world: the first fetch of the news.example article names its original page; projection «сохранность
      оригиналов» shows it: type, size, state «цел» after the first scrub; the validator and the database agree.
S6-02 live: the gateway stores a new original (write-verify) and registers it; an observation naming it is accepted;
      the same bytes stored twice are one object.
S6-03 the object is damaged inside the store: scrub records CORRUPT; the projection shows it; as of the moment before
      the scrub it still shows «цел»; a new observation naming the damaged object is refused.
S6-04 the object disappears: scrub records MISSING.
S6-05 after a restore from backup the next scrub records OK; the history of checks keeps the incident.
S6-06 the proof does not depend on the original: with the original lost the quote is still verified against the text
      bytes in the database (dossier/provenance «verified»).
S6-07 refusal of the projection is the same: no clearance, unknown claim.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s5b_tests.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
import requests  # noqa: E402
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
import s5_tests as S5  # noqa: E402
import s3_tests as S3  # noqa: E402
from object_store import ObjectStore, S3Backend, object_key  # noqa: E402
import gateway as GW  # noqa: E402

RES = []


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<6} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def custody(cid, user="ac_rd_wm", as_of=None):
    a = f", {as_of!r}::timestamptz" if as_of else ""
    return json.loads(S5.sql1(f"SELECT ac.custody('{cid}'{a});", user).splitlines()[-1])


def originals(c):
    return [o["original"] for s in c["sources"] for o in s["observations"] if "original" in o]


def start_emulator(root):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    srv = subprocess.Popen([sys.executable, str(HERE.parent / "store" / "s3_emulator.py"), str(root), str(port), "AKTEST", "sekret"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ))
    ep = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(ep + "/x", timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.1)
    return srv, ObjectStore(S3Backend(ep, "originals", "AKTEST", "sekret"))


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    S5.sql1(S3.SETUP)
    S5.sql1(S5.SETUP)
    ds, trust, content = build()
    with tempfile.TemporaryDirectory() as tmp:
        srv, store = start_emulator(Path(tmp))
        try:
            return run(ds, trust, content, store, Path(tmp) / "originals")
        finally:
            srv.terminate()


def run(ds, trust, content, store, disk):
    c8 = next(c for c in ds["records"] if c["kind"] == "Claim" and c["predicate"] == "wm.mentioned" and c["recorded_at"] == "2026-09-06T10:30:00Z")
    s2 = next(s for s in ds["records"] if s["kind"] == "Source" and any("original" in o for o in s["observations"]))
    og = next(o["original"] for o in s2["observations"] if "original" in o)
    # the world's original goes into the store the way the gateway would put it; then the first scrub
    assert store.put("tnt_demo", content[og["object"]]) == og["object"]
    time.sleep(1.1)
    st1 = GW.scrub(store)
    time.sleep(1.1)
    c = custody(c8["claim_id"])
    o1 = originals(c)
    rep = VAL.validate(ds, trust, content)
    check("S6-01", not rep.errors and st1 == {"OK": 1, "MISSING": 0, "CORRUPT": 0} and len(o1) == 1 and o1[0]["status"] == "OK"
          and o1[0]["object"] == og["object"] and o1[0]["media_type"] == "text/html; charset=utf-8" and o1[0]["checks"] == 2,
          "мир: у первого забора статьи есть оригинал страницы; проекция показывает тип, размер и состояние «цел»",
          f"scrub={st1} originals={[(x['status'], x['byte_length'], x['checks']) for x in o1]}")

    # S6-02 live registration
    text = next(s for s in ds["records"] if s["kind"] == "Source" and s["source_id"] == s2["source_id"])["content_inline"].replace(". ", ".   ", 1)
    raw = ("<!doctype html><html><body><div class=\"ad\">реклама</div><article>" + text + "</article></body></html>").encode("utf-8")
    orig = GW.register(store, "tnt_demo", raw, "text/html; charset=utf-8")
    again = GW.register(store, "tnt_demo", raw, "text/html; charset=utf-8")
    src = S5.source(text, "https://news.example/zarechye?utm_medium=rss", utc(0))
    src["observations"][0]["original"] = orig
    r2 = psql(ingest_sql([src], {}))
    time.sleep(1.1)
    m2 = S5.mention(src["source_id"], text, "Жители Заречной улицы выступили против застройки", utc(0))
    r2b = psql(ingest_sql([m2], {}))
    n_obj = S5.sql1("SELECT count(*) FROM ac.objects")
    time.sleep(1.1)
    c2 = custody(m2["claim_id"])
    check("S6-02", r2.returncode == r2b.returncode == 0 and orig == again and n_obj == "2" and [x["status"] for x in originals(c2)] == ["OK"],
          "живая запись: шлюз сохранил оригинал с проверкой чтением и зарегистрировал; наблюдение с оригиналом принято; повтор — тот же объект",
          f"db={'OK' if r2.returncode == 0 else r2.stderr[:100]} objects={n_obj}")

    # S6-03 damage inside the store
    before = utc(0)
    time.sleep(1.1)
    f = disk / object_key("tnt_demo", orig["object"])
    f.write_bytes(raw.replace("реклама".encode(), "РЕКЛАМА".encode()))
    st3 = GW.scrub(store)
    time.sleep(1.1)
    c3, c3old = custody(m2["claim_id"]), custody(m2["claim_id"], as_of=before)
    src3 = S5.source(text + " ", "https://news.example/zarechye?utm_medium=mail", utc(0))
    src3["observations"][0]["original"] = orig
    r3 = psql(ingest_sql([src3], {}))
    check("S6-03", st3 == {"OK": 1, "MISSING": 0, "CORRUPT": 1} and [x["status"] for x in originals(c3)] == ["CORRUPT"]
          and [x["status"] for x in originals(c3old)] == ["OK"] and r3.returncode != 0 and "ORIGINAL_INVALID" in r3.stderr,
          "оригинал повреждён в хранилище: проверка записала «повреждён», проекция показывает; на момент до проверки — «цел»; новое наблюдение на повреждённый оригинал отвергнуто",
          f"scrub={st3} now={[x['status'] for x in originals(c3)]} before={[x['status'] for x in originals(c3old)]} | {r3.stderr.strip()[:70]}")

    # S6-04 the object disappears
    f.unlink()
    time.sleep(1.1)
    st4 = GW.scrub(store)
    time.sleep(1.1)
    check("S6-04", st4 == {"OK": 1, "MISSING": 1, "CORRUPT": 0} and [x["status"] for x in originals(custody(m2["claim_id"]))] == ["MISSING"],
          "оригинал исчез из хранилища: «утрачен»", str(st4))

    # S6-05 restore from backup
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(raw)
    time.sleep(1.1)
    st5 = GW.scrub(store)
    time.sleep(1.1)
    o5 = originals(custody(m2["claim_id"]))
    hist = S5.sql1(f"SELECT string_agg(result, ',' ORDER BY checked_at) FROM ac.object_checks WHERE object_address = '{orig['object']}'")
    check("S6-05", st5 == {"OK": 2, "MISSING": 0, "CORRUPT": 0} and o5[0]["status"] == "OK" and hist == "OK,OK,CORRUPT,MISSING,OK",
          "после восстановления из копии следующая проверка — «цел»; история проверок хранит происшествие", hist)

    # S6-06 the proof does not depend on the original
    f.unlink()
    GW.scrub(store)
    time.sleep(1.1)
    prov = json.loads(S5.sql1(f"SELECT ac.provenance('{m2['claim_id']}');", "ac_rd_wm").splitlines()[-1])
    check("S6-06", all(e["verified"] for e in prov["evidence"]) and originals(custody(m2["claim_id"]))[0]["status"] == "MISSING",
          "доказательство не зависит от оригинала: при утраченном оригинале цитата по-прежнему сверяется с текстом в базе")

    # S6-07 refusals
    outs = []
    for user, cid in (("ac_rd_none", c8["claim_id"]), ("ac_rd_wm", "clm:sha256:" + "0" * 64)):
        rr = psql(f"SET SESSION AUTHORIZATION {user};\nSELECT ac.custody('{cid}');")
        outs.append(rr.returncode != 0 and "ACCESS_DENIED: нет допуска" in rr.stderr)
    check("S6-07", all(outs), "без допуска и для неизвестного утверждения — один и тот же отказ", str(outs))

    print(f"\ns5b_tests={len(RES)} passed={sum(RES)}")
    print("S5B_RESULT=" + ("PASS" if all(RES) else "FAIL"))
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Tests of the object store (no database): the signer against the AWS documentation examples, then the same
behaviour on both backends — a directory and an S3-compatible server (the strict emulator s3_emulator.py).

T1  AWS Signature V4: three examples published in the AWS documentation (GET object, PUT object with «$» in the
    key, list with query parameters) — exact signatures.
Per backend (fs, s3):
 B1 put -> address = sha256; get returns the same bytes; put again is idempotent.
 B2 tenants are isolated: another tenant does not see the object.
 B3 bytes changed inside the store -> get raises IntegrityError, check = CORRUPT, put of the right bytes is refused
    (no silent overwrite).
 B4 object removed from the store -> NotFound, check = MISSING.
 B5 empty object and a malformed address are refused.
 B6 a store that silently truncates on write is caught by write-verify.
 B7 listing returns every key (S3: over several pages).
S3 only:
 S1 wrong secret key -> refused; S2 request without a signature -> 403;
 S3 a correctly signed PUT whose declared payload hash is not the hash of the body -> 400.
"""
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import requests  # noqa: E402
from object_store import (ObjectStore, FsBackend, S3Backend, IntegrityError, NotFound, ObjectStoreError, address, object_key,  # noqa: E402
                          sigv4_signature)

RES = []


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<7} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


EMPTY = hashlib.sha256(b"").hexdigest()
SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
H, D = "examplebucket.s3.amazonaws.com", "20130524T000000Z"
body = b"Welcome to Amazon S3."
ph = hashlib.sha256(body).hexdigest()
s1 = sigv4_signature("GET", H, "/test.txt", {}, {"Range": "bytes=0-9", "x-amz-content-sha256": EMPTY, "x-amz-date": D}, EMPTY, SK, "us-east-1", D)[0]
s2 = sigv4_signature("PUT", H, "/test$file.text", {}, {"Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-date": D,
                                                       "x-amz-storage-class": "REDUCED_REDUNDANCY", "x-amz-content-sha256": ph}, ph, SK, "us-east-1", D)[0]
s3 = sigv4_signature("GET", H, "/", {"max-keys": "2", "prefix": "J"}, {"x-amz-content-sha256": EMPTY, "x-amz-date": D}, EMPTY, SK, "us-east-1", D)[0]
check("T1", (s1, s2, s3) == ("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
                             "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
                             "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"),
      "подпись AWS Signature V4 совпала с тремя примерами из документации AWS")


class Truncating:
    """a faulty store: drops the last byte on write"""
    def __init__(self, inner):
        self.inner = inner

    def put(self, key, data):
        self.inner.put(key, data[:-1])

    def get(self, key):
        return self.inner.get(key)


def suite(name, backend, tamper, remove):
    st = ObjectStore(backend)
    data = ("<html>Статья " + name + "</html>").encode("utf-8")
    addr = st.put("tnt_demo", data)
    check(f"{name}-B1", addr == "sha256:" + hashlib.sha256(data).hexdigest() and st.get("tnt_demo", addr) == data
          and st.put("tnt_demo", data) == addr, "запись, чтение, повторная запись тех же байтов")
    check(f"{name}-B2", raises(NotFound, lambda: st.get("tnt_other", addr)) and st.check("tnt_other", addr) == "MISSING",
          "другой tenant объекта не видит")
    key = object_key("tnt_demo", addr)
    tamper(key, data.replace(b"<html>", b"<HTML>"))
    check(f"{name}-B3", raises(IntegrityError, lambda: st.get("tnt_demo", addr)) and st.check("tnt_demo", addr, len(data)) == "CORRUPT"
          and raises(IntegrityError, lambda: st.put("tnt_demo", data)),
          "байты подменены внутри хранилища: чтение отказывает, проверка — «повреждён», молчаливой перезаписи нет")
    remove(key)
    check(f"{name}-B4", raises(NotFound, lambda: st.get("tnt_demo", addr)) and st.check("tnt_demo", addr) == "MISSING",
          "объект удалён из хранилища: «утрачен»")
    check(f"{name}-B5", raises(ObjectStoreError, lambda: st.put("tnt_demo", b"")) and raises(ObjectStoreError, lambda: st.get("tnt_demo", "sha256:xyz"))
          and raises(ObjectStoreError, lambda: st.get("../etc", addr)), "пустой объект, неверный адрес и tenant с «/» отвергнуты")
    check(f"{name}-B6", raises(IntegrityError, lambda: ObjectStore(Truncating(backend)).put("tnt_demo", b"0123456789")),
          "хранилище, обрезающее запись, поймано проверкой чтением")
    addrs = sorted(st.put("tnt_list", f"object {i}".encode()) for i in range(8))
    keys = backend.keys("tnt_list/")
    check(f"{name}-B7", sorted(k.rsplit("/", 1)[1] for k in keys) == sorted(a[7:] for a in addrs), "перечень ключей полон", f"keys={len(keys)}")


with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    fs = FsBackend(tmp / "fs")
    suite("fs", fs, lambda k, b: (tmp / "fs" / k).write_bytes(b), lambda k: (tmp / "fs" / k).unlink())

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    srv = subprocess.Popen([sys.executable, str(HERE / "s3_emulator.py"), str(tmp / "s3"), str(port), "AKTEST", "sekret"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    try:
        ep = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                requests.get(ep + "/x", timeout=1)
                break
            except requests.RequestException:
                time.sleep(0.1)
        s3b = S3Backend(ep, "originals", "AKTEST", "sekret")
        suite("s3", s3b, lambda k, b: (tmp / "s3" / "originals" / k).write_bytes(b), lambda k: (tmp / "s3" / "originals" / k).unlink())
        bad = S3Backend(ep, "originals", "AKTEST", "wrong-secret")
        check("s3-S1", raises(ObjectStoreError, lambda: bad.put("tnt_demo/sha256/aa/x", b"data")), "неверный секретный ключ — отказ")
        r = requests.put(ep + "/originals/tnt_demo/sha256/aa/y", data=b"data", timeout=5)
        check("s3-S2", r.status_code == 403, "запрос без подписи — 403", str(r.status_code))
        # a correctly signed PUT whose declared payload hash is not the hash of the body
        import datetime
        amz = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        lie = hashlib.sha256(b"other bytes").hexdigest()
        path = "/originals/tnt_demo/sha256/aa/z"
        sig, signed, scope = sigv4_signature("PUT", f"127.0.0.1:{port}", path, {}, {"x-amz-date": amz, "x-amz-content-sha256": lie}, lie, "sekret", "us-east-1", amz)
        r = requests.put(ep + path, data=b"data", timeout=5, headers={
            "x-amz-date": amz, "x-amz-content-sha256": lie,
            "Authorization": f"AWS4-HMAC-SHA256 Credential=AKTEST/{scope}, SignedHeaders={signed}, Signature={sig}"})
        check("s3-S3", r.status_code == 400 and "XAmzContentSHA256Mismatch" in r.text, "тело не соответствует объявленному хэшу — 400", str(r.status_code))
    finally:
        srv.terminate()

print(f"\nstore_tests={len(RES)} passed={sum(RES)}")
print("STORE_RESULT=" + ("PASS" if all(RES) else "FAIL"))
sys.exit(0 if all(RES) else 1)

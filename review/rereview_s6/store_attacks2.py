#!/usr/bin/env python3
"""S6 review: transient network faults vs ObjectStore.check (no database needed). A fake S3 endpoint that
(1) answers 200 with Content-Length larger than what it sends and closes, (2) answers 503 SlowDown, (3) 200 + gzip."""
import gzip, hashlib, os, socket, sys, threading
sys.path.insert(0, "/home/claude/as/store")
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
from object_store import ObjectStore, S3Backend, address
DATA = b"original bytes " * 400
MODE = {"m": "trunc"}
def serve(sock):
    while True:
        c, _ = sock.accept()
        try:
            c.recv(65536)
            if MODE["m"] == "trunc":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(DATA) + DATA[: len(DATA) // 2])
            elif MODE["m"] == "503":
                c.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 44\r\nConnection: close\r\n\r\n<Error><Code>SlowDown</Code></Error>        ")
            elif MODE["m"] == "gzip":
                z = gzip.compress(DATA)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(z) + z)
            elif MODE["m"] == "nobucket":
                c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 40\r\nConnection: close\r\n\r\n<Error><Code>NoSuchBucket</Code></Error>")
        finally:
            c.close()
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(8); port = s.getsockname()[1]
threading.Thread(target=serve, args=(s,), daemon=True).start()
import requests, urllib3
print("requests", requests.__version__, "urllib3", urllib3.__version__)
for m, what in (("trunc", "connection dropped after half of the body (Content-Length says full)"), ("503", "HTTP 503 SlowDown"),
                ("nobucket", "HTTP 404 NoSuchBucket (wrong bucket name in the gateway configuration)"),
                ("gzip", "intact object delivered with Content-Encoding: gzip (proxy in front of the store)")):
    MODE["m"] = m
    st = ObjectStore(S3Backend(f"http://127.0.0.1:{port}", "originals", "k", "s"))
    try: res = st.check("tnt_demo", address(DATA), len(DATA))
    except Exception as e: res = "raises " + type(e).__name__
    print(f"  {what:<82} -> check() = {res}")

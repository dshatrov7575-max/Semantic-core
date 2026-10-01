#!/usr/bin/env python3
"""Object store of originals (S5 part 2, D26): raw captures (pages, PDFs, scans) addressed by sha256.

  address = "sha256:<hex of the bytes>"; key = "<tenant>/sha256/<hh>/<hex>" (tenants never share a key).
  put   writes, then READS BACK and compares the hash (a store that silently truncates is caught at once);
        an existing key is never overwritten: the same address means the same bytes, anything else is corruption.
  get   returns bytes only if they still hash to the address (IntegrityError otherwise, NotFound if missing).
  check -> "OK" | "MISSING" | "CORRUPT" for the scrubber.

Backends: FsBackend (a directory; tests and single-host stands) and S3Backend (any S3-compatible service: MinIO, Ceph,
AWS) — path-style requests signed with AWS Signature V4 using only the standard library + requests; every PUT carries
x-amz-content-sha256 = the real hash of the payload, so a compliant server rejects a damaged upload by itself.
"""
import datetime
import hashlib
import hmac
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path


class ObjectStoreError(Exception):
    pass


class NotFound(ObjectStoreError):
    pass


class IntegrityError(ObjectStoreError):
    pass


def address(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


import re
_TENANT_RE = re.compile(r"^tnt_[a-z0-9_]{2,64}$")                    # same pattern as ac.objects.tenant_id (S6R-09)


def valid_tenant(tenant: str) -> bool:
    return bool(_TENANT_RE.match(tenant or ""))


def object_key(tenant: str, addr: str) -> str:
    if not (addr.startswith("sha256:") and len(addr) == 71 and all(c in "0123456789abcdef" for c in addr[7:])):
        raise ObjectStoreError(f"не адрес объекта: {addr!r}")
    if not valid_tenant(tenant):
        raise ObjectStoreError(f"недопустимый tenant: {tenant!r}")
    h = addr[7:]
    return f"{tenant}/sha256/{h[:2]}/{h}"


def tenant_prefix(tenant: str) -> str:
    """The only safe prefix for a per-tenant listing (S6R-11): a bare tenant string as a backend.keys() prefix
    also matches any OTHER tenant whose name extends it as a string (tnt_a matches tnt_ab/...). Callers that need
    to enumerate one tenant's keys MUST use this, never the tenant string alone."""
    if not valid_tenant(tenant):
        raise ObjectStoreError(f"недопустимый tenant: {tenant!r}")
    return tenant + "/"


# ---------------------------------------------------------------- backends
class FsBackend:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _p(self, key):
        return self.root / key

    def put(self, key, data):
        p = self._p(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(p)                       # atomic: a reader never sees half an object

    def get(self, key):
        p = self._p(key)
        return p.read_bytes() if p.is_file() else None

    def keys(self, prefix=""):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file() and not p.name.endswith(".part")
                      and str(p.relative_to(self.root)).startswith(prefix))


def _q(s, safe=""):
    return urllib.parse.quote(s, safe=safe + "-_.~")


def sigv4_signature(method, host, path, query, headers, payload_hash, secret_key, region, amz_date, service="s3"):
    """AWS Signature Version 4 (header authentication). headers: dict of the headers to sign (any case), host excluded.
    -> (signature hex, signed header names joined by ';', credential scope)"""
    hs = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    hs["host"] = host
    signed = ";".join(sorted(hs))
    canonical = "\n".join([
        method, _q(path, "/"),
        "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(query.items(), key=lambda kv: (_q(kv[0]), _q(str(kv[1]))))),  # sort by ENCODED pair (S6R-10.2)
        "".join(f"{k}:{hs[k]}\n" for k in sorted(hs)), signed, payload_hash])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = ("AWS4" + secret_key).encode()
    for part in (amz_date[:8], region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest(), signed, scope


def _strip_default_port(netloc, scheme):
    host, _, port = netloc.rpartition(":")
    if host and port and ((scheme == "http" and port == "80") or (scheme == "https" and port == "443")):
        return host                                   # S6R-10.1: sign the Host the HTTP library will actually send
    return netloc


def _error_code(body):
    try:
        return ET.fromstring(body).findtext("Code") or ""
    except ET.ParseError:
        return ""


class S3Backend:
    def __init__(self, endpoint, bucket, access_key, secret_key, region="us-east-1", timeout=20):
        import requests
        self.http, self.endpoint, self.bucket = requests.Session(), endpoint.rstrip("/"), bucket
        self.access_key, self.secret_key, self.region, self.timeout = access_key, secret_key, region, timeout
        u = urllib.parse.urlsplit(self.endpoint)
        self.host = _strip_default_port(u.netloc, u.scheme)

    def _call(self, method, key="", query=None, data=b"", extra_headers=None):
        query = query or {}
        path = f"/{self.bucket}" + (f"/{key}" if key else "")
        amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ph = hashlib.sha256(data).hexdigest()
        headers = {"x-amz-date": amz_date, "x-amz-content-sha256": ph, **(extra_headers or {})}
        sig, signed, scope = sigv4_signature(method, self.host, path, query, headers, ph, self.secret_key, self.region, amz_date)
        headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
        url = self.endpoint + _q(path, "/") + ("?" + "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(query.items())) if query else "")
        return self.http.request(method, url, headers=headers, data=data, timeout=self.timeout)

    def put(self, key, data):
        # If-None-Match: * (S6R-10.3): an S3 implementation that honours it turns our own read-before-write into
        # an atomic refusal of a concurrent conflicting write; one that ignores it leaves ObjectStore's own
        # write-verify (read back and compare) as the only guard, same as before.
        r = self._call("PUT", key, data=data, extra_headers={"If-None-Match": "*"})
        if r.status_code == 412:
            raise IntegrityError(f"PUT {key}: HTTP 412 — ключ уже занят (условная запись отклонена)")
        if r.status_code not in (200, 201):
            raise ObjectStoreError(f"PUT {key}: HTTP {r.status_code} {r.text[:120]}")

    def get(self, key):
        r = self._call("GET", key)
        if r.status_code == 404:
            # S6R-05: only a confirmed "this key does not exist" is an absence; a missing BUCKET (misconfiguration)
            # must not be read as "this object is missing" — it is a store-level failure and must raise.
            if _error_code(r.content) == "NoSuchBucket":
                raise ObjectStoreError(f"GET {key}: бакет {self.bucket!r} не существует")
            return None
        if r.status_code != 200:
            # S6R-05: 403/500/503/etc. are NOT "missing" — they must propagate so the caller can tell
            # "the object is gone" from "the store could not be reached right now".
            raise ObjectStoreError(f"GET {key}: HTTP {r.status_code} {r.text[:120]}")
        return r.content

    def keys(self, prefix=""):
        out, token = [], None
        while True:
            q = {"list-type": "2", "prefix": prefix}
            if token:
                q["continuation-token"] = token
            r = self._call("GET", query=q)
            if r.status_code != 200:
                raise ObjectStoreError(f"LIST: HTTP {r.status_code} {r.text[:120]}")
            root = ET.fromstring(r.content)
            ns = root.tag[:root.tag.index("}") + 1] if root.tag.startswith("{") else ""
            out += [c.findtext(f"{ns}Key") for c in root.findall(f"{ns}Contents")]
            token = root.findtext(f"{ns}NextContinuationToken")
            if root.findtext(f"{ns}IsTruncated") != "true" or not token:
                return sorted(out)


# ---------------------------------------------------------------- the store
class ObjectStore:
    def __init__(self, backend):
        self.b = backend

    def put(self, tenant, data: bytes) -> str:
        if not data:
            raise ObjectStoreError("пустой объект не сохраняется")
        addr = address(data)
        key = object_key(tenant, addr)
        old = self.b.get(key)
        if old is not None:
            if address(old) != addr:
                raise IntegrityError(f"{addr}: в хранилище под этим адресом лежат другие байты — перезапись запрещена")
            return addr                                  # idempotent
        self.b.put(key, data)
        back = self.b.get(key)
        if back is None or address(back) != addr:        # write-verify
            raise IntegrityError(f"{addr}: после записи прочитаны другие байты")
        return addr

    def get(self, tenant, addr) -> bytes:
        data = self.b.get(object_key(tenant, addr))
        if data is None:
            raise NotFound(addr)
        if address(data) != addr:
            raise IntegrityError(f"{addr}: байты в хранилище не совпадают с адресом")
        return data

    def check(self, tenant, addr, byte_length=None) -> str:
        # S6R-05: MISSING means "the backend confirms this key does not exist" (backend.get() returned None).
        # Any OTHER failure (auth rejected, 5xx, network error, wrong bucket) is NOT "lost" — it is "could not
        # tell right now", and must raise so the scrubber aborts instead of journalling a false, irreversible MISSING.
        data = self.b.get(object_key(tenant, addr))
        if data is None:
            return "MISSING"
        return "OK" if address(data) == addr and (byte_length is None or len(data) == byte_length) else "CORRUPT"

    def keys(self, tenant: str):
        """S6R-11: the only tenant-safe listing. A bare tenant string handed to backend.keys() as a prefix also
        matches any OTHER tenant whose name extends it (tnt_a matches tnt_ab/...); tenant_prefix() adds the
        separator that makes the match exact. Nothing in this codebase currently lists cross-tenant; this exists
        so nothing added later can reintroduce the bug by calling backend.keys(tenant) directly."""
        return self.b.keys(tenant_prefix(tenant))

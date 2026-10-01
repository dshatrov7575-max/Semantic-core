#!/usr/bin/env python3
"""A minimal S3-compatible server for tests (no network access to install MinIO or moto in this environment).
Path-style: /<bucket>/<key>. It is strict where it matters for the store:
  * every request must carry a valid AWS Signature V4 for the configured access/secret key (403 otherwise);
  * x-amz-content-sha256 must equal the sha256 of the body (400 XAmzContentSHA256Mismatch) — as real S3 / MinIO do;
  * PutObject, GetObject, HeadObject, DeleteObject, ListObjectsV2 (prefix, continuation).
The signer it verifies against is object_store.sigv4_signature, itself checked against the examples published in the
AWS documentation (store_tests.py, T1). It is NOT a replacement for testing on real MinIO (deployment cycle).
Usage: python3 s3_emulator.py <dir> <port> <access_key> <secret_key>
"""
import datetime
import hashlib
import sys
import urllib.parse
from pathlib import Path
from xml.sax.saxutils import escape

from flask import Flask, Response, request

from object_store import sigv4_signature

ROOT, PORT, ACCESS, SECRET = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
REGION = sys.argv[5] if len(sys.argv) > 5 else "us-east-1"
BUCKET = sys.argv[6] if len(sys.argv) > 6 else "originals"
(ROOT / BUCKET).mkdir(parents=True, exist_ok=True)   # S6R-05: a bucket is provisioned ahead of time, like real S3 —
                                                      # "nobody has written here yet" must not read as "misconfigured"
app = Flask(__name__)
PAGE = 3                                           # tiny pages: the client's continuation is exercised
SKEW = 900                                         # seconds; real AWS: ~15 minutes (RequestTimeTooSkewed)


def err(status, code, msg=""):
    return Response(f"<?xml version='1.0'?><Error><Code>{code}</Code><Message>{escape(msg)}</Message></Error>", status, mimetype="application/xml")


def authorised(body):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("AWS4-HMAC-SHA256 "):
        return err(403, "AccessDenied", "no signature")
    parts = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
    cred = parts.get("Credential", "").split("/")
    if len(cred) != 5 or cred[0] != ACCESS:
        return err(403, "InvalidAccessKeyId")
    # S6R-10.4: region and clock skew are independent of the (shared) canonicalisation code below, so a bug common
    # to client and emulator cannot hide them — real S3 would reject both (AuthorizationHeaderMalformed / RequestTimeTooSkewed).
    if cred[2] != REGION:
        return err(400, "AuthorizationHeaderMalformed", f"область не совпадает: ожидалась {REGION}")
    amz_date = request.headers.get("x-amz-date", "")
    try:
        req_t = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
        skew = abs((datetime.datetime.now(datetime.timezone.utc) - req_t).total_seconds())
    except ValueError:
        return err(400, "AuthorizationHeaderMalformed", "неверный x-amz-date")
    if skew > SKEW:
        return err(403, "RequestTimeTooSkewed", f"время запроса отличается на {skew:.0f} с")
    signed = parts.get("SignedHeaders", "").split(";")
    if not {"host", "x-amz-date", "x-amz-content-sha256"} <= set(signed):
        return err(403, "AccessDenied", "required headers are not signed")
    ph = request.headers.get("x-amz-content-sha256", "")
    if ph != hashlib.sha256(body).hexdigest():
        return err(400, "XAmzContentSHA256Mismatch")
    headers = {h: request.headers.get(h, "") for h in signed if h != "host"}
    query = {k: v for k, v in urllib.parse.parse_qsl(request.query_string.decode(), keep_blank_values=True)}
    sig, _, _ = sigv4_signature(request.method, request.headers["Host"], urllib.parse.unquote(request.path), query, headers, ph,
                                SECRET, cred[2], amz_date)
    if sig != parts.get("Signature"):
        return err(403, "SignatureDoesNotMatch")
    return None


def fpath(bucket, key):
    base = (ROOT / bucket).resolve()
    p = (base / key).resolve()
    if p != base and base not in p.parents:            # S6R-10.5: string-prefix compare let ".../originals2" through
        return None
    return p


@app.route("/<bucket>", methods=["GET"])
@app.route("/<bucket>/", methods=["GET"])
def list_objects(bucket):
    bad = authorised(b"")
    if bad:
        return bad
    base = ROOT / bucket
    if not base.is_dir():
        return err(404, "NoSuchBucket")
    prefix, token = request.args.get("prefix", ""), request.args.get("continuation-token", "")
    keys = sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
    keys = [k for k in keys if k.startswith(prefix) and k > token]
    page, more = keys[:PAGE], len(keys) > PAGE
    body = ("<?xml version='1.0' encoding='UTF-8'?><ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
            f"<Name>{bucket}</Name><Prefix>{escape(prefix)}</Prefix><KeyCount>{len(page)}</KeyCount><IsTruncated>{'true' if more else 'false'}</IsTruncated>"
            + (f"<NextContinuationToken>{escape(page[-1])}</NextContinuationToken>" if more else "")
            + "".join(f"<Contents><Key>{escape(k)}</Key><Size>{(base / k).stat().st_size}</Size></Contents>" for k in page)
            + "</ListBucketResult>")
    return Response(body, 200, mimetype="application/xml")


@app.route("/<bucket>/<path:key>", methods=["PUT", "GET", "HEAD", "DELETE"])
def obj(bucket, key):
    body = request.get_data()
    bad = authorised(body if request.method == "PUT" else b"")
    if bad:
        return bad
    p = fpath(bucket, key)
    if p is None:
        return err(400, "InvalidArgument")
    if request.method == "PUT":
        if request.headers.get("If-None-Match") == "*" and p.is_file():     # S6R-10.3: real conditional write
            return err(412, "PreconditionFailed", "ключ уже занят")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
        return Response("", 200)
    if not (ROOT / bucket).is_dir():                     # S6R-05: "bucket missing" is not "key missing"
        return err(404, "NoSuchBucket")
    if not p.is_file():
        return err(404, "NoSuchKey")
    if request.method == "DELETE":
        p.unlink()
        return Response("", 204)
    data = p.read_bytes()
    return Response(data if request.method == "GET" else b"", 200, headers={"Content-Length": str(len(data))}, mimetype="application/octet-stream")


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple("127.0.0.1", PORT, app, threaded=True)

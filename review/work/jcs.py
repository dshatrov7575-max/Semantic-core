"""RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 output.

Profile of the core ontology: numbers are integers only (|n| <= 2**53-1);
floats are rejected, so the ES6 number-serialisation part of RFC 8785 reduces
to decimal integer printing. Strings are emitted as exact code points (UTF-8),
escaping exactly as ECMAScript JSON.stringify does. Lone surrogates rejected.
"""
import hashlib
import json

MAX_SAFE = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def _str(s: str) -> str:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalizationError("lone surrogate in string")
    # ensure_ascii=False: keep code points; Python escapes \b \f \n \r \t
    # short-form and other C0 controls as lowercase \u00xx - same as JSON.stringify.
    return json.dumps(s, ensure_ascii=False)


def _key(k: str):
    return k.encode("utf-16-be")  # RFC 8785 3.2.3: sort by UTF-16 code units


def canon(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise CanonicalizationError("integer outside IEEE-754 safe range")
        return str(v)
    if isinstance(v, float):
        raise CanonicalizationError("floats are outside the core JCS profile")
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizationError("non-string key")
        items = sorted(v.items(), key=lambda kv: _key(kv[0]))
        return "{" + ",".join(_str(k) + ":" + canon(x) for k, x in items) + "}"
    raise CanonicalizationError(f"unsupported type {type(v).__name__}")


def canon_bytes(v) -> bytes:
    return canon(v).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest(v) -> str:
    return sha256_hex(canon_bytes(v))

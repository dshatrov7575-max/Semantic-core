"""Reference validator for core-ontology/0.3 (Архитектура семантики).

Inputs (all three are separate on purpose):
  dataset  - records (Project, Source, Entity, Claim, ClaimReview, Check, ArtifactReceipt, IdentityDecision, Publication);
  trust    - trust anchors (service keys per tenant), configuration OUTSIDE the data they authenticate;
  content  - object store: source bytes by source_id (Source.content_inline is accepted as well) and the bytes of
             producer artifacts by artifact_digest ("sha256:<hex>"); a receipt is checked against its artifact (RR-07).

Phases, fail-closed:
  0. pre-scan of raw values: no floats, integers within +-(2^53-1), no lone surrogates (values and keys),
     no control characters except in free text (content_inline, quote, note)        -> SCHEMA_INVALID
  1. JSON Schema Draft 2020-12, patterns as FULL match, strict calendar formats         -> SCHEMA_INVALID
  2. semantic rules, one stable code each; an unexpected exception becomes VALIDATOR_INTERNAL_ERROR.

CLI: python3 validator.py dataset.json [--trust trust.json] [--content-dir DIR] [--json]
     DIR holds blobs named by the hex of their sha256 (sources and artifacts). Exit 0 = no errors, 1 = errors.
"""
import base64
import hashlib
import json
import re
import sys
import unicodedata
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from jcs import digest, canon

HERE = Path(__file__).resolve().parent
PREDICATES = json.loads((HERE / "predicates.json").read_text(encoding="utf-8"))


def _fullmatch_patterns(node):
    """JSON Schema patterns are ECMA-262 (`$` = end of input); Python `re.search` lets `$` match before a
    trailing newline. Rewrite anchored patterns to `\\Z` so the schema means what it says."""
    if isinstance(node, dict):
        return {k: (v[:-1] + r"\Z" if k == "pattern" and isinstance(v, str) and v.endswith("$") else _fullmatch_patterns(v))
                for k, v in node.items()}
    if isinstance(node, list):
        return [_fullmatch_patterns(v) for v in node]
    return node


SCHEMA = _fullmatch_patterns(json.loads((HERE / "core.schema.json").read_text(encoding="utf-8")))
FORMATS = FormatChecker(formats=())


@FORMATS.checks("date", raises=ValueError)
def _is_date(s):
    return not isinstance(s, str) or bool(date.fromisoformat(s))


@FORMATS.checks("date-time", raises=ValueError)
def _is_ts(s):
    return not isinstance(s, str) or bool(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


DATASET_V = Draft202012Validator(SCHEMA, format_checker=FORMATS)
TRUST_V = Draft202012Validator({**SCHEMA["$defs"]["TrustAnchors"], "$defs": SCHEMA["$defs"]}, format_checker=FORMATS)
ARTIFACT_V = Draft202012Validator({**SCHEMA["$defs"]["UmrArtifact"], "$defs": SCHEMA["$defs"]}, format_checker=FORMATS)
ARTIFACT_FORMATS = PREDICATES["artifact_formats"]


def _no_dup(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("повторяющийся ключ")
    return dict(pairs)


def parse_artifact(b):
    """bytes -> (artifact dict, None) or (None, reason). Strict: UTF-8, no duplicate keys, integer profile,
    schema umr-artifact/0.3, canonical RFC 8785 bytes (one artifact = one byte string = one digest)."""
    try:
        art = json.loads(b.decode("utf-8"), object_pairs_hook=_no_dup)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "артефакт не JSON в UTF-8 или с повторяющимися ключами"
    raw = []
    prescan(art, "", raw)
    if raw:
        return None, "артефакт: " + raw[0][1]
    errs = list(ARTIFACT_V.iter_errors(art))
    if errs:
        return None, "артефакт не по схеме umr-artifact/0.3: " + errs[0].message[:120]
    if canon(art).encode("utf-8") != b:
        return None, "артефакт не в канонической форме RFC 8785"
    return art, None

ERROR_CODES = [
    "SCHEMA_INVALID", "TRUST_CONFIG_INVALID", "DUPLICATE_ID", "REF_UNRESOLVED", "CROSS_SCOPE_REFERENCE",
    "SOURCE_DIGEST_MISMATCH", "SOURCE_CONTENT_UNAVAILABLE", "CLAIM_ID_MISMATCH", "RECEIPT_ID_MISMATCH",
    "IDENTIFIER_CHECKSUM_INVALID", "ENTITY_IDENTITY_INSUFFICIENT", "ENTITY_DUPLICATE_IN_PROJECT",
    "ENTITY_MERGE_INVALID", "PREDICATE_UNKNOWN", "PREDICATE_DOMAIN_VIOLATION",
    "PREDICATE_RANGE_VIOLATION", "QUALIFIER_INVALID", "TEMPORAL_ORDER_INVALID",
    "EVIDENCE_SPAN_INVALID", "MARKING_BROADER_THAN_INPUT", "MARKING_PD_MISSING",
    "CLAIM_REVIEW_AMBIGUOUS", "CHECK_PROJECT_NOT_COMPLIANCE", "CHECK_SUBJECT_INVALID",
    "CHECK_DIMENSION_OUTSIDE_PROFILE", "CHECK_DIMENSION_MISSING", "CHECK_FINDING_INCONSISTENT",
    "CHECK_SEARCH_MISSING", "CHECK_CLAIM_NOT_ABOUT_SUBJECT", "CHECK_CLAIM_DIMENSION_MISMATCH",
    "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", "CHECK_PREVIOUS_INVALID",
    "RECEIPT_KEY_INVALID", "RECEIPT_SIGNATURE_INVALID", "RECEIPT_CLAIM_BINDING_INVALID",
    "IDENTITY_DECISION_INVALID", "ARTIFACT_INVALID", "GRAPH_NODE_INVALID", "PUBLICATION_INVALID", "ORIGINAL_INVALID", "VALIDATOR_INTERNAL_ERROR",
]
WARNING_CODES = ["CONTRADICTION_SINGLE_VALUED", "POSSIBLE_DUPLICATE"]

FREE_TEXT_KEYS = {"content_inline", "quote", "note"}
MAX_SAFE = 2**53 - 1
MAX_DEPTH = 64  # RR-05: deeper nesting is rejected instead of recursing
LEVEL = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
RISK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
ID_FIELD = {"Project": "project_id", "Source": "source_id", "Entity": "entity_id", "Claim": "claim_id",
            "ClaimReview": "review_id", "Check": "check_id", "ArtifactReceipt": "receipt_id",
            "IdentityDecision": "decision_id", "Publication": "publication_id",
            "ClassDef": "class_id", "LinkDef": "link_id", "IdentifierDef": "idef_id",
            "SchemaChange": "change_id"}


class Report:
    def __init__(self):
        self.errors, self.warnings = [], []

    def err(self, code, ref, msg):
        assert code in ERROR_CODES, code
        self.errors.append({"code": code, "ref": ref, "msg": msg})

    def warn(self, code, ref, msg):
        assert code in WARNING_CODES, code
        self.warnings.append({"code": code, "ref": ref, "msg": msg})

    def codes(self):
        return sorted({e["code"] for e in self.errors})


# ---------- phase 0 ----------

def _bad_str(s):
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _free_text(parent, key):
    """Free text is decided by place in the schema (RR-10): content_inline, quote, note, the value of a STRING literal
    and the text of an ACTION node of an artifact (it becomes a STRING literal)."""
    return key in FREE_TEXT_KEYS or (isinstance(parent, dict) and ((key == "value" and parent.get("type") == "STRING")
                                                                   or (key == "text" and parent.get("type") == "ACTION")))


def prescan(root, path, out, key=None):
    """Iterative (no recursion) scan of raw values with a depth limit (RR-05)."""
    stack = [(root, path, False, 0)]
    while stack:
        node, path, free, depth = stack.pop()
        if isinstance(node, bool) or node is None:
            continue
        if isinstance(node, float):
            out.append((path, "дробное число вне профиля (только целые)"))
        elif isinstance(node, int):
            if abs(node) > MAX_SAFE:
                out.append((path, "целое вне диапазона ±(2^53−1)"))
        elif isinstance(node, str):
            if _bad_str(node):
                out.append((path, "одиночный суррогат UTF-16"))
            elif not free and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in node):
                out.append((path, "управляющий символ в структурном поле"))
        elif isinstance(node, (list, dict)):
            if depth >= MAX_DEPTH:
                out.append((path, f"вложенность глубже {MAX_DEPTH}"))
                continue
            if isinstance(node, list):
                for n, v in enumerate(node):
                    stack.append((v, f"{path}/{n}", free, depth + 1))
            else:
                for k, v in node.items():
                    if not isinstance(k, str) or _bad_str(k) or any(ord(ch) < 0x20 for ch in k):
                        out.append((path, "недопустимый ключ"))
                        continue
                    stack.append((v, f"{path}/{k}", _free_text(node, k), depth + 1))
        else:
            out.append((path, f"недопустимый тип {type(node).__name__}"))


# ---------- identifiers ----------

_CONFUSABLE = str.maketrans({
    # Latin look-alikes -> Cyrillic
    "A": "А", "a": "а", "B": "В", "C": "С", "c": "с", "E": "Е", "e": "е", "H": "Н", "K": "К", "k": "к", "M": "М",
    "O": "О", "o": "о", "P": "Р", "p": "р", "T": "Т", "X": "Х", "x": "х", "Y": "У", "y": "у",
    # Greek look-alikes -> Cyrillic (RR-03k)
    "Α": "А", "Β": "В", "Ε": "Е", "Ζ": "З", "Η": "Н", "Ι": "І", "Κ": "К", "Μ": "М", "Ν": "Н", "Ο": "О", "Ρ": "Р",
    "Τ": "Т", "Υ": "У", "Χ": "Х", "α": "а", "ε": "е", "ι": "і", "κ": "к", "ο": "о", "ρ": "р", "τ": "т", "υ": "у",
    "χ": "х",
    # RS-12: Latin ë, Greek lunate sigma, Armenian oh, small capitals, Cherokee look-alikes -> Cyrillic
    **{chr(k): v for k, v in {
        0x00EB: "ё", 0x00CB: "Ё", 0x03F9: "С", 0x03F2: "с", 0x0555: "О", 0x0585: "о",
        0x1D00: "а", 0x0299: "в", 0x1D04: "с", 0x1D07: "е", 0x029C: "н", 0x1D0B: "к", 0x1D0D: "м", 0x1D0F: "о",
        0x1D18: "р", 0x1D1B: "т", 0x028F: "у", 0x1D26: "г", 0x1D28: "п", 0x1D2B: "л",
        0x13AA: "А", 0x13F4: "В", 0x13DF: "С", 0x13AC: "Е", 0x13BB: "Н", 0x13E6: "К", 0x13B7: "М", 0x13E2: "Р",
        0x13A2: "Т", 0x13A9: "У"}.items()}})
# second pass after casefold (casefold turns lowercase Cherokee into uppercase Cherokee, Latin capitals into small)
_CONFUSABLE_LOW = {k: v.casefold() for k, v in _CONFUSABLE.items()}
# combining diacritics dropped from the skeleton (RS-12: «Ломо\u0301в»), except breve and diaeresis (й, ё stay letters)
_MARKS = ((0x0300, 0x0305), (0x0307, 0x0307), (0x0309, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF),
          (0x20D0, 0x20FF), (0xFE20, 0xFE2F))
_QUOTES = set('"\'«»„“”‟‚‘’‛‹›`')
# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties) — invisible, must not make a second entity (RR-03h-j)
_IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
              (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
              (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
              (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
              (0x2800, 0x2800))  # + Braille blank (RS-12, B1-07)


def _ignorable(ch):
    cp = ord(ch)
    return unicodedata.category(ch) == "Cf" or any(a <= cp <= b for a, b in _IGNORABLE)


def _width(s: str) -> str:
    """fullwidth/halfwidth forms fold to ASCII/base forms; other compatibility forms (10² ≠ 102) do not"""
    return "".join(unicodedata.normalize("NFKC", ch) if unicodedata.decomposition(ch).startswith(("<wide>", "<narrow>")) else ch
                   for ch in s)


def base_key(s: str, fold=True) -> str:  # noqa: C901
    """Exact comparison key: NFC; drop invisible (default-ignorable) chars; optional casefold;
    every dash -> '-'; drop quotes; collapse spaces. No look-alike folding, no ё->е."""
    s = _width(unicodedata.normalize("NFC", s))
    s = "".join(ch for ch in s if not _ignorable(ch))
    if fold:
        s = s.casefold()
    s = "".join("-" if unicodedata.category(ch) == "Pd" or ch == "−" else ch for ch in s)
    s = "".join(ch for ch in s if ch not in _QUOTES and unicodedata.category(ch) not in ("Pi", "Pf"))
    return " ".join(s.split())


def _drop_marks(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = "".join(ch for ch in s if not any(a <= ord(ch) <= b for a, b in _MARKS))
    return unicodedata.normalize("NFC", s)


def norm(s: str, nfkc=True) -> str:
    """Skeleton (never displayed): [NFKC] + combining accents dropped + look-alikes -> Cyrillic + base_key + ё->е.
    Error-level key for names of people, organisations, events, conflicts, equipment models (mixed scripts there
    are an attack); warning-level (POSSIBLE_DUPLICATE) for equipment tags and concepts (RR-02: PT-101 vs РТ-101).
    nfkc=False for model codes: 10² is not 102 (RS-14)."""
    s = _width(unicodedata.normalize("NFC", s)).translate(_CONFUSABLE)  # before NFKC: ϲ, Ϲ would become σ, Σ
    if nfkc:
        s = unicodedata.normalize("NFKC", s)
    return base_key(_drop_marks(s).translate(_CONFUSABLE)).translate(_CONFUSABLE_LOW).replace("ё", "е")


def id_norm(v: str) -> str:
    """Registration numbers in foreign_ids/registration (RR-03d,e): NFKC, casefold, separators removed."""
    return "".join(ch for ch in base_key(unicodedata.normalize("NFKC", v)) if ch not in " -_./")


_SEP = " -_./"


def tag_norm(v: str) -> str:
    """Equipment tag exact key (RR-03f, RS-14): case-insensitive; a run of separators between a letter and a digit
    is ignored (Н-101 == н 101 == Н101), between two digits or two letters it is a group boundary '-'
    (К-1/12 != К-11/2, TT-10-1 != TT-101)."""
    s, out = base_key(v), []
    i = 0
    while i < len(s):
        if s[i] in _SEP:
            j = i
            while j < len(s) and s[j] in _SEP:
                j += 1
            if out and j < len(s) and (out[-1] in "0123456789") == (s[j] in "0123456789"):
                out.append("-")
            i = j
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def tag_compact(v: str) -> str:
    """Soft key of a tag: every separator dropped (К-1/12 ~ К-11/2 -> POSSIBLE_DUPLICATE)."""
    return "".join(ch for ch in v if ch not in _SEP)


# ---------- publications (S5, O4): one article fetched several times is one publication ----------
# whitespace class of the normalized text (explicit, the same list in the database: ac.pub_norm)
_PUB_WS = frozenset(map(chr, (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
                              0x2028, 0x2029, 0x202F, 0x205F, 0x3000)))
_TRACKING = {"fbclid", "gclid", "yclid", "_openstat", "mc_cid", "mc_eid"}


def pub_norm(text: str) -> str:
    """text of a rendition as the publication sees it: invisible characters dropped, NFC, every run of whitespace
    one space, no leading/trailing space (case, punctuation and letters are kept: an edited article is another text)"""
    t = unicodedata.normalize("NFC", "".join(ch for ch in text if not _ignorable(ch)))
    out, sp = [], False
    for ch in t:
        if ch in _PUB_WS:
            sp = True
            continue
        if sp and out:
            out.append(" ")
        sp = False
        out.append(ch)
    return "".join(out)


def text_digest_of(b: bytes):
    """sha256 of the normalized text; None — not comparable as text: not UTF-8, contains NUL (a database text cannot
    hold it, S5R-03), or contains a code point unassigned in this Unicode version (NFC of assigned characters is
    stable across versions — Unicode stability policy — so excluding unassigned ones makes the digest version-free, S5R-02)"""
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in t or any(unicodedata.category(ch) == "Cn" for ch in t):
        return None
    return "sha256:" + hashlib.sha256(pub_norm(t).encode("utf-8")).hexdigest()


_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(/[^?#]*)?(?:\?([^#]*))?(?:#.*)?", re.S)  # «.» spans line breaks as in PostgreSQL


def url_norm(u: str):
    """canonical form of a URL: http(s) only, lower-case scheme and host (ASCII / punycode), no trailing dot, no
    default port, path at least «/», no fragment, tracking parameters removed (utm_*, fbclid, gclid, yclid, …),
    the other parameters sorted. None if not an http(s) URL."""
    m = _URL.fullmatch(u)
    if not m or m.group(1).lower() not in ("http", "https"):
        return None
    scheme, host, port = m.group(1).lower(), m.group(2).lower().rstrip("."), m.group(3)
    if not host:
        return None
    if port and not ((scheme, port) in (("http", "80"), ("https", "443"))):
        host += ":" + port
    keep = sorted(p for p in (m.group(5) or "").split("&")
                  if p and not (p.split("=", 1)[0].lower().startswith("utm_") or p.split("=", 1)[0].lower() in _TRACKING))
    return f"{scheme}://{host}{m.group(4) or '/'}" + ("?" + "&".join(keep) if keep else "")


def url_outlet(u: str):
    """the outlet (publisher) of a URL: its host without port and without ONE leading «www.», «m.» or «amp.»
    (desktop, mobile and AMP versions of a site are one outlet)"""
    n = url_norm(u)
    if n is None:
        return None
    host = n.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    for pre in ("www.", "m.", "amp."):
        if host.startswith(pre) and "." in host[len(pre):]:
            return host[len(pre):]
    return host


def publication_address(tenant_id, outlet, text_digest):
    return "pub:sha256:" + digest({"tenant_id": tenant_id, "outlet": outlet, "text_digest": text_digest})


def cadastral_norm(v):
    return ":".join(str(int(p)) for p in v.split(":"))


def _digits(v):
    return [int(c) for c in v]


def _ascii_digits(v):
    return v.isascii() and v.isdigit()


def inn_ok(v: str) -> bool:
    d = _digits(v)
    def ctl(coef, n):
        return sum(c * x for c, x in zip(coef, d[:n])) % 11 % 10
    if len(d) == 10:
        return ctl([2, 4, 10, 3, 5, 9, 4, 6, 8], 9) == d[9]
    if len(d) == 12:
        return (ctl([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 10) == d[10]
                and ctl([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11) == d[11])
    return False


def ogrn_ok(v: str) -> bool:
    return len(v) == 13 and int(v[:12]) % 11 % 10 == int(v[12])


def ogrnip_ok(v: str) -> bool:
    return len(v) == 15 and int(v[:14]) % 13 % 10 == int(v[14])


def inn_any_ok(v):
    return len(v) in (10, 12) and inn_ok(v)


def imo_ok(v: str) -> bool:
    d = _digits(v)
    return len(d) == 7 and sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]


def entity_identifiers(e, R, ref):
    """Return (strong, weak, soft); emit checksum/insufficiency errors.
    strong: (scheme, value) — any collision between different owners is a duplicate.
    weak:   (scheme, value, qual) — a collision is a duplicate unless BOTH carry a qualifier and they differ
            (ФИО+дата рождения: qualifier = disambiguator; событие/конфликт: место; понятие: disambiguator).
    soft:   skeleton keys whose collision is only a POSSIBLE_DUPLICATE warning (equipment tags, models, concepts)."""
    t, i = e["entity_type"], e["identity"]
    strong, weak, soft = [], [], []
    if t == "PERSON":
        fio = norm(" ".join(x for x in (i["surname"], i["given_name"], i.get("patronymic", "")) if x))
        for f, ok, scheme in (("inn", inn_ok, "ru.inn"), ("ogrnip", ogrnip_ok, "ru.ogrnip")):
            if f in i:
                if not ok(i[f]):
                    R.err("IDENTIFIER_CHECKSUM_INVALID", ref, f"{scheme}: контрольные цифры")
                strong.append((scheme, i[f]))
        if "birth_date" in i:
            weak.append(("person.fio_dob", fio + "|" + i["birth_date"], i.get("disambiguator")))
        if not strong and not weak:
            if "disambiguator" not in i:
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "PERSON без ИНН, ОГРНИП и даты рождения требует disambiguator")
            else:
                strong.append(("person.fio_disamb", fio + "|" + i["disambiguator"]))
    elif t == "ORGANIZATION":
        form = i.get("legal_form", "LEGAL_ENTITY")
        if i.get("informal"):
            if "disambiguator" not in i or {"ogrn", "inn", "kpp"} & i.keys() or "legal_form" in i:
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "неформальная организация: только название и disambiguator")
            else:
                strong.append(("org.informal", norm(i["name"]) + "|" + i["disambiguator"]))
        else:
            if "inn" in i and not inn_ok(i["inn"]):
                R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "ИНН юрлица: контрольная цифра")
            if "ogrn" in i and not ogrn_ok(i["ogrn"]):
                R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "ОГРН: контрольная цифра")
            if form == "BRANCH":
                # a branch shares ИНН/ОГРН with its parent; its own key is ИНН+КПП
                if not ({"inn", "kpp"} <= i.keys()) or "ogrn" in i:
                    R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "филиал: ИНН и КПП головной организации, без ОГРН")
                else:
                    strong.append(("ru.inn_kpp", i["inn"] + "|" + i["kpp"]))
            else:
                if "ogrn" in i:
                    strong.append(("ru.ogrn", i["ogrn"]))
                if "inn" in i:
                    strong.append(("ru.inn", i["inn"]))
                if i["jurisdiction"] == "RU" and not ({"ogrn", "inn"} & i.keys()):
                    R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "организация РФ без ОГРН и ИНН")
            for f in i.get("foreign_ids", []):
                strong.append((f["scheme"], id_norm(f["value"])))
            if not strong and i["jurisdiction"] != "RU":
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "иностранная организация без регистрационного идентификатора")
    elif t == "REAL_ESTATE":
        strong.append(("ru.cadastral", cadastral_norm(i["cadastral_number"])))
    elif t == "MOVABLE_PROPERTY":
        need = {"VEHICLE": "vin", "VESSEL": "imo"}.get(i["subtype"])
        if "vin" in i:
            strong.append(("vin", i["vin"]))
        if "imo" in i:
            if not imo_ok(i["imo"]):
                R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "IMO: контрольная цифра")
            strong.append(("imo", i["imo"]))
        if "registration" in i:
            strong.append((i["registration"]["scheme"], id_norm(i["registration"]["value"])))
        if (need and need not in i) or not strong:
            R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, f"{i['subtype']}: нет обязательного идентификатора")
    elif t == "EVENT":
        # place is optional: the same title+date with and without place is one event (RR-03a)
        weak.append(("event", norm(i["title"]) + "|" + i["date"], norm(i["place"]) if "place" in i else None))
    elif t == "CONFLICT":
        weak.append(("conflict", norm(i["title"]) + "|" + i["started_on"], norm(i["place"]) if "place" in i else None))
    elif t == "EQUIPMENT":
        strong.append(("equipment", i["site_id"] + "|" + tag_norm(i["tag"])))
        soft.append(("equipment", i["site_id"] + "|" + tag_compact(norm(i["tag"]))))
    elif t == "EQUIPMENT_MODEL":
        # model codes: Latin/Cyrillic mixing (HM vs НМ) is a typo, not a different model — skeleton is error-level
        strong.append(("equipment_model", norm(i["manufacturer"], nfkc=False) + "|" + norm(i["model"], nfkc=False)))
    elif t == "CONCEPT":
        # no ё->е and no look-alike folding (RR-02: небо/нёбо differ); homonyms (Орёл/орёл) need disambiguators
        ns = i.get("namespace", "") + "|" + i["lang"] + "|"
        weak.append(("concept", ns + base_key(i["label"]), i.get("disambiguator")))
        soft.append(("concept", ns + norm(i["label"])))
    elif t == "THING":
        # same rules as CONCEPT: label+lang+namespace are identity, optional disambiguator for homonyms
        ns = i.get("namespace", "") + "|" + i["lang"] + "|"
        weak.append(("thing", ns + base_key(i["label"]), i.get("disambiguator")))
        soft.append(("thing", ns + norm(i["label"])))
    return strong, weak, soft


CHECKSUMS = {"ru.inn": lambda v: inn_any_ok(v), "ru.ogrn": lambda v: ogrn_ok(v),
             "ru.ogrnip": lambda v: ogrnip_ok(v), "imo": lambda v: imo_ok(v)}


# ---------- helpers ----------

def dominates(a, b):
    return LEVEL[a["level"]] >= LEVEL[b["level"]] and set(a["categories"]) >= set(b["categories"])


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def claim_digest_id(c):
    return "clm:sha256:" + digest({k: v for k, v in c.items() if k != "claim_id"})


def receipt_digest_id(r):
    return "rcp:sha256:" + digest({k: v for k, v in r.items() if k not in ("receipt_id", "signature")})


# ---------- main ----------

UNICODE_VERSION = "14.0.0"   # the database tables (keys, ignorables, unassigned code points) are generated for it (S5R-13)


def validate(ds, trust=None, content=None):
    """ds: dataset dict; trust: trust-anchors dict (None = no trusted keys);
    content: mapping source_id -> bytes (object store). Returns Report."""
    R = Report()
    if unicodedata.unidata_version != UNICODE_VERSION:   # fail-closed: keys and text digests would differ from the database
        R.err("VALIDATOR_INTERNAL_ERROR", "-", f"Unicode {unicodedata.unidata_version} != {UNICODE_VERSION}: таблицы базы сгенерированы для другой версии")
        return R
    content = content or {}
    trust = trust if trust is not None else {"trust_format": "core-trust/0.2", "keys": []}

    # phase 0 + 1: dataset (inside try: nothing may escape as an exception — RR-05)
    try:
        raw = []
        prescan(ds, "", raw)
        for p, m in raw:
            R.err("SCHEMA_INVALID", p or "/", m)
        if not raw:
            for e in DATASET_V.iter_errors(ds):
                R.err("SCHEMA_INVALID", "/" + "/".join(str(p) for p in e.absolute_path), e.message[:200])
        # trust configuration (fail-closed per tenant: a broken tenant entry trusts no key of that tenant — RR-06)
        traw = []
        prescan(trust, "", traw)
        terrs = [m for _, m in traw] or [e.message[:200] for e in TRUST_V.iter_errors(trust)]
    except RecursionError:
        R.err("SCHEMA_INVALID", "/", "слишком глубокая вложенность")
        return R
    keys, bad_tenants = {}, set()
    if not terrs:
        for k in trust["keys"]:
            kk = (k["tenant_id"], k["key_id"])
            if kk in keys:
                terrs.append(f"ключ {k['key_id']} повторяется в tenant {k['tenant_id']}")
                bad_tenants.add(k["tenant_id"])
            elif not k["not_before"] < k["not_after"] or ("revoked_at" in k and k["revoked_at"] < k["not_before"]):
                terrs.append(f"ключ {k['key_id']}: интервал действия")
                bad_tenants.add(k["tenant_id"])
            keys[kk] = k
        keys = {kk: k for kk, k in keys.items() if kk[0] not in bad_tenants}
    for m in terrs:
        R.err("TRUST_CONFIG_INVALID", "trust", m)
    if R.errors and R.codes() != ["TRUST_CONFIG_INVALID"]:
        return R  # fail-closed: no semantics on a malformed dataset
    try:
        _semantic(ds, keys, content, R)
    except Exception as ex:  # noqa: BLE001 - fail-closed safety net
        R.err("VALIDATOR_INTERNAL_ERROR", "-", f"{type(ex).__name__}: {ex}"[:200])
    return R


def _semantic(ds, keys, content, R):
    by = defaultdict(dict)
    for n, r in enumerate(ds["records"]):
        k = r["kind"]
        rid = r[ID_FIELD[k]]
        if rid in by[k]:
            R.err("DUPLICATE_ID", f"records[{n}]", f"{k} {rid} повторяется")
            continue
        by[k][rid] = r
    P, S, E, C, V, Kc, A = (by[x] for x in ("Project", "Source", "Entity", "Claim", "ClaimReview", "Check", "ArtifactReceipt"))
    CD, LD, IDD, SCX = (by[x] for x in ("ClassDef", "LinkDef", "IdentifierDef", "SchemaChange"))
    preds = {p["id"]: p for p in PREDICATES["predicates"]}
    profiles = PREDICATES["check_profiles"]

    def tenant_of(project_id):
        return P[project_id]["tenant_id"] if project_id in P else None

    # ---- sources: bytes and content addressing
    source_bytes, bad_sources = {}, set()
    for sid, s in S.items():
        inline = s["content_inline"].encode("utf-8") if "content_inline" in s else None
        stored = content.get(sid)
        if inline is not None and stored is not None and inline != stored:
            R.err("SOURCE_DIGEST_MISMATCH", sid, "content_inline не совпадает с хранилищем")
            bad_sources.add(sid)
            continue
        b = inline if inline is not None else stored
        if b is None:
            continue
        if "src:sha256:" + hashlib.sha256(b).hexdigest() != sid or len(b) != s["byte_length"]:
            R.err("SOURCE_DIGEST_MISMATCH", sid, "байты не совпадают с адресом/длиной")
            bad_sources.add(sid)
            continue
        source_bytes[sid] = b
    unavailable_reported = set()

    # ---- originals (S5 part 2, D26): an observation may name the raw capture (page, PDF, scan) kept in the object
    # store; the claim of custody is checked: the object is there, has this address and this length
    for sid, s in S.items():
        for n, o in enumerate(s["observations"]):
            og = o.get("original")
            if og is None:
                continue
            ob = content.get(og["object"])
            if ob is None:
                R.err("ORIGINAL_INVALID", sid, f"observations[{n}]: оригинала нет в хранилище объектов")
            elif "sha256:" + hashlib.sha256(ob).hexdigest() != og["object"] or len(ob) != og["byte_length"]:
                R.err("ORIGINAL_INVALID", sid, f"observations[{n}]: байты оригинала не совпадают с адресом или длиной")

    # ---- publications (S5, O4): renditions are DERIVED — every source of the tenant with the same normalized text
    # observed at the outlet; the record names the publication and is backed by renditions observed by recorded_at
    src_text = {sid: text_digest_of(b) for sid, b in source_bytes.items()}
    for pid, pb in by["Publication"].items():
        if publication_address(pb["tenant_id"], pb["outlet"], pb["text_digest"]) != pid:
            R.err("PUBLICATION_INVALID", pid, "адрес публикации != sha256(JCS(tenant, издание, текст))")
        if url_norm(pb["canonical_url"]) != pb["canonical_url"] or url_outlet(pb["canonical_url"]) != pb["outlet"]:
            R.err("PUBLICATION_INVALID", pid, "канонический адрес не в нормальной форме или другого издания")
        basis = []
        for sid, s in S.items():
            if s["tenant_id"] != pb["tenant_id"]:
                continue
            seen = [o["observed_at"] for o in s["observations"] if url_outlet(o["origin_uri"]) == pb["outlet"]]
            if not seen or min(seen) > pb["recorded_at"]:
                continue
            if src_text.get(sid) == pb["text_digest"]:    # a source without verified bytes is no rendition (S5R-07)
                basis.append((s, min(seen)))
        if not basis:
            R.err("PUBLICATION_INVALID", pid, "нет ни одного источника этого издания с этим текстом, полученного к recorded_at")
            continue
        for s, first in basis:
            if not dominates(pb["marking"], s["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", pid, "маркировка публикации шире маркировки её источника")
        if "published_at" in pb and pb["published_at"] > min(f for _, f in basis):
            R.err("TEMPORAL_ORDER_INVALID", pid, "публикация вышла позже, чем её получили")

    # ---- entities
    for eid, e in E.items():
        if e["project_id"] not in P:
            R.err("REF_UNRESOLVED", eid, "неизвестный project_id")
        if "status_changed_at" in e and e["status_changed_at"] < e["created_at"]:
            R.err("TEMPORAL_ORDER_INVALID", eid, "status_changed_at раньше created_at")
        if e["entity_type"] == "PERSON" and "PERSONAL_DATA" not in e["marking"]["categories"]:
            R.err("MARKING_PD_MISSING", eid, "PERSON без категории PERSONAL_DATA")
        if e["status"] == "MERGED":
            t = E.get(e["merged_into"])
            # the survivor must have been ACTIVE when the merge happened; it may be retired later (RR-13)
            if (t is None or not (t["status"] == "ACTIVE" or (t["status"] == "RETIRED"
                                                               and t["status_changed_at"] > e["status_changed_at"]))
                    or t["project_id"] != e["project_id"]
                    or t["entity_type"] != e["entity_type"]):
                R.err("ENTITY_MERGE_INVALID", eid, "merged_into: сущность того же типа и проекта, ACTIVE на момент слияния")
            elif not dominates(e["marking"], t["marking"]):
                # S22-01: claims about the merged entity become claims about the survivor; a broader survivor would
                # carry them into a marking they were never cleared for
                R.err("ENTITY_MERGE_INVALID", eid, "маркировка выжившей сущности шире маркировки сливаемой")

    def resolve(eid):  # one hop is enough: merge targets must be ACTIVE (ENTITY_MERGE_INVALID otherwise)
        e = E.get(eid)
        return e["merged_into"] if e and e["status"] == "MERGED" else eid

    # ---- identity decisions (RS-13, RS-15): analyst says «different» (clears a skeleton collision) or adds the
    # missing qualifier to an existing entity (append-only refinement instead of editing identity)
    qualify, qual_at, distinct_pairs = {}, {}, set()
    for did, d in by["IdentityDecision"].items():
        ids = d["entity_ids"] if d["decision"] == "DISTINCT" else [d["entity_id"]]
        ents = [E.get(x) for x in ids]
        if d["project_id"] not in P or None in ents:
            R.err("REF_UNRESOLVED", did, "неизвестный проект или сущность решения")
            continue
        if any(x["project_id"] != d["project_id"] for x in ents):
            R.err("CROSS_SCOPE_REFERENCE", did, "сущность решения из другого проекта")
            continue
        if any(d["decided_at"] < x["created_at"] for x in ents):
            R.err("TEMPORAL_ORDER_INVALID", did, "решение раньше создания сущности")
        if d["decision"] == "DISTINCT":
            if ents[0]["entity_type"] != ents[1]["entity_type"]:
                R.err("IDENTITY_DECISION_INVALID", did, "«различны» — только для сущностей одного типа")
            elif resolve(ids[0]) == resolve(ids[1]):
                R.err("IDENTITY_DECISION_INVALID", did, "решено «различны», но сущности слиты")
            else:
                distinct_pairs.add(frozenset(resolve(x) for x in ids))
            continue
        e, eid = ents[0], ids[0]
        t, idn = e["entity_type"], e["identity"]
        field = "place" if t in ("EVENT", "CONFLICT") else "disambiguator"
        fits = (t in ("EVENT", "CONFLICT", "CONCEPT") or (t == "PERSON" and "birth_date" in idn)) and field in d
        merged_before = e["status"] == "MERGED" and e["status_changed_at"] <= d["decided_at"]
        if not fits or field in idn or merged_before or eid in qualify:
            R.err("IDENTITY_DECISION_INVALID", did, f"{eid}: уточнение допустимо один раз, только недостающего {field} "
                                                    "у слабого ключа (ФИО+дата, событие, конфликт, понятие), не для слитой")
            continue
        qualify[eid] = {field: d[field]}
        qual_at[eid] = (norm(d[field]) if field == "place" else d[field], d["decided_at"])

    # uniqueness: identifiers of MERGED entities stay owned by the survivor; RETIRED keep theirs.
    # Index keys carry the entity type (RR-12).
    strong_idx, weak_idx, soft_idx = defaultdict(set), defaultdict(list), defaultdict(set)
    distinct = defaultdict(lambda: defaultdict(set))  # owner -> scheme -> values that tell namesakes apart
    for eid, e in E.items():
        strong, weak, soft = entity_identifiers(e, R, eid)
        owner = resolve(eid)
        t = e["entity_type"]
        for x in strong:
            strong_idx[(e["project_id"], t, x)].add(owner)
            if x[0] in ("ru.inn", "ru.ogrnip"):
                distinct[owner][x[0]].add(x[1])
        for sch, val, qual in weak:
            # a qualifier added by a decision counts from decided_at; it also covers keys of entities merged into the owner
            qt = None
            if qual is None and owner in qual_at:
                qual, qt = qual_at[owner]
            weak_idx[(e["project_id"], t, sch, val)].append((owner, qual, e["created_at"], qt))
        for x in soft:
            soft_idx[(e["project_id"], t, x)].add(owner)
    reported, separated = set(), set()
    for (prj, t, x), owners in strong_idx.items():
        if len(owners) > 1:
            reported.add(frozenset(owners))
            R.err("ENTITY_DUPLICATE_IN_PROJECT", ",".join(sorted(owners)), f"{prj}: {x[0]} у нескольких сущностей")

    def told_apart(a, b):  # namesakes: both carry the same kind of strong personal id and the ids differ (RR-04)
        return any(distinct[a][sch] and distinct[b][sch] and not (distinct[a][sch] & distinct[b][sch])
                   for sch in ("ru.inn", "ru.ogrnip"))
    for (prj, t, sch, val), lst in weak_idx.items():
        for a in range(len(lst)):
            for b in range(a + 1, len(lst)):
                (oa, qa, ca, ta), (ob, qb, cb, tb) = lst[a], lst[b]
                if oa == ob:
                    continue
                # a qualifier (disambiguator / place) separates only if BOTH have one and they differ (RR-03a-c) —
                # and only if it existed before both entities did (a homonym created before the refinement was a duplicate)
                if qa is not None and qb is not None and qa != qb and max(ca, cb) >= max(ta or ca, tb or cb):
                    separated.add(frozenset((oa, ob)))
                    continue
                if told_apart(oa, ob):
                    continue
                reported.add(frozenset((oa, ob)))
                R.err("ENTITY_DUPLICATE_IN_PROJECT", ",".join(sorted((oa, ob))), f"{prj}: {sch} совпадает")
    for (prj, t, x), owners in soft_idx.items():
        open_pairs = {frozenset((a, b)) for a in owners for b in owners if a < b} - reported - separated - distinct_pairs
        if open_pairs:
            R.warn("POSSIBLE_DUPLICATE", ",".join(sorted(set().union(*open_pairs))),
                   f"{prj}: {x[0]} совпадает по скелету — нужно решение аналитика (IdentityDecision)")

    # ---- claims
    for cid, c in C.items():
        if claim_digest_id(c) != cid:
            R.err("CLAIM_ID_MISMATCH", cid, "claim_id != sha256(JCS(claim без claim_id))")
        if c["project_id"] not in P:
            R.err("REF_UNRESOLVED", cid, "неизвестный project_id")
            continue
        subj = E.get(c["subject"])
        obj_ent = None
        if subj is None:
            R.err("REF_UNRESOLVED", cid, "неизвестный subject")
        elif subj["project_id"] != c["project_id"]:
            R.err("CROSS_SCOPE_REFERENCE", cid, "subject из другого проекта")
            subj = None
        if "entity" in c["object"]:
            obj_ent = E.get(c["object"]["entity"])
            if obj_ent is None:
                R.err("REF_UNRESOLVED", cid, "неизвестная сущность-объект")
            elif obj_ent["project_id"] != c["project_id"]:
                R.err("CROSS_SCOPE_REFERENCE", cid, "объект из другого проекта")
                obj_ent = None
        p = preds.get(c["predicate"])
        if p is None:
            R.err("PREDICATE_UNKNOWN", cid, c["predicate"])
        else:
            if subj is not None and subj["entity_type"] not in p["domain"]:
                R.err("PREDICATE_DOMAIN_VIOLATION", cid, f"{subj['entity_type']} не в domain {c['predicate']}")
            rng = p["range"]
            if "entity" in c["object"]:
                if "entity" not in rng or (obj_ent is not None and obj_ent["entity_type"] not in rng["entity"]):
                    R.err("PREDICATE_RANGE_VIOLATION", cid, "тип объекта вне range")
            else:
                lit = c["object"]["literal"]
                if ("literal" not in rng or lit["type"] not in rng["literal"]
                        or (lit["type"] == "IDENTIFIER" and "schemes" in rng and lit["scheme"] not in rng["schemes"])
                        or (lit["type"] == "QUANTITY" and "units" in rng and lit["unit"] not in rng["units"])):
                    R.err("PREDICATE_RANGE_VIOLATION", cid, "литерал вне range (тип, схема идентификатора или единица)")
                if lit["type"] == "IDENTIFIER" and lit["scheme"] in CHECKSUMS:
                    v = lit["value"]
                    if not (_ascii_digits(v) and CHECKSUMS[lit["scheme"]](v)):
                        R.err("IDENTIFIER_CHECKSUM_INVALID", cid, f"{lit['scheme']}: контрольные цифры литерала")
            spec = p.get("qualifiers", {})
            q = c.get("qualifiers", {})
            for name, v in q.items():
                s = spec.get(name)
                ok = s is not None and (
                    (s["type"] == "enum" and isinstance(v, str) and v in s["enum"]) or
                    (s["type"] == "integer" and isinstance(v, int) and not isinstance(v, bool)
                     and s.get("min", v) <= v <= s.get("max", v)) or
                    (s["type"] == "string" and isinstance(v, str) and v.strip() != "") or
                    (s["type"] == "boolean" and isinstance(v, bool)))
                if not ok:
                    R.err("QUALIFIER_INVALID", cid, f"квалификатор {name}={v!r}")
            for name, s in spec.items():
                if s.get("required") and name not in q:
                    R.err("QUALIFIER_INVALID", cid, f"нет обязательного квалификатора {name}")
        if "valid_from" in c and "valid_to" in c and c["valid_from"] > c["valid_to"]:
            R.err("TEMPORAL_ORDER_INVALID", cid, "valid_from > valid_to")
        for x in (subj, obj_ent):
            if x is not None and not dominates(c["marking"], x["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", cid, f"маркировка утверждения шире маркировки сущности {x['entity_id']}")
        for ev in c["evidence"]:
            sid = ev["source_id"]
            s = S.get(sid)
            if s is None:
                R.err("REF_UNRESOLVED", cid, "неизвестный источник")
                continue
            if s["tenant_id"] != tenant_of(c["project_id"]):
                R.err("CROSS_SCOPE_REFERENCE", cid, "источник другого tenant")
            if min(o["observed_at"] for o in s["observations"]) > c["recorded_at"]:
                R.err("TEMPORAL_ORDER_INVALID", cid, "утверждение записано раньше, чем получен источник")
            if not dominates(c["marking"], s["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", cid, "маркировка утверждения шире маркировки источника")
            b = source_bytes.get(sid)
            if b is None:
                if sid not in unavailable_reported and sid not in bad_sources:
                    unavailable_reported.add(sid)
                    R.err("SOURCE_CONTENT_UNAVAILABLE", sid, "нет проверенных байтов источника — фрагмент не проверяем")
                continue
            st, en = ev["span"]["start"], ev["span"]["end"]
            span_ok = st < en <= len(b)
            if span_ok:
                chunk = b[st:en]
                try:
                    txt = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    span_ok = False
                else:
                    span_ok = hashlib.sha256(chunk).hexdigest() == ev["quote_sha256"] and ev.get("quote", txt) == txt
            if not span_ok:
                R.err("EVIDENCE_SPAN_INVALID", cid, f"фрагмент [{st},{en}) не подтверждается байтами источника")

    # ---- reviews: status history ordered by system time (recorded_at), not by declared reviewed_at
    reviews_by_claim = defaultdict(list)
    for rid, rv in V.items():
        c = C.get(rv["claim_id"])
        if c is None:
            R.err("REF_UNRESOLVED", rid, "неизвестное утверждение")
            continue
        if rv["reviewed_at"] < c["recorded_at"] or rv["recorded_at"] < rv["reviewed_at"]:
            R.err("TEMPORAL_ORDER_INVALID", rid, "claim.recorded_at ≤ reviewed_at ≤ review.recorded_at")
        reviews_by_claim[rv["claim_id"]].append(rv)
    for cid, lst in reviews_by_claim.items():
        seen = defaultdict(set)
        for rv in lst:
            seen[rv["recorded_at"]].add(rv["status"])
        if any(len(v) > 1 for v in seen.values()):
            R.err("CLAIM_REVIEW_AMBIGUOUS", cid, "разные статусы с одинаковым временем записи")

    def status_at(cid, t):
        lst = [rv for rv in reviews_by_claim.get(cid, []) if t is None or rv["recorded_at"] <= t]
        return max(lst, key=lambda r: r["recorded_at"])["status"] if lst else "ASSERTED"

    # ---- contradictions (warnings)
    groups = defaultdict(list)
    for cid, c in C.items():
        p = preds.get(c["predicate"])
        if p and p["cardinality"] == "ONE" and status_at(cid, None) not in ("REFUTED", "WITHDRAWN"):
            groups[(c["project_id"], resolve(c["subject"]), c["predicate"])].append(c)
    for key, lst in groups.items():
        for a in range(len(lst)):
            for b in range(a + 1, len(lst)):
                x, y = lst[a], lst[b]
                overlap = (x.get("valid_from", "0000") <= y.get("valid_to", "9999")
                           and y.get("valid_from", "0000") <= x.get("valid_to", "9999"))
                if overlap and canon(x["object"]) != canon(y["object"]):
                    R.warn("CONTRADICTION_SINGLE_VALUED", f"{x['claim_id']}|{y['claim_id']}", f"{key[2]}: источники расходятся")

    # ---- Checks
    for kid, k in Kc.items():
        prj = P.get(k["project_id"])
        if prj is None:
            R.err("REF_UNRESOLVED", kid, "неизвестный project_id")
            continue
        if prj["product"] != "COMPLIANCE":
            R.err("CHECK_PROJECT_NOT_COMPLIANCE", kid, "Проверка вне проекта COMPLIANCE")
        done = k["status"] == "COMPLETED"
        closed_at = k.get("completed_at") or k.get("cancelled_at")
        subj = E.get(k["subject_entity_id"])
        if subj is None:
            R.err("REF_UNRESOLVED", kid, "неизвестный субъект")
        elif subj["project_id"] != k["project_id"]:
            R.err("CROSS_SCOPE_REFERENCE", kid, "субъект из другого проекта")
        else:
            # a closed Check keeps its subject even if it is merged/retired later
            # (MERGED or RETIRED strictly after closing is fine — RR-01; the survivor's later fate does not matter)
            live = subj["status"] == "ACTIVE" or (closed_at is not None and subj["status_changed_at"] > closed_at)
            if not live or subj["entity_type"] not in ("PERSON", "ORGANIZATION"):
                R.err("CHECK_SUBJECT_INVALID", kid, "субъект: ACTIVE физлицо или юрлицо (на момент закрытия Проверки)")
            if not dominates(k["marking"], subj["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", kid, "маркировка Проверки шире маркировки субъекта")
        if closed_at is not None and (closed_at < k["requested_at"] or k["as_of"] > closed_at[:10]):
            R.err("TEMPORAL_ORDER_INVALID", kid, "закрытие раньше запроса или as_of позже закрытия")
        dims = profiles[k["profile"]]
        fdims = [f["dimension"] for f in k["findings"]]
        if len(set(fdims)) != len(fdims):
            R.err("CHECK_FINDING_INCONSISTENT", kid, "повтор измерения")
        for d in sorted(set(fdims) - set(dims)):
            R.err("CHECK_DIMENSION_OUTSIDE_PROFILE", kid, f"{d} вне профиля {k['profile']}")
        if done and set(dims) - set(fdims):
            R.err("CHECK_DIMENSION_MISSING", kid, f"нет результата по {sorted(set(dims) - set(fdims))}")
        subj_id = resolve(k["subject_entity_id"])
        for f in k["findings"]:
            if (f["result"] == "FOUND") != bool(f["claim_ids"]) or (f["result"] == "NOT_FOUND" and f["risk"] != "NONE"):
                R.err("CHECK_FINDING_INCONSISTENT", kid, f"{f['dimension']}: результат/утверждения/риск не согласованы")
            if done and not any(k["requested_at"] <= s["performed_at"] <= k["completed_at"] for s in f["searches"]):
                R.err("CHECK_SEARCH_MISSING", kid, f"{f['dimension']}: нет поиска в окне Проверки")
            for s in f["searches"]:
                if "result_source_id" in s:
                    rs = S.get(s["result_source_id"])
                    if rs is None:
                        R.err("REF_UNRESOLVED", kid, "неизвестный источник результата поиска")
                    elif rs["tenant_id"] != prj["tenant_id"]:
                        R.err("CROSS_SCOPE_REFERENCE", kid, "источник результата поиска другого tenant")
                    else:
                        rsid = s["result_source_id"]
                        if rsid not in source_bytes and rsid not in bad_sources and rsid not in unavailable_reported:
                            unavailable_reported.add(rsid)
                            R.err("SOURCE_CONTENT_UNAVAILABLE", rsid, "у источника результата поиска нет проверенных байтов")
                        if not dominates(k["marking"], rs["marking"]):
                            R.err("MARKING_BROADER_THAN_INPUT", kid, "маркировка Проверки шире маркировки источника результата поиска")
            for cid in f["claim_ids"]:
                c = C.get(cid)
                if c is None:
                    R.err("REF_UNRESOLVED", kid, "неизвестное утверждение")
                    continue
                if c["project_id"] != k["project_id"]:
                    R.err("CROSS_SCOPE_REFERENCE", kid, "утверждение другого проекта")
                    continue
                touches = {resolve(c["subject"])} | ({resolve(c["object"]["entity"])} if "entity" in c["object"] else set())
                if subj_id not in touches:
                    R.err("CHECK_CLAIM_NOT_ABOUT_SUBJECT", kid, f"{cid} не о субъекте")
                p = preds.get(c["predicate"])
                if p is not None and f["dimension"] not in p["dimensions"]:
                    R.err("CHECK_CLAIM_DIMENSION_MISMATCH", kid, f"{c['predicate']} не относится к {f['dimension']}")
                # any ACCEPTED review recorded by completion implies the claim was recorded before it (review rules)
                if done and status_at(cid, k["completed_at"]) != "ACCEPTED":
                    R.err("CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", kid, f"{cid} не ACCEPTED на момент завершения")
                if not dominates(k["marking"], c["marking"]):
                    R.err("MARKING_BROADER_THAN_INPUT", kid, "маркировка Проверки шире маркировки утверждения")
        if done:
            exp = max((RISK[f["risk"]] for f in k["findings"]), default=0)
            if RISK[k["overall_risk"]] != exp:
                R.err("CHECK_FINDING_INCONSISTENT", kid, "overall_risk != max(риск по измерениям)")
        if "previous_check_id" in k:
            pv = Kc.get(k["previous_check_id"])
            if pv is None:
                R.err("REF_UNRESOLVED", kid, "неизвестная предыдущая Проверка")
            # (self-reference fails as_of; another project implies another subject - entities are project-scoped)
            elif resolve(pv["subject_entity_id"]) != subj_id or pv["as_of"] >= k["as_of"]:
                R.err("CHECK_PREVIOUS_INVALID", kid, "предыдущая Проверка: тот же субъект и более ранняя дата")
            elif pv["status"] != "COMPLETED" or pv["completed_at"] > k["requested_at"]:
                R.err("CHECK_PREVIOUS_INVALID", kid, "предыдущая Проверка завершена до запроса новой (S23-01)")
            elif not dominates(k["marking"], pv["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", kid, "Проверка уже маркировки предыдущей Проверки (S22-03)")

    # ---- artifact receipts (keys come ONLY from trust anchors)
    listed = defaultdict(list)
    for rid, r in A.items():
        if receipt_digest_id(r) != rid:
            R.err("RECEIPT_ID_MISMATCH", rid, "receipt_id != sha256(JCS(receipt без receipt_id/signature))")
        if r["project_id"] not in P:
            R.err("REF_UNRESOLVED", rid, "неизвестный project_id")
            continue
        key = keys.get((tenant_of(r["project_id"]), r["key_id"]))
        t = r["issued_at"]
        if (key is None or key["service_id"] != r["producer"]["service_id"]
                or not (key["not_before"] <= t < key["not_after"]) or ("revoked_at" in key and key["revoked_at"] <= t)):
            R.err("RECEIPT_KEY_INVALID", rid, "ключ не из доверенного реестра tenant, чужой службы или не действует на issued_at")
        else:
            try:
                Ed25519PublicKey.from_public_bytes(b64u_dec(key["public_key"])).verify(b64u_dec(r["signature"]), rid.encode("utf-8"))
            except (InvalidSignature, ValueError):
                R.err("RECEIPT_SIGNATURE_INVALID", rid, "подпись Ed25519 над receipt_id не сходится")
        for sid in r["input_source_ids"]:
            s = S.get(sid)
            if s is None:
                R.err("REF_UNRESOLVED", rid, "неизвестный входной источник")
            elif s["tenant_id"] != tenant_of(r["project_id"]):
                R.err("CROSS_SCOPE_REFERENCE", rid, "источник другого tenant")
        for cid in r["emitted_claim_ids"]:
            c = C.get(cid)
            if c is None:
                R.err("REF_UNRESOLVED", rid, "неизвестное утверждение")
                continue
            listed[cid].append(r)
            pb = c["produced_by"]
            if pb["kind"] != "PIPELINE":
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: в receipt только PIPELINE-утверждения")
                continue
            if pb["service_id"] != r["producer"]["service_id"]:
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: другая служба")
            if pb["run_id"] != r["run_id"]:
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: другой run_id")
            if c["project_id"] != r["project_id"]:
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: другой проект")
            if c["recorded_at"] > t:
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: записано после issued_at")
            if not {ev["source_id"] for ev in c["evidence"]} <= set(r["input_source_ids"]):
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: источник доказательства не во входах")
            if any("graph_node" in ev and ev["graph_node"]["artifact_digest"] != r["artifact_digest"] for ev in c["evidence"]):
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid}: узел графа из другого артефакта")
    for cid, c in C.items():
        n = len(listed.get(cid, []))
        if c["produced_by"]["kind"] == "PIPELINE" and n != 1:
            R.err("RECEIPT_CLAIM_BINDING_INVALID", cid, f"PIPELINE-утверждение в {n} receipt (нужно ровно 1)")
        if c["produced_by"]["kind"] == "HUMAN" and any("graph_node" in ev for ev in c["evidence"]):
            R.err("RECEIPT_CLAIM_BINDING_INVALID", cid, "узел графа допустим только у PIPELINE-утверждения")

    # ---- artifacts of receipts (RR-07, D17): the artifact is in the object store, is exactly the signed digest,
    # canonical JSON of a registered format and profile, agrees with its receipt; anchors fall on source bytes;
    # every claim of the receipt rests on a RELATION node of that artifact that says the same thing as the claim.
    arts = {}

    def load_artifact(dg, ref):
        b = content.get(dg)
        if b is None:
            R.err("ARTIFACT_INVALID", ref, "нет байтов артефакта в хранилище — receipt не проверяем (RR-07)")
            return None
        if "sha256:" + hashlib.sha256(b).hexdigest() != dg:
            R.err("ARTIFACT_INVALID", ref, "байты артефакта не совпадают с artifact_digest")
            return None
        art, why = parse_artifact(b)
        if art is None:
            R.err("ARTIFACT_INVALID", ref, why)
            return None
        prof = ARTIFACT_FORMATS[art["artifact_format"]]["profiles"].get(art["semantic_profile"])
        if prof is None:
            R.err("ARTIFACT_INVALID", ref, "неизвестный семантический профиль артефакта")
            return None
        roles, nodes, bad = prof["roles"], {}, []
        for n in art["nodes"]:
            if n["id"] in nodes:
                bad.append(f"узел {n['id']} повторяется")
            nodes[n["id"]] = n
        for n in art["nodes"]:
            an = n.get("anchor")
            if an is not None:
                sb = source_bytes.get(an["source_id"])
                if an["source_id"] not in art["inputs"]:
                    bad.append(f"якорь узла {n['id']}: источник не во входах артефакта")
                elif sb is None:
                    if an["source_id"] not in unavailable_reported and an["source_id"] not in bad_sources:
                        unavailable_reported.add(an["source_id"])
                        R.err("SOURCE_CONTENT_UNAVAILABLE", an["source_id"], "нет проверенных байтов источника — якорь узла не проверяем")
                else:
                    ok = an["start"] < an["end"] <= len(sb)
                    if ok:
                        try:
                            sb[an["start"]:an["end"]].decode("utf-8")
                        except UnicodeDecodeError:
                            ok = False
                    if not ok:
                        bad.append(f"якорь узла {n['id']} не попадает в байты источника")
            if n["type"] == "RELATION":
                a0, a1 = nodes.get(n["args"][0]), nodes.get(n["args"][1])
                if a0 is None or a1 is None or ("condition" in n and nodes.get(n["condition"], {}).get("type") != "CONDITION"):
                    bad.append(f"отношение {n['id']}: ссылка на несуществующий узел (или условие не CONDITION)")
                    continue
                spec = roles.get(n["role"])
                if spec is not None and not (a0["type"] == "ENTITY" and a1["type"] == spec["object"]
                                             and ("parameter" in n) == (spec.get("qualifier") == "parameter")
                                             and ("condition" in n) == (spec.get("qualifier") == "condition")):
                    bad.append(f"отношение {n['id']} ({n['role']}): аргументы или уточнение не по профилю")
        for m in bad:
            R.err("ARTIFACT_INVALID", ref, m)
        return None if bad else (art, nodes, roles)

    runs = defaultdict(list)
    for rid, r in A.items():
        if r["project_id"] in P:
            runs[(tenant_of(r["project_id"]), r["producer"]["service_id"], r["run_id"])].append(rid)
    for (_, svc, run), rids in runs.items():
        if len(rids) > 1:                                 # S4R-08: a replayed run would double the claims
            R.err("ARTIFACT_INVALID", run, f"один запуск — один receipt; у {svc}/{run} их {len(rids)}")
    for rid, r in A.items():
        if r["project_id"] not in P:
            continue
        dg = r["artifact_digest"]
        if dg not in arts:
            arts[dg] = load_artifact(dg, rid)
        if arts[dg] is None:
            continue
        art = arts[dg][0]
        if (art["artifact_format"] != r["artifact_schema_version"] or art["semantic_profile"] != r["semantic_profile_version"]
                or art["producer"] != r["producer"] or art["run_id"] != r["run_id"]
                or set(art["inputs"]) != set(r["input_source_ids"])):
            R.err("ARTIFACT_INVALID", rid, "артефакт не совпадает с receipt: формат, профиль, служба, запуск или входы")

    def ent_keys(etype, identity):
        return set(entity_identifiers({"entity_type": etype, "identity": identity}, Report(), "-")[0])

    def merged_by(x, t):
        return x["status"] == "MERGED" and x["status_changed_at"] <= t

    def same_entity(e, node, t):
        """the node names the entity e at time t (the claim's recorded_at): its strong keys are keys of e's group at t —
        the entity e resolved to at t and every entity merged into it by t (S4R-02; S4R-11: merges after t do not count)"""
        if e is None or node["type"] != "ENTITY" or e["entity_type"] != node["entity_type"]:
            return False
        owner = e["merged_into"] if merged_by(e, t) else e["entity_id"]
        group = set()
        for x in E.values():
            if x["entity_id"] == owner or (merged_by(x, t) and x["merged_into"] == owner):
                group |= ent_keys(x["entity_type"], x["identity"])
        nk = ent_keys(node["entity_type"], node["identity"])
        return bool(nk) and nk <= group

    def graph_says(c, n, nodes, roles):
        spec = roles.get(n["role"])
        if spec is None:
            return f"роль {n['role']} не отображается в предикат профиля"
        if c["predicate"] != spec["predicate"]:
            return "предикат не совпадает с ролью узла"
        a0, a1 = nodes[n["args"][0]], nodes[n["args"][1]]
        if not same_entity(E.get(c["subject"]), a0, c["recorded_at"]):
            return "субъект не совпадает с узлом-аргументом"
        obj = c["object"]
        if spec["object"] == "ENTITY":
            ok = "entity" in obj and same_entity(E.get(obj["entity"]), a1, c["recorded_at"])
        elif spec["object"] == "QUANTITY":
            ok = obj.get("literal") == {"type": "QUANTITY", "value": a1["value"], "unit": a1["unit"]}
        else:
            ok = obj.get("literal") == {"type": "STRING", "value": a1["text"]}
        if not ok:
            return "объект не совпадает с узлом-аргументом"
        want = {}
        if spec.get("qualifier") == "parameter":
            want = {"parameter": n["parameter"]}
        elif spec.get("qualifier") == "condition":
            want = {"condition": nodes[n["condition"]]["text"]}
        if c.get("qualifiers", {}) != want:
            return "уточнения не совпадают с узлом"
        if "valid_from" in c or "valid_to" in c:          # S4R-01: the profile has no validity period on relations
            return "у отношения нет срока действия, а у утверждения есть"
        return None

    node_uses = defaultdict(set)                       # one RELATION node backs exactly one evidence (claim, position)
    for rid, r in A.items():
        a = arts.get(r["artifact_digest"])
        for cid in r["emitted_claim_ids"]:
            c = C.get(cid)
            if c is None or c["produced_by"]["kind"] != "PIPELINE":
                continue
            if any("graph_node" not in ev for ev in c["evidence"]):   # S4R-07: every fragment rests on a node
                R.err("GRAPH_NODE_INVALID", cid, "доказательство утверждения из артефакта без узла графа")
                continue
            if a is None:
                continue
            _, nodes, roles = a
            for pos, ev in enumerate(c["evidence"]):
                if "graph_node" not in ev:
                    continue
                gn = ev["graph_node"]
                if gn["artifact_digest"] != r["artifact_digest"]:
                    continue                                   # RECEIPT_CLAIM_BINDING_INVALID above
                n = nodes.get(gn["node_id"])
                if n is None or n["type"] != "RELATION":
                    R.err("GRAPH_NODE_INVALID", cid, f"узла {gn['node_id']} нет в артефакте или это не отношение")
                    continue
                node_uses[(gn["artifact_digest"], n["id"])].add((cid, pos))
                an, sp = n["anchor"], ev["span"]
                if an["source_id"] != ev["source_id"] or not (an["start"] <= sp["start"] and sp["end"] <= an["end"]):
                    R.err("GRAPH_NODE_INVALID", cid, f"фрагмент доказательства вне якоря узла {n['id']}")
                why = graph_says(c, n, nodes, roles)
                if why:
                    R.err("GRAPH_NODE_INVALID", cid, f"узел {n['id']}: {why}")
    for (dg, nid), cids in node_uses.items():
        if len(cids) > 1:
            R.err("GRAPH_NODE_INVALID", nid, f"один узел графа — несколько доказательств ({len(cids)})")

    # ---- schema records (D27.1, cycle 9): ClassDef, LinkDef, IdentifierDef, SchemaChange ----
    valid_entity_types = {"PERSON", "ORGANIZATION", "REAL_ESTATE", "MOVABLE_PROPERTY", "EVENT",
                          "CONFLICT", "EQUIPMENT", "EQUIPMENT_MODEL", "CONCEPT", "THING"}

    # ClassDef: tenant isolation; parent_class_id must exist within same tenant
    for cdef_id, cdef in CD.items():
        if "parent_class_id" in cdef:
            parent = CD.get(cdef["parent_class_id"])
            if parent is None:
                R.err("REF_UNRESOLVED", cdef_id, f"parent_class_id {cdef['parent_class_id']} не найден")
            elif parent["tenant_id"] != cdef["tenant_id"]:
                R.err("CROSS_SCOPE_REFERENCE", cdef_id, "parent_class_id из другого tenant")
            elif parent["root_type"] != cdef["root_type"]:
                R.err("SCHEMA_INVALID", cdef_id, "root_type наследника должен совпадать с root_type родителя")
        # cycle detection: parent chain must not loop
        seen_chain = {cdef_id}
        cur = cdef
        while "parent_class_id" in cur:
            pid = cur["parent_class_id"]
            if pid in seen_chain:
                R.err("SCHEMA_INVALID", cdef_id, "циклическое наследование классов")
                break
            seen_chain.add(pid)
            cur = CD.get(pid, {})

    # LinkDef: domain/range class_ids must exist within same tenant
    for ldef_id, ldef in LD.items():
        for ref_field in ("domain_class_id", "range_class_id"):
            ref_id = ldef[ref_field]
            ref_cls = CD.get(ref_id)
            if ref_cls is None:
                R.err("REF_UNRESOLVED", ldef_id, f"{ref_field} {ref_id} не найден")
            elif ref_cls["tenant_id"] != ldef["tenant_id"]:
                R.err("CROSS_SCOPE_REFERENCE", ldef_id, f"{ref_field} из другого tenant")
        if "inverse_predicate_id" in ldef:
            inv_pred = ldef["inverse_predicate_id"]
            if inv_pred not in preds:
                R.err("PREDICATE_UNKNOWN", ldef_id, f"inverse_predicate_id {inv_pred} не зарегистрирован")

    # IdentifierDef: applies_to_root_type must be a valid EntityType
    for idef_id, idef in IDD.items():
        if idef["applies_to_root_type"] not in valid_entity_types:
            R.err("SCHEMA_INVALID", idef_id, f"applies_to_root_type {idef['applies_to_root_type']} не EntityType")

    # SchemaChange: target_id must exist as the named target_kind
    for scx_id, scx in SCX.items():
        kind_map = {"ClassDef": CD, "LinkDef": LD, "IdentifierDef": IDD}
        target_store = kind_map.get(scx["target_kind"])
        if target_store is not None and scx["target_id"] not in target_store:
            R.err("REF_UNRESOLVED", scx_id, f"target_id {scx['target_id']} не найден в {scx['target_kind']}")

    # ---- is_a Claims (schema.is_a predicate) ----
    # Every Claim with predicate schema.is_a must:
    #   1. have object.literal.type == CLASS_REF
    #   2. class_id in CLASS_REF must exist as ClassDef in this dataset
    #   3. entity's entity_type must match class's root_type
    for cid, c in C.items():
        if c["predicate"] != "schema.is_a":
            continue
        lit = c["object"].get("literal")
        if lit is None or lit.get("type") != "CLASS_REF":
            R.err("PREDICATE_RANGE_VIOLATION", cid, "schema.is_a: объект должен быть литералом CLASS_REF")
            continue
        class_id = lit.get("class_id")
        cls = CD.get(class_id)
        if cls is None:
            R.err("REF_UNRESOLVED", cid, f"schema.is_a: class_id {class_id} не найден")
            continue
        # tenant isolation: class must belong to same tenant as claim's project
        claim_tenant = tenant_of(c["project_id"])
        if claim_tenant is not None and cls["tenant_id"] != claim_tenant:
            R.err("CROSS_SCOPE_REFERENCE", cid, "schema.is_a: ClassDef из другого tenant")
        # entity root_type must match class root_type
        subj_ent = E.get(c["subject"])
        if subj_ent is not None and subj_ent["entity_type"] != cls["root_type"]:
            R.err("PREDICATE_DOMAIN_VIOLATION", cid,
                  f"schema.is_a: entity_type {subj_ent['entity_type']} != ClassDef.root_type {cls['root_type']}")


def main(argv):
    args = argv[1:]
    as_json = "--json" in args
    trust = content_dir = None
    if "--trust" in args:
        trust = args[args.index("--trust") + 1]
    if "--content-dir" in args:
        content_dir = Path(args[args.index("--content-dir") + 1])
    try:
        ds = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        tr = json.loads(Path(trust).read_text(encoding="utf-8")) if trust else None
    except (OSError, ValueError, IndexError, RecursionError) as ex:
        print(f"ERROR SCHEMA_INVALID - не удалось прочитать вход: {type(ex).__name__}")
        return 1
    content = {}
    if content_dir is not None:
        for f in content_dir.iterdir():
            if f.is_file():
                content["src:sha256:" + f.name] = content["sha256:" + f.name] = f.read_bytes()
    R = validate(ds, tr, content)
    if as_json:
        print(json.dumps({"errors": R.errors, "warnings": R.warnings}, ensure_ascii=False, indent=1))
    else:
        for e in R.errors:
            print("ERROR", e["code"], e["ref"], e["msg"])
        for w in R.warnings:
            print("WARN ", w["code"], w["ref"], w["msg"])
        print(f"errors={len(R.errors)} warnings={len(R.warnings)}")
    return 1 if R.errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

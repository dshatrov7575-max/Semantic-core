"""Reference validator for core-ontology/0.2 (Архитектура семантики).

Inputs (all three are separate on purpose):
  dataset  - records (Project, Source, Entity, Claim, ClaimReview, Check, ArtifactReceipt);
  trust    - trust anchors (service keys per tenant), configuration OUTSIDE the data they authenticate;
  content  - source bytes by source_id (object store); Source.content_inline is accepted as well.

Phases, fail-closed:
  0. pre-scan of raw values: no floats, integers within +-(2^53-1), no lone surrogates (values and keys),
     no control characters except in free text (content_inline, quote, note)        -> SCHEMA_INVALID
  1. JSON Schema Draft 2020-12, patterns as FULL match, strict calendar formats         -> SCHEMA_INVALID
  2. semantic rules, one stable code each; an unexpected exception becomes VALIDATOR_INTERNAL_ERROR.

CLI: python3 validator.py dataset.json [--trust trust.json] [--content-dir DIR] [--json]
     DIR holds files named by the hex part of source_id. Exit 0 = no errors, 1 = errors.
"""
import base64
import hashlib
import json
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
    "VALIDATOR_INTERNAL_ERROR",
]
WARNING_CODES = ["CONTRADICTION_SINGLE_VALUED"]

FREE_TEXT_KEYS = {"content_inline", "quote", "note"}
MAX_SAFE = 2**53 - 1
LEVEL = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
RISK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
ID_FIELD = {"Project": "project_id", "Source": "source_id", "Entity": "entity_id", "Claim": "claim_id",
            "ClaimReview": "review_id", "Check": "check_id", "ArtifactReceipt": "receipt_id"}


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


def prescan(node, path, out, key=None):
    if isinstance(node, bool) or node is None:
        return
    if isinstance(node, float):
        out.append((path, "дробное число вне профиля (только целые)"))
    elif isinstance(node, int):
        if abs(node) > MAX_SAFE:
            out.append((path, "целое вне диапазона ±(2^53−1)"))
    elif isinstance(node, str):
        if _bad_str(node):
            out.append((path, "одиночный суррогат UTF-16"))
        elif key not in FREE_TEXT_KEYS and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in node):
            out.append((path, "управляющий символ в структурном поле"))
    elif isinstance(node, list):
        for n, v in enumerate(node):
            prescan(v, f"{path}/{n}", out, key)
    elif isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str) or _bad_str(k) or any(ord(ch) < 0x20 for ch in k):
                out.append((path, "недопустимый ключ"))
                continue
            prescan(v, f"{path}/{k}", out, k)
    else:
        out.append((path, f"недопустимый тип {type(node).__name__}"))


# ---------- identifiers ----------

_CONFUSABLE = str.maketrans({"A": "А", "a": "а", "B": "В", "C": "С", "c": "с", "E": "Е", "e": "е", "H": "Н",
                             "K": "К", "k": "к", "M": "М", "O": "О", "o": "о", "P": "Р", "p": "р", "T": "Т",
                             "X": "Х", "x": "х", "Y": "У", "y": "у"})
_QUOTES = set('"\'«»„“”‟‚‘’‛‹›`')


def norm(s: str) -> str:
    """Comparison skeleton for names/tags (never displayed): NFKC; drop format chars (ZWSP, soft hyphen, BOM…);
    Latin letters that look Cyrillic -> Cyrillic; casefold; ё->е; every dash -> '-'; drop quotes; collapse spaces."""
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    s = s.translate(_CONFUSABLE).casefold().replace("ё", "е")
    s = "".join("-" if unicodedata.category(ch) == "Pd" or ch == "−" else ch for ch in s)
    s = "".join(ch for ch in s if ch not in _QUOTES and unicodedata.category(ch) not in ("Pi", "Pf"))
    return " ".join(s.split())


def cadastral_norm(v):
    return ":".join(str(int(p)) for p in v.split(":"))


def _digits(v):
    return [int(c) for c in v]


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


def imo_ok(v: str) -> bool:
    d = _digits(v)
    return len(d) == 7 and sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]


def entity_identifiers(e, R, ref):
    """Return (strong, weak) identifier lists; emit checksum/insufficiency errors.
    strong: any collision between different entities is a duplicate.
    weak (ФИО+дата рождения): collision is a duplicate unless both carry different ИНН."""
    t, i = e["entity_type"], e["identity"]
    strong, weak = [], []
    if t == "PERSON":
        fio = norm(" ".join(x for x in (i["surname"], i["given_name"], i.get("patronymic", "")) if x))
        for f, ok, scheme in (("inn", inn_ok, "ru.inn"), ("ogrnip", ogrnip_ok, "ru.ogrnip")):
            if f in i:
                if not ok(i[f]):
                    R.err("IDENTIFIER_CHECKSUM_INVALID", ref, f"{scheme}: контрольные цифры")
                strong.append((scheme, i[f]))
        if "birth_date" in i:
            weak.append(("person.fio_dob", fio + "|" + i["birth_date"] + "|" + i.get("disambiguator", "")))
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
                strong.append((f["scheme"], f["value"]))
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
            strong.append((i["registration"]["scheme"], i["registration"]["value"]))
        if (need and need not in i) or not strong:
            R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, f"{i['subtype']}: нет обязательного идентификатора")
    elif t == "EVENT":
        strong.append(("event", norm(i["title"]) + "|" + i["date"] + "|" + norm(i.get("place", ""))))
    elif t == "CONFLICT":
        strong.append(("conflict", norm(i["title"]) + "|" + i["started_on"] + "|" + norm(i.get("place", ""))))
    elif t == "EQUIPMENT":
        strong.append(("equipment", i["site_id"] + "|" + norm(i["tag"])))
    elif t == "EQUIPMENT_MODEL":
        strong.append(("equipment_model", norm(i["manufacturer"]) + "|" + norm(i["model"])))
    elif t == "CONCEPT":
        strong.append(("concept", i.get("namespace", "") + "|" + i["lang"] + "|" + norm(i["label"])))
    return strong, weak


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

def validate(ds, trust=None, content=None):
    """ds: dataset dict; trust: trust-anchors dict (None = no trusted keys);
    content: mapping source_id -> bytes (object store). Returns Report."""
    R = Report()
    content = content or {}
    trust = trust if trust is not None else {"trust_format": "core-trust/0.2", "keys": []}

    # phase 0 + 1: dataset
    raw = []
    prescan(ds, "", raw)
    for p, m in raw:
        R.err("SCHEMA_INVALID", p or "/", m)
    if not raw:
        for e in DATASET_V.iter_errors(ds):
            R.err("SCHEMA_INVALID", "/" + "/".join(str(p) for p in e.absolute_path), e.message[:200])
    # trust configuration (fail-closed: an invalid trust file trusts nothing)
    traw = []
    prescan(trust, "", traw)
    terrs = [m for _, m in traw] or [e.message[:200] for e in TRUST_V.iter_errors(trust)]
    keys = {}
    if not terrs:
        for k in trust["keys"]:
            if k["key_id"] in keys:
                terrs.append(f"ключ {k['key_id']} повторяется")
            elif not k["not_before"] < k["not_after"] or ("revoked_at" in k and k["revoked_at"] < k["not_before"]):
                terrs.append(f"ключ {k['key_id']}: интервал действия")
            keys[k["key_id"]] = k
    for m in terrs:
        R.err("TRUST_CONFIG_INVALID", "trust", m)
    if terrs:
        keys = {}
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
            if (t is None or t["status"] != "ACTIVE" or t["project_id"] != e["project_id"]
                    or t["entity_type"] != e["entity_type"]):
                R.err("ENTITY_MERGE_INVALID", eid, "merged_into: другая ACTIVE сущность того же типа и проекта")

    def resolve(eid):  # one hop is enough: merge targets must be ACTIVE (ENTITY_MERGE_INVALID otherwise)
        e = E.get(eid)
        return e["merged_into"] if e and e["status"] == "MERGED" else eid

    # uniqueness: identifiers of MERGED entities stay owned by the survivor; RETIRED keep theirs
    strong_idx, weak_idx, inns = defaultdict(set), defaultdict(set), defaultdict(set)
    for eid, e in E.items():
        strong, weak = entity_identifiers(e, R, eid)
        owner = resolve(eid)
        for x in strong:
            strong_idx[(e["project_id"], x)].add(owner)
            if x[0] == "ru.inn":
                inns[owner].add(x[1])
        for x in weak:
            weak_idx[(e["project_id"], x)].add(owner)
    for (prj, x), owners in strong_idx.items():
        if len(owners) > 1:
            R.err("ENTITY_DUPLICATE_IN_PROJECT", ",".join(sorted(owners)), f"{prj}: {x[0]} у нескольких сущностей")
    for (prj, x), owners in weak_idx.items():
        o = sorted(owners)
        for a in range(len(o)):
            for b in range(a + 1, len(o)):
                if not (inns[o[a]] and inns[o[b]] and not (inns[o[a]] & inns[o[b]])):
                    R.err("ENTITY_DUPLICATE_IN_PROJECT", f"{o[a]},{o[b]}", f"{prj}: ФИО+дата рождения без различающих ИНН")

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
            live = subj["status"] == "ACTIVE" or (closed_at is not None and subj["status_changed_at"] > closed_at
                                                  and E.get(resolve(subj["entity_id"]), {}).get("status") == "ACTIVE")
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

    # ---- artifact receipts (keys come ONLY from trust anchors)
    listed = defaultdict(list)
    for rid, r in A.items():
        if receipt_digest_id(r) != rid:
            R.err("RECEIPT_ID_MISMATCH", rid, "receipt_id != sha256(JCS(receipt без receipt_id/signature))")
        if r["project_id"] not in P:
            R.err("REF_UNRESOLVED", rid, "неизвестный project_id")
            continue
        key = keys.get(r["key_id"])
        t = r["issued_at"]
        if (key is None or key["tenant_id"] != tenant_of(r["project_id"]) or key["service_id"] != r["producer"]["service_id"]
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
    except (OSError, ValueError, IndexError) as ex:
        print(f"ERROR SCHEMA_INVALID - не удалось прочитать вход: {type(ex).__name__}")
        return 1
    content = {}
    if content_dir is not None:
        for f in content_dir.iterdir():
            content["src:sha256:" + f.name] = f.read_bytes()
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

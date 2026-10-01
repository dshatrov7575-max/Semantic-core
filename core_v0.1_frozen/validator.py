"""Reference validator for core-ontology/0.1 (Архитектура семантики).

Two phases, fail-closed:
  1. strict JSON Schema (Draft 2020-12) + calendar validity of every date/timestamp;
     any failure -> only SCHEMA_INVALID is reported, semantic phase is not run;
  2. semantic rules (ids, references, scope, identity, uniqueness, evidence,
     markings, Check, receipts). Each rule emits one stable error code.

Usage: python3 validator.py <dataset.json> [--json]
Exit code 0 = no errors (warnings allowed), 1 = errors.
"""
import base64
import hashlib
import json
import sys
import unicodedata
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from jcs import digest, canon

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE / "core.schema.json").read_text(encoding="utf-8"))
PREDICATES = json.loads((HERE / "predicates.json").read_text(encoding="utf-8"))

ERROR_CODES = [
    "SCHEMA_INVALID", "DUPLICATE_ID", "REF_UNRESOLVED", "CROSS_SCOPE_REFERENCE",
    "SOURCE_DIGEST_MISMATCH", "CLAIM_ID_MISMATCH", "RECEIPT_ID_MISMATCH",
    "IDENTIFIER_CHECKSUM_INVALID", "ENTITY_IDENTITY_INSUFFICIENT", "ENTITY_DUPLICATE_IN_PROJECT",
    "ENTITY_MERGE_INVALID", "PREDICATE_UNKNOWN", "PREDICATE_DOMAIN_VIOLATION",
    "PREDICATE_RANGE_VIOLATION", "QUALIFIER_INVALID", "TEMPORAL_ORDER_INVALID",
    "EVIDENCE_SPAN_INVALID", "MARKING_BROADER_THAN_INPUT", "MARKING_PD_MISSING",
    "CLAIM_REVIEW_AMBIGUOUS", "CHECK_PROJECT_NOT_COMPLIANCE", "CHECK_SUBJECT_INVALID",
    "CHECK_DIMENSION_OUTSIDE_PROFILE", "CHECK_DIMENSION_MISSING", "CHECK_FINDING_INCONSISTENT",
    "CHECK_CLAIM_NOT_ABOUT_SUBJECT", "CHECK_CLAIM_DIMENSION_MISMATCH",
    "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", "CHECK_PREVIOUS_INVALID",
    "RECEIPT_KEY_INVALID", "RECEIPT_SIGNATURE_INVALID", "RECEIPT_CLAIM_BINDING_INVALID",
]
WARNING_CODES = ["CONTRADICTION_SINGLE_VALUED"]

TS_FIELDS = {"created_at", "published_at", "observed_at", "recorded_at", "reviewed_at", "requested_at",
             "completed_at", "not_before", "not_after", "revoked_at", "issued_at"}
DATE_FIELDS = {"birth_date", "date", "started_on", "valid_from", "valid_to", "as_of"}
LEVEL = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
RISK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
ID_FIELD = {"Project": "project_id", "Source": "source_id", "Entity": "entity_id", "Claim": "claim_id",
            "ClaimReview": "review_id", "Check": "check_id", "ServiceKey": "key_id", "ArtifactReceipt": "receipt_id"}


class Report:
    def __init__(self, disabled=frozenset()):
        self.disabled = set(disabled)
        self.errors, self.warnings = [], []

    def err(self, code, ref, msg):
        assert code in ERROR_CODES, code
        if code not in self.disabled:
            self.errors.append({"code": code, "ref": ref, "msg": msg})

    def warn(self, code, ref, msg):
        assert code in WARNING_CODES, code
        if code not in self.disabled:
            self.warnings.append({"code": code, "ref": ref, "msg": msg})

    def codes(self):
        return sorted({e["code"] for e in self.errors})


# ---------- identifiers ----------

def norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).casefold().replace("ё", "е")
    return " ".join(s.split())


def inn_ok(v: str) -> bool:
    d = [int(c) for c in v]
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


def imo_ok(v: str) -> bool:
    d = [int(c) for c in v]
    return sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]


def entity_identifiers(e, R, ref):
    """Return the identifier set of an entity; emit checksum/insufficiency errors."""
    t, i = e["entity_type"], e["identity"]
    ids = []
    if t == "PERSON":
        fio = norm(" ".join(x for x in (i["surname"], i["given_name"], i.get("patronymic", "")) if x))
        if "inn" in i:
            if not inn_ok(i["inn"]):
                R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "ИНН физлица: контрольные цифры")
            ids.append(("ru.inn", i["inn"]))
        if "birth_date" in i:
            ids.append(("person.fio_dob", fio + "|" + i["birth_date"]))
        if not ids:
            if "disambiguator" not in i:
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "PERSON без ИНН и даты рождения требует disambiguator")
            else:
                ids.append(("person.fio_weak", fio + "|" + i["disambiguator"]))
    elif t == "ORGANIZATION":
        if i.get("informal"):
            if "disambiguator" not in i or "ogrn" in i or "inn" in i:
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "неформальная организация: только disambiguator, без ОГРН/ИНН")
            else:
                ids.append(("org.informal", norm(i["name"]) + "|" + i["disambiguator"]))
        else:
            if "ogrn" in i:
                if not ogrn_ok(i["ogrn"]):
                    R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "ОГРН: контрольная цифра")
                ids.append(("ru.ogrn", i["ogrn"]))
            if "inn" in i:
                if not inn_ok(i["inn"]):
                    R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "ИНН юрлица: контрольная цифра")
                ids.append(("ru.inn", i["inn"]))
            for f in i.get("foreign_ids", []):
                ids.append((f["scheme"], f["value"]))
            if i["jurisdiction"] == "RU" and not ({"ogrn", "inn"} & i.keys()):
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "организация РФ без ОГРН и ИНН")
            elif not ids:
                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "иностранная организация без регистрационного идентификатора")
    elif t == "REAL_ESTATE":
        ids.append(("ru.cadastral", i["cadastral_number"]))
    elif t == "MOVABLE_PROPERTY":
        need = {"VEHICLE": "vin", "VESSEL": "imo"}.get(i["subtype"])
        if "vin" in i:
            ids.append(("vin", i["vin"]))
        if "imo" in i:
            if not imo_ok(i["imo"]):
                R.err("IDENTIFIER_CHECKSUM_INVALID", ref, "IMO: контрольная цифра")
            ids.append(("imo", i["imo"]))
        if "registration" in i:
            ids.append((i["registration"]["scheme"], i["registration"]["value"]))
        if (need and need not in i) or not ids:
            R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, f"{i['subtype']}: нет обязательного идентификатора")
    elif t == "EVENT":
        ids.append(("event", norm(i["title"]) + "|" + i["date"]))
    elif t == "CONFLICT":
        ids.append(("conflict", norm(i["title"]) + "|" + i["started_on"]))
    elif t == "EQUIPMENT":
        ids.append(("equipment", i["site_id"] + "|" + norm(i["tag"])))
    elif t == "CONCEPT":
        ids.append(("concept", i.get("namespace", "") + "|" + i["lang"] + "|" + norm(i["label"])))
    return ids


# ---------- helpers ----------

def dominates(a, b):
    return LEVEL[a["level"]] >= LEVEL[b["level"]] and set(a["categories"]) >= set(b["categories"])


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def claim_digest_id(c):
    body = {k: v for k, v in c.items() if k != "claim_id"}
    return "clm:sha256:" + digest(body)


def receipt_digest_id(r):
    body = {k: v for k, v in r.items() if k not in ("receipt_id", "signature")}
    return "rcp:sha256:" + digest(body)


def _dates_ok(node, path, bad):
    if isinstance(node, dict):
        if node.get("type") == "DATE" and isinstance(node.get("value"), str):
            try:
                date.fromisoformat(node["value"])
            except ValueError:
                bad.append(path + "/value")
        for k, v in node.items():
            if isinstance(v, str) and k in TS_FIELDS:
                try:
                    datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    bad.append(f"{path}/{k}")
            elif isinstance(v, str) and k in DATE_FIELDS:
                try:
                    date.fromisoformat(v)
                except ValueError:
                    bad.append(f"{path}/{k}")
            else:
                _dates_ok(v, f"{path}/{k}", bad)
    elif isinstance(node, list):
        for n, v in enumerate(node):
            _dates_ok(v, f"{path}/{n}", bad)


# ---------- main ----------

def validate(ds, disabled=frozenset()):
    R = Report(disabled)

    # Phase 1: strict schema
    bad = False
    for e in Draft202012Validator(SCHEMA).iter_errors(ds):
        R.err("SCHEMA_INVALID", "/" + "/".join(str(p) for p in e.absolute_path), e.message[:200])
        bad = True
    if not bad:
        badd = []
        _dates_ok(ds["records"], "/records", badd)
        for p in badd:
            R.err("SCHEMA_INVALID", p, "несуществующая календарная дата/время")
            bad = True
    if bad:  # fail-closed: semantic rules never run on a malformed dataset
        return R

    recs = ds["records"]
    by = defaultdict(dict)
    for n, r in enumerate(recs):
        k = r["kind"]
        rid = r[ID_FIELD[k]]
        if rid in by[k]:
            R.err("DUPLICATE_ID", f"records[{n}]", f"{k} {rid} повторяется")
            continue
        by[k][rid] = r
    P, S, E, C, V, K, Kc, A = (by[x] for x in ("Project", "Source", "Entity", "Claim", "ClaimReview",
                                                "ServiceKey", "Check", "ArtifactReceipt"))
    preds = {p["id"]: p for p in PREDICATES["predicates"]}
    profiles = PREDICATES["check_profiles"]

    def tenant_of(project_id):
        return P[project_id]["tenant_id"] if project_id in P else None

    # Sources: content addressing
    for sid, s in S.items():
        if "content_inline" in s:
            b = s["content_inline"].encode("utf-8")
            if "src:sha256:" + hashlib.sha256(b).hexdigest() != sid or len(b) != s["byte_length"]:
                R.err("SOURCE_DIGEST_MISMATCH", sid, "содержимое не совпадает с адресом/длиной")

    # Entities
    ident_index = defaultdict(list)
    for eid, e in E.items():
        if e["project_id"] not in P:
            R.err("REF_UNRESOLVED", eid, "неизвестный project_id")
            continue
        ids = entity_identifiers(e, R, eid)
        if e["entity_type"] == "PERSON" and "PERSONAL_DATA" not in e["marking"]["categories"]:
            R.err("MARKING_PD_MISSING", eid, "PERSON без категории PERSONAL_DATA")
        if e["status"] == "ACTIVE":
            for x in ids:
                ident_index[(e["project_id"], x)].append(eid)
        if e["status"] == "MERGED":
            t = E.get(e["merged_into"])
            if (t is None or t["status"] != "ACTIVE" or t["project_id"] != e["project_id"]
                    or t["entity_type"] != e["entity_type"] or t["entity_id"] == eid):
                R.err("ENTITY_MERGE_INVALID", eid, "merged_into должен указывать на ACTIVE сущность того же типа и проекта")
    for (prj, x), lst in ident_index.items():
        if len(lst) > 1:
            R.err("ENTITY_DUPLICATE_IN_PROJECT", ",".join(sorted(lst)), f"{prj}: идентификатор {x[0]} у нескольких ACTIVE сущностей")

    def resolve(eid):
        e = E.get(eid)
        return e["merged_into"] if e and e["status"] == "MERGED" else eid

    # Claims
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
        if "entity" in c["object"]:
            obj_ent = E.get(c["object"]["entity"])
            if obj_ent is None:
                R.err("REF_UNRESOLVED", cid, "неизвестная сущность-объект")
            elif obj_ent["project_id"] != c["project_id"]:
                R.err("CROSS_SCOPE_REFERENCE", cid, "объект из другого проекта")
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
            elif "literal" not in rng or c["object"]["literal"]["type"] not in rng["literal"]:
                R.err("PREDICATE_RANGE_VIOLATION", cid, "тип литерала вне range")
            spec = p.get("qualifiers", {})
            q = c.get("qualifiers", {})
            for name, v in q.items():
                s = spec.get(name)
                ok = s is not None and (
                    (s["type"] == "enum" and v in s["enum"]) or
                    (s["type"] == "integer" and isinstance(v, int) and not isinstance(v, bool)
                     and s.get("min", v) <= v <= s.get("max", v)) or
                    (s["type"] == "string" and isinstance(v, str) and v != "") or
                    (s["type"] == "boolean" and isinstance(v, bool)))
                if not ok:
                    R.err("QUALIFIER_INVALID", cid, f"квалификатор {name}={v!r}")
            for name, s in spec.items():
                if s.get("required") and name not in q:
                    R.err("QUALIFIER_INVALID", cid, f"нет обязательного квалификатора {name}")
        if "valid_from" in c and "valid_to" in c and c["valid_from"] > c["valid_to"]:
            R.err("TEMPORAL_ORDER_INVALID", cid, "valid_from > valid_to")
        pd_needed = any(x is not None and x["entity_type"] == "PERSON" for x in (subj, obj_ent))
        if pd_needed and "PERSONAL_DATA" not in c["marking"]["categories"]:
            R.err("MARKING_PD_MISSING", cid, "утверждение о физлице без PERSONAL_DATA")
        for ev in c["evidence"]:
            s = S.get(ev["source_id"])
            if s is None:
                R.err("REF_UNRESOLVED", cid, "неизвестный источник")
                continue
            if s["tenant_id"] != tenant_of(c["project_id"]):
                R.err("CROSS_SCOPE_REFERENCE", cid, "источник другого tenant")
            if min(o["observed_at"] for o in s["observations"]) > c["recorded_at"]:
                R.err("TEMPORAL_ORDER_INVALID", cid, "утверждение записано раньше, чем получен источник")
            if not dominates(c["marking"], s["marking"]):
                R.err("MARKING_BROADER_THAN_INPUT", cid, "маркировка утверждения шире маркировки источника")
            st, en = ev["span"]["start"], ev["span"]["end"]
            span_ok = st < en <= s["byte_length"]
            if span_ok and "content_inline" in s:
                chunk = s["content_inline"].encode("utf-8")[st:en]
                try:
                    txt = chunk.decode("utf-8")
                except UnicodeDecodeError:
                    span_ok = False
                else:
                    span_ok = (hashlib.sha256(chunk).hexdigest() == ev["quote_sha256"]
                               and ev.get("quote", txt) == txt)
            elif span_ok and "quote" in ev:
                span_ok = hashlib.sha256(ev["quote"].encode("utf-8")).hexdigest() == ev["quote_sha256"] \
                    and len(ev["quote"].encode("utf-8")) == en - st
            if not span_ok:
                R.err("EVIDENCE_SPAN_INVALID", cid, f"фрагмент [{st},{en}) не подтверждается источником")

    # Reviews
    reviews_by_claim = defaultdict(list)
    for rid, rv in V.items():
        c = C.get(rv["claim_id"])
        if c is None:
            R.err("REF_UNRESOLVED", rid, "неизвестное утверждение")
            continue
        if rv["reviewed_at"] < c["recorded_at"]:
            R.err("TEMPORAL_ORDER_INVALID", rid, "проверка раньше записи утверждения")
        reviews_by_claim[rv["claim_id"]].append(rv)
    for cid, lst in reviews_by_claim.items():
        seen = defaultdict(set)
        for rv in lst:
            seen[rv["reviewed_at"]].add(rv["status"])
        if any(len(v) > 1 for v in seen.values()):
            R.err("CLAIM_REVIEW_AMBIGUOUS", cid, "разные статусы с одинаковым временем")

    def status_at(cid, t):
        lst = [rv for rv in reviews_by_claim.get(cid, []) if t is None or rv["reviewed_at"] <= t]
        return max(lst, key=lambda r: r["reviewed_at"])["status"] if lst else "ASSERTED"

    # Contradictions (warnings): single-valued predicate, different objects, overlapping validity
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
                    R.warn("CONTRADICTION_SINGLE_VALUED", f"{x['claim_id']}|{y['claim_id']}",
                           f"{key[2]}: источники расходятся")

    # Checks
    for kid, k in Kc.items():
        prj = P.get(k["project_id"])
        if prj is None:
            R.err("REF_UNRESOLVED", kid, "неизвестный project_id")
            continue
        if prj["product"] != "COMPLIANCE":
            R.err("CHECK_PROJECT_NOT_COMPLIANCE", kid, "Проверка вне проекта COMPLIANCE")
        subj = E.get(k["subject_entity_id"])
        if subj is None:
            R.err("REF_UNRESOLVED", kid, "неизвестный субъект")
        elif subj["project_id"] != k["project_id"]:
            R.err("CROSS_SCOPE_REFERENCE", kid, "субъект из другого проекта")
        elif subj["status"] != "ACTIVE" or subj["entity_type"] not in ("PERSON", "ORGANIZATION"):
            R.err("CHECK_SUBJECT_INVALID", kid, "субъект Проверки: ACTIVE физлицо или юрлицо")
        done = k["status"] == "COMPLETED"
        if done and (k["completed_at"] < k["requested_at"] or k["as_of"] > k["completed_at"][:10]):
            R.err("TEMPORAL_ORDER_INVALID", kid, "completed_at < requested_at или as_of позже завершения")
        dims = profiles[k["profile"]]
        fdims = [f["dimension"] for f in k["findings"]]
        if len(set(fdims)) != len(fdims):
            R.err("CHECK_FINDING_INCONSISTENT", kid, "повтор измерения")
        for d in set(fdims) - set(dims):
            R.err("CHECK_DIMENSION_OUTSIDE_PROFILE", kid, f"{d} вне профиля {k['profile']}")
        if done and set(dims) - set(fdims):
            R.err("CHECK_DIMENSION_MISSING", kid, f"нет результата по {sorted(set(dims) - set(fdims))}")
        for f in k["findings"]:
            if (f["result"] == "FOUND") != bool(f["claim_ids"]) or (f["result"] == "NOT_FOUND" and f["risk"] != "NONE"):
                R.err("CHECK_FINDING_INCONSISTENT", kid, f"{f['dimension']}: результат/утверждения/риск не согласованы")
            for cid in f["claim_ids"]:
                c = C.get(cid)
                if c is None:
                    R.err("REF_UNRESOLVED", kid, "неизвестное утверждение")
                    continue
                if c["project_id"] != k["project_id"]:
                    R.err("CROSS_SCOPE_REFERENCE", kid, "утверждение другого проекта")
                    continue
                subj_id = resolve(k["subject_entity_id"])
                touches = {resolve(c["subject"])} | ({resolve(c["object"]["entity"])} if "entity" in c["object"] else set())
                if subj_id not in touches:
                    R.err("CHECK_CLAIM_NOT_ABOUT_SUBJECT", kid, f"{cid} не о субъекте")
                p = preds.get(c["predicate"])
                if p is not None and f["dimension"] not in p["dimensions"]:
                    R.err("CHECK_CLAIM_DIMENSION_MISMATCH", kid, f"{c['predicate']} не относится к {f['dimension']}")
                if done and (c["recorded_at"] > k["completed_at"] or status_at(cid, k["completed_at"]) != "ACCEPTED"):
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
            elif (pv["check_id"] == kid or pv["project_id"] != k["project_id"]
                  or pv["subject_entity_id"] != k["subject_entity_id"] or pv["as_of"] >= k["as_of"]):
                R.err("CHECK_PREVIOUS_INVALID", kid, "предыдущая Проверка: тот же субъект и более ранняя дата")

    # Service keys
    for kid, key in K.items():
        if not key["not_before"] < key["not_after"] or ("revoked_at" in key and key["revoked_at"] < key["not_before"]):
            R.err("TEMPORAL_ORDER_INVALID", kid, "интервал действия ключа")

    # Artifact receipts
    listed = defaultdict(list)
    for rid, r in A.items():
        if receipt_digest_id(r) != rid:
            R.err("RECEIPT_ID_MISMATCH", rid, "receipt_id != sha256(JCS(receipt без receipt_id/signature))")
        if r["project_id"] not in P:
            R.err("REF_UNRESOLVED", rid, "неизвестный project_id")
            continue
        key = K.get(r["key_id"])
        t = r["issued_at"]
        if (key is None or key["service_id"] != r["producer"]["service_id"]
                or not (key["not_before"] <= t < key["not_after"])
                or ("revoked_at" in key and key["revoked_at"] <= t)):
            R.err("RECEIPT_KEY_INVALID", rid, "ключ неизвестен, чужой или не действует на issued_at")
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            try:
                Ed25519PublicKey.from_public_bytes(b64u_dec(key["public_key"])).verify(
                    b64u_dec(r["signature"]), rid.encode("utf-8"))
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
            listed[cid].append(rid)
            pb = c["produced_by"]
            if (pb["kind"] != "PIPELINE" or pb["service_id"] != r["producer"]["service_id"] or pb["run_id"] != r["run_id"]
                    or c["project_id"] != r["project_id"] or c["recorded_at"] > t
                    or not {ev["source_id"] for ev in c["evidence"]} <= set(r["input_source_ids"])):
                R.err("RECEIPT_CLAIM_BINDING_INVALID", rid, f"{cid} не соответствует receipt")
    for cid, c in C.items():
        if c["produced_by"]["kind"] == "PIPELINE" and len(listed.get(cid, [])) != 1:
            R.err("RECEIPT_CLAIM_BINDING_INVALID", cid, "PIPELINE-утверждение должно быть ровно в одном receipt")
    return R


def main():
    ds = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    R = validate(ds)
    if "--json" in sys.argv:
        print(json.dumps({"errors": R.errors, "warnings": R.warnings}, ensure_ascii=False, indent=1))
    else:
        for e in R.errors:
            print("ERROR", e["code"], e["ref"], e["msg"])
        for w in R.warnings:
            print("WARN ", w["code"], w["ref"], w["msg"])
        print(f"errors={len(R.errors)} warnings={len(R.warnings)}")
    sys.exit(1 if R.errors else 0)


if __name__ == "__main__":
    main()

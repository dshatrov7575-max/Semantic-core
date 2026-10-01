"""Independent hostile review of core-ontology/0.1 — executable attack suite.

Runs every attack of ONTOLOGY_v0.1_INDEPENDENT_REVIEW.md against the code in CORE
(default /home/claude/as/core, override with env CORE=...). CORE is only read:
bytecode writing is disabled and fixtures.main() is never called.

Sections
  FA  false accepts   : dataset violates the documented meaning; expected = error code
  FR  false rejects   : dataset obeys every documented rule;   expected = OK
  CR  crashes         : expected = a report (no exception)
  DG  design gaps     : expected = what the product needs
  OK  verified correct: must keep passing after fixes (regression guard)
  T3  honesty of T3   : disabled-rule run == filtered normal run for every vector
  MU  mutants         : weakened validator.py copies run against the author's tests.py;
                        SURVIVED = rule not isolated by the vectors
  JCS Python vs Node vs independent expected bytes

Output: table "id | expected | got | verdict".  verdict FINDING = defect reproduced,
fixed = attack no longer works, ok = regression guard holds.
Usage: python3 ontology_attacks.py [--no-mutants]
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
CORE = Path(os.environ.get("CORE", "/home/claude/as/core")).resolve()
REVIEW = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE))

import fixtures  # noqa: E402
import validator  # noqa: E402
from fixtures import (world, finalize, build, VECTORS, SEEDS, SV, pub, inn12, inn10, ogrn,  # noqa: E402
                      INN_DEV, OGRN_DEV, mk, PUB, INT, PUB_PD, CONF_PD, CONF_CS, CONF_CS_PD)
from validator import validate  # noqa: E402

ROWS = []


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def run(ds):
    try:
        R = validate(ds)
    except Exception as e:  # noqa: BLE001 — a crash is itself a result
        return f"CRASH:{type(e).__name__}"
    return "OK" if not R.errors else ",".join(R.codes())


def run_w(W, post=None):
    ds, ix = finalize(W)
    if post:
        post(ds, ix)
    return run(ds)


def row(section, aid, expected, got, note):
    if section == "OK":
        verdict = "ok" if got == expected else "REGRESSION"
    elif section == "MU":
        verdict = {"SURVIVED": "FINDING", "KILLED": "ok"}.get(got, got)
        if aid.startswith("M-CTRL"):
            verdict = "ok" if got == "KILLED" else "REGRESSION"
    elif section == "CR":
        verdict = "FINDING" if got.startswith("CRASH") else "fixed"
    else:
        ok = got == expected or (expected.startswith("ERR") and got not in ("OK",) and not got.startswith("CRASH"))
        verdict = "fixed" if ok else "FINDING"
    ROWS.append((section, aid, expected, got, verdict, note))


def ent(W, name, prj, etype, identity, marking, status="ACTIVE", merged_into=None, display=None):
    r = {"kind": "Entity", "schema_version": SV, "entity_id": name, "project_id": prj, "entity_type": etype,
         "identity": identity, "display_name": display or name, "status": status,
         "created_at": "2026-09-05T12:00:00Z", "marking": marking}
    if merged_into:
        r["merged_into"] = merged_into
    W[name] = r


def clm(W, name, prj, subj, pred, obj, evs, marking, recorded, by=None, q=None):
    r = {"kind": "Claim", "schema_version": SV, "project_id": prj, "subject": subj, "predicate": pred,
         "object": obj, "evidence": [{"$ev": list(e)} for e in evs],
         "produced_by": by or {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": recorded,
         "marking": marking}
    if q:
        r["qualifiers"] = q
    W[name] = r


def rec_of(ds, ix, name):
    return ds["records"][ix[name]]


def recompute_claim(r):
    r["claim_id"] = validator.claim_digest_id(r)


LOMOV = {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"}

# =====================================================================================
# FA — false accepts
# =====================================================================================

def fa01():  # Latin 'o' in a Cyrillic surname
    W = world()
    ent(W, "ent_d_lomov_lat", "prj_dossier", "PERSON", {**LOMOV, "surname": "Лoмов"}, CONF_PD)
    return run_w(W)


def fa02():  # Latin 'H' in equipment tag
    W = world()
    ent(W, "ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101"}, INT)
    return run_w(W)


def fa03():  # non-breaking hyphen U+2011 in tag (NFKC -> U+2010, not '-')
    W = world()
    ent(W, "ent_ts_pump_nbh", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н‑101"}, INT)
    return run_w(W)


def fa04():  # zero-width space inside surname
    W = world()
    ent(W, "ent_d_lomov_zw", "prj_dossier", "PERSON", {**LOMOV, "surname": "Ло​мов"}, CONF_PD)
    return run_w(W)


def fa05():  # informal org: ASCII quotes instead of «», same disambiguator
    W = world()
    ent(W, "ent_c_initiative2", "prj_conflict_land", "ORGANIZATION",
        {"name": 'Инициативная группа "Заречная, 12"', "jurisdiction": "RU", "informal": True,
         "disambiguator": "zarechnaya-12"}, CONF_PD)
    return run_w(W)


def fa06():  # cadastral number with a leading zero in the parcel part
    W = world()
    ent(W, "ent_d_land2", "prj_dossier", "REAL_ESTATE",
        {"cadastral_number": "50:12:0101001:0245", "address": "г. Заречный, ул. Заречная, 12"}, CONF_PD)
    return run_w(W)


def fa07():  # trailing '\n' passes every ^...$ pattern (re.search) -> second vehicle with same VIN
    W = world()
    ent(W, "ent_d_car2", "prj_dossier", "MOVABLE_PROPERTY",
        {"subtype": "VEHICLE", "vin": "XTA210990Y1234567\n", "description": "легковой автомобиль"}, CONF_PD)
    return run_w(W)


def fa08():  # identifier of a MERGED duplicate is re-used by a new ACTIVE entity
    W = world()
    inn_b = inn12("7701234567")
    ent(W, "ent_d_lomov_old", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "inn": inn_b},
        CONF_PD, "MERGED", "ent_d_lomov")
    ent(W, "ent_d_lomov_new", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "inn": inn_b},
        CONF_PD)
    return run_w(W)


def fa09():  # ru.inn smuggled through foreign_ids: checksum never computed
    W = world()
    ent(W, "ent_d_kz", "prj_dossier", "ORGANIZATION",
        {"name": "ТОО Пример", "jurisdiction": "KZ", "foreign_ids": [{"scheme": "ru.inn", "value": "1234567890"}]},
        CONF_PD)
    return run_w(W)


FAKE = "Синий кит — вид хищных китов"  # same UTF-8 length as the real quote "... усатых китов"


def fa10():  # production shape: Source without content_inline -> fabricated quote accepted
    W = world()
    assert len(FAKE.encode()) == len("Синий кит — вид усатых китов".encode())
    W["c24"]["_ev_patch"] = lambda evs, _W: evs[0].update(quote=FAKE, quote_sha256=sha(FAKE))
    return run_w(W, post=lambda ds, ix: rec_of(ds, ix, "s10").pop("content_inline"))


def fa10b():  # same, no quote at all and a random quote_sha256
    W = world()
    W["c24"]["_ev_patch"] = lambda evs, _W: (evs[0].pop("quote"), evs[0].update(quote_sha256=sha("anything")))
    return run_w(W, post=lambda ds, ix: rec_of(ds, ix, "s10").pop("content_inline"))


def fa11():  # anyone can register a ServiceKey for svc_techsense and mint 'TechSense' claims
    W = world()
    SEEDS["key_evil"] = SEEDS["OTHER"]
    W["key_evil"] = {"kind": "ServiceKey", "schema_version": SV, "key_id": "key_evil", "service_id": "svc_techsense",
                     "algorithm": "Ed25519", "public_key": pub(SEEDS["OTHER"]),
                     "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z"}
    clm(W, "c_evil", "prj_ts_pumps", "ent_ts_pump", "ts.has_parameter",
        {"literal": {"type": "QUANTITY", "value": "25", "unit": "bar"}},
        [("s1", "Максимальное рабочее давление насоса Н-101")], INT, "2026-09-06T09:59:00Z",
        {"kind": "PIPELINE", "service_id": "svc_techsense", "run_id": "run_evil"}, {"parameter": "max_working_pressure"})
    W["rcp_evil"] = {"kind": "ArtifactReceipt", "schema_version": SV, "project_id": "prj_ts_pumps",
                     "producer": {"service_id": "svc_techsense", "version": "0.9.0"}, "run_id": "run_evil",
                     "artifact_digest": "sha256:" + sha("x"), "artifact_schema_version": "umr-artifact/0.3",
                     "semantic_profile_version": "ts-semantic/0.2", "input_source_ids": ["@S:s1"],
                     "emitted_claim_ids": ["@C:c_evil"], "issued_at": "2026-09-06T10:00:00Z", "key_id": "key_evil"}
    return run_w(W)


def _chk_person(marking):
    W = world()
    W["chk_lomov_1"] = {"kind": "Check", "schema_version": SV, "check_id": "chk_lomov_1", "project_id": "prj_compliance",
                        "subject_entity_id": "ent_k_lomov", "profile": "EXPRESS_NEGATIVE", "as_of": "2026-09-10",
                        "requested_at": "2026-09-10T08:00:00Z", "requested_by": "usr_bank_officer",
                        "status": "COMPLETED", "completed_at": "2026-09-10T12:00:00Z",
                        "findings": [{"dimension": "NEGATIVE", "result": "NOT_FOUND", "risk": "NONE", "claim_ids": []}],
                        "overall_risk": "NONE", "marking": marking}
    return W


def fa12():  # Check about a PERSON, PUBLIC, no PERSONAL_DATA
    return run_w(_chk_person(mk("PUBLIC")))


def fa13():  # claim about CONFIDENTIAL entity published as PUBLIC (entity is an input of the claim)
    W = world()
    W["c7"]["marking"] = PUB_PD  # subject ent_c_lomov is CONFIDENTIAL+PD
    return run_w(W)


def fa14():  # N36 with reviewed_at moved 1 s before completion -> retroactive acceptance undetectable
    W = world()
    W["rev_c18_a"]["reviewed_at"] = "2026-09-10T11:59:59Z"
    W["rev_c18_a"]["note"] = "внесено 2026-09-29 задним числом"
    return run_w(W)


def fa15():  # IDENTIFIER literal scheme not checked against predicate: court case id with scheme 'telegram'
    W = world()
    W["c19"]["object"] = {"literal": {"type": "IDENTIFIER", "scheme": "telegram", "value": "@zarechye_dev"}}
    return run_w(W)


def fa16():  # string qualifier consisting of whitespace only
    W = world()
    W["c2"]["qualifiers"] = {"parameter": " "}
    return run_w(W)


def fa17():  # QUANTITY unit not constrained: pump pressure in kilograms
    W = world()
    W["c2"]["object"] = {"literal": {"type": "QUANTITY", "value": "16", "unit": "kg"}}
    return run_w(W)


# =====================================================================================
# FR — false rejects
# =====================================================================================

def fr01():  # two different people (different valid INNs), same full name and birth date
    W = world()
    base = {"surname": "Иванов", "given_name": "Сергей", "patronymic": "Александрович", "birth_date": "1980-01-01"}
    ent(W, "ent_d_ivanov_a", "prj_dossier", "PERSON", {**base, "inn": inn12("7700000001")}, CONF_PD)
    ent(W, "ent_d_ivanov_b", "prj_dossier", "PERSON", {**base, "inn": inn12("5000000002")}, CONF_PD)
    return run_w(W)


def fr02():  # two rallies with the same title on the same day in different towns
    W = world()
    ent(W, "ent_c_rally_a", "prj_conflict_land", "EVENT",
        {"title": "Митинг против застройки", "date": "2026-09-10", "place": "г. Заречный"}, CONF_PD)
    ent(W, "ent_c_rally_b", "prj_conflict_land", "EVENT",
        {"title": "Митинг против застройки", "date": "2026-09-10", "place": "г. Тверь"}, CONF_PD)
    return run_w(W)


def fr03():  # legitimate merge of the Check subject after two Checks were COMPLETED
    W = world()
    W["ent_k_dev_main"] = {**copy.deepcopy(W["ent_k_developer"]), "entity_id": "ent_k_dev_main"}
    W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_main")
    W["chk_tenders_1"]["subject_entity_id"] = "ent_k_dev_main"  # the running Check is re-pointed
    return run_w(W)


def fr04():  # registry-is-data: a new predicate whose string qualifier is named 'date'
    W = world()
    extra = {"id": "court.hearing", "label_ru": "заседание", "domain": ["ORGANIZATION"],
             "range": {"literal": ["IDENTIFIER"]}, "cardinality": "MANY", "dimensions": ["COURT"],
             "qualifiers": {"date": {"type": "string", "required": True}}}
    validator.PREDICATES["predicates"].append(extra)
    try:
        clm(W, "c_hear", "prj_compliance", "ent_k_developer", "court.hearing",
            {"literal": {"type": "IDENTIFIER", "scheme": "ru.arbitr", "value": "А41-12345/2026"}},
            [("s6", "Делу присвоен номер А41-12345/2026")], CONF_CS, "2026-09-07T10:00:00Z", q={"date": "осень 2026"})
        return run_w(W)
    finally:
        validator.PREDICATES["predicates"].remove(extra)


# =====================================================================================
# CR — crashes (fail-closed violated: exception instead of report)
# =====================================================================================

def cr01():
    W = world()
    W["ent_d_developer"]["identity"]["inn"] = INN_DEV + "\n"
    return run_w(W)


def cr02():
    W = world()
    ent(W, "ent_d_ship", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VESSEL", "imo": "9074729\n", "description": "судно"},
        CONF_PD)
    return run_w(W)


def cr03():  # 6000.0 is 'integer' for JSON Schema, float for JCS
    W = world()
    W["c11"]["qualifiers"]["share_bp"] = 6000

    def post(ds, ix):
        rec_of(ds, ix, "c11")["qualifiers"]["share_bp"] = 6000.0
    return run_w(W, post)


def cr04():
    ds, ix = finalize(world())  # finalize itself canonicalises claims -> mutate afterwards
    rec_of(ds, ix, "c20")["qualifiers"]["contract_amount_minor"] = 2 ** 53
    return run(ds)


def cr05():  # lone surrogate in source text (json.loads accepts "\ud800")
    ds, ix = finalize(world())
    rec_of(ds, ix, "s10")["content_inline"] += "\ud800"
    return run(ds)


def cr06():  # lone surrogate in a claim string
    ds, ix = finalize(world())
    rec_of(ds, ix, "c9")["object"]["literal"]["value"] = "x\ud800"
    return run(ds)


def cr07():  # lone surrogate in a qualifier KEY
    ds, ix = finalize(world())
    rec_of(ds, ix, "c9")["qualifiers"]["\ud800"] = "x"
    return run(ds)


def cr08():  # span start 5.0
    ds, ix = finalize(world())
    rec_of(ds, ix, "c24")["evidence"][0]["span"]["start"] = float(rec_of(ds, ix, "c24")["evidence"][0]["span"]["start"])
    return run(ds)


def cr09():  # the same through the CLI with a JSON file
    ds, ix = finalize(world())
    txt = json.dumps(ds, ensure_ascii=False).replace('"share_bp": 6000', '"share_bp": 6000.0')
    p = REVIEW / "work_cr09.json"
    p.write_text(txt, encoding="utf-8")
    r = subprocess.run([sys.executable, str(CORE / "validator.py"), str(p)], capture_output=True, text=True,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    p.unlink()
    return "CRASH:Traceback" if "Traceback" in r.stderr else f"exit={r.returncode}"


# =====================================================================================
# DG — design gaps demonstrated by execution
# =====================================================================================

def dg01():  # individual entrepreneur (ИП): 12-digit INN + 15-digit ОГРНИП as ORGANIZATION
    W = world()
    ent(W, "ent_k_ip", "prj_compliance", "ORGANIZATION",
        {"name": "ИП Ломов А. С.", "jurisdiction": "RU", "inn": inn12("6952031418"), "ogrn": "321695200012345"}, CONF_CS_PD)
    return run_w(W)


def dg02():  # FULL Check, all NOT_FOUND, no trace of what was searched
    W = world()
    W["chk_tenders_1"].update(profile="FULL", status="COMPLETED", completed_at="2026-09-29T10:00:00Z", overall_risk="NONE",
                              findings=[{"dimension": d, "result": "NOT_FOUND", "risk": "NONE", "claim_ids": []}
                                        for d in ["NEGATIVE", "TENDERS", "SOCIAL_MEDIA", "CORPORATE", "PROPERTY", "COURT"]])
    return run_w(W)


def dg03():  # TechSense: equipment TYPE from a manual (no installation site) is not representable
    W = world()
    ent(W, "ent_ts_model", "prj_ts_pumps", "EQUIPMENT", {"tag": "Насос серии Н-101", "description": "модель"}, INT)
    return run_w(W)


def dg04():  # machine-readable condition is free text: any string is a valid 'condition'
    W = world()
    W["c3"]["qualifiers"] = {"condition": "когда-нибудь"}
    return run_w(W)


def dg05():  # Web Monitoring: same article, same URL, re-fetched with a trailing newline -> 2nd Source
    W = world()
    W["s2b"] = {**copy.deepcopy(W["s2"]), "content_inline": W["s2"]["content_inline"] + "\n"}
    return run_w(W)


# =====================================================================================
# OK — verified correct (regression guards)
# =====================================================================================

def ok_two_receipts():
    W = world()
    W["rcp_2"] = {**copy.deepcopy(W["rcp_1"]), "emitted_claim_ids": ["@C:c1"], "issued_at": "2026-09-06T10:00:01Z"}
    return run_w(W)


def ok_human_in_receipt():
    W = world()
    W["rcp_1"]["emitted_claim_ids"].append("@C:c24")
    return run_w(W)


def ok_revoked_eq_issued():
    W = world()
    W["key_ts_1"]["revoked_at"] = "2026-09-06T10:00:00Z"
    return run_w(W)


def ok_issued_eq_not_before():
    W = world()
    W["key_ts_1"]["not_before"] = "2026-09-06T10:00:00Z"
    return run_w(W)


def ok_bool_as_int():
    W = world()
    W["c11"]["qualifiers"]["share_bp"] = True
    return run_w(W)


def ok_int_as_bool():
    W = world()
    W["c7b"]["qualifiers"]["explicit"] = 1
    return run_w(W)


def _emoji_world(cut):
    W = world()
    text = "Синий кит 🐋 — вид усатых китов."
    W["s_emoji"] = {"kind": "Source", "schema_version": SV, "tenant_id": "tnt_demo", "source_kind": "DOCUMENT",
                    "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "emoji",
                    "content_inline": text, "marking": PUB,
                    "observations": [{"observed_at": "2026-09-02T09:00:00Z", "origin_uri": "urn:demo:e",
                                      "observed_by": "svc_webmon"}]}
    b = text.encode()
    st = b.find("🐋".encode()) + (2 if cut else 0)
    en = st + (2 if cut else 4)

    def patch(evs, _W):
        chunk = b[st:en]
        evs[0].pop("quote")
        evs[0].update(span={"start": st, "end": en}, quote_sha256=hashlib.sha256(chunk).hexdigest())
    clm(W, "c_emoji", "prj_wiki_whales", "ent_wk_blue", "wiki.property",
        {"literal": {"type": "STRING", "value": "эмодзи"}}, [("s_emoji", "Синий кит")], PUB, "2026-09-03T09:00:00Z",
        q={"property": "icon"})
    W["c_emoji"]["_ev_patch"] = patch
    return W


def ok_emoji_cut():  # hash matches the cut bytes -> only the UTF-8 boundary rule can reject
    return run_w(_emoji_world(True))


def ok_emoji_whole():
    return run_w(_emoji_world(False))


def ok_zero_span():
    W = world()
    W["c25"]["_ev_patch"] = lambda evs, _W: (evs[0].pop("quote"), evs[0]["span"].update(end=evs[0]["span"]["start"]),
                                            evs[0].update(quote_sha256=sha("")))
    return run_w(W)


def ok_merge_chain():
    W = world()
    ent(W, "ent_d_lomov_x", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "А", "disambiguator": "xx-1"},
        CONF_PD, "MERGED", "ent_d_lomov_media")
    return run_w(W)


def ok_merge_cross_project():
    W = world()
    W["ent_d_lomov_media"]["merged_into"] = "ent_k_lomov"
    return run_w(W)


def ok_claim_after_completion():
    W = world()
    W["c18"]["recorded_at"] = "2026-09-10T12:00:01Z"
    W["rev_c18_a"]["reviewed_at"] = "2026-09-10T12:00:02Z"  # accepted too late anyway; isolate recorded_at
    return run_w(W)


def ok_cancelled_with_completed_at():
    W = world()
    W["chk_tenders_1"].update(status="CANCELLED", completed_at="2026-09-29T10:00:00Z")
    return run_w(W)


def ok_inprogress_disputed_claim():
    W = world()
    W["chk_tenders_1"]["findings"] = [{"dimension": "TENDERS", "result": "FOUND", "risk": "LOW", "claim_ids": ["@C:c20"]}]
    return run_w(W)


def ok_leap_second():
    W = world()
    W["prj_dossier"]["created_at"] = "2026-09-01T23:59:60Z"
    return run_w(W)


def ok_nfkc_fullwidth():  # compatibility forms ARE normalised
    W = world()
    ent(W, "ent_ts_pump_fw", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н－１０１"}, INT)
    return run_w(W)


def ok_real_checksums():
    ok = (validator.inn_ok("7707083893") and validator.ogrn_ok("1027700132195") and validator.inn_ok("7736207543")
          and validator.ogrn_ok("1027700229193") and validator.inn_ok("500100732259") and validator.imo_ok("9074729")
          and not validator.inn_ok("7707083894") and not validator.inn_ok("500100732258"))
    return "OK" if ok else "BAD"


# =====================================================================================
# T3 honesty
# =====================================================================================

def t3_equivalence():
    """T3 (validate with rule disabled == clean) is implied by T2: 'disabled' only filters output."""
    bad = 0
    for v in VECTORS:
        d = build(v)
        full = validate(d).errors
        for dis in (set(v["expected"]), set(validator.ERROR_CODES[1::2])):
            if validate(d, disabled=dis).errors != [e for e in full if e["code"] not in dis]:
                bad += 1
    return "EQUIVALENT" if bad == 0 else f"DIFFERS:{bad}"


# =====================================================================================
# MU — mutants
# =====================================================================================

MUTANTS = [
    # (id, description, old, new)
    ("M01", "без NFKC", 'unicodedata.normalize("NFKC", s).casefold()', "s.casefold()"),
    ("M03", "без схлопывания пробелов", 'return " ".join(s.split())', "return s"),
    ("M04", "revoked_at <= t -> <", 'key["revoked_at"] <= t', 'key["revoked_at"] < t'),
    ("M05", "not_before <= t -> <", 'key["not_before"] <= t < key["not_after"]', 'key["not_before"] < t < key["not_after"]'),
    ("M06", "без проверки границы UTF-8", 'chunk.decode("utf-8")', 'chunk.decode("utf-8", "replace")'),
    ("M07", "Проверка игнорирует слияния", 'touches = {resolve(c["subject"])} | ({resolve(c["object"]["entity"])}',
     'touches = {c["subject"]} | ({c["object"]["entity"]}'),
    ("M09", "повтор измерения не проверяется", "if len(set(fdims)) != len(fdims):", "if False:"),
    ("M10", "NOT_FOUND с риском != NONE", ' or (f["result"] == "NOT_FOUND" and f["risk"] != "NONE")', ""),
    ("M11", "утверждение записано после завершения", 'c["recorded_at"] > k["completed_at"] or ', ""),
    ("M12", "HUMAN-утверждение в receipt", 'pb["kind"] != "PIPELINE" or ', 'pb.get("kind") == "X" or '),
    ("M13", "run_id не сверяется", ' or pb["run_id"] != r["run_id"]', ""),
    ("M14", "служба не сверяется", 'or pb["service_id"] != r["producer"]["service_id"] ', ""),
    ("M15", "проект не сверяется", 'or c["project_id"] != r["project_id"] or c["recorded_at"] > t', 'or c["recorded_at"] > t'),
    ("M16", "recorded_at > issued_at не проверяется", 'or c["project_id"] != r["project_id"] or c["recorded_at"] > t',
     'or c["project_id"] != r["project_id"]'),
    ("M17", "«ровно один receipt» -> «хотя бы один»", 'len(listed.get(cid, [])) != 1', 'len(listed.get(cid, [])) < 1'),
    ("M18", "as_of позже завершения", ' or k["as_of"] > k["completed_at"][:10]', ""),
    ("M19", "not_before < not_after не проверяется", 'not key["not_before"] < key["not_after"] or ', ""),
    ("M20", "revoked_at < not_before не проверяется", ' or ("revoked_at" in key and key["revoked_at"] < key["not_before"])', ""),
    ("M21", "IMO без контрольной цифры", "return sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]", "return True"),
    ("M22", "ИНН-12: только первая контрольная цифра",
     "\n                and ctl([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11) == d[11])", ")"),
    ("M24", "объект из другого проекта", 'elif obj_ent["project_id"] != c["project_id"]:', "elif False:"),
    ("M25", "tenant входов receipt", 'elif s["tenant_id"] != tenant_of(r["project_id"]):', "elif False:"),
    ("M26", "PD только по субъекту, не по объекту", "for x in (subj, obj_ent))", "for x in (subj,))"),
    ("M27", "byte_length не сверяется", ' or len(b) != s["byte_length"]', ""),
    ("M28", "range: тип сущности-объекта не проверяется",
     ' or (obj_ent is not None and obj_ent["entity_type"] not in rng["entity"])', ""),
    ("M29", "enum-квалификатор принимает любое значение", '(s["type"] == "enum" and v in s["enum"])', '(s["type"] == "enum")'),
    ("M30", "bool принимается как integer", " and not isinstance(v, bool)", ""),
    ("M31", "boolean-квалификатор принимает что угодно", '(s["type"] == "boolean" and isinstance(v, bool))',
     '(s["type"] == "boolean")'),
    ("M32", "необъявленный квалификатор принимается", "ok = s is not None and (", "ok = s is None or ("),
    ("M33", "субъект Проверки не обязан быть ACTIVE", 'subj["status"] != "ACTIVE" or ', ""),
    ("M34", "слияние в другой проект", ' or t["project_id"] != e["project_id"]', ""),
    ("M35", "слияние в не-ACTIVE", 't["status"] != "ACTIVE" or ', ""),
    ("M37", "неформальная организация с ИНН", 'if "disambiguator" not in i or "ogrn" in i or "inn" in i:',
     'if "disambiguator" not in i:'),
    ("M38", "previous: субъект не сверяется", ' or pv["subject_entity_id"] != k["subject_entity_id"]', ""),
    ("M39", "previous: проект не сверяется", 'pv["check_id"] == kid or pv["project_id"] != k["project_id"]', 'pv["check_id"] == kid'),
    ("M40", "календарь не проверяется для дат (DATE_FIELDS)",
     'DATE_FIELDS = {"birth_date", "date", "started_on", "valid_from", "valid_to", "as_of"}', "DATE_FIELDS = set()"),
    ("M41", "календарь DATE-литералов не проверяется", 'if node.get("type") == "DATE" and isinstance(node.get("value"), str):',
     "if False:"),
    ("M43", "уникальность среди всех, а не только ACTIVE (строже)", 'if e["status"] == "ACTIVE":\n            for x in ids:',
     "if True:\n            for x in ids:"),
    ("M44", "CANCELLED считается завершённой (строже)", 'done = k["status"] == "COMPLETED"', 'done = k["status"] != "IN_PROGRESS"'),
    ("M45", "источник: max(observed_at) вместо min", 'min(o["observed_at"] for o in s["observations"])',
     'max(o["observed_at"] for o in s["observations"])'),
    # controls: must be KILLED
    ("M-CTRL-1", "контроль: без ё→е", '.replace("ё", "е")', ""),
    ("M-CTRL-2", "контроль: resolve() игнорирует слияния", 'return e["merged_into"] if e and e["status"] == "MERGED" else eid',
     "return eid"),
    ("M-CTRL-3", "контроль: без ОГРН", 'return len(v) == 13 and int(v[:12]) % 11 % 10 == int(v[12])', "return True"),
    ("M-CTRL-4", "контроль: status_at < вместо <=", 'rv["reviewed_at"] <= t', 'rv["reviewed_at"] < t'),
    ("M-CTRL-5", "контроль: измерение предиката не проверяется", 'if p is not None and f["dimension"] not in p["dimensions"]:',
     "if False:"),
]


def run_mutants():
    root = REVIEW / "mutants"
    shutil.rmtree(root, ignore_errors=True)
    src = CORE / "validator.py"
    code = src.read_text(encoding="utf-8")
    for mid, desc, old, new in MUTANTS:
        n = code.count(old)
        if n != 1:
            row("MU", mid, "KILLED", f"N/A(pattern x{n})", desc)
            continue
        d = root / mid
        d.mkdir(parents=True)
        for f in ("fixtures.py", "tests.py", "jcs.py", "jcs.mjs", "core.schema.json", "predicates.json"):
            shutil.copy(CORE / f, d / f)
        (d / "validator.py").write_text(code.replace(old, new), encoding="utf-8")
        r = subprocess.run([sys.executable, "tests.py"], cwd=d, capture_output=True, text=True, timeout=300,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        got = "SURVIVED" if (r.returncode == 0 and "ALL PASS" in r.stdout) else "KILLED"
        row("MU", mid, "KILLED", got, desc)
    shutil.rmtree(root, ignore_errors=True)


# =====================================================================================
# JCS — Python vs Node vs independent expected bytes
# =====================================================================================

JCS_CASES = [
    # (id, json text, expected canonical text or None = must be rejected by both)
    ("J01", '{"\\ue000":1,"\\ud83d\\ude00":2}', '{"\U0001F600":2,"":1}'),
    ("J02", '{"\\u0080":1,"\\u007f":2,"\\uffff":3,"\\ud800\\udc00":4}', '{"\x7f":2,"\x80":1,"\U00010000":4,"￿":3}'),
    ("J03", '"\\u2028\\u2029"', '"  "'),
    ("J04", '"\\u0000\\u001f\\u007f"', '"\\u0000\\u001f\x7f"'),
    ("J05", '"\\b\\f\\n\\r\\t\\"\\\\/"', '"\\b\\f\\n\\r\\t\\"\\\\/"'),
    ("J06", '{"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/"}',
     '{"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'),  # RFC 8785 §3.2.2.2 example
    ("J07", '{"1":1,"10":2,"2":3,"a":4}', '{"1":1,"10":2,"2":3,"a":4}'),
    ("J08", '{"__proto__":1,"a":2}', '{"__proto__":1,"a":2}'),
    ("J09", '{"\\u00e9":1,"e\\u0301":2}', '{"é":2,"é":1}'),
    ("J10", '-0', '0'),
    ("J11", '"\\ud800"', None),
    ("J12", '9007199254740993', None),
    ("J13", '1.5', None),
    ("J14", '1.0', None),              # integer-only profile: must be rejected by both
    ("J15", '{"\\ud800":1}', None),    # lone surrogate in a KEY
    ("J16", '1e2', None),
]

NODE_DRIVER = r"""
import { canon } from %s;
let buf = '';
process.stdin.on('data', d => buf += d);
process.stdin.on('end', () => {
  const out = JSON.parse(buf).map(t => { try { return {ok: true, v: canon(JSON.parse(t))}; }
                                         catch (e) { return {ok: false, v: String(e.message)}; } });
  process.stdout.write(JSON.stringify(out));
});
"""


def run_jcs():
    from jcs import canon
    drv = REVIEW / "_jcs_driver.mjs"
    drv.write_text(NODE_DRIVER % json.dumps((CORE / "jcs.mjs").as_uri()), encoding="utf-8")
    try:
        r = subprocess.run(["node", str(drv)], input=json.dumps([c[1] for c in JCS_CASES]), capture_output=True,
                           text=True, check=True)
        node = json.loads(r.stdout)
    finally:
        drv.unlink()
    for (jid, text, exp), n in zip(JCS_CASES, node):
        try:
            py = ("ok", canon(json.loads(text)))
        except Exception as e:  # noqa: BLE001
            py = ("rej", type(e).__name__)
        nd = ("ok", n["v"]) if n["ok"] else ("rej", "Error")
        want = "REJECT" if exp is None else exp
        got_py = py[1] if py[0] == "ok" else "REJECT"
        got_nd = nd[1] if nd[0] == "ok" else "REJECT"
        got = "py=node=expected" if got_py == got_nd == want else f"py={got_py!r} node={got_nd!r}"
        ROWS.append(("JCS", jid, repr(want)[:40], got[:70], "ok" if got == "py=node=expected" else "FINDING", text[:40]))


# =====================================================================================

ATTACKS = [
    ("FA", "OR-FA01", "ENTITY_DUPLICATE_IN_PROJECT", fa01, "PERSON: латинская o в «Ломов»"),
    ("FA", "OR-FA02", "ENTITY_DUPLICATE_IN_PROJECT", fa02, "EQUIPMENT: латинская H в «Н-101»"),
    ("FA", "OR-FA03", "ENTITY_DUPLICATE_IN_PROJECT", fa03, "EQUIPMENT: неразрывный дефис U+2011"),
    ("FA", "OR-FA04", "ENTITY_DUPLICATE_IN_PROJECT", fa04, "PERSON: U+200B внутри фамилии"),
    ("FA", "OR-FA05", "ENTITY_DUPLICATE_IN_PROJECT", fa05, "неформальная орг.: \"\" вместо «», тот же disambiguator"),
    ("FA", "OR-FA06", "ENTITY_DUPLICATE_IN_PROJECT", fa06, "кадастровый :245 vs :0245"),
    ("FA", "OR-FA07", "ERR(SCHEMA_INVALID|DUP)", fa07, "VIN + '\\n' проходит ^…$ -> второй автомобиль"),
    ("FA", "OR-FA08", "ENTITY_DUPLICATE_IN_PROJECT", fa08, "ИНН слитого дубля у новой ACTIVE сущности"),
    ("FA", "OR-FA09", "IDENTIFIER_CHECKSUM_INVALID", fa09, "ru.inn через foreign_ids без контрольной суммы"),
    ("FA", "OR-FA10", "EVIDENCE_SPAN_INVALID", fa10, "источник без content_inline: подложная цитата"),
    ("FA", "OR-FA10b", "EVIDENCE_SPAN_INVALID", fa10b, "источник без content_inline: без цитаты, любой sha"),
    ("FA", "OR-FA11", "RECEIPT_KEY_INVALID", fa11, "свой ServiceKey для svc_techsense + подложный receipt"),
    ("FA", "OR-FA12", "MARKING_PD_MISSING", fa12, "Проверка физлица PUBLIC без PERSONAL_DATA"),
    ("FA", "OR-FA13", "MARKING_BROADER_THAN_INPUT", fa13, "PUBLIC-утверждение о CONFIDENTIAL-сущности"),
    ("FA", "OR-FA14", "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", fa14, "ACCEPTED задним числом (reviewed_at самозаявлен)"),
    ("FA", "OR-FA15", "PREDICATE_RANGE_VIOLATION", fa15, "номер дела со scheme=telegram"),
    ("FA", "OR-FA16", "QUALIFIER_INVALID", fa16, "строковый квалификатор ' '"),
    ("FA", "OR-FA17", "PREDICATE_RANGE_VIOLATION", fa17, "давление в kg"),
    ("FR", "OR-FR01", "OK", fr01, "тёзки с одной датой рождения и разными ИНН"),
    ("FR", "OR-FR02", "OK", fr02, "два митинга: одно название, одна дата, разные места"),
    ("FR", "OR-FR03", "OK", fr03, "слияние субъекта после завершённых Проверок"),
    ("FR", "OR-FR04", "OK", fr04, "реестр-данные: строковый квалификатор с именем 'date'"),
    ("CR", "OR-CR01", "ERR(report)", cr01, "ИНН '…\\n' -> int('\\n')"),
    ("CR", "OR-CR02", "ERR(report)", cr02, "IMO '…\\n'"),
    ("CR", "OR-CR03", "ERR(report)", cr03, "share_bp 6000.0 (integer для схемы, float для JCS)"),
    ("CR", "OR-CR04", "ERR(report)", cr04, "contract_amount_minor 2^53"),
    ("CR", "OR-CR05", "ERR(report)", cr05, "одиночный суррогат в content_inline"),
    ("CR", "OR-CR06", "ERR(report)", cr06, "одиночный суррогат в литерале"),
    ("CR", "OR-CR07", "ERR(report)", cr07, "одиночный суррогат в ключе квалификатора"),
    ("CR", "OR-CR08", "ERR(report)", cr08, "span.start = 5.0"),
    ("CR", "OR-CR09", "exit=1", cr09, "CLI: файл с 6000.0"),
    ("DG", "OR-DG01", "OK", dg01, "ИП: ИНН-12 + ОГРНИП-15 как ORGANIZATION"),
    ("DG", "OR-DG02", "ERR(no search trace)", dg02, "FULL, всё NOT_FOUND, ни одного источника"),
    ("DG", "OR-DG03", "OK", dg03, "EQUIPMENT-тип без site_id"),
    ("DG", "OR-DG04", "ERR(QUALIFIER_INVALID)", dg04, "condition='когда-нибудь'"),
    ("DG", "OR-DG05", "ERR(same publication)", dg05, "та же статья + '\\n' -> второй Source"),
    ("OK", "V-01", "RECEIPT_CLAIM_BINDING_INVALID", ok_two_receipts, "утверждение в двух receipt"),
    ("OK", "V-02", "RECEIPT_CLAIM_BINDING_INVALID", ok_human_in_receipt, "HUMAN-утверждение в receipt"),
    ("OK", "V-03", "RECEIPT_KEY_INVALID", ok_revoked_eq_issued, "revoked_at == issued_at"),
    ("OK", "V-04", "OK", ok_issued_eq_not_before, "issued_at == not_before"),
    ("OK", "V-05", "QUALIFIER_INVALID", ok_bool_as_int, "True как integer"),
    ("OK", "V-06", "QUALIFIER_INVALID", ok_int_as_bool, "1 как boolean"),
    ("OK", "V-07", "EVIDENCE_SPAN_INVALID", ok_emoji_cut, "span режет 4-байтовый эмодзи, sha совпадает"),
    ("OK", "V-08", "OK", ok_emoji_whole, "span ровно по эмодзи"),
    ("OK", "V-09", "EVIDENCE_SPAN_INVALID", ok_zero_span, "span нулевой длины"),
    ("OK", "V-10", "ENTITY_MERGE_INVALID", ok_merge_chain, "цепочка слияний A->B(MERGED)"),
    ("OK", "V-11", "ENTITY_MERGE_INVALID", ok_merge_cross_project, "слияние в другой проект"),
    ("OK", "V-12", "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", ok_claim_after_completion, "утверждение записано после завершения"),
    ("OK", "V-13", "SCHEMA_INVALID", ok_cancelled_with_completed_at, "CANCELLED с completed_at"),
    ("OK", "V-14", "OK", ok_inprogress_disputed_claim, "IN_PROGRESS с оспоренным утверждением"),
    ("OK", "V-15", "SCHEMA_INVALID", ok_leap_second, "секунда 60"),
    ("OK", "V-16", "ENTITY_DUPLICATE_IN_PROJECT", ok_nfkc_fullwidth, "полноширинные «－１０１» (NFKC)"),
    ("OK", "V-17", "OK", ok_real_checksums, "реальные ИНН/ОГРН/IMO"),
]


def main():
    for sec, aid, exp, fn, note in ATTACKS:
        got = fn()
        row(sec, aid, exp, got, note)
    row("T3", "OR-T3", "INDEPENDENT", t3_equivalence(), "T3 == фильтр вывода T2")
    run_jcs()
    if "--no-mutants" not in sys.argv:
        run_mutants()
    w = [max(len(str(r[i])) for r in ROWS) for i in range(5)]
    print(f"{'sec':<4} | {'id':<{w[1]}} | {'expected':<40} | {'got':<60} | verdict | note")
    for s, a, e, g, v, n in ROWS:
        print(f"{s:<4} | {a:<{w[1]}} | {str(e)[:40]:<40} | {str(g)[:60]:<60} | {v:<7} | {n}")
    nf = sum(1 for r in ROWS if r[4] == "FINDING")
    nr = sum(1 for r in ROWS if r[4] == "REGRESSION")
    print(f"\nFINDING={nf} REGRESSION={nr} fixed={sum(1 for r in ROWS if r[4] == 'fixed')} "
          f"ok={sum(1 for r in ROWS if r[4] == 'ok')} total={len(ROWS)}")


if __name__ == "__main__":
    main()

"""Independent hostile RE-review of core-ontology/0.2 — executable attack suite.

Re-checks every v0.1 finding (OR-01..OR-18, OR-G1..G5) against the v0.2 API and runs the new attacks
(RR-*) on what v0.2 added. CORE (default /home/claude/as/core, env CORE=...) is only read: bytecode
writing is disabled, fixtures.main() is never called.

API v0.2: vectors.build(v) -> (ds, trust, content); fixtures.finalize(W) -> (ds, ix, trust, content);
          validator.validate(ds, trust, content)

Sections: OR  = re-check of v0.1 findings (verdict closed / OPEN)
          RR  = new attacks (verdict FINDING / fixed)
          OK  = verified correct, regression guards (ok / REGRESSION)
          JCS = Python vs Node vs expected bytes
          MU  = extra mutants run through the author's own harness (mutants.run_one), SURVIVED = FINDING
Usage: python3 ontology_attacks_v0.2.py [--no-mutants]
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
CORE = Path(os.environ.get("CORE", "/home/claude/as/core")).resolve()
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(CORE))

import fixtures  # noqa: E402
import validator  # noqa: E402
from fixtures import world, finalize, SV, T, SEEDS, pub, inn12, inn10, ogrnip, INN_DEV, INN_LOMOV, ARTIFACT  # noqa: E402
from fixtures import mk, PUB, INT, PUB_PD, CONF_PD, CONF_CS, CONF_CS_PD, srch  # noqa: E402
from validator import validate  # noqa: E402

ROWS = []


def sha(s):
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode("utf-8")).hexdigest()


def run3(ds, trust, content):
    try:
        R = validate(ds, trust, content)
    except BaseException as e:  # noqa: BLE001 - a crash is itself the result (RecursionError is not Exception-safe)
        return f"CRASH:{type(e).__name__}"
    return "OK" if not R.errors else ",".join(R.codes())


def run_w(W, post=None):
    ds, ix, trust, content = finalize(W)
    env = {"trust": trust, "content": content}
    if post:
        post(ds, ix, env)
    return run3(ds, env["trust"], env["content"])


def rec(ds, ix, name):
    return ds["records"][ix[name]]


def ent(W, name, prj, etype, identity, marking, status="ACTIVE", merged_into=None, changed=None):
    r = {"kind": "Entity", "schema_version": SV, "entity_id": name, "project_id": prj, "entity_type": etype,
         "identity": identity, "display_name": name, "status": status, "created_at": "2026-09-05T12:00:00Z",
         "marking": marking}
    if merged_into:
        r["merged_into"] = merged_into
    if changed:
        r["status_changed_at"] = changed
    W[name] = r


def clm(W, name, prj, subj, pred, obj, evs, marking, recorded, by=None, q=None):
    r = {"kind": "Claim", "schema_version": SV, "project_id": prj, "subject": subj, "predicate": pred, "object": obj,
         "evidence": [{"$ev": list(e)} for e in evs], "produced_by": by or {"kind": "HUMAN", "actor_id": "usr_analyst1"},
         "recorded_at": recorded, "marking": marking}
    if q:
        r["qualifiers"] = q
    W[name] = r


def row(section, aid, expected, got, note, sev=""):
    if section == "OK":
        verdict = "ok" if got == expected else "REGRESSION"
    elif section == "MU":
        verdict = ("equiv" if aid in EQUIV_BY_REVIEWER else "FINDING") if got == "SURVIVED" else "ok"
    elif expected == "NO-CRASH":
        verdict = "FINDING" if got.startswith("CRASH") else "closed" if section == "OR" else "fixed"
    else:
        good = got == expected or (expected.startswith("ERR") and got != "OK" and not got.startswith("CRASH"))
        verdict = ("closed" if good else "OPEN") if section == "OR" else ("fixed" if good else "FINDING")
    ROWS.append((section, aid, sev, expected, got, verdict, note))


LOMOV = {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"}

# =====================================================================================
# OR — re-check of v0.1 findings
# =====================================================================================

def or01a():  # prod shape: no inline bytes, no store bytes, fabricated quote
    W = world()
    fake = "Синий кит — вид хищных китов"
    W["c24"]["_ev_patch"] = lambda evs: evs[0].update(quote=fake, quote_sha256=sha(fake))

    def post(ds, ix, env):
        s = rec(ds, ix, "s10")
        s.pop("content_inline")
        env["content"].pop(s["source_id"])
    return run_w(W, post)


def or01b():  # prod shape: bytes in store, fabricated quote
    W = world()
    fake = "Синий кит — вид хищных китов"
    W["c24"]["_ev_patch"] = lambda evs: evs[0].update(quote=fake, quote_sha256=sha(fake))
    return run_w(W, lambda ds, ix, env: rec(ds, ix, "s10").pop("content_inline"))


def or02():  # attacker key: dataset may not carry keys any more; sign with an unregistered key under key_ts_1
    W = world()
    W["rcp_1"]["_sign_seed"] = "OTHER"
    return run_w(W)


def or02b():  # attacker smuggles a ServiceKey record into the dataset
    W = world()
    W["key_evil"] = {"kind": "ServiceKey", "schema_version": SV, "key_id": "key_evil", "service_id": "svc_techsense",
                     "algorithm": "Ed25519", "public_key": pub(SEEDS["OTHER"]),
                     "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z"}
    ORDER = fixtures.ORDER
    fixtures.ORDER = ORDER + ["ServiceKey"]
    try:
        return run_w(W)
    finally:
        fixtures.ORDER = ORDER


def or03():  # INN of a MERGED duplicate reused by a new ACTIVE entity
    W = world()
    inn_b = inn12("7701234567")
    ent(W, "ent_d_old", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "inn": inn_b}, CONF_PD,
        "MERGED", "ent_d_lomov", "2026-09-06T15:00:00Z")
    ent(W, "ent_d_new", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "inn": inn_b}, CONF_PD)
    return run_w(W)


def or04():  # trailing \n in VIN
    W = world()
    ent(W, "ent_d_car2", "prj_dossier", "MOVABLE_PROPERTY",
        {"subtype": "VEHICLE", "vin": "XTA210990Y1234567\n", "description": "авто"}, CONF_PD)
    return run_w(W)


def _chk_person(marking):
    W = world()
    W["chk_xx"] = {"kind": "Check", "schema_version": SV, "check_id": "chk_xx", "project_id": "prj_compliance",
                  "subject_entity_id": "ent_k_lomov", "profile": "EXPRESS_NEGATIVE", "as_of": "2026-09-10",
                  "requested_at": "2026-09-10T08:00:00Z", "requested_by": "usr_bank_officer", "status": "COMPLETED",
                  "completed_at": "2026-09-10T12:00:00Z",
                  "findings": [{"dimension": "NEGATIVE", "result": "NOT_FOUND", "risk": "NONE", "claim_ids": [],
                                "searches": [srch("СМИ", "ФИО", "2026-09-10T09:00:00Z")]}],
                  "overall_risk": "NONE", "marking": marking}
    return W


def or05():
    return run_w(_chk_person(mk("PUBLIC")))


def _post_set(name, path, value):
    def post(ds, ix, env):
        node = rec(ds, ix, name)
        for p in path[:-1]:
            node = node[p]
        node[path[-1]] = value
    return post


def or06(case):
    W = world()
    if case == "inn_nl":
        W["ent_d_developer"]["identity"]["inn"] = INN_DEV + "\n"
        return run_w(W)
    if case == "imo_nl":
        ent(W, "ent_d_ship", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VESSEL", "imo": "9074729\n", "description": "судно"}, CONF_PD)
        return run_w(W)
    if case == "float_q":
        return run_w(W, _post_set("c11", ["qualifiers", "share_bp"], 6000.0))
    if case == "big_int":
        return run_w(W, _post_set("c20", ["qualifiers", "contract_amount_minor"], 2 ** 53))
    if case == "sur_content":
        return run_w(W, lambda ds, ix, env: rec(ds, ix, "s10").__setitem__("content_inline", rec(ds, ix, "s10")["content_inline"] + "\ud800"))
    if case == "sur_literal":
        return run_w(W, _post_set("c9", ["object", "literal", "value"], "x\ud800"))
    if case == "sur_key":
        return run_w(W, _post_set("c9", ["qualifiers", "\ud800"], "x"))
    if case == "span_float":
        return run_w(W, lambda ds, ix, env: rec(ds, ix, "c24")["evidence"][0]["span"].__setitem__("start", 0.0))


def or06_cli():
    ds, ix, trust, content = finalize(world())
    txt = json.dumps(ds, ensure_ascii=False).replace('"share_bp": 6000', '"share_bp": 6000.0')
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "d.json"
        p.write_text(txt, encoding="utf-8")
        r = subprocess.run([sys.executable, str(CORE / "validator.py"), str(p)], capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return "CRASH:Traceback" if "Traceback" in r.stderr else f"exit={r.returncode}"


def or09():  # merge of the subject after two completed Checks
    W = world()
    W["ent_k_dev_main"] = {**copy.deepcopy(W["ent_k_developer"]), "entity_id": "ent_k_dev_main"}
    W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_main", status_changed_at="2026-09-28T00:00:00Z")
    W["chk_tenders_1"]["subject_entity_id"] = "ent_k_dev_main"
    return run_w(W)


def or10():
    W = world()
    base = {"surname": "Иванов", "given_name": "Сергей", "patronymic": "Александрович", "birth_date": "1980-01-01"}
    ent(W, "ent_d_iv_a", "prj_dossier", "PERSON", {**base, "inn": inn12("7700000001")}, CONF_PD)
    ent(W, "ent_d_iv_b", "prj_dossier", "PERSON", {**base, "inn": inn12("5000000002")}, CONF_PD)
    return run_w(W)


def or11():
    W = world()
    for n, pl in (("a", "г. Заречный"), ("b", "г. Тверь")):
        ent(W, f"ent_c_rally_{n}", "prj_conflict_land", "EVENT", {"title": "Митинг против застройки", "date": "2026-09-10", "place": pl}, CONF_PD)
    return run_w(W)


def or12(case):
    W = world()
    if case == "lat_o":
        ent(W, "ent_d_x", "prj_dossier", "PERSON", {**LOMOV, "surname": "Лoмов"}, CONF_PD)
    elif case == "lat_H":
        ent(W, "ent_ts_x", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101"}, INT)
    elif case == "nbh":
        ent(W, "ent_ts_x", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н‑101"}, INT)
    elif case == "zwsp":
        ent(W, "ent_d_x", "prj_dossier", "PERSON", {**LOMOV, "surname": "Ло​мов"}, CONF_PD)
    elif case == "quotes":
        ent(W, "ent_c_x", "prj_conflict_land", "ORGANIZATION", {"name": 'Инициативная группа "Заречная, 12"', "jurisdiction": "RU",
                                                                "informal": True, "disambiguator": "zarechnaya-12"}, CONF_PD)
    elif case == "cadastral":
        ent(W, "ent_d_x", "prj_dossier", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:0245", "address": "ул. Заречная, 12"}, CONF_PD)
    return run_w(W)


def or13():  # back-dating: both declared and "system" time moved 1 s before completion
    W = world()
    W["rev_c18_a"].update(reviewed_at="2026-09-10T11:59:59Z", recorded_at="2026-09-10T11:59:59Z", note="внесено 29.09 задним числом")
    return run_w(W)


def or14():
    W = world()
    ent(W, "ent_d_kz", "prj_dossier", "ORGANIZATION", {"name": "ТОО Пример", "jurisdiction": "KZ",
                                                        "foreign_ids": [{"scheme": "ru.inn", "value": "1234567890"}]}, CONF_PD)
    return run_w(W)


def or16():  # registry-is-data: string qualifier named 'date'
    W = world()
    extra = {"id": "court.hearing", "label_ru": "заседание", "domain": ["ORGANIZATION"], "range": {"literal": ["IDENTIFIER"]},
             "cardinality": "MANY", "dimensions": ["COURT"], "qualifiers": {"date": {"type": "string", "required": True}}}
    validator.PREDICATES["predicates"].append(extra)
    try:
        clm(W, "c_h", "prj_compliance", "ent_k_developer", "court.hearing",
            {"literal": {"type": "IDENTIFIER", "scheme": "ru.arbitr", "value": "А41-12345/2026"}},
            [("s6", "Делу присвоен номер А41-12345/2026")], CONF_CS, "2026-09-07T10:00:00Z", q={"date": "осень 2026"})
        return run_w(W)
    finally:
        validator.PREDICATES["predicates"].remove(extra)


def or17(case):
    W = world()
    if case == "scheme":
        W["c19"]["object"] = {"literal": {"type": "IDENTIFIER", "scheme": "telegram", "value": "@zarechye_dev"}}
    elif case == "blank":
        W["c2"]["qualifiers"] = {"parameter": " "}
    elif case == "unit":
        W["c2"]["object"] = {"literal": {"type": "QUANTITY", "value": "16", "unit": "kg"}}
    return run_w(W)


def or18():
    W = world()
    W["c7"]["marking"] = PUB_PD
    return run_w(W)


def g1_ip():  # ИП as PERSON with ОГРНИП (real published sample 304500116000157) + INN
    W = world()
    ent(W, "ent_k_ip", "prj_compliance", "PERSON", {"surname": "Петров", "given_name": "Пётр", "birth_date": "1970-01-01",
                                                     "inn": inn12("5001000001"), "ogrnip": "304500116000157"}, CONF_CS_PD)
    return run_w(W)


def g2_nf():  # FULL Check, all NOT_FOUND, no search trace
    W = world()
    W["chk_tenders_1"].update(profile="FULL", status="COMPLETED", completed_at="2026-09-29T10:00:00Z", overall_risk="NONE",
                              findings=[{"dimension": d, "result": "NOT_FOUND", "risk": "NONE", "claim_ids": [], "searches": []}
                                        for d in ["NEGATIVE", "TENDERS", "SOCIAL_MEDIA", "CORPORATE", "PROPERTY", "COURT"]])
    return run_w(W)


def g3_model():
    W = world()
    ent(W, "ent_ts_model2", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": "НМ 25-50"}, INT)
    return run_w(W)


def g4_wm():  # same article + '\n' -> second Source
    W = world()
    W["s2b"] = {**copy.deepcopy(W["s2"]), "content_inline": W["s2"]["content_inline"] + "\n"}
    return run_w(W)


# =====================================================================================
# RR — new attacks on v0.2
# =====================================================================================

def rr_retired_after_close():  # §6: closed Check subject may be "слит/выведен строго позже закрытия"
    W = world()
    W["ent_k_developer"].update(status="RETIRED", status_changed_at="2026-09-30T00:00:00Z")
    W["chk_tenders_1"].update(status="CANCELLED", cancelled_at="2026-09-29T10:00:00Z")
    return run_w(W)


def rr_tag_pt():  # different instruments: Latin PT-101 (pressure transmitter, ГОСТ 21.208) vs Cyrillic РТ-101 (регулятор температуры)
    W = world()
    ent(W, "ent_ts_pt", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "PT-101", "description": "датчик давления"}, INT)
    ent(W, "ent_ts_rt", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "РТ-101", "description": "регулятор температуры"}, INT)
    return run_w(W)


def rr_concept_yo():  # «небо» (sky) vs «нёбо» (palate)
    W = world()
    ent(W, "ent_wk_sky", "prj_wiki_whales", "CONCEPT", {"label": "небо", "lang": "ru", "namespace": "whales"}, PUB)
    ent(W, "ent_wk_palate", "prj_wiki_whales", "CONCEPT", {"label": "нёбо", "lang": "ru", "namespace": "whales"}, PUB)
    return run_w(W)


def rr_concept_case():  # «Орёл» (city) vs «орёл» (bird)
    W = world()
    ent(W, "ent_wk_city", "prj_wiki_whales", "CONCEPT", {"label": "Орёл", "lang": "ru", "namespace": "whales"}, PUB)
    ent(W, "ent_wk_bird", "prj_wiki_whales", "CONCEPT", {"label": "орёл", "lang": "ru", "namespace": "whales"}, PUB)
    return run_w(W)


def rr_concept_sup():  # NFKC: «10²» vs «102»
    W = world()
    ent(W, "ent_wk_a", "prj_wiki_whales", "CONCEPT", {"label": "10²", "lang": "ru", "namespace": "whales"}, PUB)
    ent(W, "ent_wk_b", "prj_wiki_whales", "CONCEPT", {"label": "102", "lang": "ru", "namespace": "whales"}, PUB)
    return run_w(W)


def rr_person_yo():  # Лёвин vs Левин, same name/DOB, no INN known, no marks -> merged (fixable only by marks)
    W = world()
    b = {"given_name": "Константин", "patronymic": "Дмитриевич", "birth_date": "1980-05-05"}
    ent(W, "ent_d_lyovin", "prj_dossier", "PERSON", {**b, "surname": "Лёвин"}, CONF_PD)
    ent(W, "ent_d_levin", "prj_dossier", "PERSON", {**b, "surname": "Левин"}, CONF_PD)
    return run_w(W)


def rr_event_noplace():  # same event, one record with place, one without
    W = world()
    ent(W, "ent_k_tender2", "prj_compliance", "EVENT", {"title": "Электронный аукцион № 0148300000126000017", "date": "2026-08-15",
                                                          "place": "zakupki.gov.ru"}, CONF_CS)
    return run_w(W)


def rr_conflict_noplace():
    W = world()
    ent(W, "ent_c_conflict2", "prj_conflict_land", "CONFLICT", {"title": "Застройка участка на ул. Заречной", "started_on": "2026-09-02"}, CONF_PD)
    return run_w(W)


def rr_registration():  # registration numbers are not normalised at all
    W = world()
    for n, v in (("a", "RA-12345"), ("b", "ra 12345")):
        ent(W, f"ent_d_plane_{n}", "prj_dossier", "MOVABLE_PROPERTY",
            {"subtype": "AIRCRAFT", "description": "самолёт", "registration": {"scheme": "ru.aircraft", "value": v}}, CONF_PD)
    return run_w(W)


def rr_foreign_id():
    W = world()
    for n, v in (("a", "HRB 12345"), ("b", "HRB12345")):
        ent(W, f"ent_d_de_{n}", "prj_dossier", "ORGANIZATION", {"name": f"Beispiel GmbH {n}", "jurisdiction": "DE",
                                                                "foreign_ids": [{"scheme": "de.hrb", "value": v}]}, CONF_PD)
    return run_w(W)


def rr_weak_one_mark():  # the duplicate carries a disambiguator, the original does not -> weak key silently disabled
    W = world()
    ent(W, "ent_d_lomov_dup", "prj_dossier", "PERSON", {**LOMOV, "disambiguator": "from-s9"}, CONF_PD)
    return run_w(W)


def rr_invisible(ch):  # invisible / homoglyph characters that the skeleton keeps
    def f():
        W = world()
        ent(W, "ent_d_lomov_inv", "prj_dossier", "PERSON", {**LOMOV, "surname": "Ло" + ch + "мов"}, CONF_PD)
        return run_w(W)
    return f


def rr_tag_space():  # «Н-101» vs «Н101» vs «Н 101»
    W = world()
    ent(W, "ent_ts_x", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н101"}, INT)
    return run_w(W)


def rr_branch_as_head():  # head organisation re-entered as a BRANCH with its own INN and KPP -> 2nd card of the same legal entity
    W = world()
    ent(W, "ent_d_dev_br", "prj_dossier", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU",
                                                            "legal_form": "BRANCH", "inn": INN_DEV, "kpp": "501201001"}, CONF_PD)
    return run_w(W)


def rr_ogrnip_only_namesakes():  # two ИП, same FIO+DOB, different OGRNIP, INN unknown -> treated as one person
    W = world()
    b = {"surname": "Сидоров", "given_name": "Павел", "birth_date": "1985-02-02"}
    ent(W, "ent_d_ip_a", "prj_dossier", "PERSON", {**b, "ogrnip": ogrnip("30450010000001")}, CONF_PD)
    ent(W, "ent_d_ip_b", "prj_dossier", "PERSON", {**b, "ogrnip": ogrnip("31277460000002")}, CONF_PD)
    return run_w(W)


def rr_trust_empty():
    W = world()
    return run_w(W, lambda ds, ix, env: env.__setitem__("trust", {"trust_format": "core-trust/0.2", "keys": []}))


def rr_trust_broken():
    W = world()
    return run_w(W, lambda ds, ix, env: env.__setitem__("trust", {"trust_format": "core-trust/0.2", "keys": [{"key_id": "x"}]}))


def rr_trust_other_tenant():
    W = world()
    return run_w(W, lambda ds, ix, env: env["trust"]["keys"][0].__setitem__("tenant_id", "tnt_other"))


def rr_trust_crosstenant_dup():  # another tenant happens to use the same key_id -> every tenant loses every key
    W = world()

    def post(ds, ix, env):
        env["trust"]["keys"].append({**env["trust"]["keys"][0], "tenant_id": "tnt_other", "public_key": pub(SEEDS["OTHER"])})
    return run_w(W, post)


def rr_trust_none_no_receipts():  # no trust at all, no receipts, no PIPELINE claims -> fine
    W = world()
    for n in ("rcp_1",):
        W.pop(n)
    for c in ("c0", "c1", "c2", "c3"):
        W[c]["produced_by"] = {"kind": "HUMAN", "actor_id": "usr_analyst1"}
        for ev in W[c]["evidence"]:
            ev.pop("graph_node", None)
    return run_w(W, lambda ds, ix, env: env.__setitem__("trust", None))


def rr_graph_node_fake():  # node id that does not exist in any graph; the artifact itself is never checked
    W = world()
    W["c2"]["evidence"][0]["graph_node"]["node_id"] = "no-such-node-999"
    return run_w(W)


def rr_search_scope_any():  # COURT answered by a "search" in a cooking blog, query 'x', by the reviewer himself
    W = world()
    for f in W["chk_full_1"]["findings"]:
        if f["dimension"] == "COURT":
            f["searches"] = [{"search_scope": "кулинарный блог", "query": "x", "performed_at": "2026-09-25T10:00:00Z",
                              "performed_by": "usr_bank_officer"}]
    return run_w(W)


def rr_search_source_nobytes():  # search result source without any bytes is accepted
    W = world()

    def post(ds, ix, env):
        s = rec(ds, ix, "s12")
        s.pop("content_inline")
        env["content"].pop(s["source_id"])
    return run_w(W, post)


def rr_search_source_marking():  # Check (CONF+PD+CS) cites a RESTRICTED/OFFICIAL_USE search result
    W = world()
    W["s12"]["marking"] = mk("RESTRICTED", "PERSONAL_DATA", "OFFICIAL_USE")
    return run_w(W)


def rr_status_changed_future():  # merge time is self-declared: a merge dated 2099 keeps any closed Check valid
    W = world()
    W["ent_k_dev_main"] = {**copy.deepcopy(W["ent_k_developer"]), "entity_id": "ent_k_dev_main"}
    W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_main", status_changed_at="2099-01-01T00:00:00Z")
    W["chk_tenders_1"]["subject_entity_id"] = "ent_k_dev_main"
    return run_w(W)


def rr_ogrnip_literal():  # IDENTIFIER literal ru.ogrnip: no checksum, not tied to the subject's own ОГРНИП
    W = world()
    W["c17b"]["object"] = {"literal": {"type": "IDENTIFIER", "scheme": "ru.ogrnip", "value": "123456789012345"}}
    return run_w(W)


def rr_merge_into_retired():  # survivor of a merge is later retired (e.g. company liquidated)
    W = world()
    W["ent_d_lomov"].update(status="RETIRED", status_changed_at="2026-09-29T00:00:00Z")
    return run_w(W)


def rr_scheme_collision():  # user-chosen foreign_ids scheme equals an internal key namespace ('equipment')
    W = world()
    ent(W, "ent_ts_vendor", "prj_ts_pumps", "ORGANIZATION", {"name": "Pumpen GmbH", "jurisdiction": "DE",
        "foreign_ids": [{"scheme": "equipment", "value": "site_ns2|н-101"}]}, INT)
    return run_w(W)


def rr_literal_newline():  # a multi-line STRING literal (TechSense action text) is rejected by phase 0
    W = world()
    W["c3"]["object"] = {"literal": {"type": "STRING", "value": "1. остановить насос\n2. сообщить дежурному инженеру"}}
    return run_w(W)


def rr_deep_nesting():
    ds, ix, trust, content = finalize(world())
    x = []
    for _ in range(5000):
        x = [x]
    ds["x"] = x
    return run3(ds, trust, content)


def rr_cli_deep():
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "d.json"
        p.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        r = subprocess.run([sys.executable, str(CORE / "validator.py"), str(p)], capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return "CRASH:Traceback" if "Traceback" in r.stderr else f"exit={r.returncode}"


def rr_cli_contentdir():
    ds, ix, trust, content = finalize(world())
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "d.json").write_text(json.dumps(ds, ensure_ascii=False), encoding="utf-8")
        (t / "tr.json").write_text(json.dumps(trust), encoding="utf-8")
        (t / "c").mkdir()
        (t / "c" / "subdir").mkdir()  # e.g. a sharded object store layout
        for sid, b in content.items():
            (t / "c" / sid.split(":")[-1]).write_bytes(b)
        r = subprocess.run([sys.executable, str(CORE / "validator.py"), str(t / "d.json"), "--trust", str(t / "tr.json"),
                            "--content-dir", str(t / "c")], capture_output=True, text=True,
                           env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return "CRASH:Traceback" if "Traceback" in r.stderr else f"exit={r.returncode}"


def rr_content_str():  # object store returns text instead of bytes
    ds, ix, trust, content = finalize(world())
    s = rec(ds, ix, "s10")
    s.pop("content_inline")
    content[s["source_id"]] = content[s["source_id"]].decode()
    return run3(ds, trust, content)


# =====================================================================================
# OK — regression guards (verified correct in v0.2)
# =====================================================================================

def ok_store_swap():
    W = world()

    def post(ds, ix, env):
        s = rec(ds, ix, "s10")
        s.pop("content_inline")
        env["content"][s["source_id"]] = env["content"][rec(ds, ix, "s1")["source_id"]]
    return run_w(W, post)


def ok_inline_vs_store():
    W = world()
    return run_w(W, lambda ds, ix, env: env["content"].__setitem__(rec(ds, ix, "s10")["source_id"], b"x"))


def ok_trust_revoked_eq():
    return run_w(world(), lambda ds, ix, env: env["trust"]["keys"][0].__setitem__("revoked_at", "2026-09-06T10:00:00Z"))


def ok_bool_int():
    W = world()
    W["c11"]["qualifiers"]["share_bp"] = True
    return run_w(W)


def ok_emoji_cut():
    W = world()
    text = "Синий кит 🐋 — вид усатых китов."
    W["s_e"] = {"kind": "Source", "schema_version": SV, "tenant_id": T, "source_kind": "DOCUMENT", "media_type": "text/plain; charset=utf-8",
                "language": "ru", "title": "emoji", "content_inline": text, "marking": PUB,
                "observations": [{"observed_at": "2026-09-02T09:00:00Z", "origin_uri": "urn:demo:e", "observed_by": "svc_webmon"}]}
    b = text.encode()
    st = b.find("🐋".encode()) + 2
    clm(W, "c_e", "prj_wiki_whales", "ent_wk_blue", "wiki.property", {"literal": {"type": "STRING", "value": "эмодзи"}},
        [("s_e", "Синий кит")], PUB, "2026-09-03T09:00:00Z", q={"property": "icon"})
    W["c_e"]["_ev_patch"] = lambda evs: (evs[0].pop("quote"), evs[0].update(span={"start": st, "end": st + 2},
                                                                                quote_sha256=sha(b[st:st + 2])))
    return run_w(W)


def ok_real_checksums():
    v = validator
    ok = (v.inn_ok("7707083893") and v.ogrn_ok("1027700132195") and v.inn_ok("500100732259") and v.imo_ok("9074729")
          and v.ogrnip_ok("304500116000157") and not v.ogrnip_ok("304500116000158") and not v.inn_ok("7707083894"))
    return "OK" if ok else "BAD"


def ok_fullwidth():
    W = world()
    ent(W, "ent_ts_x", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н－１０１"}, INT)
    return run_w(W)


def ok_retro_by_recorded():  # declared time before completion, system time after -> rejected
    W = world()
    W["rev_c18_a"].update(reviewed_at="2026-09-10T11:00:00Z", recorded_at="2026-09-10T13:00:00Z")
    return run_w(W)


def ok_check_merged_before_close():
    W = world()
    W["ent_k_dev_main"] = {**copy.deepcopy(W["ent_k_developer"]), "entity_id": "ent_k_dev_main"}
    W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_main", status_changed_at="2026-09-20T00:00:00Z")
    W["chk_tenders_1"]["subject_entity_id"] = "ent_k_dev_main"
    return run_w(W)


# =====================================================================================
# JCS
# =====================================================================================

JCS_CASES = [
    ("J01", '{"\\ue000":1,"\\ud83d\\ude00":2}', '{"\U0001F600":2,"":1}'),
    ("J02", '{"\\u0080":1,"\\u007f":2,"\\uffff":3,"\\ud800\\udc00":4}', '{"\x7f":2,"\x80":1,"\U00010000":4,"￿":3}'),
    ("J03", '"\\u2028\\u2029"', '"  "'),
    ("J04", '"\\u0000\\u001f\\u007f"', '"\\u0000\\u001f\x7f"'),
    ("J06", '{"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/"}', '{"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'),
    ("J08", '{"__proto__":1,"a":2}', '{"__proto__":1,"a":2}'),
    ("J10", '-0', '0'),
    ("J11", '"\\ud800"', None),
    ("J12", '9007199254740993', None),
    ("J13", '1.5', None),
    ("J14", '1.0', None),
    ("J15", '{"\\ud800":1}', None),
    ("J16", '1e2', None),
    ("J17", '{"a":{"\\udc00":1}}', None),
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
    with tempfile.TemporaryDirectory() as t:
        drv = Path(t) / "drv.mjs"
        drv.write_text(NODE_DRIVER % json.dumps((CORE / "jcs.mjs").as_uri()), encoding="utf-8")
        r = subprocess.run(["node", str(drv)], input=json.dumps([c[1] for c in JCS_CASES]), capture_output=True, text=True, check=True)
    node = json.loads(r.stdout)
    for (jid, text, exp), n in zip(JCS_CASES, node):
        try:
            py = canon(json.loads(text))
        except Exception:  # noqa: BLE001
            py = "REJECT"
        nd = n["v"] if n["ok"] else "REJECT"
        want = "REJECT" if exp is None else exp
        got = "py=node=expected" if py == nd == want else f"py={py!r} node={nd!r}"
        ROWS.append(("JCS", jid, "", repr(want)[:30], got[:60], "ok" if got == "py=node=expected" else "FINDING", text[:40]))


# =====================================================================================
# MU — extra mutants through the author's harness (single process)
# =====================================================================================

# survivors the reviewer considers equivalent: X06 only changes the message count (codes are a set);
# X08: enum values are strings, a non-string can never be `in` them
EQUIV_BY_REVIEWER = {"X06", "X08"}

EXTRA_MUTANTS = [
    ("X01", "RETIRED/MERGED после закрытия: не требовать ACTIVE у resolve()",
     '\n                                                  and E.get(resolve(subj["entity_id"]), {}).get("status") == "ACTIVE")', ")"),
    ("X02", "0x7F в значениях разрешён", " or ord(ch) == 0x7F for ch in node)", " for ch in node)"),
    ("X03", "минус U+2212 не приводится к «-»", ' or ch == "−" else ch', " else ch"),
    ("X04", "ASCII-кавычки не удаляются", "if ch not in _QUOTES and unicodedata", "if unicodedata"),
    ("X06", "повторный SOURCE_CONTENT_UNAVAILABLE по тому же источнику", "if sid not in unavailable_reported and sid not in bad_sources:",
     "if sid not in bad_sources:"),
    ("X08", "enum без isinstance(str)", '(s["type"] == "enum" and isinstance(v, str) and v in s["enum"])', '(s["type"] == "enum" and v in s["enum"])'),
    ("X09", "cross-scope субъект не обнуляется", '            R.err("CROSS_SCOPE_REFERENCE", cid, "subject из другого проекта")\n            subj = None',
     '            R.err("CROSS_SCOPE_REFERENCE", cid, "subject из другого проекта")'),
]


def _string_paths(node, p=()):
    if isinstance(node, str):
        yield p
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _string_paths(v, p + (k,))
    elif isinstance(node, list):
        for n, v in enumerate(node):
            yield from _string_paths(v, p + (n,))


def equivalence_probe(mut):
    """Try to kill the author's EQUIVALENT mutants M001/M005/M006 with inputs outside the vectors."""
    src = mut.SRC
    spec = {m[0]: m for m in mut.M}
    base_ds, ix, trust, content = finalize(world())
    inputs = []
    for path in _string_paths(base_ds):  # every string leaf + '\n'
        d = copy.deepcopy(base_ds)
        node = d
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = node[path[-1]] + "\n"
        inputs.append((d, trust))
    for path in _string_paths(trust):
        t = copy.deepcopy(trust)
        node = t
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = node[path[-1]] + "\n"
        inputs.append((base_ds, t))
    for key in ("\ud800", "a\u0001", "note\n", "\u007f"):
        for where in ("top", "record", "qualifiers", "identity", "span"):
            d = copy.deepcopy(base_ds)
            tgt = {"top": d, "record": d["records"][0], "qualifiers": rec(d, ix, "c11")["qualifiers"],
                   "identity": rec(d, ix, "ent_d_lomov")["identity"], "span": rec(d, ix, "c11")["evidence"][0]["span"]}[where]
            tgt[key] = 1
            inputs.append((d, trust))
    for val in (1.0, 0.5, -0.0, 1e300):
        d = copy.deepcopy(base_ds)
        rec(d, ix, "c11")["qualifiers"]["share_bp"] = val
        inputs.append((d, trust))
    res = {}
    for mid in ("M001", "M005", "M006"):
        _, _, old, new = spec[mid]
        m = mut.load(src.replace(old, new))
        diff = 0
        for d, t in inputs:
            try:
                a = validate(d, t, content).codes()
            except BaseException as e:  # noqa: BLE001
                a = type(e).__name__
            try:
                b = m.validate(d, t, content).codes()
            except BaseException as e:  # noqa: BLE001
                b = type(e).__name__
            diff += a != b
        res[mid] = (len(inputs), diff)
    return res


def run_mutants():
    import importlib
    sys.path.insert(0, str(CORE))
    mut = importlib.import_module("mutants")
    from vectors import VECTORS, build
    mut.CASES = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
    for mid, (n, diff) in equivalence_probe(mut).items():
        got = "EQUIVALENT" if diff == 0 else f"KILLED on {diff}/{n}"
        ROWS.append(("MU", mid, "", "EQUIVALENT (author)", f"{got} ({n} inputs)", "ok" if diff == 0 else "FINDING",
                     "проверка обоснования эквивалентности"))
    for mid, desc, old, new in EXTRA_MUTANTS:
        r = mut.run_one((mid, desc, old, new))
        got = "SURVIVED" if r[1] == "SURVIVED" else r[1][:40]
        row("MU", mid, got, got, desc)


# =====================================================================================

ATTACKS = [
    # re-check of v0.1
    ("OR", "OR-01a", "P0", "ERR(SOURCE_CONTENT_UNAVAILABLE)", or01a, "нет байтов нигде, подложная цитата"),
    ("OR", "OR-01b", "P0", "EVIDENCE_SPAN_INVALID", or01b, "байты в хранилище, подложная цитата"),
    ("OR", "OR-02a", "P0", "ERR(RECEIPT_SIGNATURE_INVALID)", or02, "подпись чужим ключом под key_ts_1"),
    ("OR", "OR-02b", "P0", "ERR(SCHEMA_INVALID)", or02b, "ServiceKey в данных"),
    ("OR", "OR-03", "P0", "ENTITY_DUPLICATE_IN_PROJECT", or03, "ИНН слитого дубля у новой сущности"),
    ("OR", "OR-04", "P0", "ERR(SCHEMA_INVALID)", or04, "VIN + '\\n'"),
    ("OR", "OR-05", "P0", "MARKING_BROADER_THAN_INPUT", or05, "Проверка физлица PUBLIC"),
    ("OR", "OR-06a", "P1", "NO-CRASH", lambda: or06("inn_nl"), "ИНН + '\\n'"),
    ("OR", "OR-06b", "P1", "NO-CRASH", lambda: or06("imo_nl"), "IMO + '\\n'"),
    ("OR", "OR-06c", "P1", "NO-CRASH", lambda: or06("float_q"), "6000.0"),
    ("OR", "OR-06d", "P1", "NO-CRASH", lambda: or06("big_int"), "2^53"),
    ("OR", "OR-06e", "P1", "NO-CRASH", lambda: or06("sur_content"), "суррогат в content_inline"),
    ("OR", "OR-06f", "P1", "NO-CRASH", lambda: or06("sur_literal"), "суррогат в литерале"),
    ("OR", "OR-06g", "P1", "NO-CRASH", lambda: or06("sur_key"), "суррогат в ключе"),
    ("OR", "OR-06h", "P1", "NO-CRASH", lambda: or06("span_float"), "span 0.0"),
    ("OR", "OR-06i", "P1", "exit=1", or06_cli, "CLI 6000.0"),
    ("OR", "OR-09", "P1", "OK", or09, "слияние субъекта после закрытых Проверок"),
    ("OR", "OR-10", "P1", "OK", or10, "тёзки с разными ИНН"),
    ("OR", "OR-11", "P1", "OK", or11, "одноимённые события в разных местах"),
    ("OR", "OR-12a", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("lat_o"), "латинская o"),
    ("OR", "OR-12b", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("lat_H"), "латинская H"),
    ("OR", "OR-12c", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("nbh"), "U+2011"),
    ("OR", "OR-12d", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("zwsp"), "U+200B"),
    ("OR", "OR-12e", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("quotes"), "кавычки"),
    ("OR", "OR-12f", "P1", "ENTITY_DUPLICATE_IN_PROJECT", lambda: or12("cadastral"), ":0245"),
    ("OR", "OR-13", "P1", "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", or13, "задним числом (обе метки времени)"),
    ("OR", "OR-14", "P1", "ERR(SCHEMA_INVALID)", or14, "ru.inn через foreign_ids"),
    ("OR", "OR-16", "P2", "OK", or16, "квалификатор с именем date"),
    ("OR", "OR-17a", "P2", "PREDICATE_RANGE_VIOLATION", lambda: or17("scheme"), "scheme telegram у дела"),
    ("OR", "OR-17b", "P2", "QUALIFIER_INVALID", lambda: or17("blank"), "квалификатор ' '"),
    ("OR", "OR-17c", "P2", "PREDICATE_RANGE_VIOLATION", lambda: or17("unit"), "давление в kg"),
    ("OR", "OR-18", "P2", "MARKING_BROADER_THAN_INPUT", or18, "утверждение шире сущности"),
    ("OR", "OR-G1", "", "OK", g1_ip, "ИП: PERSON + ОГРНИП"),
    ("OR", "OR-G2", "", "CHECK_SEARCH_MISSING", g2_nf, "NOT_FOUND без поиска"),
    ("OR", "OR-G3", "", "OK", g3_model, "EQUIPMENT_MODEL"),
    ("OR", "OR-G4", "", "ERR(same publication)", g4_wm, "статья + '\\n' -> 2-й Source (O4)"),
    # new
    ("RR", "RR-01", "P1", "OK", rr_retired_after_close, "субъект RETIRED после закрытия Проверок"),
    ("RR", "RR-02a", "P1", "OK", rr_tag_pt, "PT-101 (лат.) и РТ-101 (кир.) — разные приборы"),
    ("RR", "RR-02b", "P1", "OK", rr_concept_yo, "понятия «небо» и «нёбо»"),
    ("RR", "RR-02c", "P1", "OK", rr_concept_case, "понятия «Орёл» (город) и «орёл» (птица)"),
    ("RR", "RR-02d", "P2", "OK", rr_concept_sup, "понятия «10²» и «102»"),
    ("OK", "V-14", "", "ENTITY_DUPLICATE_IN_PROJECT", rr_person_yo, "Лёвин/Левин без ИНН: слабый ключ склеивает (ожидаемо, снимается пометками)"),
    ("RR", "RR-03a", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_event_noplace, "то же событие с местом и без"),
    ("RR", "RR-03b", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_conflict_noplace, "тот же конфликт без места"),
    ("RR", "RR-03c", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_weak_one_mark, "дубль Ломова с disambiguator у одного"),
    ("RR", "RR-03h", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_invisible("\u034f"), "U+034F CGJ (Mn, невидим) в фамилии"),
    ("RR", "RR-03i", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_invisible("\ufe0f"), "U+FE0F VS16 (Mn, невидим) в фамилии"),
    ("RR", "RR-03j", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_invisible("\u03bf"), "греческая ο вместо о"),
    ("RR", "RR-03k", "P1", "ENTITY_DUPLICATE_IN_PROJECT", rr_invisible("\u3164"), "U+3164 Hangul filler (Lo, невидим)"),
    ("RR", "RR-03d", "P2", "ENTITY_DUPLICATE_IN_PROJECT", rr_registration, "регистрация RA-12345 / ra 12345"),
    ("RR", "RR-03e", "P2", "ENTITY_DUPLICATE_IN_PROJECT", rr_foreign_id, "HRB 12345 / HRB12345"),
    ("RR", "RR-03f", "P2", "ENTITY_DUPLICATE_IN_PROJECT", rr_tag_space, "тег Н-101 / Н101"),
    ("RR", "RR-03g", "P2", "ERR(duplicate)", rr_branch_as_head, "головная организация повторно как BRANCH"),
    ("RR", "RR-04", "P2", "OK", rr_ogrnip_only_namesakes, "два ИП-тёзки с разными ОГРНИП без ИНН"),
    ("RR", "RR-05a", "P1", "NO-CRASH", rr_deep_nesting, "вложенность 5000 (библиотека)"),
    ("RR", "RR-05b", "P1", "exit=1", rr_cli_deep, "CLI: вложенность 100000"),
    ("RR", "RR-05c", "P2", "exit=0", rr_cli_contentdir, "CLI: подкаталог в --content-dir"),
    ("OK", "V-15", "", "VALIDATOR_INTERNAL_ERROR", rr_content_str, "хранилище вернуло str: fail-closed"),
    ("RR", "RR-06", "P2", "OK", rr_trust_crosstenant_dup, "повтор key_id у другого tenant"),
    ("RR", "RR-07", "P2", "ERR(unverifiable node)", rr_graph_node_fake, "несуществующий узел графа"),
    ("RR", "RR-08a", "P2", "ERR(search scope)", rr_search_scope_any, "COURT «проверен» в кулинарном блоге"),
    ("RR", "RR-08b", "P2", "ERR(SOURCE_CONTENT_UNAVAILABLE)", rr_search_source_nobytes, "источник результата поиска без байтов"),
    ("RR", "RR-08c", "P2", "MARKING_BROADER_THAN_INPUT", rr_search_source_marking, "Проверка шире источника поиска"),
    ("RR", "RR-09", "P2", "ERR(time bound)", rr_status_changed_future, "status_changed_at = 2099"),
    ("RR", "RR-11", "P2", "ERR(IDENTIFIER_CHECKSUM_INVALID)", rr_ogrnip_literal, "литерал ru.ogrnip с неверной контрольной цифрой"),
    ("RR", "RR-12", "P2", "OK", rr_scheme_collision, "foreign_ids scheme 'equipment' = ключ насоса Н-101"),
    ("RR", "RR-13", "P1", "OK", rr_merge_into_retired, "выживший после слияния выведен из оборота"),
    ("RR", "RR-10", "P2", "OK", rr_literal_newline, "многострочный STRING-литерал"),
    # guards
    ("OK", "V-01", "", "SOURCE_DIGEST_MISMATCH", ok_store_swap, "в хранилище байты другого источника"),
    ("OK", "V-02", "", "SOURCE_DIGEST_MISMATCH", ok_inline_vs_store, "inline ≠ хранилище"),
    ("OK", "V-03", "", "RECEIPT_KEY_INVALID", rr_trust_empty, "пустой реестр доверия"),
    ("OK", "V-04", "", "RECEIPT_KEY_INVALID,TRUST_CONFIG_INVALID", rr_trust_broken, "битый реестр"),
    ("OK", "V-05", "", "RECEIPT_KEY_INVALID", rr_trust_other_tenant, "ключ другого tenant"),
    ("OK", "V-06", "", "OK", rr_trust_none_no_receipts, "без реестра и без receipt"),
    ("OK", "V-07", "", "RECEIPT_KEY_INVALID", ok_trust_revoked_eq, "revoked_at == issued_at"),
    ("OK", "V-08", "", "QUALIFIER_INVALID", ok_bool_int, "True как integer"),
    ("OK", "V-09", "", "EVIDENCE_SPAN_INVALID", ok_emoji_cut, "разрез эмодзи при верном sha"),
    ("OK", "V-10", "", "OK", ok_real_checksums, "реальные ИНН/ОГРН/ОГРНИП/IMO"),
    ("OK", "V-11", "", "ENTITY_DUPLICATE_IN_PROJECT", ok_fullwidth, "полноширинные формы"),
    ("OK", "V-12", "", "CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION", ok_retro_by_recorded, "reviewed_at до, recorded_at после"),
    ("OK", "V-13", "", "CHECK_SUBJECT_INVALID", ok_check_merged_before_close, "слияние до закрытия Проверки"),
]


def main():
    for sec, aid, sev, exp, fn, note in ATTACKS:
        row(sec, aid, exp, fn(), note, sev)
    run_jcs()
    if "--no-mutants" not in sys.argv:
        run_mutants()
    print(f"{'sec':<4} | {'id':<7} | {'sev':<3} | {'expected':<40} | {'got':<55} | verdict    | note")
    for s, a, sev, e, g, v, n in ROWS:
        print(f"{s:<4} | {a:<7} | {sev:<3} | {str(e)[:40]:<40} | {str(g)[:55]:<55} | {v:<10} | {n}")
    cnt = {}
    for r in ROWS:
        cnt[r[5]] = cnt.get(r[5], 0) + 1
    print("\n" + " ".join(f"{k}={v}" for k, v in sorted(cnt.items())) + f" total={len(ROWS)}")


if __name__ == "__main__":
    main()

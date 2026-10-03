"""Vectors for core-ontology/0.3: each negative vector must yield EXACTLY its expected error-code set;
each positive vector (expected == []) must be clean. pre(W) mutates the symbolic world before content
addresses/signatures are computed; post(ds, ix, env) tampers with the finished dataset, trust or content store.
"""
import copy
import hashlib

from fixtures import (world, finalize, SV, SV3, T, INN_DEV, OGRN_DEV, OGRN_TRUB, INN_TRUB, INN_LOMOV, OGRNIP_IP,
                      INT, PUB, CONF_PD, CONF_CS, CONF_CS_PD, srch, inn12, ogrnip)


def V(vid, codes, desc, pre=None, post=None, warn=None):
    """warn: expected list of warning codes (None = not checked)."""
    return {"id": vid, "expected": sorted(set(codes)), "desc": desc, "pre": pre, "post": post, "warn": warn}


def build(vec=None):
    """-> (dataset, trust, content)"""
    W = world()
    if vec and vec["pre"]:
        vec["pre"](W)
    ds, ix, trust, content = finalize(W)
    env = {"trust": trust, "content": content}
    if vec and vec["post"]:
        vec["post"](ds, ix, env)
    return ds, env["trust"], env["content"]


# ---------------- helpers ----------------

def art_in(x):
    """add an input to the NS-2 artifact as well (the artifact and its receipt must list the same inputs)"""
    return lambda W: W["__artifacts__"]["umr_ns2"]["inputs"].append(x)


def art_node(nid, key, value):
    def f(W):
        node = next(n for n in W["__artifacts__"]["umr_ns2"]["nodes"] if n["id"] == nid)
        if value is None:
            node.pop(key)
        else:
            node[key] = value
    return f


def rec(ds, ix, name):
    return ds["records"][ix[name]]


def seq(*fs):
    def run(*a):
        for f in fs:
            f(*a)
    return run


def setk(name, key, value):
    return lambda W: W[name].__setitem__(key, value)


def setid(name, key, value):
    return lambda W: W[name]["identity"].__setitem__(key, value)


def setq(name, key, value):
    return lambda W: W[name].setdefault("qualifiers", {}).__setitem__(key, value)


def pop(name, *path):
    def f(W):
        node = W[name]
        for p in path[:-1]:
            node = node[p]
        node.pop(path[-1])
    return f


def evp(name, fn):
    return setk(name, "_ev_patch", fn)


def add_entity(name, prj, etype, identity, marking=CONF_PD, status="ACTIVE", merged_into=None, changed=None):
    def f(W):
        r = {"kind": "Entity", "schema_version": SV, "entity_id": name, "project_id": prj, "entity_type": etype,
             "identity": identity, "display_name": name, "status": status, "created_at": "2026-09-05T12:00:00Z", "marking": marking}
        if merged_into:
            r["merged_into"] = merged_into
        if changed:
            r["status_changed_at"] = changed
        W[name] = r
    return f


def add_claim(name, prj, subj, pred, obj, ev, marking, recorded="2026-09-07T10:00:00Z", by=None, q=None):
    def f(W):
        r = {"kind": "Claim", "schema_version": SV, "project_id": prj, "subject": subj, "predicate": pred, "object": obj,
             "evidence": [{"$ev": list(ev)}], "produced_by": by or {"kind": "HUMAN", "actor_id": "usr_analyst1"},
             "recorded_at": recorded, "marking": marking}
        if q:
            r["qualifiers"] = q
        W[name] = r
    return f


def add_review(name, claim, status, at, rec_at):
    return lambda W: W.__setitem__(name, {"kind": "ClaimReview", "schema_version": SV, "review_id": name, "claim_id": "@C:" + claim,
                                          "status": status, "reviewer": "usr_reviewer1", "reviewed_at": at, "recorded_at": rec_at})


def add_source(name, text, tenant=T, marking=PUB, observed="2026-09-04T09:00:00Z"):
    return lambda W: W.__setitem__(name, {"kind": "Source", "schema_version": SV, "tenant_id": tenant, "source_kind": "DOCUMENT",
        "media_type": "text/plain; charset=utf-8", "language": "ru", "title": name, "content_inline": text, "marking": marking,
        "observations": [{"observed_at": observed, "origin_uri": f"urn:demo:{name}", "observed_by": "svc_webmon"}]})


def finding(dim, result, risk, claims, searches=None):
    return {"dimension": dim, "result": result, "risk": risk, "claim_ids": ["@C:" + c for c in claims],
            "searches": searches if searches is not None else []}


def add_finding(check, f):
    return lambda W: W[check]["findings"].append(f)


def trust0(fn):
    return lambda ds, ix, env: fn(env["trust"]["keys"][0])


_OTHER_PUB = __import__("fixtures").pub(hashlib.sha256(b"other-tenant-key").digest())


def _nest(n):
    x = []
    for _ in range(n):
        x = [x]
    return x


def sha(b):
    return hashlib.sha256(b).hexdigest()


def strip_inline(*names):
    def f(ds, ix, env):
        for n in names:
            rec(ds, ix, n).pop("content_inline")
    return f


def _inn12_bad11(p10):
    from fixtures import _ctl
    good = inn12(p10)
    d11 = str((int(good[10]) + 1) % 10)
    a = p10 + d11
    return a + _ctl(a, [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8])


def _cut_emoji(evs):
    evs[0]["span"]["start"] += 1
    evs[0].pop("quote")


EMOJI_SRC = "Кит 🐋 — крупнейшее животное."
S10_TEXT = "Синий кит — вид усатых китов. Длина синего кита достигает 30 метров, а масса — 150 тонн."
FS = "2026-09-25T10:00:00Z"


def _namesake(surname, given, patronymic, eid="ent_d_ns"):
    """a second person in the dossier with Ломов's name and birth date, without ИНН"""
    return add_entity(eid, "prj_dossier", "PERSON", {"surname": surname, "given_name": given, "patronymic": patronymic,
                                                     "birth_date": "1971-03-14"})


def _decision(did, prj, decision, **kw):
    def f(W):
        W[did] = {"kind": "IdentityDecision", "schema_version": SV, "decision_id": did, "project_id": prj, "decision": decision,
                  "decided_by": "usr_analyst1", "decided_at": "2026-09-06T11:00:00Z", **kw}
    return f


def _qualify(did, prj, eid, **field):
    return _decision(did, prj, "QUALIFY", entity_id=eid, **field)


def _distinct(did, prj, a, b):
    return _decision(did, prj, "DISTINCT", entity_ids=[a, b])


# ---------------- vectors ----------------

VECTORS = [
    # ===== phase 0/1: raw values, schema, calendar
    V("N001", ["SCHEMA_INVALID"], "дробное число (0.9) — только целые", post=lambda d, ix, e: rec(d, ix, "c2").__setitem__("confidence", 0.9)),
    V("N002", ["SCHEMA_INVALID"], "6000.0: для схемы integer, для JCS float", post=lambda d, ix, e: rec(d, ix, "c11")["qualifiers"].__setitem__("share_bp", 6000.0)),
    V("N003", ["SCHEMA_INVALID"], "целое 2^53", post=lambda d, ix, e: rec(d, ix, "c20")["qualifiers"].__setitem__("contract_amount_minor", 2**53)),
    V("N004", ["SCHEMA_INVALID"], "одиночный суррогат в значении", post=lambda d, ix, e: rec(d, ix, "c9")["object"]["literal"].__setitem__("value", "\ud800x")),
    V("N005", ["SCHEMA_INVALID"], "одиночный суррогат в ключе", post=lambda d, ix, e: rec(d, ix, "c9")["qualifiers"].__setitem__("\ud800", "x")),
    V("N006", ["SCHEMA_INVALID"], "VIN + перевод строки", post=lambda d, ix, e: rec(d, ix, "ent_d_car")["identity"].__setitem__("vin", "XTA210990Y1234567\n")),
    V("N007", ["SCHEMA_INVALID"], "несуществующая дата-время 2026-02-30", post=lambda d, ix, e: rec(d, ix, "prj_dossier").__setitem__("created_at", "2026-02-30T09:00:00Z")),
    V("N008", ["SCHEMA_INVALID"], "DATE-литерал 2026-02-30", pre=setk("c13", "object", {"literal": {"type": "DATE", "value": "2026-02-30"}})),
    V("N009", ["SCHEMA_INVALID"], "valid_from 2021-02-30", pre=setk("c10", "valid_from", "2021-02-30")),
    V("N010", ["SCHEMA_INVALID"], "ServiceKey в данных запрещён — ключи только в доверенном реестре",
      post=lambda d, ix, e: d["records"].append({"kind": "ServiceKey", "schema_version": SV, "key_id": "key_x"})),
    V("N011", ["SCHEMA_INVALID"], "ИНН через foreign_ids (зарезервированная схема)",
      pre=lambda W: W["ent_d_trub"]["identity"].__setitem__("foreign_ids", [{"scheme": "ru.inn", "value": "1234567890"}])),
    V("N012", ["SCHEMA_INVALID"], "управляющий символ в структурном поле", post=lambda d, ix, e: rec(d, ix, "ent_d_land")["identity"].__setitem__("address", "ул.\tЗаречная")),
    V("N013", ["SCHEMA_INVALID"], "строка из одних пробелов", pre=setk("ent_wk_blue", "display_name", "   ")),
    V("N014", ["SCHEMA_INVALID"], "CANCELLED с completed_at", pre=lambda W: W["chk_tenders_1"].update(status="CANCELLED", completed_at="2026-09-29T10:00:00Z", cancelled_at="2026-09-29T10:00:00Z")),
    # ===== trust configuration
    V("N020", ["TRUST_CONFIG_INVALID", "RECEIPT_KEY_INVALID"], "ключ в реестре доверия повторяется",
      post=lambda d, ix, e: e["trust"]["keys"].append(copy.deepcopy(e["trust"]["keys"][0]))),
    V("N021", ["TRUST_CONFIG_INVALID", "RECEIPT_KEY_INVALID"], "not_before >= not_after в реестре доверия", post=trust0(lambda k: k.__setitem__("not_before", k["not_after"]))),
    V("N022", ["TRUST_CONFIG_INVALID", "RECEIPT_KEY_INVALID"], "revoked_at < not_before", post=trust0(lambda k: k.__setitem__("revoked_at", "2026-08-01T00:00:00Z"))),
    V("N023", ["TRUST_CONFIG_INVALID", "RECEIPT_KEY_INVALID"], "реестр доверия не по схеме", post=trust0(lambda k: k.__setitem__("algorithm", "RSA"))),
    # ===== ids, references, scope
    V("N030", ["DUPLICATE_ID"], "сущность записана дважды", post=lambda d, ix, e: d["records"].append(copy.deepcopy(rec(d, ix, "ent_d_developer")))),
    V("N031", ["DUPLICATE_ID"], "Web Monitoring: та же статья вторым источником", post=lambda d, ix, e: d["records"].append(copy.deepcopy(rec(d, ix, "s2")))),
    V("N032", ["REF_UNRESOLVED"], "субъект утверждения неизвестен", pre=setk("c9", "subject", "ent_unknown_x")),
    V("N033", ["REF_UNRESOLVED"], "объект утверждения неизвестен", pre=setk("c15", "object", {"entity": "ent_unknown_x"})),
    V("N034", ["REF_UNRESOLVED"], "источник доказательства неизвестен", pre=evp("c24", lambda evs: evs[0].__setitem__("source_id", "src:sha256:" + "0" * 64))),
    V("N035", ["REF_UNRESOLVED"], "рецензия на неизвестное утверждение", pre=setk("rev_c13_a", "claim_id", "clm:sha256:" + "1" * 64)),
    V("N036", ["REF_UNRESOLVED"], "Проверка ссылается на неизвестное утверждение",
      pre=lambda W: W["chk_tenders_1"]["findings"].append({"dimension": "TENDERS", "result": "FOUND", "risk": "LOW", "claim_ids": ["clm:sha256:" + "2" * 64], "searches": []})),
    V("N037", ["REF_UNRESOLVED"], "неизвестная предыдущая Проверка", pre=setk("chk_tenders_1", "previous_check_id", "chk_nope")),
    V("N038", ["REF_UNRESOLVED"], "неизвестный субъект Проверки", pre=seq(setk("chk_tenders_1", "subject_entity_id", "ent_nope"), pop("chk_tenders_1", "previous_check_id"))),
    V("N039", ["REF_UNRESOLVED"], "неизвестный источник результата поиска",
      pre=lambda W: W["chk_social_lomov"]["findings"][0]["searches"][0].__setitem__("result_source_id", "src:sha256:" + "3" * 64)),
    V("N040", ["REF_UNRESOLVED"], "receipt: неизвестное утверждение", pre=lambda W: W["rcp_1"]["emitted_claim_ids"].append("clm:sha256:" + "4" * 64)),
    V("N041", ["REF_UNRESOLVED"], "receipt: неизвестный входной источник", pre=seq(lambda W: W["rcp_1"]["input_source_ids"].append("src:sha256:" + "5" * 64), art_in("src:sha256:" + "5" * 64))),
    V("N042", ["REF_UNRESOLVED"], "сущность неизвестного проекта", pre=add_entity("ent_orphan", "prj_nope", "CONCEPT", {"label": "Сирота", "lang": "ru"}, PUB)),
    V("N043", ["REF_UNRESOLVED"], "утверждение неизвестного проекта", pre=setk("c9", "project_id", "prj_nope")),
    V("N044", ["REF_UNRESOLVED"], "Проверка неизвестного проекта", pre=setk("chk_tenders_1", "project_id", "prj_nope")),
    V("N045", ["REF_UNRESOLVED", "RECEIPT_CLAIM_BINDING_INVALID"], "receipt неизвестного проекта: его утверждения остаются без receipt",
      pre=setk("rcp_1", "project_id", "prj_nope")),
    V("N046", ["CROSS_SCOPE_REFERENCE"], "субъект утверждения из другого проекта", pre=setk("c13", "subject", "ent_k_lomov")),
    V("N047", ["CROSS_SCOPE_REFERENCE"], "объект утверждения из другого проекта", pre=setk("c15", "object", {"entity": "ent_k_land"})),
    V("N048", ["CROSS_SCOPE_REFERENCE"], "источник другого tenant", pre=setk("s10", "tenant_id", "tnt_other")),
    V("N049", ["CROSS_SCOPE_REFERENCE"], "субъект Проверки из другого проекта", pre=seq(setk("chk_tenders_1", "subject_entity_id", "ent_d_developer"), pop("chk_tenders_1", "previous_check_id"))),
    V("N050", ["CROSS_SCOPE_REFERENCE"], "утверждение другого проекта в Проверке", pre=add_finding("chk_tenders_1", finding("TENDERS", "FOUND", "LOW", ["c15"]))),
    V("N051", ["CROSS_SCOPE_REFERENCE"], "источник результата поиска другого tenant",
      pre=seq(add_source("s99", "Чужой tenant.", tenant="tnt_other", marking=CONF_PD),
              lambda W: W["chk_social_lomov"]["findings"][0]["searches"][0].__setitem__("result_source_id", "@S:s99"))),
    V("N052", ["CROSS_SCOPE_REFERENCE"], "receipt: входной источник другого tenant",
      pre=seq(add_source("s99", "Чужой tenant.", tenant="tnt_other"), lambda W: W["rcp_1"]["input_source_ids"].append("@S:s99"), art_in("@S:s99"))),
    # ===== source bytes
    V("N060", ["SOURCE_DIGEST_MISMATCH"], "содержимое изменено после адресации",
      post=lambda d, ix, e: rec(d, ix, "s10").__setitem__("content_inline", rec(d, ix, "s10")["content_inline"][:-1] + "!")),
    V("N061", ["SOURCE_DIGEST_MISMATCH"], "byte_length не совпадает", pre=lambda W: W["s10"].__setitem__("byte_length", len(W["s10"]["content_inline"].encode()) + 1)),
    V("N062", ["SOURCE_DIGEST_MISMATCH"], "content_inline и хранилище расходятся",
      post=lambda d, ix, e: e["content"].__setitem__(rec(d, ix, "s10")["source_id"], b"other")),
    V("N063", ["SOURCE_DIGEST_MISMATCH"], "прод: в хранилище чужие байты", post=seq(strip_inline("s10"), lambda d, ix, e: e["content"].__setitem__(rec(d, ix, "s10")["source_id"], b"forged"))),
    V("N064", ["SOURCE_CONTENT_UNAVAILABLE"], "прод: байтов нет ни в данных, ни в хранилище",
      post=seq(strip_inline("s10"), lambda d, ix, e: e["content"].pop(rec(d, ix, "s10")["source_id"]))),
    V("N065", ["CLAIM_ID_MISMATCH"], "утверждение изменено без пересчёта id", post=lambda d, ix, e: rec(d, ix, "c9").__setitem__("recorded_at", "2026-09-06T11:00:00Z")),
    V("N066", ["RECEIPT_ID_MISMATCH"], "receipt изменён после подписи", post=lambda d, ix, e: rec(d, ix, "rcp_1")["emitted_claim_ids"].reverse()),
    # ===== identity: checksums and sufficiency
    V("N070", ["IDENTIFIER_CHECKSUM_INVALID"], "ИНН юрлица", pre=setid("ent_d_developer", "inn", INN_DEV[:9] + str((int(INN_DEV[9]) + 1) % 10))),
    V("N071", ["IDENTIFIER_CHECKSUM_INVALID"], "ОГРН", pre=setid("ent_d_trub", "ogrn", OGRN_TRUB[:12] + str((int(OGRN_TRUB[12]) + 1) % 10))),
    V("N072", ["IDENTIFIER_CHECKSUM_INVALID"], "ИНН-12: верна 11-я цифра, неверна 12-я", pre=setid("ent_d_lomov", "inn", INN_LOMOV[:11] + str((int(INN_LOMOV[11]) + 1) % 10))),
    V("N073", ["IDENTIFIER_CHECKSUM_INVALID"], "ИНН-12: неверна 11-я цифра", pre=setid("ent_d_lomov", "inn", _inn12_bad11("6952031418"))),
    V("N074", ["IDENTIFIER_CHECKSUM_INVALID"], "ОГРНИП", pre=setid("ent_d_ip", "ogrnip", OGRNIP_IP[:14] + str((int(OGRNIP_IP[14]) + 1) % 10))),
    V("N075", ["IDENTIFIER_CHECKSUM_INVALID"], "IMO", pre=add_entity("ent_d_ship", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VESSEL", "imo": "9074728", "description": "судно"})),
    V("N076", ["IDENTIFIER_CHECKSUM_INVALID"], "ИНН филиала", pre=setid("ent_d_trub_branch", "inn", INN_TRUB[:9] + str((int(INN_TRUB[9]) + 1) % 10))),
    V("P077", [], "IMO с верной контрольной цифрой", pre=add_entity("ent_d_ship", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VESSEL", "imo": "9074729", "description": "судно"})),
    V("N078", ["ENTITY_IDENTITY_INSUFFICIENT"], "организация РФ без ОГРН и ИНН", pre=lambda W: [W["ent_w_developer"]["identity"].pop(k) for k in ("ogrn", "inn")]),
    V("N079", ["ENTITY_IDENTITY_INSUFFICIENT"], "физлицо без ИНН, даты и disambiguator", pre=pop("ent_c_grachyova", "identity", "disambiguator")),
    V("N080", ["ENTITY_IDENTITY_INSUFFICIENT"], "неформальная организация с ИНН", pre=setid("ent_w_initiative", "inn", INN_DEV)),
    V("N081", ["ENTITY_IDENTITY_INSUFFICIENT"], "неформальная организация без disambiguator", pre=pop("ent_w_initiative", "identity", "disambiguator")),
    V("N082", ["ENTITY_IDENTITY_INSUFFICIENT"], "неформальная организация с legal_form", pre=setid("ent_w_initiative", "legal_form", "LEGAL_ENTITY")),
    V("N083", ["ENTITY_IDENTITY_INSUFFICIENT"], "филиал без КПП", pre=pop("ent_d_trub_branch", "identity", "kpp")),
    V("N084", ["ENTITY_IDENTITY_INSUFFICIENT"], "филиал с ОГРН", pre=setid("ent_d_trub_branch", "ogrn", OGRN_TRUB)),
    V("N085", ["ENTITY_IDENTITY_INSUFFICIENT"], "иностранная организация без идентификатора", pre=add_entity("ent_d_kz", "prj_dossier", "ORGANIZATION", {"name": "ТОО «Степь»", "jurisdiction": "KZ"})),
    V("P086", [], "иностранная организация с foreign_ids", pre=add_entity("ent_d_kz", "prj_dossier", "ORGANIZATION", {"name": "ТОО «Степь»", "jurisdiction": "KZ", "foreign_ids": [{"scheme": "kz.bin", "value": "123456789012"}]})),
    V("N087", ["ENTITY_IDENTITY_INSUFFICIENT"], "автомобиль без VIN (только регистрация)", pre=lambda W: (W["ent_d_car"]["identity"].pop("vin"), W["ent_d_car"]["identity"].__setitem__("registration", {"scheme": "ru.grz", "value": "А123ВС50"}))),
    V("N088", ["ENTITY_IDENTITY_INSUFFICIENT"], "имущество OTHER без идентификатора", pre=add_entity("ent_d_other", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "OTHER", "description": "станок"})),
    V("P089", [], "имущество OTHER с регистрацией", pre=add_entity("ent_d_other", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "OTHER", "description": "станок", "registration": {"scheme": "ru.gtn", "value": "77-01-123"}})),
    # ===== uniqueness in project
    V("N090", ["ENTITY_DUPLICATE_IN_PROJECT"], "вторая организация с тем же ИНН", pre=add_entity("ent_d_dev2", "prj_dossier", "ORGANIZATION", {"name": "Заречье Девелопмент", "jurisdiction": "RU", "inn": INN_DEV})),
    V("N091", ["ENTITY_DUPLICATE_IN_PROJECT"], "вторая организация с тем же ОГРН", pre=add_entity("ent_d_dev2", "prj_dossier", "ORGANIZATION", {"name": "Заречье Девелопмент", "jurisdiction": "RU", "ogrn": OGRN_DEV})),
    V("N092", ["ENTITY_DUPLICATE_IN_PROJECT"], "«ЛОМОВ … Семенович» (регистр, ё/е) + та же дата, без ИНН",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "ЛОМОВ", "given_name": "Аркадий", "patronymic": "Семенович", "birth_date": "1971-03-14"})),
    V("N093", ["ENTITY_DUPLICATE_IN_PROJECT"], "латинская «o» в фамилии", pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Лoмов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"})),
    V("P094", [], "латинская «H» в теге: теги PT-101/РТ-101 бывают разными приборами — только предупреждение (RR-02)",
      pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101"}, INT),
      warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("N095", ["ENTITY_DUPLICATE_IN_PROJECT"], "неразрывный дефис U+2011 в теге", pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н‑101"}, INT)),
    V("N096", ["ENTITY_DUPLICATE_IN_PROJECT"], "U+200B внутри тега", pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-\u200B101"}, INT)),
    V("N097", ["ENTITY_DUPLICATE_IN_PROJECT"], "полноширинные символы (NFKC)", pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н\uFF0D\uFF11\uFF10\uFF11"}, INT)),
    V("N098", ["ENTITY_DUPLICATE_IN_PROJECT"], "лишние пробелы", pre=add_entity("ent_ts_st2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": " НС-2  "}, INT)),
    V("N099", ["ENTITY_DUPLICATE_IN_PROJECT"], "кавычки \"\" вместо «»", pre=add_entity("ent_w_init2", "prj_wm_region", "ORGANIZATION", {"name": "Инициативная группа \"Заречная, 12\"", "jurisdiction": "RU", "informal": True, "disambiguator": "zarechnaya-12"}, PUB)),
    V("N100", ["ENTITY_DUPLICATE_IN_PROJECT"], "кадастровый :245 и :0245", pre=add_entity("ent_d_land2", "prj_dossier", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:0245", "address": "то же"})),
    V("N101", ["ENTITY_DUPLICATE_IN_PROJECT"], "ИНН слитого дубля занят новой ACTIVE сущностью",
      pre=seq(lambda W: W["ent_d_lomov_media"]["identity"].__setitem__("inn", inn12("5000000001")),
              add_entity("ent_d_new", "prj_dossier", "PERSON", {"surname": "Новиков", "given_name": "Олег", "inn": inn12("5000000001")}))),
    V("N102", ["ENTITY_DUPLICATE_IN_PROJECT"], "ИНН RETIRED сущности занят новой",
      pre=seq(lambda W: W["ent_d_trub"].update(status="RETIRED", status_changed_at="2026-09-06T00:00:00Z"),
              add_entity("ent_d_trub2", "prj_dossier", "ORGANIZATION", {"name": "ООО «Трубопрокат-2»", "jurisdiction": "RU", "inn": INN_TRUB}))),
    V("N103", ["ENTITY_DUPLICATE_IN_PROJECT"], "тёзка с той же датой: у одного нет ИНН",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14", "ogrnip": ogrnip("32650120000999")})),
    V("P104", [], "тёзки с одной датой рождения и разными ИНН",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14", "inn": inn12("7707123450")})),
    V("P105", [], "два одноимённых события в один день в разных местах",
      pre=seq(add_entity("ent_c_rally1", "prj_conflict_land", "EVENT", {"title": "Митинг против застройки", "date": "2026-09-20", "place": "г. Заречный"}),
              add_entity("ent_c_rally2", "prj_conflict_land", "EVENT", {"title": "Митинг против застройки", "date": "2026-09-20", "place": "г. Подольск"}))),
    V("N106", ["ENTITY_DUPLICATE_IN_PROJECT"], "одноимённые события в один день в одном месте",
      pre=seq(add_entity("ent_c_rally1", "prj_conflict_land", "EVENT", {"title": "Митинг против застройки", "date": "2026-09-20", "place": "г. Заречный"}),
              add_entity("ent_c_rally2", "prj_conflict_land", "EVENT", {"title": "Митинг  против застройки", "date": "2026-09-20", "place": "г.Заречный".replace(".", ". ")}))),
    V("N107", ["ENTITY_DUPLICATE_IN_PROJECT"], "филиал с тем же ИНН+КПП",
      pre=add_entity("ent_d_branch2", "prj_dossier", "ORGANIZATION", {"name": "Филиал-2", "jurisdiction": "RU", "legal_form": "BRANCH", "inn": INN_TRUB, "kpp": "290145001"})),
    V("N108", ["ENTITY_DUPLICATE_IN_PROJECT"], "модель оборудования записана дважды", pre=add_entity("ent_ts_model2", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "\"НасосМаш\"", "model": "HM 16-100"}, INT)),
    V("N109", ["ENTITY_DUPLICATE_IN_PROJECT"], "понятие записано дважды", pre=add_entity("ent_wk_blue2", "prj_wiki_whales", "CONCEPT", {"label": "синий  КИТ", "lang": "ru", "namespace": "whales"}, PUB)),
    V("N110", ["ENTITY_DUPLICATE_IN_PROJECT"], "конфликт записан дважды", pre=add_entity("ent_c_conf2", "prj_conflict_land", "CONFLICT", {"title": "застройка участка на ул. Заречной", "started_on": "2026-09-02", "place": "г. Заречный"})),
    V("N111", ["ENTITY_DUPLICATE_IN_PROJECT"], "второй автомобиль с тем же VIN", pre=add_entity("ent_d_car2", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VEHICLE", "vin": "XTA210990Y1234567", "description": "то же"})),
    V("N112", ["ENTITY_DUPLICATE_IN_PROJECT"], "второе физлицо с тем же ОГРНИП", pre=add_entity("ent_d_ip2", "prj_dossier", "PERSON", {"surname": "Иванова", "given_name": "Ирина", "ogrnip": OGRNIP_IP})),
    V("N113", ["ENTITY_DUPLICATE_IN_PROJECT"], "две неформальные «слабые» персоны с одним disambiguator", pre=add_entity("ent_c_lomov2", "prj_conflict_land", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "disambiguator": "director-zarechye"})),
    V("P114", [], "та же организация в двух проектах — не дубль (проекты изолированы)", pre=None),
    # ===== merges
    V("N120", ["ENTITY_MERGE_INVALID"], "слияние физлица в организацию", pre=setk("ent_d_lomov_media", "merged_into", "ent_d_developer")),
    V("N121", ["ENTITY_MERGE_INVALID"], "слияние в сущность другого проекта", pre=setk("ent_d_lomov_media", "merged_into", "ent_k_lomov")),
    V("N122", ["ENTITY_MERGE_INVALID"], "цепочка слияний", pre=seq(add_entity("ent_d_x", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "А.", "disambiguator": "chain"}, status="MERGED", merged_into="ent_d_lomov_media", changed="2026-09-06T16:00:00Z"))),
    V("N123", ["ENTITY_MERGE_INVALID"], "слияние в неизвестную сущность", pre=setk("ent_d_lomov_media", "merged_into", "ent_nope")),
    V("N124", ["TEMPORAL_ORDER_INVALID"], "статус изменён раньше создания", pre=setk("ent_d_lomov_media", "status_changed_at", "2026-09-01T00:00:00Z")),
    # ===== predicates, literals, qualifiers
    V("N130", ["PREDICATE_UNKNOWN"], "предикат вне реестра", pre=setk("c26", "predicate", "wiki.mass")),
    V("N131", ["PREDICATE_DOMAIN_VIOLATION"], "организация как руководитель", pre=setk("c10", "subject", "ent_d_trub")),
    V("N132", ["PREDICATE_RANGE_VIOLATION"], "дата рождения строкой", pre=setk("c13", "object", {"literal": {"type": "STRING", "value": "14.03.1971"}})),
    V("N133", ["PREDICATE_RANGE_VIOLATION"], "владеет организацией (тип объекта)", pre=setk("c15", "object", {"entity": "ent_d_trub"})),
    V("N134", ["PREDICATE_RANGE_VIOLATION"], "сущность там, где нужен литерал", pre=setk("c13", "object", {"entity": "ent_d_developer"})),
    V("N135", ["PREDICATE_RANGE_VIOLATION"], "литерал там, где нужна сущность", pre=setk("c15", "object", {"literal": {"type": "STRING", "value": "участок"}})),
    V("N136", ["PREDICATE_RANGE_VIOLATION"], "номер дела со схемой telegram", pre=lambda W: W["c19"]["object"]["literal"].__setitem__("scheme", "telegram")),
    V("N137", ["PREDICATE_RANGE_VIOLATION", "GRAPH_NODE_INVALID"], "единица вне списка предиката (lx)", pre=lambda W: W["c2"]["object"]["literal"].__setitem__("unit", "lx")),
    V("N138", ["QUALIFIER_INVALID"], "доля 120%", pre=setq("c11", "share_bp", 12000)),
    V("N139", ["QUALIFIER_INVALID"], "доля 0", pre=setq("c11", "share_bp", 0)),
    V("P140", [], "доля ровно 100% и 0,01%", pre=seq(setq("c11", "share_bp", 10000), setq("c12", "share_bp", 1))),
    V("N141", ["QUALIFIER_INVALID"], "enum вне списка", pre=setq("c18", "severity", "EXTREME")),
    V("N142", ["QUALIFIER_INVALID"], "True как integer", pre=setq("c11", "share_bp", True)),
    V("N143", ["QUALIFIER_INVALID"], "1 как boolean", pre=setq("c7b", "explicit", 1)),
    V("N144", ["QUALIFIER_INVALID"], "необъявленный квалификатор", pre=setq("c13", "x", "y")),
    V("N145", ["QUALIFIER_INVALID", "GRAPH_NODE_INVALID"], "строковый квалификатор из пробела", pre=setq("c2", "parameter", " ")),
    V("N146", ["QUALIFIER_INVALID", "GRAPH_NODE_INVALID"], "нет обязательного квалификатора", pre=pop("c2", "qualifiers")),
    V("N147", ["QUALIFIER_INVALID"], "строка вместо boolean", pre=setq("c7b", "explicit", "true")),
    # ===== time
    V("N150", ["TEMPORAL_ORDER_INVALID"], "valid_from позже valid_to", pre=setk("c17", "valid_to", "2024-01-01")),
    V("N151", ["TEMPORAL_ORDER_INVALID"], "утверждение раньше первого получения источника", pre=setk("c21", "recorded_at", "2026-09-04T10:00:00Z")),
    V("N152", ["TEMPORAL_ORDER_INVALID"], "рецензия раньше записи утверждения", pre=lambda W: W["rev_c18_a"].update(reviewed_at="2026-09-06T00:00:00Z")),
    V("N153", ["TEMPORAL_ORDER_INVALID"], "рецензия записана раньше, чем принята", pre=lambda W: W["rev_c13_a"].update(recorded_at="2026-09-07T08:00:00Z")),
    V("N154", ["TEMPORAL_ORDER_INVALID", "CHECK_SEARCH_MISSING"], "Проверка завершена раньше запроса (окно поиска пусто)", pre=setk("chk_full_1", "completed_at", "2026-09-25T07:00:00Z")),
    V("N155", ["TEMPORAL_ORDER_INVALID"], "as_of позже завершения", pre=setk("chk_express_1", "as_of", "2026-09-11")),
    V("N156", ["TEMPORAL_ORDER_INVALID"], "отменена раньше запроса", pre=lambda W: W["chk_tenders_1"].update(status="CANCELLED", cancelled_at="2026-09-29T08:00:00Z")),
    # ===== evidence spans
    V("N160", ["EVIDENCE_SPAN_INVALID"], "фрагмент за пределами источника", pre=evp("c24", lambda evs: evs[0]["span"].__setitem__("end", 10_000))),
    V("N161", ["EVIDENCE_SPAN_INVALID"], "фрагмент нулевой длины", pre=evp("c25", lambda evs: evs[0]["span"].__setitem__("end", evs[0]["span"]["start"]))),
    V("N162", ["EVIDENCE_SPAN_INVALID"], "граница режет эмодзи, sha совпадает с разрезанными байтами",
      pre=seq(add_source("s_emoji", EMOJI_SRC), add_claim("c_emoji", "prj_wiki_whales", "ent_wk_blue", "wiki.property", {"literal": {"type": "STRING", "value": "крупнейшее"}},
              ("s_emoji", "🐋 — крупнейшее"), PUB, "2026-09-05T00:00:00Z", q={"property": "rank"}),
              evp("c_emoji", lambda evs: (evs[0]["span"].__setitem__("start", evs[0]["span"]["start"] + 1), evs[0].pop("quote"),
                                           evs[0].__setitem__("quote_sha256", sha(EMOJI_SRC.encode()[evs[0]["span"]["start"]:evs[0]["span"]["end"]])))))),
    V("P163", [], "фрагмент ровно по эмодзи",
      pre=seq(add_source("s_emoji", EMOJI_SRC), add_claim("c_emoji", "prj_wiki_whales", "ent_wk_blue", "wiki.property", {"literal": {"type": "STRING", "value": "крупнейшее"}},
              ("s_emoji", "🐋 — крупнейшее"), PUB, "2026-09-05T00:00:00Z", q={"property": "rank"}))),
    V("N164", ["EVIDENCE_SPAN_INVALID"], "quote_sha256 не совпадает", pre=evp("c24", lambda evs: evs[0].__setitem__("quote_sha256", sha("другое".encode())))),
    V("N165", ["EVIDENCE_SPAN_INVALID"], "quote не совпадает при верном sha", pre=evp("c24", lambda evs: evs[0].__setitem__("quote", "вид хищных китов"))),
    V("N166", ["EVIDENCE_SPAN_INVALID"], "прод: подложная цитата, байты из хранилища",
      pre=evp("c24", lambda evs: evs[0].__setitem__("quote", "вид хищных китов")), post=strip_inline("s10")),
    V("P167", [], "прод: все источники без content_inline, байты из хранилища",
      post=lambda d, ix, e: [r.pop("content_inline") for r in d["records"] if r["kind"] == "Source"]),
    # ===== markings
    V("N170", ["MARKING_BROADER_THAN_INPUT"], "PUBLIC-утверждение из INTERNAL-документа", pre=setk("c1", "marking", PUB)),
    V("N171", ["MARKING_BROADER_THAN_INPUT"], "утверждение о физлице без PERSONAL_DATA (шире сущности)", pre=setk("c6", "marking", INT)),
    V("N172", ["MARKING_BROADER_THAN_INPUT"], "PUBLIC-утверждение о CONFIDENTIAL-сущности (субъект)",
      pre=seq(setk("ent_wk_baleen", "marking", CONF_CS), setk("c24", "marking", PUB), setk("ent_wk_blue", "marking", PUB))),
    V("N173", ["MARKING_BROADER_THAN_INPUT"], "утверждение шире сущности-объекта", pre=setk("ent_wk_baleen", "marking", CONF_CS)),
    V("N173b", ["MARKING_BROADER_THAN_INPUT"], "утверждение шире сущности, которая в мире бывает ТОЛЬКО объектом "
      "(с цикла 9 «Усатые киты» — ещё и субъект schema.is_a, поэтому N172/N173 больше не отличали проверку объекта от проверки субъекта)",
      pre=seq(add_entity("ent_wk_cetacea", "prj_wiki_whales", "CONCEPT", {"label": "Китообразные", "lang": "ru", "namespace": "whales"}, CONF_CS),
              add_claim("c_obj_only", "prj_wiki_whales", "ent_wk_blue", "wiki.is_a", {"entity": "ent_wk_cetacea"}, ("s10", "Синий кит"), PUB))),
    V("N174", ["MARKING_BROADER_THAN_INPUT"], "Проверка шире утверждения", pre=seq(setk("chk_full_1", "marking", CONF_CS), pop("chk_full_1", "previous_check_id"))),
    V("N175", ["MARKING_BROADER_THAN_INPUT"], "Проверка по физлицу без PERSONAL_DATA", pre=setk("chk_social_lomov", "marking", CONF_CS)),
    V("N176", ["MARKING_PD_MISSING"], "физлицо без PERSONAL_DATA", pre=lambda W: (W["ent_c_grachyova"].__setitem__("marking", INT))),
    # ===== reviews
    V("N180", ["CLAIM_REVIEW_AMBIGUOUS"], "ACCEPTED и DISPUTED записаны в одну секунду",
      pre=seq(add_review("rev_c9_a", "c9", "ACCEPTED", "2026-09-08T10:00:00Z", "2026-09-08T10:05:00Z"),
              add_review("rev_c9_d", "c9", "DISPUTED", "2026-09-08T10:01:00Z", "2026-09-08T10:05:00Z"))),
    V("P181", [], "одинаковое заявленное время, разное время записи — порядок однозначен",
      pre=seq(add_review("rev_c9_a", "c9", "ACCEPTED", "2026-09-08T10:00:00Z", "2026-09-08T10:05:00Z"),
              add_review("rev_c9_d", "c9", "DISPUTED", "2026-09-08T10:00:00Z", "2026-09-08T10:06:00Z"))),
    # ===== Check
    V("N190", ["CHECK_PROJECT_NOT_COMPLIANCE"], "Проверка в проекте Dossier",
      pre=lambda W: W.__setitem__("chk_wrong", {**{k: v for k, v in copy.deepcopy(W["chk_tenders_1"]).items() if k != "previous_check_id"},
            "check_id": "chk_wrong", "project_id": "prj_dossier", "subject_entity_id": "ent_d_developer", "marking": CONF_PD})),
    V("N191", ["CHECK_SUBJECT_INVALID"], "субъект — земельный участок", pre=seq(setk("chk_tenders_1", "subject_entity_id", "ent_k_land"), pop("chk_tenders_1", "previous_check_id"))),
    V("N192", ["CHECK_SUBJECT_INVALID"], "идущая Проверка по слитому субъекту",
      pre=seq(add_entity("ent_k_dev_new", "prj_compliance", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", "inn": INN_DEV}, CONF_CS),
              lambda W: W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_new", status_changed_at="2026-09-28T00:00:00Z"))),
    V("P193", [], "слияние субъекта ПОСЛЕ завершённых Проверок; идущая Проверка — на выжившей сущности",
      pre=seq(add_entity("ent_k_dev_new", "prj_compliance", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", "inn": INN_DEV}, CONF_CS),
              lambda W: W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_new", status_changed_at="2026-09-28T00:00:00Z"),
              setk("chk_tenders_1", "subject_entity_id", "ent_k_dev_new"))),
    V("N194", ["CHECK_SUBJECT_INVALID"], "завершённая Проверка по субъекту, слитому ДО завершения",
      pre=seq(add_entity("ent_k_dev_new", "prj_compliance", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", "inn": INN_DEV}, CONF_CS),
              lambda W: W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_new", status_changed_at="2026-09-26T00:00:00Z"),
              setk("chk_tenders_1", "subject_entity_id", "ent_k_dev_new"))),
    V("N195", ["CHECK_DIMENSION_OUTSIDE_PROFILE"], "в «только тендеры» — негатив", pre=add_finding("chk_tenders_1", finding("NEGATIVE", "FOUND", "MEDIUM", ["c18"]))),
    V("N196", ["CHECK_DIMENSION_MISSING"], "полная Проверка без судов", pre=lambda W: W["chk_full_1"].__setitem__("findings", [f for f in W["chk_full_1"]["findings"] if f["dimension"] != "COURT"])),
    V("P197", [], "отменённая Проверка без измерений и поисков", pre=lambda W: W["chk_tenders_1"].update(status="CANCELLED", cancelled_at="2026-09-29T10:00:00Z")),
    V("N198", ["CHECK_FINDING_INCONSISTENT"], "FOUND без утверждений", pre=lambda W: W["chk_full_1"]["findings"][2].__setitem__("claim_ids", [])),
    V("N199", ["CHECK_FINDING_INCONSISTENT"], "NOT_FOUND с утверждениями", pre=lambda W: W["chk_full_1"]["findings"][2].__setitem__("result", "NOT_FOUND")),
    V("N200", ["CHECK_FINDING_INCONSISTENT"], "NOT_FOUND с риском", pre=lambda W: W["chk_social_lomov"]["findings"][0].__setitem__("risk", "LOW")),
    V("N201", ["CHECK_FINDING_INCONSISTENT"], "повтор измерения", pre=lambda W: W["chk_express_1"]["findings"].append(copy.deepcopy(W["chk_express_1"]["findings"][0]))),
    V("N202", ["CHECK_FINDING_INCONSISTENT"], "итоговый риск не равен максимуму", pre=setk("chk_express_1", "overall_risk", "HIGH")),
    V("N203", ["CHECK_SEARCH_MISSING"], "результат без следа поиска", pre=lambda W: W["chk_social_lomov"]["findings"][0].__setitem__("searches", [])),
    V("N204", ["CHECK_SEARCH_MISSING"], "поиск после завершения", pre=lambda W: W["chk_express_1"]["findings"][0]["searches"][0].__setitem__("performed_at", "2026-09-10T12:00:01Z")),
    V("N205", ["CHECK_SEARCH_MISSING"], "поиск до запроса", pre=lambda W: W["chk_express_1"]["findings"][0]["searches"][0].__setitem__("performed_at", "2026-09-10T07:59:59Z")),
    V("P206", [], "поиск ровно в момент запроса и ровно в момент завершения",
      pre=seq(lambda W: W["chk_express_1"]["findings"][0]["searches"].__setitem__(0, srch("СМИ", "x", "2026-09-10T08:00:00Z")),
              lambda W: W["chk_social_lomov"]["findings"][0]["searches"][0].__setitem__("performed_at", "2026-09-27T12:00:00Z"))),
    V("N207", ["CHECK_CLAIM_NOT_ABOUT_SUBJECT"], "Проверка физлица включает тендер организации",
      pre=seq(setk("chk_tenders_1", "subject_entity_id", "ent_k_lomov"), pop("chk_tenders_1", "previous_check_id"),
              add_finding("chk_tenders_1", finding("TENDERS", "FOUND", "LOW", ["c20"])))),
    V("P208", [], "утверждение о слитом дубле субъекта засчитывается субъекту",
      pre=seq(add_entity("ent_k_dev_media", "prj_compliance", "ORGANIZATION", {"name": "Заречье-Девелопмент (СМИ)", "jurisdiction": "RU", "inn": INN_DEV}, CONF_CS,
                         status="MERGED", merged_into="ent_k_developer", changed="2026-09-06T00:00:00Z"),
              setk("c21", "subject", "ent_k_dev_media"))),
    V("N209", ["CHECK_CLAIM_DIMENSION_MISMATCH"], "негатив в измерении «тендеры»", pre=add_finding("chk_tenders_1", finding("TENDERS", "FOUND", "LOW", ["c18"]))),
    V("N210", ["CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION"], "принятие задним числом: заявлено до, записано после завершения",
      pre=lambda W: W["rev_c18_a"].update(reviewed_at="2026-09-10T11:59:00Z", recorded_at="2026-09-10T12:00:01Z")),
    V("P211", [], "ACCEPTED записан ровно в момент завершения", pre=lambda W: W["rev_c18_a"].update(reviewed_at="2026-09-10T11:59:00Z", recorded_at="2026-09-10T12:00:00Z")),
    V("N212", ["CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION"], "утверждение без рецензии", pre=lambda W: W.pop("rev_c21_a")),
    V("N213", ["CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION"], "последний статус на момент завершения — DISPUTED",
      pre=add_review("rev_c21_d", "c21", "DISPUTED", "2026-09-21T10:00:00Z", "2026-09-21T10:05:00Z")),
    V("P214", [], "оспаривание после завершения не меняет завершённую Проверку (база) — без него то же", pre=lambda W: W.pop("rev_c20_d")),
    V("N215", ["CHECK_PREVIOUS_INVALID"], "предыдущая Проверка позже текущей", pre=setk("chk_express_1", "previous_check_id", "chk_full_1")),
    V("N216", ["CHECK_PREVIOUS_INVALID"], "предыдущая Проверка по другому субъекту", pre=setk("chk_social_lomov", "previous_check_id", "chk_express_1")),
    V("N217", ["CHECK_PREVIOUS_INVALID", "CHECK_PROJECT_NOT_COMPLIANCE"], "предыдущая Проверка из другого проекта",
      pre=seq(lambda W: W.__setitem__("chk_other", {**{k: v for k, v in copy.deepcopy(W["chk_tenders_1"]).items() if k != "previous_check_id"},
              "check_id": "chk_other", "project_id": "prj_dossier", "subject_entity_id": "ent_d_developer", "as_of": "2026-09-01", "marking": CONF_PD}),
              setk("chk_express_1", "previous_check_id", "chk_other"))),
    V("N218", ["CHECK_PREVIOUS_INVALID"], "предыдущая Проверка — она сама", pre=setk("chk_express_1", "previous_check_id", "chk_express_1")),
    # ===== receipts and trust
    V("N230", ["RECEIPT_SIGNATURE_INVALID"], "подпись незарегистрированным ключом", pre=setk("rcp_1", "_sign_seed", "OTHER")),
    V("N231", ["RECEIPT_KEY_INVALID"], "ключ отозван до выдачи", post=trust0(lambda k: k.__setitem__("revoked_at", "2026-09-06T09:00:00Z"))),
    V("N232", ["RECEIPT_KEY_INVALID"], "ключ отозван в момент выдачи", post=trust0(lambda k: k.__setitem__("revoked_at", "2026-09-06T10:00:00Z"))),
    V("P233", [], "ключ отозван после выдачи", post=trust0(lambda k: k.__setitem__("revoked_at", "2026-09-06T10:00:01Z"))),
    V("N234", ["RECEIPT_KEY_INVALID"], "issued_at == not_after", post=trust0(lambda k: k.__setitem__("not_after", "2026-09-06T10:00:00Z"))),
    V("P235", [], "issued_at = not_after − 1 с", post=trust0(lambda k: k.__setitem__("not_after", "2026-09-06T10:00:01Z"))),
    V("N236", ["RECEIPT_KEY_INVALID"], "issued_at раньше not_before", post=trust0(lambda k: k.__setitem__("not_before", "2026-09-06T10:00:01Z"))),
    V("P237", [], "issued_at == not_before", post=trust0(lambda k: k.__setitem__("not_before", "2026-09-06T10:00:00Z"))),
    V("N238", ["RECEIPT_KEY_INVALID"], "ключ другой службы", post=trust0(lambda k: k.__setitem__("service_id", "svc_other"))),
    V("N239", ["RECEIPT_KEY_INVALID"], "ключ другого tenant", post=trust0(lambda k: k.__setitem__("tenant_id", "tnt_other"))),
    V("N240", ["RECEIPT_KEY_INVALID"], "реестр доверия пуст (ключ из данных не признаётся)", post=lambda d, ix, e: e["trust"].__setitem__("keys", [])),
    V("N241", ["RECEIPT_CLAIM_BINDING_INVALID"], "PIPELINE-утверждение вне receipt", pre=lambda W: W["rcp_1"]["emitted_claim_ids"].remove("@C:c3")),
    V("N242", ["RECEIPT_CLAIM_BINDING_INVALID", "ARTIFACT_INVALID"], "утверждение в двух receipt (одного запуска)",
      pre=lambda W: W.__setitem__("rcp_2", {**copy.deepcopy(W["rcp_1"]), "issued_at": "2026-09-06T10:00:05Z"})),
    V("N243", ["RECEIPT_CLAIM_BINDING_INVALID"], "HUMAN-утверждение в receipt",
      pre=seq(add_claim("c31", "prj_ts_pumps", "ent_ts_pump", "ts.part_of", {"entity": "ent_ts_station"}, ("s1", "входит в состав"), INT, "2026-09-06T09:00:00Z"),
              lambda W: W["rcp_1"]["emitted_claim_ids"].append("@C:c31"))),
    V("N244", ["RECEIPT_CLAIM_BINDING_INVALID"], "другой run_id", pre=lambda W: W["c3"]["produced_by"].__setitem__("run_id", "run_ts_0002")),
    V("N245", ["RECEIPT_CLAIM_BINDING_INVALID"], "другая служба", pre=lambda W: W["c3"]["produced_by"].__setitem__("service_id", "svc_other")),
    V("N246", ["RECEIPT_CLAIM_BINDING_INVALID", "GRAPH_NODE_INVALID"], "утверждение другого проекта в receipt (и без узла графа)",
      pre=seq(lambda W: W["c26"].__setitem__("produced_by", {"kind": "PIPELINE", "service_id": "svc_techsense", "run_id": "run_ts_0001"}),
              lambda W: W["rcp_1"]["emitted_claim_ids"].append("@C:c26"), lambda W: W["rcp_1"]["input_source_ids"].append("@S:s10"),
              art_in("@S:s10"))),
    V("N247", ["RECEIPT_CLAIM_BINDING_INVALID"], "утверждение записано после выдачи receipt", pre=setk("c3", "recorded_at", "2026-09-06T10:00:01Z")),
    V("P248", [], "утверждение записано ровно в момент выдачи", pre=setk("c3", "recorded_at", "2026-09-06T10:00:00Z")),
    V("N249", ["RECEIPT_CLAIM_BINDING_INVALID", "GRAPH_NODE_INVALID"], "источник доказательства не во входах receipt (и без узла)", pre=lambda W: W["c3"]["evidence"].append({"$ev": ["s2", "работы начнутся весной"]})),
    V("N250", ["RECEIPT_CLAIM_BINDING_INVALID"], "узел графа из другого артефакта",
      pre=lambda W: W["c2"]["evidence"][0]["graph_node"].__setitem__("artifact_digest", "sha256:" + "6" * 64)),
    V("N251", ["RECEIPT_CLAIM_BINDING_INVALID"], "узел графа у HUMAN-утверждения",
      pre=lambda W: W["c24"]["evidence"][0].__setitem__("graph_node", {"artifact_digest": "sha256:" + "7" * 64, "node_id": "n1"})),
]

VECTORS += [
    V("P115", [], "тёзки с одной датой рождения без ИНН, но с разными disambiguator (аналитик их различил)",
      pre=seq(add_entity("ent_d_n1", "prj_dossier", "PERSON", {"surname": "Петров", "given_name": "Иван", "birth_date": "1980-01-01", "disambiguator": "moscow-engineer"}),
              add_entity("ent_d_n2", "prj_dossier", "PERSON", {"surname": "Петров", "given_name": "Иван", "birth_date": "1980-01-01", "disambiguator": "tver-driver"}))),
    V("P116", [], "слитый дубль с тем же ИНН, что у выжившей сущности, — не дубль",
      pre=seq(lambda W: W["ent_d_lomov_media"]["identity"].__setitem__("inn", INN_LOMOV))),
    V("N168", ["EVIDENCE_SPAN_INVALID"], "end за пределами источника при sha, совпадающем с остатком",
      pre=evp("c25", lambda evs: (evs[0].pop("quote"), evs[0]["span"].__setitem__("end", 10_000),
                                  evs[0].__setitem__("quote_sha256", sha(S10_TEXT.encode()[evs[0]["span"]["start"]:]))))),
    V("N169", ["EVIDENCE_SPAN_INVALID"], "фрагмент нулевой длины с sha пустой строки",
      pre=evp("c25", lambda evs: (evs[0].pop("quote"), evs[0]["span"].__setitem__("end", evs[0]["span"]["start"]),
                                  evs[0].__setitem__("quote_sha256", sha(b""))))),
    V("N197", ["CHECK_SUBJECT_INVALID"], "субъект слит ровно в момент завершения Проверки",
      pre=seq(add_entity("ent_k_dev_new", "prj_compliance", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", "inn": INN_DEV}, CONF_CS),
              lambda W: W["ent_k_developer"].update(status="MERGED", merged_into="ent_k_dev_new", status_changed_at="2026-09-26T15:00:00Z"),
              setk("chk_tenders_1", "subject_entity_id", "ent_k_dev_new"))),
    V("N219", ["CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION"], "порядок статусов — по времени записи, а не по заявленному времени",
      pre=add_review("rev_c21_d", "c21", "DISPUTED", "2026-09-19T10:00:00Z", "2026-09-21T10:00:00Z")),
    V("N220", ["CHECK_PREVIOUS_INVALID"], "предыдущая Проверка с той же датой as_of", pre=setk("chk_tenders_1", "as_of", "2026-09-25")),
    V("P221", [], "отклонённое утверждение не порождает противоречия",
      pre=add_review("rev_c14_r", "c14", "REFUTED", "2026-09-07T12:00:00Z", "2026-09-07T12:05:00Z"), warn=[]),
    V("P222", [], "непересекающиеся сроки — не противоречие",
      pre=seq(setk("c13", "valid_to", "2000-01-01"), setk("c14", "valid_from", "2001-01-01")), warn=[]),
    V("P223", [], "одинаковые значения из двух источников — не противоречие",
      pre=setk("c14", "object", {"literal": {"type": "DATE", "value": "1971-03-14"}}), warn=[]),
    V("N067", ["SOURCE_DIGEST_MISMATCH"], "прод: в хранилище подменены байты той же длины",
      post=seq(strip_inline("s10"), lambda d, ix, e: e["content"].__setitem__(rec(d, ix, "s10")["source_id"], S10_TEXT.replace("150", "160").encode()))),
    V("N177", ["MARKING_BROADER_THAN_INPUT"], "утверждение шире источника при равной маркировке сущностей", pre=setk("s10", "marking", INT)),
    V("N225", ["CHECK_FINDING_INCONSISTENT"], "NOT_FOUND с риском в идущей Проверке (без итогового риска)",
      pre=add_finding("chk_tenders_1", finding("TENDERS", "NOT_FOUND", "LOW", []))),
    V("P224", [], "база: ровно одно предупреждение о расхождении даты рождения", warn=["CONTRADICTION_SINGLE_VALUED"]),
    # ================= v0.2.1: closing RR-01…RR-15 of the v0.2 re-review =================
    # RR-01: a closed Check keeps a subject that was RETIRED strictly after closing
    V("P300", [], "субъект закрытых Проверок выведен из оборота после их закрытия (RR-01)",
      pre=seq(lambda W: W.pop("chk_tenders_1"), lambda W: W["ent_k_developer"].update(status="RETIRED", status_changed_at="2026-09-28T00:00:00Z"))),
    V("N301", ["CHECK_SUBJECT_INVALID"], "субъект выведен из оборота ДО закрытия полной Проверки",
      pre=seq(lambda W: W.pop("chk_tenders_1"), lambda W: W["ent_k_developer"].update(status="RETIRED", status_changed_at="2026-09-26T00:00:00Z"))),
    V("N302", ["CHECK_SUBJECT_INVALID"], "субъект выведен из оборота ровно в момент закрытия",
      pre=seq(lambda W: W.pop("chk_tenders_1"), lambda W: W["ent_k_developer"].update(status="RETIRED", status_changed_at="2026-09-26T15:00:00Z"))),
    # RR-13: the survivor of a merge may be retired later, but must be ACTIVE at the moment of the merge
    V("P303", [], "выжившая сущность выведена из оборота после слияния — дубли остаются корректными (RR-13)",
      pre=lambda W: W["ent_d_lomov"].update(status="RETIRED", status_changed_at="2026-09-20T00:00:00Z")),
    V("N304", ["ENTITY_MERGE_INVALID"], "слияние в сущность, уже выведенную из оборота",
      pre=lambda W: W["ent_d_lomov"].update(status="RETIRED", status_changed_at="2026-09-06T00:00:00Z")),
    V("N305", ["ENTITY_MERGE_INVALID"], "слияние в момент вывода цели из оборота",
      pre=lambda W: W["ent_d_lomov"].update(status="RETIRED", status_changed_at="2026-09-06T15:00:00Z")),
    # RR-02: look-alike-only collisions of equipment tags / concepts are warnings, homonyms need disambiguators
    V("P306", [], "PT-101 (латиница, датчик давления) и РТ-101 (кириллица, регулятор) — разные приборы, предупреждение",
      pre=seq(add_entity("ent_ts_pt", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "PT-101"}, INT),
              add_entity("ent_ts_rt", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "РТ-101"}, INT)),
      warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P307", [], "понятия «небо» и «нёбо» различны — только предупреждение",
      pre=seq(add_entity("ent_wk_sky", "prj_wiki_whales", "CONCEPT", {"label": "небо", "lang": "ru"}, PUB),
              add_entity("ent_wk_palate", "prj_wiki_whales", "CONCEPT", {"label": "нёбо", "lang": "ru"}, PUB)),
      warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P308", [], "омонимы «Орёл» (город) и «орёл» (птица) с разными пометками — не дубль и без предупреждения",
      pre=seq(add_entity("ent_wk_orel_c", "prj_wiki_whales", "CONCEPT", {"label": "Орёл", "lang": "ru", "disambiguator": "city"}, PUB),
              add_entity("ent_wk_orel_b", "prj_wiki_whales", "CONCEPT", {"label": "орёл", "lang": "ru", "disambiguator": "bird"}, PUB)),
      warn=["CONTRADICTION_SINGLE_VALUED"]),
    V("N309", ["ENTITY_DUPLICATE_IN_PROJECT"], "«Орёл» и «орёл» без пометок — дубль",
      pre=seq(add_entity("ent_wk_orel_c", "prj_wiki_whales", "CONCEPT", {"label": "Орёл", "lang": "ru"}, PUB),
              add_entity("ent_wk_orel_b", "prj_wiki_whales", "CONCEPT", {"label": "орёл", "lang": "ru"}, PUB))),
    V("N309b", ["ENTITY_DUPLICATE_IN_PROJECT"], "омоним с пометкой только у одного — дубль",
      pre=seq(add_entity("ent_wk_orel_c", "prj_wiki_whales", "CONCEPT", {"label": "Орёл", "lang": "ru", "disambiguator": "city"}, PUB),
              add_entity("ent_wk_orel_b", "prj_wiki_whales", "CONCEPT", {"label": "орёл", "lang": "ru"}, PUB))),
    V("N310", ["ENTITY_DUPLICATE_IN_PROJECT"], "тег без дефиса (Н101 = Н-101) (RR-03f)",
      pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н101"}, INT)),
    # RR-03a-c: an optional place / disambiguator separates only when BOTH sides carry it and they differ
    V("N312", ["ENTITY_DUPLICATE_IN_PROJECT"], "то же событие с местом и без места (RR-03a)",
      pre=add_entity("ent_k_tender2", "prj_compliance", "EVENT", {"title": "Электронный аукцион № 0148300000126000017", "date": "2026-08-15", "place": "Москва"}, CONF_CS)),
    V("N313", ["ENTITY_DUPLICATE_IN_PROJECT"], "тот же конфликт без места (RR-03b)",
      pre=add_entity("ent_c_conf2", "prj_conflict_land", "CONFLICT", {"title": "Застройка участка на ул. Заречной", "started_on": "2026-09-02"})),
    V("N314", ["ENTITY_DUPLICATE_IN_PROJECT"], "тёзка с той же датой рождения: пометка только у одного, ИНН только у одного (RR-03c)",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14", "disambiguator": "other-lomov"})),
    V("N315", ["ENTITY_DUPLICATE_IN_PROJECT"], "невидимый U+034F CGJ в фамилии (RR-03h)",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ло\u034Fмов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"})),
    V("N316", ["ENTITY_DUPLICATE_IN_PROJECT"], "селектор варианта U+FE0F в фамилии (RR-03i)",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ломов\uFE0F", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"})),
    V("N317", ["ENTITY_DUPLICATE_IN_PROJECT"], "заполнитель U+3164 в имени (RR-03j)",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Арка\u3164дий", "patronymic": "Семёнович", "birth_date": "1971-03-14"})),
    V("N318", ["ENTITY_DUPLICATE_IN_PROJECT"], "греческая ο в фамилии (RR-03k)",
      pre=add_entity("ent_d_lomov2", "prj_dossier", "PERSON", {"surname": "Лοмов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"})),
    V("N319", ["ENTITY_DUPLICATE_IN_PROJECT"], "бортовой номер RA-12345 и «ra 12345» (RR-03d)",
      pre=seq(add_entity("ent_d_plane1", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "AIRCRAFT", "description": "самолёт", "registration": {"scheme": "aviareg", "value": "RA-12345"}}, CONF_PD),
              add_entity("ent_d_plane2", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "AIRCRAFT", "description": "самолёт", "registration": {"scheme": "aviareg", "value": "ra 12345"}}, CONF_PD))),
    V("N320", ["ENTITY_DUPLICATE_IN_PROJECT"], "минус U+2212 вместо дефиса в названии события (RR-15 X03)",
      pre=seq(add_entity("ent_c_ev1", "prj_conflict_land", "EVENT", {"title": "Сход-2026", "date": "2026-09-21", "place": "г. Заречный"}),
              add_entity("ent_c_ev2", "prj_conflict_land", "EVENT", {"title": "Сход−2026", "date": "2026-09-21", "place": "г. Заречный"}))),
    # RR-04: sole proprietors with different ОГРНИП are different people even without ИНН
    V("P321", [], "два ИП-тёзки с одной датой рождения и разными ОГРНИП (RR-04)",
      pre=seq(add_entity("ent_d_ip_a", "prj_dossier", "PERSON", {"surname": "Сидоров", "given_name": "Пётр", "birth_date": "1980-05-05", "ogrnip": ogrnip("30450010000111")}),
              add_entity("ent_d_ip_b", "prj_dossier", "PERSON", {"surname": "Сидоров", "given_name": "Пётр", "birth_date": "1980-05-05", "ogrnip": ogrnip("30450010000222")}))),
    # RR-05: deep nesting must not escape as RecursionError
    V("N322", ["SCHEMA_INVALID"], "вложенность 5000 уровней (RR-05)",
      post=lambda d, ix, e: rec(d, ix, "c11")["qualifiers"].__setitem__("x", _nest(5000))),
    V("N322b", ["TRUST_CONFIG_INVALID", "RECEIPT_KEY_INVALID"], "вложенность 5000 уровней в реестре доверия (RR-05)",
      post=lambda d, ix, e: e["trust"].__setitem__("extra", _nest(5000))),
    # RR-06: key ids are unique per tenant; another tenant's entry must not break this tenant
    V("P323", [], "ключ с тем же key_id у другого tenant (другой открытый ключ, первым в реестре) не подменяет ключ этого tenant (RR-06)",
      post=lambda d, ix, e: e["trust"]["keys"].insert(0, dict(e["trust"]["keys"][0], tenant_id="tnt_other", public_key=_OTHER_PUB))),
    V("N323b", ["TRUST_CONFIG_INVALID"], "битая запись другого tenant: ошибка реестра, но ключи этого tenant действуют (RR-06)",
      post=lambda d, ix, e: e["trust"]["keys"].extend([dict(e["trust"]["keys"][0], tenant_id="tnt_other"),
                                                        dict(e["trust"]["keys"][0], tenant_id="tnt_other")]),
      warn=None),
    # RR-08b,c: the result source of a search is evidence too
    V("N325", ["SOURCE_CONTENT_UNAVAILABLE"], "источник результата поиска без байтов ни в данных, ни в хранилище (RR-08b)",
      post=seq(strip_inline("s12"), lambda d, ix, e: e["content"].pop(rec(d, ix, "s12")["source_id"], None))),
    V("N326", ["MARKING_BROADER_THAN_INPUT"], "Проверка уже маркировки источника результата поиска (RR-08c)",
      pre=setk("s12", "marking", {"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "OFFICIAL_USE"]})),
    # RR-10: free text is decided by place in the schema, not by key name
    V("P327", [], "многострочное действие TechSense (STRING-литерал) (RR-10)",
      pre=seq(lambda W: W["c3"]["object"]["literal"].__setitem__("value", "1) остановить насос;\n2) сообщить дежурному инженеру"),
              art_node("n5", "text", "1) остановить насос;\n2) сообщить дежурному инженеру"))),
    V("N327b", ["SCHEMA_INVALID"], "перевод строки в структурном поле рядом с литералом",
      pre=lambda W: W["c3"]["object"]["literal"].__setitem__("lang", "ru\n")),
    # RR-11: identifier literals of reserved schemes carry check digits
    V("N328", ["IDENTIFIER_CHECKSUM_INVALID"], "ОГРНИП-литерал с неверной контрольной цифрой (RR-11)",
      pre=lambda W: W["c17b"]["object"]["literal"].__setitem__("value", OGRNIP_IP[:-1] + str((int(OGRNIP_IP[-1]) + 1) % 10))),
    V("N328b", ["IDENTIFIER_CHECKSUM_INVALID"], "ОГРНИП-литерал не из цифр",
      pre=lambda W: W["c17b"]["object"]["literal"].__setitem__("value", "ОГРНИП-не-число")),
    # RR-12: identifier spaces are separated by entity type
    V("P330", [], "одинаковая пара «схема+значение» у организации и у имущества — разные пространства (RR-12)",
      pre=seq(add_entity("ent_d_plane1", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "AIRCRAFT", "description": "самолёт", "registration": {"scheme": "x.reg", "value": "AB1"}}, CONF_PD),
              add_entity("ent_d_orgx", "prj_dossier", "ORGANIZATION", {"name": "Foreign Ltd", "jurisdiction": "GB", "foreign_ids": [{"scheme": "x.reg", "value": "AB1"}]}, CONF_PD))),
    V("N332", ["ENTITY_DUPLICATE_IN_PROJECT"], "римская цифра Ⅱ (U+2161) и «II» — NFKC в скелете",
      pre=seq(add_entity("ent_c_ev1", "prj_conflict_land", "EVENT", {"title": "Съезд II", "date": "2026-09-21", "place": "г. Заречный"}),
              add_entity("ent_c_ev2", "prj_conflict_land", "EVENT", {"title": "Съезд \u2161", "date": "2026-09-21", "place": "г. Заречный"}))),
    V("N333", ["MARKING_BROADER_THAN_INPUT"], "Проверка без утверждений уже маркировки субъекта-физлица",
      pre=lambda W: W.__setitem__("chk_new", dict(copy.deepcopy(W["chk_tenders_1"]), check_id="chk_new", subject_entity_id="ent_k_lomov",
                                                  profile="SOCIAL_ONLY", marking=CONF_CS, **{"previous_check_id": None}))
                    or W["chk_new"].pop("previous_check_id")),
    V("N334", ["SCHEMA_INVALID"], "перевод строки в значении IDENTIFIER-литерала (свободный текст — только STRING)",
      pre=lambda W: W["c17b"]["object"]["literal"].__setitem__("value", "3265012000041\n2")),
    # RR-15 X02: DEL (0x7F) is a control character
    V("N331", ["SCHEMA_INVALID"], "символ DEL (0x7F) в структурном поле (RR-15 X02)",
      post=lambda d, ix, e: rec(d, ix, "ent_d_lomov").__setitem__("display_name", "Ломов\x7f")),
    # ===== v0.2.2: skeleton hardening (RS-12), tag and model keys (RS-14), identity decisions (RS-13, RS-15)
    V("N400", ["ENTITY_DUPLICATE_IN_PROJECT"], "ударение U+0301 в фамилии: «Ломо\u0301в» = Ломов (RS-12 B1-01)",
      pre=_namesake("Ломо\u0301в", "Аркадий", "Семёнович")),
    V("N401", ["ENTITY_DUPLICATE_IN_PROJECT"], "латинская ë в отчестве (RS-12 B1-02)", pre=_namesake("Ломов", "Аркадий", "Семëнович")),
    V("N402", ["ENTITY_DUPLICATE_IN_PROJECT"], "армянская օ (RS-12 B1-03)", pre=_namesake("Лօмов", "Аркадий", "Семёнович")),
    V("N403", ["ENTITY_DUPLICATE_IN_PROJECT"], "латинская капитель ᴏ (RS-12 B1-04)", pre=_namesake("Лᴏмов", "Аркадий", "Семёнович")),
    V("N404", ["ENTITY_DUPLICATE_IN_PROJECT"], "греческая лунная Ϲ (RS-12 B1-05)", pre=_namesake("Ломов", "Аркадий", "Ϲемёнович")),
    V("N405", ["ENTITY_DUPLICATE_IN_PROJECT"], "чероки Ꭺ (RS-12 B1-06)", pre=_namesake("Ломов", "Ꭺркадий", "Семёнович")),
    V("N406", ["ENTITY_DUPLICATE_IN_PROJECT"], "пробел Брайля U+2800 внутри фамилии (RS-12 B1-07)", pre=_namesake("Ло\u2800мов", "Аркадий", "Семёнович")),
    V("N406b", ["ENTITY_DUPLICATE_IN_PROJECT"], "строчная чероки ꭺ сворачивается в прописную (второй проход таблицы двойников)",
      pre=_namesake("Ломов", "ꭺркадий", "Семёнович")),
    V("N407", ["ENTITY_DUPLICATE_IN_PROJECT"], "неформальная группа «Заре\u0301чная, 12» (RS-12 B3-05)",
      pre=add_entity("ent_c_init2", "prj_conflict_land", "ORGANIZATION", {"name": "Инициативная группа «Заре\u0301чная, 12»", "jurisdiction": "RU",
                                                                            "informal": True, "disambiguator": "zarechnaya-12"})),
    V("P408", [], "тег «Н\u0301-101»: точный ключ другой, скелет тот же — предупреждение (RS-12 B2-04)",
      pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н\u0301-101"}, INT), warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P409", [], "й не теряется: Зуйков и Зуиков с одной датой рождения — разные люди",
      pre=seq(add_entity("ent_d_z1", "prj_dossier", "PERSON", {"surname": "Зуйков", "given_name": "Олег", "birth_date": "1980-01-01"}),
              add_entity("ent_d_z2", "prj_dossier", "PERSON", {"surname": "Зуиков", "given_name": "Олег", "birth_date": "1980-01-01"}))),
    V("P410", [], "К-1/12 и К-11/2 без решения аналитика — предупреждение, не дубль (RS-14 B2-01)",
      pre=lambda W: W.pop("idd_valves"), warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P411", [], "TT-10-1 и TT-101 — предупреждение, не дубль (RS-14 B2-02)",
      pre=seq(add_entity("ent_ts_t1", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "TT-10-1"}, INT),
              add_entity("ent_ts_t2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "TT-101"}, INT)), warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P412", [], "модели «ЦНС 10²» и «ЦНС 102» — разные (без NFKC в ключе модели, RS-14 B2-09)",
      pre=seq(add_entity("ent_ts_m1", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": "ЦНС 10²"}, INT),
              add_entity("ent_ts_m2", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": "ЦНС 102"}, INT))),
    V("N413", ["ENTITY_DUPLICATE_IN_PROJECT"], "полноширинная модель «\uFF2E\uFF2D 16-100» — та же (свёртка ширины остаётся)",
      pre=add_entity("ent_ts_m3", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": "\uFF28\uFF2D 16-100"}, INT)),
    V("N413b", ["ENTITY_DUPLICATE_IN_PROJECT"], "тег Н-101 через пробел и точку («н . 101») — тот же насос (буква|цифра)",
      pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "н . 101"}, INT)),
    V("P414", [], "«Н-1-01» и «Н-101»: граница групп цифр значима — предупреждение",
      pre=add_entity("ent_ts_pump2", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-1-01"}, INT), warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("N420", ["IDENTITY_DECISION_INVALID"], "уточнение организации (сильный ключ) недопустимо",
      pre=_qualify("idd_xx", "prj_dossier", "ent_d_developer", disambiguator="zzz")),
    V("N421", ["IDENTITY_DECISION_INVALID"], "уточнение сущности, у которой disambiguator уже есть",
      pre=_qualify("idd_xx", "prj_wiki_whales", "ent_wk_blue_colour", disambiguator="zzz")),
    V("N422", ["IDENTITY_DECISION_INVALID"], "второе уточнение той же сущности",
      pre=_qualify("idd_xx", "prj_wiki_whales", "ent_wk_blue", disambiguator="whale-2")),
    V("N423", ["IDENTITY_DECISION_INVALID"], "уточнение понятия местом (поле не того типа)",
      pre=_qualify("idd_xx", "prj_wiki_whales", "ent_wk_baleen", place="Атлантика")),
    V("N424", ["IDENTITY_DECISION_INVALID"], "уточнение слитой сущности",
      pre=seq(add_entity("ent_d_lomov_x", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "birth_date": "1971-03-14"},
                         status="MERGED", merged_into="ent_d_lomov", changed="2026-09-06T10:00:00Z"),
              _qualify("idd_xx", "prj_dossier", "ent_d_lomov_x", disambiguator="zzz"))),
    V("P424b", [], "уточнение, а слияние позже — допустимо (решение проверяется на момент принятия)",
      pre=seq(add_entity("ent_d_lomov_x", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "birth_date": "1971-03-14"},
                         status="MERGED", merged_into="ent_d_lomov", changed="2026-09-06T15:00:00Z"),
              _qualify("idd_xx", "prj_dossier", "ent_d_lomov_x", disambiguator="zzz"))),
    V("N425", ["IDENTITY_DECISION_INVALID"], "«различны» для сущностей разных типов",
      pre=_distinct("idd_xx", "prj_dossier", "ent_d_developer", "ent_d_lomov")),
    V("N426", ["IDENTITY_DECISION_INVALID"], "«различны» для слитых друг в друга",
      pre=_distinct("idd_xx", "prj_dossier", "ent_d_lomov", "ent_d_lomov_media")),
    V("N427", ["REF_UNRESOLVED"], "решение о неизвестной сущности", pre=_distinct("idd_xx", "prj_dossier", "ent_d_lomov", "ent_nope")),
    V("N427b", ["REF_UNRESOLVED"], "решение неизвестного проекта", pre=_qualify("idd_xx", "prj_nope", "ent_wk_baleen", disambiguator="zzz")),
    V("N428", ["CROSS_SCOPE_REFERENCE"], "решение о сущности другого проекта", pre=_distinct("idd_xx", "prj_dossier", "ent_d_lomov", "ent_k_lomov")),
    V("N429", ["TEMPORAL_ORDER_INVALID"], "решение раньше создания сущности", pre=setk("idd_blue_whale", "decided_at", "2026-09-05T11:59:59Z")),
    V("N430", ["SCHEMA_INVALID"], "«различны» с одной и той же сущностью дважды",
      pre=_distinct("idd_xx", "prj_dossier", "ent_d_lomov", "ent_d_lomov")),
    V("N430b", ["SCHEMA_INVALID"], "«различны» с полем entity_id", pre=lambda W: W["idd_valves"].__setitem__("entity_id", "ent_ts_pump")),
    V("N431", ["SCHEMA_INVALID"], "уточнение сразу disambiguator и place", pre=lambda W: W["idd_blue_whale"].__setitem__("place", "Атлантика")),
    V("N431b", ["SCHEMA_INVALID"], "уточнение без поля", pre=lambda W: W["idd_blue_whale"].pop("disambiguator")),
    V("N432", ["ENTITY_DUPLICATE_IN_PROJECT"], "без уточнения оригинала омоним «синий кит» — дубль (RS-15 D04)", pre=lambda W: W.pop("idd_blue_whale")),
    V("P433", [], "событие без места уточняется местом, затем заводится одноимённое событие в другом месте (RS-15)",
      pre=seq(_qualify("idd_xx", "prj_compliance", "ent_k_tender", place="г. Заречный"),
              add_entity("ent_k_tender2", "prj_compliance", "EVENT", {"title": "Электронный аукцион № 0148300000126000017", "date": "2026-08-15",
                                                                        "place": "г. Москва"}, CONF_CS),
              setk("ent_k_tender2", "created_at", "2026-09-06T12:00:00Z"))),
    V("N434", ["ENTITY_DUPLICATE_IN_PROJECT"], "уточнение тем же disambiguator, что у омонима, не разделяет",
      pre=setk("idd_blue_whale", "disambiguator", "colour-name")),
    V("P435", [], "понятие с латинской C: два решения «различны» снимают оба предупреждения (RS-13)",
      pre=seq(add_entity("ent_wk_c", "prj_wiki_whales", "CONCEPT", {"label": "Cиний кит", "lang": "ru", "namespace": "whales"}, PUB),
              _distinct("idd_x1", "prj_wiki_whales", "ent_wk_c", "ent_wk_blue"), _distinct("idd_x2", "prj_wiki_whales", "ent_wk_c", "ent_wk_blue_colour")),
      warn=["CONTRADICTION_SINGLE_VALUED"]),
    V("P436", [], "одно решение из двух нужных — предупреждение остаётся (RS-13)",
      pre=seq(add_entity("ent_wk_c", "prj_wiki_whales", "CONCEPT", {"label": "Cиний кит", "lang": "ru", "namespace": "whales"}, PUB),
              _distinct("idd_x1", "prj_wiki_whales", "ent_wk_c", "ent_wk_blue")),
      warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("P437", [], "уточнение физлица с датой рождения (ИНН есть) — допустимо",
      pre=_qualify("idd_xx", "prj_dossier", "ent_d_lomov", disambiguator="director")),
    V("N438", ["ENTITY_DUPLICATE_IN_PROJECT"], "тёзка с той же датой: уточнён только оригинал — новый без пометки остаётся дублем",
      pre=seq(_qualify("idd_xx", "prj_dossier", "ent_d_lomov", disambiguator="director"),
              _namesake("Ломов", "Аркадий", "Семёнович"))),
    V("N439", ["ENTITY_DUPLICATE_IN_PROJECT"], "омоним заведён раньше, чем уточнён оригинал: был дублем до уточнения (RS-15)",
      pre=setk("ent_wk_blue_colour", "created_at", "2026-09-06T09:00:00Z")),
    V("P439b", [], "омоним заведён в ту же секунду, что и уточнение оригинала",
      pre=setk("ent_wk_blue_colour", "created_at", "2026-09-06T10:00:00Z")),
    V("N440", ["ENTITY_DUPLICATE_IN_PROJECT"], "слитая в уточнённую сущность без своей пометки: уточнение выжившей распространяется на её ключ",
      pre=seq(add_entity("ent_wk_blue_old", "prj_wiki_whales", "CONCEPT", {"label": "синий кит", "lang": "ru", "namespace": "whales"}, PUB,
                         status="MERGED", merged_into="ent_wk_blue", changed="2026-09-05T13:00:00Z"),
              setk("idd_blue_whale", "disambiguator", "colour-name"))),
    V("P440b", [], "слитая в уточнённую сущность без своей пометки: омоним с другой пометкой допустим",
      pre=add_entity("ent_wk_blue_old", "prj_wiki_whales", "CONCEPT", {"label": "синий кит", "lang": "ru", "namespace": "whales"}, PUB,
                     status="MERGED", merged_into="ent_wk_blue", changed="2026-09-05T13:00:00Z")),
    # ===== v0.2.3: markings across merges and Check chains (S22-01, S22-03)
    V("N441", ["ENTITY_MERGE_INVALID"], "слияние в сущность с более широкой маркировкой (S22-01)",
      pre=seq(add_entity("ent_k_plot2", "prj_compliance", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:999", "address": "Московская обл., г. Заречный, уч. 999"},
                         {"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}),
              setk("ent_k_land", "status", "MERGED"), setk("ent_k_land", "merged_into", "ent_k_plot2"),
              setk("ent_k_land", "status_changed_at", "2026-09-06T10:00:00Z"))),
    V("P441b", [], "слияние в сущность с той же маркировкой допустимо",
      pre=seq(add_entity("ent_k_plot2", "prj_compliance", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:999", "address": "Московская обл., г. Заречный, уч. 999"}, CONF_CS),
              setk("ent_k_land", "status", "MERGED"), setk("ent_k_land", "merged_into", "ent_k_plot2"),
              setk("ent_k_land", "status_changed_at", "2026-09-06T10:00:00Z"))),
    V("N442", ["MARKING_BROADER_THAN_INPUT"], "Проверка уже маркировки предыдущей Проверки (S22-03)",
      pre=setk("chk_tenders_1", "marking", CONF_CS)),
    V("N444", ["ENTITY_MERGE_INVALID"], "слияние в сущность другого проекта при равной маркировке",
      pre=seq(setk("ent_d_trub", "status", "MERGED"), setk("ent_d_trub", "merged_into", "ent_c_developer"),
              setk("ent_d_trub", "status_changed_at", "2026-09-06T10:00:00Z"))),
    # S23-01v: the previous Check is COMPLETED before the new one is requested
    V("N445", ["CHECK_PREVIOUS_INVALID"], "предыдущая Проверка ещё не завершена (S23-01)",
      pre=seq(pop("chk_tenders_1", "previous_check_id"), setk("chk_full_1", "previous_check_id", "chk_tenders_1"),
              setk("chk_tenders_1", "as_of", "2026-09-20"), setk("chk_tenders_1", "requested_at", "2026-09-20T09:00:00Z"))),
]


# ===== v0.2.4 (S4): the artifact behind a receipt and the graph nodes behind claims (RR-07, D17)
A_DG = lambda d: rec(d[0], d[1], "rcp_1")["artifact_digest"]  # noqa: E731


def art(fn):
    return lambda W: fn(W["__artifacts__"]["umr_ns2"])


def art_bytes(tf):
    return art(lambda a: a.__setitem__("_bytes_tf", tf))


def ev_quote(name, quote):
    return lambda W: W[name]["evidence"][0].__setitem__("$ev", ["s1", quote])


def gnode(name, node_id):
    return lambda W: W[name]["evidence"][0]["graph_node"].__setitem__("node_id", node_id)


def add_node(node):
    return art(lambda a: a["nodes"].append(node))


def drop_store(d, ix, e):
    e["content"].pop(rec(d, ix, "rcp_1")["artifact_digest"])


def tamper_store(d, ix, e):
    dg = rec(d, ix, "rcp_1")["artifact_digest"]
    e["content"][dg] = e["content"][dg].replace("бар".encode(), "атм".encode(), 1)


VECTORS += [
    # --- the artifact itself
    V("N500", ["ARTIFACT_INVALID"], "receipt без байтов артефакта в хранилище (RR-07)", post=drop_store),
    V("N501", ["ARTIFACT_INVALID"], "байты артефакта подменены после адресации", post=tamper_store),
    V("N502", ["ARTIFACT_INVALID"], "артефакт не в канонической форме RFC 8785 (лишний пробел)",
      pre=art_bytes(lambda b: b.replace(b'":', b'": ', 1))),
    V("N503", ["ARTIFACT_INVALID"], "артефакт с повторяющимся ключом",
      pre=art_bytes(lambda b: b[:-1] + b',"run_id":"run_other"}')),
    V("N504", ["ARTIFACT_INVALID"], "артефакт не в UTF-8", pre=art_bytes(lambda b: b.replace("Насос".encode(), "Насос".encode("cp1251"), 1))),
    V("N505", ["ARTIFACT_INVALID"], "отношение без якоря (схема артефакта)", pre=art(lambda a: a["nodes"][-1].pop("anchor"))),
    V("N506", ["ARTIFACT_INVALID"], "неизвестный семантический профиль (receipt и артефакт согласны)",
      pre=seq(art(lambda a: a.__setitem__("semantic_profile", "ts-semantic/9.9")), setk("rcp_1", "semantic_profile_version", "ts-semantic/9.9"))),
    V("N507", ["ARTIFACT_INVALID"], "артефакт другой версии службы, чем в receipt",
      pre=art(lambda a: a["producer"].__setitem__("version", "0.9.1"))),
    V("N508", ["ARTIFACT_INVALID"], "артефакт другого запуска", pre=art(lambda a: a.__setitem__("run_id", "run_ts_0002"))),
    V("N509", ["ARTIFACT_INVALID"], "во входах артефакта лишний источник", pre=art_in("@S:s2")),
    V("N510", ["ARTIFACT_INVALID"], "повторяющийся id узла", pre=art(lambda a: a["nodes"][4].__setitem__("id", "n4"))),
    V("N511", ["ARTIFACT_INVALID"], "якорь узла за концом источника",
      pre=art(lambda a: a["nodes"][3].__setitem__("anchor", {"source_id": "@S:s1", "start": 10, "end": 100000}))),
    V("N512", ["ARTIFACT_INVALID"], "якорь узла режет символ UTF-8",
      pre=art(lambda a: a["nodes"][3].__setitem__("anchor", {"source_id": "@S:s1", "start": 1, "end": 4}))),
    V("N513", ["ARTIFACT_INVALID"], "якорь узла в источнике вне входов артефакта",
      pre=art(lambda a: a["nodes"][3].__setitem__("anchor", {"source_id": "@S:s2", "start": 0, "end": 4}))),
    V("N514", ["ARTIFACT_INVALID"], "отношение ссылается на несуществующий узел", pre=art(lambda a: a["nodes"][6].__setitem__("args", ["n1", "n99"]))),
    V("N515", ["ARTIFACT_INVALID"], "has-parameter с действием вместо величины", pre=art(lambda a: a["nodes"][8].__setitem__("args", ["n1", "n5"]))),
    V("N516", ["ARTIFACT_INVALID"], "has-parameter без parameter", pre=art(lambda a: a["nodes"][8].pop("parameter"))),
    V("N517", ["ARTIFACT_INVALID"], "условие ссылается не на CONDITION", pre=art(lambda a: a["nodes"][9].__setitem__("condition", "n4"))),
    V("N518", ["ARTIFACT_INVALID"], "receipt объявляет другой формат артефакта", pre=setk("rcp_1", "artifact_schema_version", "umr-artifact/0.4")),
    # --- graph nodes behind claims
    V("N520", ["GRAPH_NODE_INVALID"], "несуществующий узел графа (атака RR-07)", pre=gnode("c2", "no-such-node-999")),
    V("N521", ["GRAPH_NODE_INVALID"], "узел — сущность, а не отношение", pre=gnode("c0", "n1")),
    V("N522", ["GRAPH_NODE_INVALID"], "узел другого отношения (параметр ↔ действие)", pre=gnode("c2", "n13")),
    V("N523", ["GRAPH_NODE_INVALID"], "фрагмент доказательства вне якоря узла",
      pre=ev_quote("c0", "Максимальное рабочее давление насоса Н-101 — 16 бар")),
    V("N524", ["GRAPH_NODE_INVALID"], "субъект утверждения не тот, что в графе", pre=setk("c2", "subject", "ent_ts_station")),
    V("N525", ["GRAPH_NODE_INVALID"], "значение утверждения не то, что в графе (17 вместо 16)",
      pre=lambda W: W["c2"]["object"]["literal"].__setitem__("value", "17")),
    V("N526", ["GRAPH_NODE_INVALID"], "уточнение утверждения не то, что в графе", pre=setq("c2", "parameter", "max_pressure")),
    V("N527", ["GRAPH_NODE_INVALID"], "роль узла отображается в другой предикат", pre=art(lambda a: a["nodes"][6].__setitem__("role", "part-of"))),
    V("N528", ["GRAPH_NODE_INVALID"], "роль узла не отображается в профиль", pre=art(lambda a: a["nodes"][6].__setitem__("role", "model-of"))),
    V("N529", ["GRAPH_NODE_INVALID"], "утверждение из артефакта без узла графа", pre=pop("c0", "evidence", 0, "graph_node")),
    V("N530", ["GRAPH_NODE_INVALID"], "один узел — два утверждения",
      pre=seq(lambda W: W.__setitem__("c0b", {**copy.deepcopy(W["c0"]), "recorded_at": "2026-09-06T09:59:30Z"}),
              lambda W: W["rcp_1"]["emitted_claim_ids"].append("@C:c0b"))),
    V("N531", ["GRAPH_NODE_INVALID"], "объект — сущность-двойник с латинской «H» (другой строгий ключ)",
      pre=seq(add_entity("ent_ts_station_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "HC-2"}, INT),
              lambda W: W["c1"].__setitem__("object", {"entity": "ent_ts_station_lat"})),
      warn=["POSSIBLE_DUPLICATE", "CONTRADICTION_SINGLE_VALUED"]),
    V("N532", ["GRAPH_NODE_INVALID"], "узел другой площадки", pre=art(lambda a: a["nodes"][0]["identity"].__setitem__("site_id", "site_ns3"))),
    V("N533", ["GRAPH_NODE_INVALID"], "условие утверждения не то, что в графе", pre=setq("c3", "condition", "давление > 10 бар")),
    V("P534", [], "фрагмент доказательства — часть якоря узла", pre=ev_quote("c1", "входит в состав насосной станции НС-2")),
    V("P535", [], "в артефакте есть неотображаемое отношение, которое не дало утверждения",
      pre=add_node({"id": "n14", "type": "RELATION", "role": "mentions", "args": ["n1", "n3"],
                    "anchor": {"$anchor": ["s1", "Насос Н-101"]}})),
    V("P536", [], "тег в графе записан «Н 101» — тот же строгий ключ, что «Н-101»",
      pre=art(lambda a: a["nodes"][0]["identity"].__setitem__("tag", "Н 101"))),
    V("P537", [], "узел-сущность без якоря допустим", pre=art(lambda a: a["nodes"][1].pop("anchor"))),
]
VECTORS += [
    V("N538", ["GRAPH_NODE_INVALID"], "одно утверждение дважды ссылается на один узел",
      pre=lambda W: W["c2"]["evidence"].append(copy.deepcopy(W["c2"]["evidence"][0]))),
]


VECTORS += [
    V("N539", ["ARTIFACT_INVALID"], "целое вне ±(2^53−1) в границе якоря (профиль чисел)",
      pre=seq(art(lambda a: a["nodes"][3].__setitem__("anchor", {"source_id": "@S:s1", "start": 0, "end": 777777})),
              art_bytes(lambda b: b.replace(b"777777", b"9007199254740993", 1)))),
    V("N540", ["ARTIFACT_INVALID"], "повтор id узла при одинаковом содержимом",
      pre=art(lambda a: a["nodes"].append(copy.deepcopy(a["nodes"][5])))),
    V("N541", ["ARTIFACT_INVALID"], "receipt и артефакт расходятся в семантическом профиле",
      pre=setk("rcp_1", "semantic_profile_version", "ts-semantic/0.3")),
    V("N542", ["GRAPH_NODE_INVALID"], "фрагмент начинается до якоря узла и кончается внутри",
      pre=ev_quote("c2", "НС-2. Максимальное рабочее давление насоса Н-101 — 16 бар")),
    V("N543", ["GRAPH_NODE_INVALID"], "фрагмент из другого источника в тех же числовых границах, что якорь узла",
      pre=seq(art_in("@S:s2"), lambda W: W["rcp_1"]["input_source_ids"].append("@S:s2"),
              lambda W: W["c2"]["evidence"][0].__setitem__("$ev", ["s2", "стке 50:12:0101001:245. Жители Заречной улицы выступили "]))),
    V("N544", ["GRAPH_NODE_INVALID"], "действие утверждения не то, что в графе",
      pre=lambda W: W["c3"]["object"]["literal"].__setitem__("value", "остановить насос")),
]

# ===== review S4 (S4R-01, 02, 07, 08)
VECTORS += [
    V("N545", ["GRAPH_NODE_INVALID"], "утверждение ограничивает узел сроком действия (S4R-01)", pre=setk("c2", "valid_to", "2020-01-01")),
    V("N546", ["GRAPH_NODE_INVALID"], "лишнее доказательство без узла у утверждения из артефакта (S4R-07)",
      pre=lambda W: W["c2"]["evidence"].append({"$ev": ["s1", "Насос Н-101"]})),
    V("N547", ["ARTIFACT_INVALID"], "повтор запуска другим артефактом и receipt (S4R-08)",
      pre=seq(lambda W: W["__artifacts__"].__setitem__("umr_ns2b", {**copy.deepcopy(W["__artifacts__"]["umr_ns2"]),
                                                                     "nodes": copy.deepcopy(W["__artifacts__"]["umr_ns2"]["nodes"][:6])
                                                                     + [copy.deepcopy(W["__artifacts__"]["umr_ns2"]["nodes"][8])]}),
              lambda W: W.__setitem__("c2b", {**copy.deepcopy(W["c2"]), "recorded_at": "2026-09-06T09:59:30Z"}),
              lambda W: W["c2b"]["evidence"][0]["graph_node"].__setitem__("artifact_digest", "@A:umr_ns2b"),
              lambda W: W.__setitem__("rcp_2", {**copy.deepcopy(W["rcp_1"]), "artifact_digest": "@A:umr_ns2b",
                                                "emitted_claim_ids": ["@C:c2b"], "issued_at": "2026-09-06T10:00:05Z"}))),
    V("P548", [], "узел назван ключом слитой сущности, утверждение — о выжившей (S4R-02)",
      pre=seq(add_entity("ent_ts_pump_old", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-101/с"}, INT,
                         status="MERGED", merged_into="ent_ts_pump", changed="2026-09-05T13:00:00Z"),
              art(lambda a: a["nodes"][0]["identity"].__setitem__("tag", "Н-101/с")))),
    V("N549", ["GRAPH_NODE_INVALID"], "узел назван ключом сущности, слитой в другую",
      pre=seq(add_entity("ent_ts_st_old", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-101/с"}, INT,
                         status="MERGED", merged_into="ent_ts_station", changed="2026-09-05T13:00:00Z"),
              art(lambda a: a["nodes"][0]["identity"].__setitem__("tag", "Н-101/с")))),
]

VECTORS += [
    V("N550", ["GRAPH_NODE_INVALID"], "узел назван ключом сущности, слитой ПОСЛЕ записи утверждения (S4R-11)",
      pre=seq(add_entity("ent_ts_pump_old", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-101/с"}, INT,
                         status="MERGED", merged_into="ent_ts_pump", changed="2026-09-07T13:00:00Z"),
              art(lambda a: a["nodes"][0]["identity"].__setitem__("tag", "Н-101/с")))),
]

# ===== v0.2.5 (S5, O4): publications — one article fetched several times is one publication
VECTORS += [
    V("N600", ["PUBLICATION_INVALID"], "адрес публикации не по (tenant, издание, текст)",
      post=lambda d, ix, e: rec(d, ix, "pub_zarechye").__setitem__("publication_id", "pub:sha256:" + "8" * 64)),
    V("N601", ["PUBLICATION_INVALID"], "канонический адрес с меткой utm_source", pre=setk("pub_zarechye", "canonical_url", "https://news.example/zarechye?utm_source=x")),
    V("N602", ["PUBLICATION_INVALID"], "канонический адрес другого издания", pre=setk("pub_zarechye", "canonical_url", "https://agg.example/r/123")),
    V("N603", ["PUBLICATION_INVALID"], "у издания нет источника с таким текстом", pre=setk("pub_zarechye", "text_digest", {"$textdigest": "s3"})),
    V("N604", ["PUBLICATION_INVALID"], "публикация записана раньше, чем получен хоть один её источник",
      pre=setk("pub_zarechye", "recorded_at", "2026-09-02T09:00:00Z")),
    V("N605", ["MARKING_BROADER_THAN_INPUT"], "маркировка публикации шире маркировки мобильной версии (невидимый символ в тексте)",
      pre=setk("s2c", "marking", CONF_PD)),
    V("N606", ["TEMPORAL_ORDER_INVALID"], "публикация вышла позже, чем её получили", pre=setk("pub_zarechye", "published_at", "2026-09-02T11:00:00Z")),
    V("N607", ["DUPLICATE_ID"], "две записи одной публикации с разными каноническими адресами",
      pre=lambda W: W.__setitem__("pub_dup", {**copy.deepcopy(W["pub_zarechye"]), "canonical_url": "https://news.example/amp/zarechye"})),
    V("P608", [], "отредактированная статья (другое слово) — не рендеринг: отдельный источник без ошибки",
      pre=seq(add_source("s2d", "ООО «Заречье-Девелопмент» получило разрешение. Жители Заречной улицы выступили против стройки."),
              lambda W: W["s2d"]["observations"][0].__setitem__("origin_uri", "https://news.example/zarechye"))),
    V("P610", [], "канонический адрес с упорядоченными параметрами", pre=setk("pub_zarechye", "canonical_url", "https://news.example/zarechye?a=1&b=2")),
    V("N611", ["PUBLICATION_INVALID"], "публикация чужого tenant (там нет источников)", pre=setk("pub_zarechye", "tenant_id", "tnt_other")),
    V("N612", ["PUBLICATION_INVALID"], "канонический адрес с портом по умолчанию", pre=setk("pub_zarechye", "canonical_url", "https://news.example:443/zarechye")),
    V("N613", ["PUBLICATION_INVALID"], "параметры канонического адреса не упорядочены", pre=setk("pub_zarechye", "canonical_url", "https://news.example/zarechye?b=2&a=1")),
    V("N614", ["MARKING_BROADER_THAN_INPUT"], "маркировка публикации шире маркировки версии с лишними пробелами",
      pre=seq(setk("s2b", "marking", CONF_PD), setk("c8b", "marking", CONF_PD))),
    V("N615", ["PUBLICATION_INVALID"], "текст есть, но получен не с этого издания",
      pre=seq(setk("pub_zarechye", "outlet", "other.example"), setk("pub_zarechye", "canonical_url", "https://other.example/zarechye"))),
]


def _drop_bytes(name):
    def f(d, ix, e):
        r = rec(d, ix, name)
        r.pop("content_inline", None)
        e["content"].pop(r["source_id"], None)
    return f


# ===== review S5 (S5R-07, S5R-09)
VECTORS += [
    V("P616", [], "адрес наблюдения с «@» — не рендеринг издания (S5R-09): маркировка такой версии публикацию не ограничивает",
      pre=seq(setk("s2c", "marking", CONF_PD),
              lambda W: W["s2c"]["observations"][0].__setitem__("origin_uri", "https://m.news.example@evil.example/zarechye"))),
    V("P617", [], "версия статьи без байтов, на которую никто не ссылается, — не рендеринг и не ошибка (S5R-07)", post=_drop_bytes("s2c")),
]


# ===== v0.2.6 (S5 part 2, D26): originals in the object store
def _orig(d, ix):
    return rec(d, ix, "s2")["observations"][0]["original"]


VECTORS += [
    V("N700", ["ORIGINAL_INVALID"], "оригинала наблюдения нет в хранилище объектов",
      post=lambda d, ix, e: e["content"].pop(_orig(d, ix)["object"])),
    V("N701", ["ORIGINAL_INVALID"], "байты оригинала подменены (та же длина)",
      post=lambda d, ix, e: e["content"].__setitem__(_orig(d, ix)["object"], e["content"][_orig(d, ix)["object"]].replace(b"nav", b"NAV", 1))),
    V("N702", ["ORIGINAL_INVALID"], "длина оригинала не та, что заявлена",
      pre=lambda W: W["s2"]["observations"][0]["original"].__setitem__("byte_length", 5)),
    V("N703", ["SCHEMA_INVALID"], "оригинал без типа содержимого", pre=lambda W: W["s2"]["observations"][0]["original"].pop("media_type")),
    V("P704", [], "два наблюдения ссылаются на один оригинал",
      pre=lambda W: W["s2"]["observations"][1].__setitem__("original", copy.deepcopy(W["s2"]["observations"][0]["original"]))),
]


# S6R-12 (S6 review): N700-N703 only ever plant the defect on observations[0] of a source that has text in the
# content store, and only ever in the "declared shorter than actual" direction — a vector set with that shape
# cannot tell a correct ORIGINAL_INVALID check from one that is silently narrower in any of three ways
# (M703-M705 in core/mutants.py are exactly those three narrowings).
def _no_bytes_bad_original(d, ix, e):
    r = rec(d, ix, "s2e")
    r["observations"][0]["original"] = {"object": "sha256:" + "1" * 64, "media_type": "text/plain", "byte_length": 10}
    r.pop("content_inline", None)
    e["content"].pop(r["source_id"], None)


VECTORS += [
    V("N704", ["ORIGINAL_INVALID"], "плохой оригинал у ВТОРОГО наблюдения источника, не у первого (ловит мутант, проверяющий только observations[0])",
      post=lambda d, ix, e: rec(d, ix, "s2")["observations"][1].__setitem__(
          "original", {"object": "sha256:" + "0" * 64, "media_type": "text/html", "byte_length": 10})),
    V("N705", ["ORIGINAL_INVALID"], "заявленная длина оригинала БОЛЬШЕ фактической (ловит мутант, принимающий оригинал короче заявленного)",
      pre=lambda W: W["s2"]["observations"][0]["original"].__setitem__("byte_length", 999999)),
    V("N706", ["ORIGINAL_INVALID"], "у источника нет текста в общем хранилище, а у его единственного наблюдения — плохой оригинал "
      "(ловит мутант, который пропускает проверку оригинала, когда у источника нет байтов текста)",
      pre=add_source("s2e", "Текст источника N706 (будет изъят из общего хранилища после вычисления адресов)."),
      post=_no_bytes_bad_original),
]

# ---- Cycle 9: «Схема как данные» (D27.1) — ClassDef / LinkDef / IdentifierDef, schema.is_a, tenant predicates «x.…» ----
# The valid world already holds a small schema of the SemanticWiki tenant (fixtures: sd_*, s20, c40–c46); every vector
# below changes one thing in it.
WK = "prj_wiki_whales"
_IDF = {"ClassDef": "class_id", "LinkDef": "link_id", "IdentifierDef": "idef_id"}
T_SD = "2026-09-02T13:00:00Z"      # after the schema of the world, before its claims (2026-09-03T09:30)
T_LATE = "2026-09-04T10:00:00Z"    # after the claims of the world


def sd(key, kind, did, version, ctype, at=T_SD, tenant=T, marking=PUB, **body):
    """add one version of a schema definition"""
    def f(W):
        W[key] = {"kind": kind, "schema_version": SV3, _IDF[kind]: did, "tenant_id": tenant, "version": version, **body,
                  "marking": marking, "change": {"type": ctype, "description": "вектор", "recorded_at": at,
                                                 "recorded_by": "usr_modeler1"}}
    return f


def cls(key, did, version=1, ctype="ADD_CLASS", root="CONCEPT", name="Класс вектора", **kw):
    return sd(key, "ClassDef", did, version, ctype, root_type=root, name=name, **kw)


def nextv(src_key, key, ctype, at=T_SD, **changes):
    """the next version of the definition W[src_key]: a copy with `changes` (value None = drop the field)"""
    def f(W):
        r = copy.deepcopy(W[src_key])
        r["version"] += 1
        r["change"] = {"type": ctype, "description": "вектор", "recorded_at": at, "recorded_by": "usr_modeler1"}
        for k, v in changes.items():
            if v is None:
                r.pop(k, None)
            else:
                r[k] = v
        W[key] = r
    return f


def sdset(key, field, value):
    return lambda W: W[key].__setitem__(field, value)


def sdtime(key, at):
    return lambda W: W[key]["change"].__setitem__("recorded_at", at)


def kref(class_id):
    return {"literal": {"type": "CLASS_REF", "class_id": class_id}}


def v3(name):
    """the record uses the vocabulary of 0.3 — it is marked 0.3"""
    return lambda W: W[name].__setitem__("schema_version", SV3)


def isa(name, subj, class_id, quote=("s10", "Синий кит"), marking=PUB, recorded="2026-09-03T09:30:00Z", prj=WK):
    return seq(add_claim(name, prj, subj, "schema.is_a", kref(class_id), quote, marking, recorded), v3(name))


def xclaim(name, subj, pred, obj, quote=("s10", "Синий кит"), marking=PUB, recorded="2026-09-03T10:00:00Z", prj=WK, q=None):
    return seq(add_claim(name, prj, subj, pred, obj, quote, marking, recorded, q=q), v3(name))


def thing(name, identity):
    return seq(add_entity(name, WK, "THING", identity, PUB), v3(name))


def drop(*names):
    def f(W):
        for n in names:
            del W[n]
    return f


def lit(**kw):
    return {"literal": kw}


ATTR_LEN = {"predicate_id": "x.max_length", "name": "наибольшая длина", "value_type": "QUANTITY", "unit": "m",
            "cardinality": "ONE", "required": True}
ATTR_ITIS = {"predicate_id": "x.itis_tsn", "name": "номер ITIS", "value_type": "IDENTIFIER", "scheme": "x.itis",
             "cardinality": "ONE", "required": False}
ATTR_RANK = {"predicate_id": "x.rank", "name": "ранг", "value_type": "STRING", "cardinality": "ONE", "required": False}
ATTR_NOTE = {"predicate_id": "x.note", "name": "заметка", "value_type": "STRING", "cardinality": "MANY", "required": False}
FMT9 = [{"chars": "DIGIT", "min": 1, "max": 9}]
WARN0 = ["CONTRADICTION_SINGLE_VALUED"]   # the one warning of the valid world


def idef(key, did, scheme="x.zoobank", root="CONCEPT", strength="WEAK", priority=5, fmt=FMT9, **kw):
    body = dict(scheme=scheme, name="Тип идентификатора вектора", applies_to_root_type=root, strength=strength, priority=priority, **kw)
    if fmt is not None:
        body["format"] = fmt
    return sd(key, "IdentifierDef", did, 1, "ADD_IDENTIFIER", **body)


def link(key, did, pred="x.related_to", dom="sdf_taxon", rng="sdf_taxon", **kw):
    return sd(key, "LinkDef", did, 1, "ADD_LINK", predicate_id=pred, name="связь вектора", domain_class_id=dom,
              range_class_id=rng, cardinality="MANY", **kw)


def _secret_class(W):
    """an INTERNAL class with an attribute; the skeleton is stated (INTERNAL) to be of it"""
    cls("sd_secret", "sdf_secret", root="THING", marking=INT, attributes=[ATTR_NOTE])(W)
    isa("c_isa_secret", "ent_wk_skeleton", "sdf_secret", ("s20", "скелет синего кита"), INT)(W)


def _borrower(W):
    """a tenant attribute on a class of borrowers in the compliance project"""
    cls("sd_borrower", "sdf_borrower", root="ORGANIZATION", marking=PUB,
        attributes=[{"predicate_id": "x.tender_note", "name": "заметка о закупке", "value_type": "STRING",
                     "cardinality": "MANY", "required": False}])(W)
    isa("c_isa_borrower", "ent_k_developer", "sdf_borrower", ("s7", "Победитель: ООО «Заречье-Девелопмент»"), CONF_CS,
        "2026-09-26T10:00:00Z", "prj_compliance")(W)
    xclaim("c_x_tender", "ent_k_developer", "x.tender_note", lit(type="STRING", value="победитель аукциона"),
           ("s7", "Победитель: ООО «Заречье-Девелопмент»"), CONF_CS, "2026-09-26T10:05:00Z", "prj_compliance")(W)


VECTORS += [
    # ---------------- versions and the journal entry of each version ----------------
    V("P900", [], "версия 2 класса: переименование (RENAME_CLASS) — одно допустимое отличие",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS", name="Таксон (группа организмов)")),
    V("P901", [], "связь выведена из употребления ПОСЛЕ утверждения c43: старое утверждение читается по своей версии схемы",
      pre=nextv("sd_belongs", "sd_belongs_v2", "DEPRECATE_LINK", at=T_LATE, deprecated=True)),
    V("P902", [], "атрибут x.max_length удалён версией 3 ПОСЛЕ утверждения c42: утверждение остаётся действительным",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "REMOVE_ATTRIBUTE", at=T_LATE, attributes=[ATTR_ITIS])),
    V("P903", [], "CHANGE_ATTRIBUTE: кардинальность атрибута ONE → MANY (тип значения не тронут)",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE", attributes=[{**ATTR_LEN, "cardinality": "MANY"}, ATTR_ITIS])),
    V("P904", [], "CHANGE_IDENTIFIER_STRENGTH: сила типа идентификатора tenant STRONG → WEAK",
      pre=nextv("sd_itis", "sd_itis_v2", "CHANGE_IDENTIFIER_STRENGTH", strength="WEAK")),
    V("P905", [], "тот же class_id в другом tenant — другая схема (область схемы — tenant)",
      pre=sd("sd_other", "ClassDef", "sdf_taxon", 1, "ADD_CLASS", tenant="tnt_other", root_type="ORGANIZATION", name="Чужой класс")),
    V("P906", [], "IdentifierDef для встроенной схемы ru.inn: только порядок (приоритет) у корневого типа, без формата",
      pre=idef("sd_inn", "sdf_inn_org", scheme="ru.inn", root="ORGANIZATION", strength="STRONG", priority=2, fmt=None)),
    V("P907", [], "симметричная связь между сущностями одного класса", pre=link("sd_sym", "sdf_sym", symmetric=True)),
    V("N900", ["DUPLICATE_ID"], "та же версия определения дважды (ключ записи схемы — tenant, id, версия)",
      pre=lambda W: W.__setitem__("sd_taxon_dup", copy.deepcopy(W["sd_taxon"]))),
    V("N901", ["SCHEMA_DEF_INVALID"], "версии идут не подряд: есть 1 и 2, добавлена 4 (она в схему не входит: её удаление "
      "атрибута не действует на c42)",
      pre=seq(nextv("sd_whale_v2", "sd_whale_v4", "REMOVE_ATTRIBUTE", attributes=[ATTR_ITIS]), sdset("sd_whale_v4", "version", 4))),
    V("N902", ["TEMPORAL_ORDER_INVALID"], "версия 2 записана раньше версии 1",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS", at="2026-09-02T11:59:30Z", name="Таксон (группа)")),
    V("N903", ["SCHEMA_CHANGE_INVALID"], "запись журнала не равна отличию: имя изменено, заявлено DEPRECATE_CLASS",
      pre=nextv("sd_taxon", "sd_taxon_v2", "DEPRECATE_CLASS", name="Таксон (группа)")),
    V("N904", ["SCHEMA_CHANGE_INVALID"], "два изменения в одной версии: имя и атрибут",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS", name="Таксон (группа)", attributes=[ATTR_RANK])),
    V("N905", ["SCHEMA_CHANGE_INVALID"], "новая версия меняет маркировку определения (замороженное поле)",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS", marking=INT)),
    V("N906", ["SCHEMA_CHANGE_INVALID"], "новая версия меняет родителя класса (замороженное поле)",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "RENAME_CLASS", parent_class_id="sdf_organism")),
    V("N907", ["SCHEMA_CHANGE_INVALID"], "версия после вывода из употребления",
      pre=seq(nextv("sd_exhibit", "sd_exhibit_v2", "DEPRECATE_CLASS", at=T_LATE, deprecated=True),
              nextv("sd_exhibit_v2", "sd_exhibit_v3", "RENAME_CLASS", at="2026-09-04T11:00:00Z", name="Экспонат"))),
    V("N915", ["TEMPORAL_ORDER_INVALID"], "версия 2 записана в ту же секунду, что версия 1 (порядок версий должен быть строгим)",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS", at="2026-09-02T12:00:00Z", name="Таксон (группа)")),
    V("N916", ["SCHEMA_CHANGE_INVALID"], "возврат класса в употребление (снятие deprecated) — вывод из употребления окончателен",
      pre=seq(nextv("sd_exhibit", "sd_exhibit_v2", "DEPRECATE_CLASS", at=T_LATE, deprecated=True),
              nextv("sd_exhibit_v2", "sd_exhibit_v3", "DEPRECATE_CLASS", at="2026-09-04T11:00:00Z", deprecated=None))),
    V("N917", ["SCHEMA_CHANGE_INVALID"], "вывод из употребления вместе с переименованием в одной версии",
      pre=nextv("sd_exhibit", "sd_exhibit_v2", "DEPRECATE_CLASS", at=T_LATE, deprecated=True, name="Экспонат")),
    V("N918", ["SCHEMA_CHANGE_INVALID"], "смена силы идентификатора вместе со сменой формата",
      pre=nextv("sd_itis", "sd_itis_v2", "CHANGE_IDENTIFIER_STRENGTH", strength="WEAK", format=[{"chars": "DIGIT", "min": 1, "max": 8}])),
    V("N919", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE меняет два атрибута сразу",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE",
                attributes=[{**ATTR_LEN, "name": "длина"}, {**ATTR_ITIS, "name": "ITIS"}])),
    V("N935", ["SCHEMA_CHANGE_INVALID"], "ADD_ATTRIBUTE: один атрибут добавлен и один удалён",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "ADD_ATTRIBUTE", at=T_LATE, attributes=[ATTR_LEN, ATTR_RANK])),
    V("N936", ["SCHEMA_CHANGE_INVALID"], "REMOVE_ATTRIBUTE: один атрибут удалён и один добавлен",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "REMOVE_ATTRIBUTE", at=T_LATE, attributes=[ATTR_LEN, ATTR_RANK])),
    V("N937", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE: один атрибут изменён и один добавлен",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE", at=T_LATE,
                attributes=[{**ATTR_LEN, "name": "длина"}, ATTR_ITIS, ATTR_RANK])),
    V("P924", [], "записи версий в наборе идут не по порядку версий (версия 2 раньше версии 1) — порядок записей не важен",
      pre=nextv("sd_taxon", "sd_a_taxon_v2", "RENAME_CLASS", name="Таксон (группа организмов)")),
    V("N908", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE меняет тип значения атрибута (QUANTITY → STRING)",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE",
                attributes=[{"predicate_id": "x.max_length", "name": "наибольшая длина", "value_type": "STRING",
                             "cardinality": "ONE", "required": True}, ATTR_ITIS])),
    V("N939", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE меняет только тип значения (STRING → BOOLEAN; единицы и схемы нет)",
      pre=seq(nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[ATTR_RANK]),
              nextv("sd_taxon_v2", "sd_taxon_v3", "CHANGE_ATTRIBUTE", at="2026-09-02T14:00:00Z", attributes=[{**ATTR_RANK, "value_type": "BOOLEAN"}]))),
    V("N947", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE меняет только единицу атрибута (m → t)",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE", at=T_LATE, attributes=[{**ATTR_LEN, "unit": "t"}, ATTR_ITIS])),
    V("N948", ["SCHEMA_CHANGE_INVALID"], "CHANGE_ATTRIBUTE меняет только схему идентификатора атрибута (x.itis → ru.inn)",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "CHANGE_ATTRIBUTE", at=T_LATE, attributes=[ATTR_LEN, {**ATTR_ITIS, "scheme": "ru.inn"}])),
    V("N909", ["SCHEMA_CHANGE_INVALID"], "первая версия класса с записью журнала ADD_LINK",
      pre=cls("sd_new", "sdf_new", ctype="ADD_LINK")),
    V("N910", ["SCHEMA_CHANGE_INVALID"], "версия 2 ничем не отличается от версии 1",
      pre=nextv("sd_taxon", "sd_taxon_v2", "RENAME_CLASS")),
    V("N911", ["SCHEMA_CHANGE_INVALID"], "ADD_ATTRIBUTE добавляет два атрибута сразу",
      pre=nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[ATTR_RANK, ATTR_NOTE])),
    V("N912", ["SCHEMA_CHANGE_INVALID"], "REMOVE_ATTRIBUTE удаляет два атрибута сразу",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "REMOVE_ATTRIBUTE", at=T_LATE, attributes=None)),
    V("N913", ["SCHEMA_CHANGE_INVALID"], "CHANGE_IDENTIFIER_STRENGTH заявлено, а изменён формат (замороженное поле)",
      pre=nextv("sd_itis", "sd_itis_v2", "CHANGE_IDENTIFIER_STRENGTH", format=[{"chars": "DIGIT", "min": 1, "max": 8}])),
    V("N914", ["SCHEMA_CHANGE_INVALID"], "новая версия связи меняет класс-диапазон (замороженное поле)",
      pre=nextv("sd_belongs", "sd_belongs_v2", "RENAME_LINK", range_class_id="sdf_whale_species")),

    # ---------------- ClassDef ----------------
    V("N920", ["REF_UNRESOLVED"], "родителя класса нет в схеме", pre=cls("sd_new", "sdf_new", parent_class_id="sdf_nowhere")),
    V("N921", ["REF_UNRESOLVED"], "родитель класса есть только в схеме другого tenant (ответ тот же, что «нет»)",
      pre=seq(sd("sd_foreign", "ClassDef", "sdf_foreign", 1, "ADD_CLASS", tenant="tnt_other", root_type="CONCEPT", name="Чужой"),
              cls("sd_new", "sdf_new", parent_class_id="sdf_foreign"))),
    V("N922", ["SCHEMA_DEF_INVALID"], "корневой тип наследника (THING) не равен корневому типу родителя (CONCEPT)",
      pre=cls("sd_new", "sdf_new", root="THING", parent_class_id="sdf_taxon")),
    V("N923", ["SCHEMA_DEF_INVALID"], "циклическое наследование A → B → A",
      pre=seq(cls("sd_a", "sdf_cyc_a", parent_class_id="sdf_cyc_b"), cls("sd_b", "sdf_cyc_b", parent_class_id="sdf_cyc_a"))),
    V("N924", ["SCHEMA_DEF_INVALID"], "класс — родитель самому себе", pre=cls("sd_a", "sdf_self", parent_class_id="sdf_self")),
    V("N925", ["TEMPORAL_ORDER_INVALID"], "родитель записан позже наследника",
      pre=seq(cls("sd_par", "sdf_par", at=T_LATE), cls("sd_new", "sdf_new", parent_class_id="sdf_par"))),
    V("N926", ["SCHEMA_DEF_INVALID"], "родитель выведен из употребления до создания наследника",
      pre=seq(cls("sd_par", "sdf_par", at="2026-09-02T12:20:00Z"),
              nextv("sd_par", "sd_par_v2", "DEPRECATE_CLASS", at="2026-09-02T12:30:00Z", deprecated=True),
              cls("sd_new", "sdf_new", parent_class_id="sdf_par"))),
    V("P908", [], "наследник создан ДО вывода родителя из употребления — остаётся действительным",
      pre=seq(cls("sd_par", "sdf_par", at="2026-09-02T12:20:00Z"), cls("sd_new", "sdf_new", parent_class_id="sdf_par"),
              nextv("sd_par", "sd_par_v2", "DEPRECATE_CLASS", at=T_LATE, deprecated=True))),
    V("N927", ["MARKING_BROADER_THAN_INPUT"], "наследник PUBLIC у родителя INTERNAL",
      pre=seq(cls("sd_par", "sdf_par", at="2026-09-02T12:20:00Z", marking=INT), cls("sd_new", "sdf_new", parent_class_id="sdf_par"))),
    V("N928", ["SCHEMA_DEF_INVALID"], "атрибут повторяется в одном классе",
      pre=cls("sd_new", "sdf_new", attributes=[ATTR_RANK, {**ATTR_RANK, "name": "ранг ещё раз"}])),
    V("N929", ["SCHEMA_DEF_INVALID"], "один предикат определён атрибутами двух классов",
      pre=cls("sd_new", "sdf_new", attributes=[ATTR_LEN])),
    V("N930", ["SCHEMA_DEF_INVALID"], "один предикат определён атрибутом класса и связью",
      pre=link("sd_l", "sdf_lnk", pred="x.max_length")),
    V("N931", ["REF_UNRESOLVED"], "атрибут-идентификатор с типом идентификатора, которого нет в схеме tenant",
      pre=cls("sd_new", "sdf_new", attributes=[{**ATTR_ITIS, "predicate_id": "x.other_id", "scheme": "x.nowhere"}])),
    V("N932", ["IDENTIFIER_SCHEME_INVALID", "REF_UNRESOLVED"], "тип идентификатора определён для другого корневого типа (THING, а класс — CONCEPT)",
      pre=sdset("sd_itis", "applies_to_root_type", "THING")),
    V("N933", ["REF_UNRESOLVED"], "тип идентификатора записан позже версии класса, которая на него ссылается",
      pre=sdtime("sd_itis", "2026-09-02T12:20:00Z")),
    V("N934", ["REF_UNRESOLVED"], "тип идентификатора выведен из употребления до версии класса, которая на него ссылается",
      pre=seq(idef("sd_zb", "sdf_zb", at="2026-09-02T12:20:00Z"),
              nextv("sd_zb", "sd_zb_v2", "DEPRECATE_IDENTIFIER", at="2026-09-02T12:30:00Z", deprecated=True),
              cls("sd_new", "sdf_new", attributes=[{**ATTR_ITIS, "predicate_id": "x.zb_id", "scheme": "x.zoobank"}]))),
    V("N938", ["REF_UNRESOLVED"], "тип идентификатора атрибута определён только в схеме другого tenant",
      pre=seq(sd("sd_fid", "IdentifierDef", "sdf_fid", 1, "ADD_IDENTIFIER", at="2026-09-02T12:20:00Z", tenant="tnt_other",
                 scheme="x.foreign", name="Чужой тип", applies_to_root_type="CONCEPT", strength="WEAK", priority=3, format=FMT9),
              cls("sd_new", "sdf_new", attributes=[{**ATTR_ITIS, "predicate_id": "x.other_id", "scheme": "x.foreign"}]))),
    V("P925", [], "тип идентификатора выведен из употребления ПОСЛЕ атрибута и утверждения; следующая версия класса "
      "(переименование) атрибут не трогает — всё действительно",
      pre=seq(nextv("sd_itis", "sd_itis_v2", "DEPRECATE_IDENTIFIER", at=T_LATE, deprecated=True),
              nextv("sd_whale_v2", "sd_whale_v3", "RENAME_CLASS", at="2026-09-04T11:00:00Z", name="Виды китов"))),
    V("P909", [], "атрибут-идентификатор встроенной схемы ru.inn: определение tenant не требуется",
      pre=cls("sd_new", "sdf_new", root="ORGANIZATION",
              attributes=[{**ATTR_ITIS, "predicate_id": "x.partner_inn", "scheme": "ru.inn"}])),

    # ---------------- LinkDef ----------------
    V("N940", ["REF_UNRESOLVED"], "класса-домена связи нет в схеме", pre=link("sd_l", "sdf_lnk", dom="sdf_nowhere")),
    V("N941", ["REF_UNRESOLVED"], "класса-диапазона связи нет в схеме", pre=link("sd_l", "sdf_lnk", rng="sdf_nowhere")),
    V("N942", ["REF_UNRESOLVED"], "класс-диапазон связи есть только в схеме другого tenant",
      pre=seq(sd("sd_foreign", "ClassDef", "sdf_foreign", 1, "ADD_CLASS", tenant="tnt_other", root_type="CONCEPT", name="Чужой"),
              link("sd_l", "sdf_lnk", rng="sdf_foreign"))),
    V("N943", ["TEMPORAL_ORDER_INVALID"], "связь записана раньше своего класса", pre=link("sd_l", "sdf_lnk", at="2026-09-02T11:59:30Z")),
    V("N944", ["SCHEMA_DEF_INVALID"], "класс-домен связи выведен из употребления до её создания",
      pre=seq(cls("sd_old", "sdf_old", at="2026-09-02T12:20:00Z"),
              nextv("sd_old", "sd_old_v2", "DEPRECATE_CLASS", at="2026-09-02T12:30:00Z", deprecated=True),
              link("sd_l", "sdf_lnk", dom="sdf_old"))),
    V("N945", ["SCHEMA_DEF_INVALID"], "симметричная связь между разными классами",
      pre=link("sd_l", "sdf_lnk", dom="sdf_whale_species", rng="sdf_taxon", symmetric=True)),
    V("N946", ["MARKING_BROADER_THAN_INPUT"], "связь PUBLIC на класс INTERNAL",
      pre=seq(cls("sd_int", "sdf_int", at="2026-09-02T12:20:00Z", marking=INT), link("sd_l", "sdf_lnk", rng="sdf_int"))),

    # ---------------- IdentifierDef ----------------
    V("N950", ["SCHEMA_DEF_INVALID"], "второе определение той же схемы для того же корневого типа",
      pre=idef("sd_itis2", "sdf_itis_again", scheme="x.itis", priority=7)),
    V("P910", [], "та же схема tenant для ДРУГОГО корневого типа — отдельное определение",
      pre=idef("sd_itis2", "sdf_itis_thing", scheme="x.itis", root="THING", priority=1)),
    V("P926", [], "та же схема и тот же корневой тип в схеме ДРУГОГО tenant — отдельное определение",
      pre=sd("sd_fid", "IdentifierDef", "sdf_fid", 1, "ADD_IDENTIFIER", tenant="tnt_other", scheme="x.itis", name="Чужой ITIS",
             applies_to_root_type="CONCEPT", strength="WEAK", priority=1, format=FMT9)),
    V("N951", ["SCHEMA_DEF_INVALID"], "приоритет 1 у корневого типа CONCEPT уже занят", pre=idef("sd_zb", "sdf_zb", priority=1)),
    V("N952", ["SCHEMA_DEF_INVALID"], "формат: min > max", pre=idef("sd_zb", "sdf_zb", fmt=[{"chars": "DIGIT", "min": 5, "max": 4}])),
    V("N953", ["SCHEMA_DEF_INVALID"], "формат: значение длиннее 64 символов",
      pre=idef("sd_zb", "sdf_zb", fmt=[{"chars": "DIGIT", "min": 1, "max": 64}, {"lit": "-"}])),
    V("N954", ["SCHEMA_INVALID"], "схема tenant без формата", pre=idef("sd_zb", "sdf_zb", fmt=None)),
    V("N955", ["SCHEMA_INVALID"], "встроенная схема ru.inn объявлена слабой",
      pre=idef("sd_inn", "sdf_inn_org", scheme="ru.inn", root="ORGANIZATION", strength="WEAK", fmt=None)),
    V("N956", ["SCHEMA_INVALID"], "встроенной схеме ru.inn задан формат (её проверяет ядро)",
      pre=idef("sd_inn", "sdf_inn_org", scheme="ru.inn", root="ORGANIZATION", strength="STRONG")),
    V("N957", ["SCHEMA_INVALID"], "формат как регулярное выражение — не принимается (формат — данные, список сегментов)",
      pre=idef("sd_zb", "sdf_zb", fmt="(a+)+$")),
    V("N958", ["SCHEMA_INVALID"], "схема вне пространства tenant и не встроенная (telegram)",
      pre=idef("sd_zb", "sdf_zb", scheme="telegram")),

    # ---------------- schema.is_a ----------------
    V("N960", ["REF_UNRESOLVED"], "schema.is_a: класса нет в схеме", pre=isa("c_isa", "ent_wk_blue_colour", "sdf_nowhere")),
    V("N961", ["REF_UNRESOLVED"], "schema.is_a: класс есть только в схеме другого tenant",
      pre=seq(sd("sd_foreign", "ClassDef", "sdf_foreign", 1, "ADD_CLASS", tenant="tnt_other", root_type="CONCEPT", name="Чужой"),
              isa("c_isa", "ent_wk_blue_colour", "sdf_foreign"))),
    V("N962", ["TEMPORAL_ORDER_INVALID"], "schema.is_a записано раньше, чем класс",
      pre=seq(cls("sd_new", "sdf_new", at=T_LATE), isa("c_isa", "ent_wk_blue_colour", "sdf_new"))),
    V("N963", ["CLASS_NOT_INSTANTIABLE"], "schema.is_a на абстрактный класс", pre=isa("c_isa", "ent_wk_blue_colour", "sdf_organism")),
    V("N964", ["CLASS_NOT_INSTANTIABLE"], "schema.is_a на класс, выведенный из употребления до записи утверждения",
      pre=seq(cls("sd_new", "sdf_new"), nextv("sd_new", "sd_new_v2", "DEPRECATE_CLASS", at="2026-09-02T14:00:00Z", deprecated=True),
              isa("c_isa", "ent_wk_blue_colour", "sdf_new"))),
    V("P927", [], "schema.is_a записано в ту же секунду, что и класс («записан к моменту t» включает t)",
      pre=seq(cls("sd_new", "sdf_new", at="2026-09-03T09:30:00Z"), isa("c_isa", "ent_wk_blue_colour", "sdf_new"))),
    V("P911", [], "schema.is_a записано ДО вывода класса из употребления — остаётся действительным",
      pre=seq(cls("sd_new", "sdf_new"), isa("c_isa", "ent_wk_blue_colour", "sdf_new"),
              nextv("sd_new", "sd_new_v2", "DEPRECATE_CLASS", at=T_LATE, deprecated=True))),
    V("N965", ["PREDICATE_DOMAIN_VIOLATION"], "schema.is_a: сущность THING, класс с корнем CONCEPT",
      pre=isa("c_isa", "ent_wk_skeleton", "sdf_taxon", ("s20", "скелет синего кита"))),
    V("N966", ["MARKING_BROADER_THAN_INPUT"], "schema.is_a PUBLIC на класс INTERNAL",
      pre=seq(cls("sd_new", "sdf_new", marking=INT), isa("c_isa", "ent_wk_blue_colour", "sdf_new"))),
    V("N967", ["PREDICATE_RANGE_VIOLATION"], "schema.is_a: объект — строка, а не ссылка на класс",
      pre=xclaim("c_isa", "ent_wk_blue_colour", "schema.is_a", lit(type="STRING", value="sdf_taxon"))),
    V("N968", ["SCHEMA_INVALID"], "CLASS_REF с полем tenant_id (класс всегда ищется в tenant проекта)",
      pre=xclaim("c_isa", "ent_wk_blue_colour", "schema.is_a", lit(type="CLASS_REF", class_id="sdf_taxon", tenant_id="tnt_other"))),

    # ---------------- claims with tenant predicates «x.…»: the claim against the schema of its time ----------------
    V("N970", ["PREDICATE_UNKNOWN"], "предиката x.… нет в схеме tenant",
      pre=xclaim("c_x", "ent_wk_blue", "x.nowhere", lit(type="STRING", value="вид"))),
    V("N971", ["PREDICATE_UNKNOWN"], "атрибут добавлен версией 2 ПОЗЖЕ записи утверждения c44", pre=sdtime("sd_whale_v2", T_LATE)),
    V("N972", ["PREDICATE_UNKNOWN"], "атрибут x.max_length удалён версией 3 ДО записи утверждения c42",
      pre=nextv("sd_whale_v2", "sd_whale_v3", "REMOVE_ATTRIBUTE", attributes=[ATTR_ITIS])),
    V("N973", ["PREDICATE_UNKNOWN"], "связь выведена из употребления ДО записи утверждения c43",
      pre=nextv("sd_belongs", "sd_belongs_v2", "DEPRECATE_LINK", deprecated=True)),
    V("N974", ["PREDICATE_UNKNOWN"], "предикат определён только в схеме другого tenant",
      pre=seq(sd("sd_foreign", "ClassDef", "sdf_foreign", 1, "ADD_CLASS", tenant="tnt_other", root_type="CONCEPT", name="Чужой",
                 attributes=[ATTR_RANK]),
              xclaim("c_x", "ent_wk_blue", "x.rank", lit(type="STRING", value="вид")))),
    V("N975", ["PREDICATE_DOMAIN_VIOLATION"], "атрибут класса «Вид китов» у сущности класса «Таксон» (вверх по дереву не наследуется)",
      pre=xclaim("c_x", "ent_wk_baleen", "x.max_length", lit(type="QUANTITY", value="30", unit="m"), ("s10", "усатых китов"))),
    V("P912", [], "атрибут родительского класса у экземпляра наследника (наследование вниз по дереву)",
      pre=seq(nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[ATTR_RANK]),
              xclaim("c_x", "ent_wk_blue", "x.rank", lit(type="STRING", value="вид"), ("s10", "вид")))),
    V("N976", ["PREDICATE_DOMAIN_VIOLATION"], "принадлежность классу записана позже утверждений с его атрибутами",
      pre=setk("c41", "recorded_at", T_LATE)),
    V("N987", ["PREDICATE_DOMAIN_VIOLATION"], "принадлежность классу отозвана до записи нового утверждения с атрибутом "
      "(прежние утверждения, записанные до отзыва, остаются действительными)",
      pre=seq(add_review("rev_c41_w", "c41", "WITHDRAWN", "2026-09-03T09:35:00Z", "2026-09-03T09:40:00Z"),
              xclaim("c_x", "ent_wk_blue", "x.max_length", lit(type="QUANTITY", value="30", unit="m"),
                     ("s10", "Длина синего кита достигает 30 метров"), recorded="2026-09-03T10:00:00Z"))),
    V("N988", ["PREDICATE_DOMAIN_VIOLATION"], "принадлежность классу опровергнута (REFUTED) до записи нового утверждения с атрибутом",
      pre=seq(add_review("rev_c41_r", "c41", "REFUTED", "2026-09-03T09:35:00Z", "2026-09-03T09:40:00Z"),
              xclaim("c_x", "ent_wk_blue", "x.max_length", lit(type="QUANTITY", value="30", unit="m"),
                     ("s10", "Длина синего кита достигает 30 метров"), recorded="2026-09-03T10:00:00Z"))),
    V("N989", ["IDENTIFIER_CHECKSUM_INVALID"], "атрибут tenant со встроенной схемой ru.inn: контрольные цифры значения проверяет ядро",
      pre=seq(nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[{**ATTR_ITIS, "predicate_id": "x.keeper_inn", "scheme": "ru.inn"}]),
              xclaim("c_x", "ent_wk_blue", "x.keeper_inn", lit(type="IDENTIFIER", scheme="ru.inn", value="1234567890"), ("s10", "вид")))),
    V("P931", [], "атрибут tenant со встроенной схемой ru.inn: верный ИНН принят",
      pre=seq(nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[{**ATTR_ITIS, "predicate_id": "x.keeper_inn", "scheme": "ru.inn"}]),
              xclaim("c_x", "ent_wk_blue", "x.keeper_inn", lit(type="IDENTIFIER", scheme="ru.inn", value=INN_DEV), ("s10", "вид")))),
    V("P928", [], "принадлежность отозвана и восстановлена (ACCEPTED) до записи нового утверждения — действует последняя рецензия",
      pre=seq(add_review("rev_c41_w", "c41", "WITHDRAWN", "2026-09-03T09:35:00Z", "2026-09-03T09:40:00Z"),
              add_review("rev_c41_a", "c41", "ACCEPTED", "2026-09-03T09:45:00Z", "2026-09-03T09:50:00Z"),
              xclaim("c_x", "ent_wk_blue", "x.max_length", lit(type="QUANTITY", value="30", unit="m"),
                     ("s10", "Длина синего кита достигает 30 метров"), recorded="2026-09-03T10:00:00Z"))),
    V("P929", [], "принадлежность отозвана ПОСЛЕ утверждений с атрибутами — они остаются; отозванная принадлежность не требует "
      "обязательных атрибутов (предупреждения нет)",
      pre=seq(drop("c42"), add_review("rev_c41_w", "c41", "WITHDRAWN", "2026-09-10T10:00:00Z", "2026-09-10T10:05:00Z")), warn=WARN0),
    V("N977", ["PREDICATE_RANGE_VIOLATION"], "значение атрибута не того типа (STRING вместо QUANTITY)",
      pre=setk("c42", "object", lit(type="STRING", value="тридцать метров"))),
    V("N986", ["PREDICATE_RANGE_VIOLATION"], "значение строкового атрибута — целое число",
      pre=seq(nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[ATTR_RANK]),
              xclaim("c_x", "ent_wk_blue", "x.rank", lit(type="INTEGER", value=7), ("s10", "вид")))),
    V("N978", ["PREDICATE_RANGE_VIOLATION"], "значение атрибута не в той единице (t вместо m)",
      pre=setk("c42", "object", lit(type="QUANTITY", value="30", unit="t"))),
    V("N979", ["PREDICATE_RANGE_VIOLATION"], "объект атрибута — сущность",
      pre=setk("c42", "object", {"entity": "ent_wk_baleen"})),
    V("N980", ["PREDICATE_RANGE_VIOLATION"], "идентификатор не той схемы, что объявлена у атрибута",
      pre=setk("c44", "object", lit(type="IDENTIFIER", scheme="telegram", value="180528"))),
    V("N981", ["PREDICATE_RANGE_VIOLATION"], "объект связи — литерал", pre=setk("c43", "object", lit(type="STRING", value="усатые киты"))),
    V("N982", ["PREDICATE_RANGE_VIOLATION"], "объект связи не является экземпляром класса-диапазона",
      pre=setk("c43", "object", {"entity": "ent_wk_blue_colour"})),
    V("N983", ["QUALIFIER_INVALID"], "у предиката схемы tenant квалификатор", pre=setq("c42", "property", "max_length")),
    V("N984", ["MARKING_BROADER_THAN_INPUT"], "утверждение PUBLIC с атрибутом класса INTERNAL",
      pre=seq(_secret_class, xclaim("c_x", "ent_wk_skeleton", "x.note", lit(type="STRING", value="скелет"), ("s20", "скелет синего кита")))),
    V("P913", [], "утверждение INTERNAL с атрибутом класса INTERNAL",
      pre=seq(_secret_class, xclaim("c_x", "ent_wk_skeleton", "x.note", lit(type="STRING", value="скелет"),
                                    ("s20", "скелет синего кита"), INT))),
    V("P914", [], "два разных значения атрибута с кардинальностью ONE — предупреждение о расхождении источников",
      pre=xclaim("c_x", "ent_wk_blue", "x.max_length", lit(type="QUANTITY", value="33", unit="m"),
                 ("s10", "Длина синего кита достигает 30 метров")), warn=WARN0 * 2),
    V("N985", ["CHECK_CLAIM_DIMENSION_MISMATCH"], "утверждение с предикатом схемы tenant в измерении Проверки (у таких предикатов нет измерений риска)",
      pre=seq(_borrower, add_finding("chk_tenders_1", finding("TENDERS", "FOUND", "LOW", ["c_x_tender"])))),
    V("P915", [], "мир с атрибутом tenant в проекте проверок без ссылки из Проверки", pre=_borrower),

    # ---------------- required attributes (warning) ----------------
    V("P916", [], "у экземпляра класса нет обязательного атрибута — предупреждение",
      pre=drop("c42"), warn=WARN0 + ["REQUIRED_ATTRIBUTE_MISSING"]),
    V("P917", [], "обязательный атрибут есть, но утверждение отозвано — предупреждение",
      pre=add_review("rev_c42_w", "c42", "WITHDRAWN", "2026-09-10T10:00:00Z", "2026-09-10T10:05:00Z"),
      warn=WARN0 + ["REQUIRED_ATTRIBUTE_MISSING"]),
    V("P918", [], "обязательный атрибут родителя не заполнен у экземпляров родителя и наследника — два предупреждения",
      pre=nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", attributes=[{**ATTR_RANK, "required": True}]),
      warn=WARN0 + ["REQUIRED_ATTRIBUTE_MISSING"] * 2),
    V("P919", [], "обязательный атрибут удалён последней версией класса — предупреждения нет",
      pre=seq(drop("c42"), nextv("sd_whale_v2", "sd_whale_v3", "REMOVE_ATTRIBUTE", at=T_LATE, attributes=[ATTR_ITIS])), warn=WARN0),

    # ---------------- identifier literals of tenant schemes ----------------
    V("N990", ["IDENTIFIER_SCHEME_INVALID"], "значение не в формате схемы tenant (буква среди цифр)",
      pre=setk("c44", "object", lit(type="IDENTIFIER", scheme="x.itis", value="18O528"))),
    V("N991", ["IDENTIFIER_SCHEME_INVALID"], "значение длиннее формата (10 цифр при максимуме 9)",
      pre=setk("c44", "object", lit(type="IDENTIFIER", scheme="x.itis", value="1805281234"))),
    V("N992", ["IDENTIFIER_SCHEME_INVALID"], "значение с пробелом в конце (формат — полное совпадение)",
      pre=setk("c44", "object", lit(type="IDENTIFIER", scheme="x.itis", value="180528 "))),
    V("N993", ["IDENTIFIER_SCHEME_INVALID"], "тип идентификатора выведен из употребления до записи утверждения",
      pre=nextv("sd_itis", "sd_itis_v2", "DEPRECATE_IDENTIFIER", deprecated=True)),
    V("P920", [], "формат с литералом: «ZB-» + 6 знаков",
      pre=seq(idef("sd_zb", "sdf_zb", at="2026-09-02T12:20:00Z",
                   fmt=[{"lit": "Z"}, {"lit": "B"}, {"lit": "-"}, {"chars": "ALNUM_UPPER", "min": 6, "max": 6}]),
              nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", at="2026-09-02T12:30:00Z",
                    attributes=[{**ATTR_ITIS, "predicate_id": "x.zb_id", "scheme": "x.zoobank"}]),
              xclaim("c_x", "ent_wk_blue", "x.zb_id", lit(type="IDENTIFIER", scheme="x.zoobank", value="ZB-A1B2C3")))),
    V("N994", ["IDENTIFIER_SCHEME_INVALID"], "литерал формата не совпал («ZB.» вместо «ZB-»: точка не «любой символ»)",
      pre=seq(idef("sd_zb", "sdf_zb", at="2026-09-02T12:20:00Z",
                   fmt=[{"lit": "Z"}, {"lit": "B"}, {"lit": "."}, {"chars": "ALNUM_UPPER", "min": 6, "max": 6}]),
              nextv("sd_taxon", "sd_taxon_v2", "ADD_ATTRIBUTE", at="2026-09-02T12:30:00Z",
                    attributes=[{**ATTR_ITIS, "predicate_id": "x.zb_id", "scheme": "x.zoobank"}]),
              xclaim("c_x", "ent_wk_blue", "x.zb_id", lit(type="IDENTIFIER", scheme="x.zoobank", value="ZB-A1B2C3")))),

    # ---------------- record versions: 0.2 records stay valid, 0.3 vocabulary needs a 0.3 record ----------------
    V("P930", [], "записи прежних девяти видов в мире помечены core-ontology/0.2 (их производителям и адресам менять нечего); "
      "та же запись с пометкой core-ontology/0.3 тоже действительна",
      post=lambda d, ix, e: rec(d, ix, "ent_ts_pump").__setitem__("schema_version", "core-ontology/0.3")),
    V("N996", ["SCHEMA_INVALID"], "сущность THING в записи, помеченной core-ontology/0.2",
      post=lambda d, ix, e: rec(d, ix, "ent_wk_skeleton").__setitem__("schema_version", "core-ontology/0.2")),
    V("N997", ["SCHEMA_INVALID"], "schema.is_a в записи, помеченной core-ontology/0.2",
      pre=lambda W: W["c41"].__setitem__("schema_version", "core-ontology/0.2")),
    V("N998", ["SCHEMA_INVALID"], "утверждение с предикатом tenant в записи, помеченной core-ontology/0.2",
      pre=lambda W: W["c42"].__setitem__("schema_version", "core-ontology/0.2")),
    V("N999", ["SCHEMA_INVALID"], "определение класса с пометкой core-ontology/0.2",
      pre=lambda W: W["sd_taxon"].__setitem__("schema_version", "core-ontology/0.2")),

    # ---------------- THING (the tenth root type) ----------------
    V("N995", ["ENTITY_DUPLICATE_IN_PROJECT"], "вторая вещь с тем же названием в том же пространстве имён",
      pre=thing("ent_wk_skeleton2", {"label": "скелет  синего кита", "lang": "ru", "namespace": "museum"})),
    V("P921", [], "одноимённые вещи с разными пометками — разные сущности",
      pre=seq(setid("ent_wk_skeleton", "disambiguator", "zoo-museum"),
              thing("ent_wk_skeleton2", {"label": "Скелет синего кита", "lang": "ru", "namespace": "museum",
                                                           "disambiguator": "city-museum"}))),
    V("P922", [], "решение аналитика уточняет вещь пометкой (как понятие)",
      pre=_qualify("idd_skeleton", WK, "ent_wk_skeleton", disambiguator="zoo-museum")),
    V("P923", [], "вещи, совпадающие только по скелету (латинская «c»), — предупреждение, не ошибка",
      pre=thing("ent_wk_skeleton2", {"label": "Cкелет синего кита", "lang": "ru", "namespace": "museum"}),
      warn=["POSSIBLE_DUPLICATE"] + WARN0),
]


# ---- Cycle 10: datasets (D27.2, D27.4) — a version of a dataset is a Source whose bytes are the manifest; evidence ROW ----
# The valid world holds one version (s30: a registry of five legal entities, two files) and one claim that rests on a
# row of it (c50: the registered address of the developer; the key and the address are quoted, the rest are leaves).
import json as _json

from dataset import DatasetVersion
from fixtures import REGISTRY_COLUMNS, REGISTRY_ROWS, SV4, demo_registry
from jcs import canon as _canon
from validator import cell_leaf as _cell_leaf, merkle_root as _merkle_root, row_leaf as _row_leaf

ROW0 = REGISTRY_ROWS[0]
ADDR_TRUB = REGISTRY_ROWS[1]["address"]
CASE_COL = {"name": "case_no", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.arbitr", "predicate": "court.party_to_case"}
RIVAL_COL = {"name": "rival_ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn", "predicate": "competitor.competes_with"}


def _sid(W, name):
    return "src:sha256:" + hashlib.sha256(W[name]["content_inline"].encode("utf-8")).hexdigest()


def mset(fn, src="s30"):
    """edit the manifest of the dataset version (its bytes stay canonical; the address of the source follows)"""
    def f(W):
        m = _json.loads(W[src]["content_inline"])
        fn(m)
        W[src]["content_inline"] = _canon(m)
    return f


def mraw(fn):
    return lambda W: W["s30"].__setitem__("content_inline", fn(W["s30"]["content_inline"]))


def regds(make=None, nofiles=False, **kw):
    """replace the dataset version s30: demo_registry(**kw) or make(W); nofiles: its row files are not in the store"""
    def f(W):
        dv = make(W) if make else demo_registry(**kw)
        if nofiles:
            dv.files = []
        W["__datasets__"]["s30"] = dv
        W["s30"]["content_inline"] = dv.manifest_bytes.decode("utf-8")
    return f


def add_ds(name, dv, tenant=T, observed="2026-09-04T08:00:00Z"):
    def f(W):
        W["__datasets__"][name] = dv
        W[name] = {"kind": "Source", "schema_version": SV4, "tenant_id": tenant, "source_kind": "DATASET_VERSION",
                   "media_type": "application/vnd.ac.dataset-manifest+json", "language": "ru", "title": name,
                   "content_inline": dv.manifest_bytes.decode("utf-8"), "marking": PUB,
                   "observations": [{"observed_at": observed, "origin_uri": f"urn:demo:{name}", "observed_by": "svc_dataset_loader"}]}
    return f


def rowev(key, quote):
    """c50 rests on the row with this key (a callable gets the dataset version), quoting these columns"""
    def f(W):
        k = key(W["__datasets__"]["s30"]) if callable(key) else key
        W["c50"]["evidence"] = [{"$row": ["s30", k, list(quote)]}]
    return f


def obj50(**kw):
    return setk("c50", "object", {"literal": kw})


def ev0(fn):
    """tamper with the finished ROW evidence of c50 (before the claim is addressed)"""
    return evp("c50", lambda evs: fn(evs[0]))


def _cell(ev, name):
    return next(x for x in ev["cells"] if x["name"] == name)


def _flip(h):
    return ("0" if h[0] != "0" else "1") + h[1:]


def _hide(ev, name):
    c = _cell(ev, name)
    leaf = _cell_leaf(bytes.fromhex(c["salt"]), name, c["value"]).hex()
    c.clear()
    c.update(name=name, leaf=leaf)


def rows_with(i=0, **changes):
    rows = copy.deepcopy(REGISTRY_ROWS)
    rows[i].update(changes)
    return rows


def cols_with(*extra, **patch):
    """registry columns: patch = {column: {field: value | None}}, extra columns appended"""
    cols = copy.deepcopy(REGISTRY_COLUMNS)
    for c in cols:
        for k, v in patch.get(c["name"], {}).items():
            if v is None:
                c.pop(k, None)
            else:
                c[k] = v
    return cols + [copy.deepcopy(x) for x in extra]


def _foreign_row(ev):
    """a row that is NOT in the version: consistent cells and row hash (a hidden cell differs), the proof of the real row"""
    other = demo_registry(rows=rows_with(director="Подставной Иван Иванович")).evidence([OGRN_DEV], ["address"])
    ev.update(row_sha256=other["row_sha256"], cells=other["cells"])


_DV_PREV = demo_registry(rows=REGISTRY_ROWS[:3])
_DV_OTHER = DatasetVersion("dst_other_registry", T, "2026-08-01", REGISTRY_COLUMNS, ["ogrn"], REGISTRY_ROWS[:2], chunk_rows=4)
_CASE = dict(type="IDENTIFIER", scheme="ru.arbitr", value="А41-12345/2026")


def _case_claim(W):
    """the registry also lists a court case of each company; c50 states the case of the developer from its row"""
    regds(columns=cols_with(CASE_COL), rows=[dict(r, case_no="А41-12345/2026" if n == 0 else None) for n, r in enumerate(REGISTRY_ROWS)])(W)
    W["c50"].update(predicate="court.party_to_case", object={"literal": dict(_CASE)}, qualifiers=copy.deepcopy(W["c19"]["qualifiers"]))
    rowev([OGRN_DEV], ["case_no"])(W)


def _rival_claim(rival=OGRN_TRUB, col=RIVAL_COL):
    """the registry names a competitor of each company by OGRN; c50 states «developer competes with Трубопроводстрой»"""
    def f(W):
        add_entity("ent_k_trub", "prj_compliance", "ORGANIZATION", {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU",
                                                                    "ogrn": OGRN_TRUB, "inn": INN_TRUB}, CONF_CS)(W)
        regds(columns=cols_with(col), rows=[dict(r, **{col["name"]: rival if n == 0 else None}) for n, r in enumerate(REGISTRY_ROWS)])(W)
        W["c50"].update(predicate="competitor.competes_with", object={"entity": "ent_k_trub"})
        rowev([OGRN_DEV], [col["name"]])(W)
    return f


_ROWS13 = [{"ogrn": "10%011d" % n, "inn": None, "name": "Запись %d" % n, "address": None, "director": None, "registered_on": None,
            "active": None, "employees": n} for n in range(4)] + REGISTRY_ROWS + [
           {"ogrn": "90%011d" % n, "inn": None, "name": "Запись %d" % n, "address": None, "director": None, "registered_on": None,
            "active": None, "employees": n} for n in range(4)]

MI, RI = ["DATASET_MANIFEST_INVALID"], ["EVIDENCE_ROW_INVALID"]


def refile(fn, n=0, fix_root=False, **kw):
    """the row file n of the version is rewritten by fn(list of row dicts {h,k,s,v}) -> list of lines (dicts or bytes);
    the manifest takes the new address and length (and, with fix_root, the root of the new rows) — everything else stays"""
    def make(W):
        dv = demo_registry(**kw)
        addr, data = dv.files[n]
        rows = [_json.loads(x) for x in data.decode("utf-8").splitlines()]
        out = fn(rows)
        lines = out if isinstance(out, bytes) else b"".join((x if isinstance(x, bytes) else _canon(x).encode("utf-8")) + b"\n" for x in out)
        f = dv.manifest["files"][n]
        f["object"], f["byte_length"] = "sha256:" + hashlib.sha256(lines).hexdigest(), len(lines)
        if fix_root:
            f["rows_root"] = _merkle_root([_row_leaf(bytes.fromhex(x["h"])) for x in out]).hex()
        dv.files[n] = (f["object"], lines)
        dv.manifest_bytes = _canon(dv.manifest).encode("utf-8")
        dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
        return dv
    return regds(make)


def _set(row, **kw):
    row.update(kw)
    return row


def _rehash(row):
    """the hash of a file row recomputed from ITS values and ITS secret (a producer that is consistent with itself)"""
    from validator import cell_salt as _cs
    names = [c["name"] for c in REGISTRY_COLUMNS]
    secret = bytes.fromhex(row["s"] + ("0" if len(row["s"]) % 2 else ""))
    row["h"] = _merkle_root([_cell_leaf(_cs(secret, n), n, v) for n, v in zip(names, row["v"])]).hex()
    return row


def _lie_rows(dv):
    """the rows of file 0 are said to be 3 (they are 4, and the root is the root of 4); row_count follows"""
    dv.manifest["files"][0]["rows"], dv.manifest["row_count"] = 3, 4
    dv.manifest_bytes = _canon(dv.manifest).encode("utf-8")
    dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
    return dv


def _key_in_two_files():
    """the version of five rows plus a second file that repeats the key of «Бета» with another address"""
    a = demo_registry(chunk_rows=5)
    b = demo_registry(rows=[dict(REGISTRY_ROWS[3], address="г. Москва, ул. Другая, д. 2")], chunk_rows=5)
    a.manifest["files"] += b.manifest["files"]
    a.manifest["row_count"] = 6
    a.files += b.files
    a.manifest_bytes = _canon(a.manifest).encode("utf-8")
    a.source_id = "src:sha256:" + hashlib.sha256(a.manifest_bytes).hexdigest()
    return a


def _producer_order(W):
    """a producer hashed the cells in an order other than the manifest's and gives the cells in ITS order"""
    c = REGISTRY_COLUMNS
    dv = demo_registry(columns=c[:2] + [c[3], c[2]] + c[4:])        # «address» before «name»: two columns of one type
    dv.manifest["columns"] = copy.deepcopy(REGISTRY_COLUMNS)
    dv.files = []
    dv.manifest_bytes = _canon(dv.manifest).encode("utf-8")
    dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
    return dv


def _two_rows_as_one(W):
    """the manifest says the file has ONE row, its root is the root of TWO; the developer is the right leaf"""
    dv = demo_registry(rows=[REGISTRY_ROWS[2], REGISTRY_ROWS[0]], chunk_rows=2)
    assert dv.rows[1][1] == [OGRN_DEV]
    dv.manifest["row_count"] = 1
    dv.manifest["files"][0]["rows"] = 1
    dv.files = []
    dv.manifest_bytes = _canon(dv.manifest).encode("utf-8")
    dv.source_id = "src:sha256:" + hashlib.sha256(dv.manifest_bytes).hexdigest()
    return dv


def _rival_merged(at):
    """the row names the competitor by the OGRN of «Альфа-Сервис», which was merged into the object of the claim at «at»"""
    og2, in2 = REGISTRY_ROWS[2]["ogrn"], REGISTRY_ROWS[2]["inn"]
    return seq(_rival_claim(rival=og2),
               add_entity("ent_k_alfa", "prj_compliance", "ORGANIZATION", {"name": "ООО «Альфа-Сервис»", "jurisdiction": "RU", "ogrn": og2,
                                                                         "inn": in2}, CONF_CS, "MERGED", "ent_k_trub", at))


def _birth_claim(W):
    """a dataset of persons: the column of dates is declared for person.birth_date; c50 states the date as a DATE literal"""
    inn = W["ent_k_lomov"]["identity"]["inn"]
    pd = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
    cols = [{"name": "inn", "type": "STRING", "marking": pd, "identifier_scheme": "ru.inn"},
            {"name": "born", "type": "DATE", "marking": pd, "predicate": "person.birth_date"}]
    regds(lambda W_: DatasetVersion("dst_persons_demo", T, "2026-09-01", cols, ["inn"], [{"inn": inn, "born": "1971-03-14"}],
                                    subject=("inn",), dataset_key=b"k" * 32))(W)
    W["c50"].update(subject="ent_k_lomov", predicate="person.birth_date", object={"literal": {"type": "DATE", "value": "1971-03-14"}},
                    marking=CONF_CS_PD)
    rowev([inn], ["born"])(W)

VECTORS += [
    # ---------------- the manifest ----------------
    V("NR01", MI, "манифест не в канонической форме (пробелы)", pre=mraw(lambda t: _json.dumps(_json.loads(t), ensure_ascii=False))),
    V("NR02", MI, "повторяющийся ключ в манифесте", pre=mraw(lambda t: t.replace('"row_count":5', '"row_count":5,"row_count":5'))),
    V("NR03", MI, "байты версии набора — не JSON", pre=mraw(lambda t: "реестр юридических лиц")),
    V("NR04", MI, "манифест с неизвестным полем", pre=mset(lambda m: m.__setitem__("owner", "ФНС"))),
    V("NR05", MI, "манифест другого формата", pre=mset(lambda m: m.__setitem__("manifest_format", "ac-dataset-manifest/9.9"))),
    V("NR06", MI, "имя колонки повторяется", pre=mset(lambda m: m["columns"][2].__setitem__("name", "inn"))),
    V("NR07", MI, "ключ набора называет колонку, которой нет", pre=mset(lambda m: m.__setitem__("key", ["ogrn", "kpp"]))),
    V("NR08", MI, "row_count не равен сумме строк файлов", pre=mset(lambda m: m.__setitem__("row_count", 6))),
    V("NR09", MI, "схема идентификатора у нестроковой колонки", pre=mset(lambda m: m["columns"][7].__setitem__("identifier_scheme", "ru.inn"))),
    V("NR10", MI, "манифест другого tenant, чем источник", pre=mset(lambda m: m.__setitem__("tenant_id", "tnt_other"))),
    V("NR11", MI, "дробное число в манифесте", pre=mraw(lambda t: t.replace('"row_count":5', '"row_count":5.5'))),
    V("NR12", MI, "previous — источник, который не версия набора", pre=lambda W: regds(previous=_sid(W, "s7"))(W)),
    V("NR13", MI, "previous — версия другого набора данных", pre=seq(add_ds("s29", _DV_OTHER), regds(previous=_DV_OTHER.source_id))),
    V("PR22", [], "previous называет источник другого tenant — для этого tenant он неизвестен",
      pre=seq(add_source("s99", "Чужой tenant.", tenant="tnt_other"), lambda W: regds(previous=_sid(W, "s99"))(W))),
    V("PR23", [], "словарь 0.3 (предикат tenant) в записи, помеченной core-ontology/0.4", pre=setk("c42", "schema_version", SV4)),
    V("NR15", MI, "subject называет колонку без схемы идентификатора", pre=mset(lambda m: m.__setitem__("subject", ["ogrn", "name"]))),
    V("NR16", MI, "subject называет колонку, которой нет", pre=mset(lambda m: m.__setitem__("subject", ["kpp"]))),
    V("NR17", MI, "имя колонки не по шаблону", pre=mset(lambda m: m["columns"][2].__setitem__("name", "Наименование"))),
    V("NR18", MI, "файл без строк в манифесте", pre=mset(lambda m: (m["files"][1].__setitem__("rows", 0), m.__setitem__("row_count", 4)))),
    V("NR19", MI, "манифест в UTF-8 с BOM", pre=mraw(lambda t: "﻿" + t)),
    V("NR1E", MI, "целое вне 2^53 в манифесте", pre=mraw(lambda t: t.replace('"row_count":5', '"row_count":1152921504606846976'))),
    V("NR1A", ["SCHEMA_INVALID"], "версия набора данных с типом содержимого text/plain", pre=setk("s30", "media_type", "text/plain; charset=utf-8")),
    V("NR1B", ["SCHEMA_INVALID"], "версия набора данных в записи, помеченной core-ontology/0.3", pre=setk("s30", "schema_version", SV3)),
    V("NR1C", ["SCHEMA_INVALID"], "доказательство-строка в утверждении, помеченном core-ontology/0.3", pre=setk("c50", "schema_version", SV3)),
    V("NR1F", ["SCHEMA_INVALID"], "набор записей объявлен core-ontology/0.3, а несёт записи 0.4",
      post=lambda d, ix, e: d.__setitem__("ontology_version", SV3)),
    V("PR25", [], "набор без записей 0.4 может быть объявлен core-ontology/0.3",
      post=lambda d, ix, e: (d.__setitem__("records", [r for r in d["records"] if r["schema_version"] != SV4]),
                             d.__setitem__("ontology_version", SV3))),
    V("NR1D", ["SOURCE_CONTENT_UNAVAILABLE"], "манифеста версии набора нет — строку проверить нечем", post=_drop_bytes("s30")),
    V("PR01", [], "версия набора со ссылкой на предыдущую версию того же набора", pre=seq(add_ds("s29", _DV_PREV), regds(previous=_DV_PREV.source_id))),
    V("PR02", [], "предыдущая версия не входит в этот набор записей — ссылка допустима", pre=regds(previous=_DV_PREV.source_id)),
    V("PR03", [], "версия набора, на строки которой никто не ссылается", pre=add_ds("s29", _DV_OTHER)),

    # ---------------- the row: cells, hash of the row, proof of inclusion ----------------
    V("NR20", RI, "доказательство-строка ссылается на источник, который не версия набора данных",
      pre=seq(setk("s30", "source_kind", "DOCUMENT"), setk("s30", "media_type", "text/plain; charset=utf-8"))),
    V("NR21", RI, "ячейки не в порядке колонок манифеста", pre=ev0(lambda ev: ev["cells"].reverse())),
    V("NR22", RI, "одной ячейки нет", pre=ev0(lambda ev: ev["cells"].pop())),
    V("NR23", RI, "лишняя ячейка", pre=ev0(lambda ev: ev["cells"].append(copy.deepcopy(ev["cells"][-1])))),
    V("NR24", RI, "значение процитированной ячейки подменено (и утверждение повторяет подмену)",
      pre=seq(obj50(type="STRING", value="г. Москва, ул. Выдуманная, д. 1"),
              ev0(lambda ev: _cell(ev, "address").__setitem__("value", "г. Москва, ул. Выдуманная, д. 1")))),
    V("NR25", RI, "соль ячейки подменена", pre=ev0(lambda ev: _cell(ev, "address").__setitem__("salt", _flip(_cell(ev, "address")["salt"])))),
    V("NR26", RI, "лист скрытой ячейки подменён", pre=ev0(lambda ev: _cell(ev, "director").__setitem__("leaf", _flip(_cell(ev, "director")["leaf"])))),
    V("NR27", RI, "хэш строки подменён", pre=ev0(lambda ev: ev.__setitem__("row_sha256", _flip(ev["row_sha256"])))),
    V("NR28", RI, "строки нет в версии набора: ячейки и хэш строки согласованы, но доказательство включения — от другой строки",
      pre=ev0(_foreign_row)),
    V("NR29", RI, "хэш в доказательстве включения подменён", pre=seq(regds(chunk_rows=4096), ev0(lambda ev: ev["proof"]["hashes"].__setitem__(0, _flip(ev["proof"]["hashes"][0]))))),
    V("NR30", RI, "номер строки в файле не тот", pre=seq(regds(chunk_rows=4096), ev0(lambda ev: ev["proof"].__setitem__("index", ev["proof"]["index"] - 1)))),
    V("NR31", RI, "номер строки за пределами файла", pre=seq(regds(chunk_rows=4096), ev0(lambda ev: ev["proof"].__setitem__("index", 5)))),
    V("NR32", RI, "файла с таким номером в манифесте нет", pre=ev0(lambda ev: ev["proof"].__setitem__("file", 2))),
    V("NR33", RI, "строка заявлена в другом файле версии", pre=seq(regds(chunk_rows=2), ev0(lambda ev: ev["proof"].__setitem__("file", 0)))),
    V("NR34", RI, "доказательство включения с лишним хэшем", pre=seq(regds(chunk_rows=4096), ev0(lambda ev: ev["proof"]["hashes"].append("0" * 64)))),
    V("NR35", RI, "доказательство включения укорочено", pre=seq(regds(chunk_rows=4096), ev0(lambda ev: ev["proof"]["hashes"].pop()))),
    V("NR36", RI, "строка единственного в файле места заявлена с непустым путём",
      pre=seq(regds(chunk_rows=1), ev0(lambda ev: ev["proof"]["hashes"].append(ev["row_sha256"])))),
    V("PR19", [], "дерево из 13 строк: путь из нескольких хэшей", pre=regds(chunk_rows=4096, rows=_ROWS13)),
    V("NR37", RI, "дерево из 13 строк: подменён последний хэш пути",
      pre=seq(regds(chunk_rows=4096, rows=_ROWS13), ev0(lambda ev: ev["proof"]["hashes"].__setitem__(-1, _flip(ev["proof"]["hashes"][-1]))))),
    V("NR38", RI, "дерево из 13 строк: хэши пути переставлены",
      pre=seq(regds(chunk_rows=4096, rows=_ROWS13), ev0(lambda ev: ev["proof"]["hashes"].reverse()))),
    V("NR39", RI, "дерево из 13 строк: путь верен, но номер строки соседний",
      pre=seq(regds(chunk_rows=4096, rows=_ROWS13), ev0(lambda ev: ev["proof"].__setitem__("index", ev["proof"]["index"] ^ 1)))),
    V("NR3A", RI, "файл из одной строки, номер строки вне файла, путь пуст",
      pre=seq(regds(chunk_rows=1), ev0(lambda ev: ev["proof"].__setitem__("index", 3)))),
    V("PR04", [], "файл из одной строки: путь доказательства пуст", pre=regds(chunk_rows=1)),
    V("PR05", [], "все строки в одном файле (дерево из пяти листьев)", pre=regds(chunk_rows=4096)),
    V("PR06", [], "файлы по две строки", pre=regds(chunk_rows=2)),
    V("PR07", [], "строка из первого файла версии (файлы по три строки)", pre=regds(chunk_rows=3, rows=REGISTRY_ROWS[:1] + [dict(r, ogrn=r["ogrn"]) for r in REGISTRY_ROWS[1:]] + [
        {"ogrn": "9" * 13, "inn": None, "name": "Запись-заполнитель", "address": None, "director": None, "registered_on": None, "active": None, "employees": None}])),

    # ---------------- the key of the row ----------------
    V("NR40", RI, "колонка ключа скрыта", pre=ev0(lambda ev: _hide(ev, "ogrn"))),
    V("NR41", RI, "row_key не равен значениям колонок ключа", pre=ev0(lambda ev: ev.__setitem__("row_key", [OGRN_TRUB]))),
    V("NR42", RI, "row_key не указан у набора с ключом", pre=ev0(lambda ev: ev.pop("row_key"))),
    V("NR43", RI, "row_key указан у набора без ключа",
      pre=seq(regds(key=()), rowev(lambda dv: next(k for k, kv, s, h, vals in dv.rows if vals[0] == OGRN_DEV), ["ogrn", "address"]),
              ev0(lambda ev: ev.__setitem__("row_key", [OGRN_DEV])))),
    V("NR44", RI, "составной ключ: процитирована только одна его колонка",
      pre=seq(regds(key=("ogrn", "inn")), rowev([OGRN_DEV, INN_DEV], ["address"]), ev0(lambda ev: _hide(ev, "inn")))),
    V("NR45", RI, "составной ключ: одна колонка скрыта, row_key укорочен до процитированных",
      pre=seq(regds(key=("ogrn", "inn")), rowev([OGRN_DEV, INN_DEV], ["address"]),
              ev0(lambda ev: (_hide(ev, "inn"), ev.__setitem__("row_key", [OGRN_DEV]))))),
    V("PR08", [], "набор без ключа: строка называется своим хэшем",
      pre=seq(regds(key=()), rowev(lambda dv: next(k for k, kv, s, h, vals in dv.rows if vals[0] == OGRN_DEV), ["ogrn", "address"]))),
    V("PR24", [], "ключ строки с табуляцией: ключ — те же данные, что и ячейки",
      pre=seq(regds(key=("name",), subject=("ogrn",), rows=rows_with(name="ООО\t«Заречье»")), rowev(["ООО\t«Заречье»"], ["address", "ogrn"]))),
    V("PR09", [], "составной ключ", pre=seq(regds(key=("ogrn", "inn")), rowev([OGRN_DEV, INN_DEV], ["address"]))),

    # ---------------- values of the cells fit the types of the columns ----------------
    V("NR50", RI, "строка в целочисленной колонке", pre=seq(regds(rows=rows_with(employees="48"), check=False, nofiles=True), rowev([OGRN_DEV], ["address", "employees"]))),
    V("NR51", RI, "число в булевой колонке", pre=seq(regds(rows=rows_with(active=1), check=False, nofiles=True), rowev([OGRN_DEV], ["address", "active"]))),
    V("NR52", RI, "true в целочисленной колонке", pre=seq(regds(rows=rows_with(employees=True), check=False, nofiles=True), rowev([OGRN_DEV], ["address", "employees"]))),
    V("NR53", RI, "несуществующая дата в колонке дат", pre=seq(regds(rows=rows_with(registered_on="2021-02-30"), check=False, nofiles=True),
                                                              rowev([OGRN_DEV], ["address", "registered_on"]))),
    V("NR54", RI, "дата не в виде ГГГГ-ММ-ДД", pre=seq(regds(rows=rows_with(registered_on="20210212"), check=False, nofiles=True),
                                                       rowev([OGRN_DEV], ["address", "registered_on"]))),
    V("NR55", RI, "символ NUL в строковой ячейке", pre=seq(regds(rows=rows_with(name="ООО\u0000«Заречье»"), check=False, nofiles=True), rowev([OGRN_DEV], ["address", "name"]))),
    V("NR56", RI, "число в строковой колонке", pre=seq(regds(rows=rows_with(name=7), check=False, nofiles=True), rowev([OGRN_DEV], ["address", "name"]))),
    V("PR10", [], "процитированы ячейки всех типов (строка, дата, булево, целое)",
      pre=rowev([OGRN_DEV], ["address", "name", "registered_on", "active", "employees"])),
    V("PR11", [], "пустые ячейки процитированы", pre=seq(regds(rows=rows_with(employees=None, registered_on=None, active=None)),
                                                         rowev([OGRN_DEV], ["address", "registered_on", "active", "employees"]))),
    V("PR12", [], "перевод строки и табуляция в строковой ячейке — свободный текст",
      pre=seq(regds(rows=rows_with(address="г. Заречный,\n\tул. Заречная, д. 1")), obj50(type="STRING", value="г. Заречный,\n\tул. Заречная, д. 1"))),

    # ---------------- the row is about the subject of the claim ----------------
    V("NR60", RI, "строка другой организации: адрес «Трубопроводстроя» приписан девелоперу",
      pre=seq(rowev([OGRN_TRUB], ["address"]), obj50(type="STRING", value=ADDR_TRUB))),
    V("NR61", RI, "ОГРН строки чужой, ИНН совпал с субъектом — идентификаторы расходятся",
      pre=seq(regds(rows=rows_with(1, inn=INN_DEV, address=ROW0["address"])[1:]), rowev([OGRN_TRUB], ["address", "inn"]))),
    V("NR62", RI, "ни один идентификатор субъекта строки не процитирован",
      pre=seq(regds(key=("name",), subject=("ogrn",)), rowev([ROW0["name"]], ["address"]))),
    V("NR63", RI, "идентификатор субъекта строки пуст",
      pre=seq(regds(key=("name",), subject=("inn",), rows=rows_with(inn=None)), rowev([ROW0["name"]], ["address", "inn"]))),
    V("PR13", [], "субъект строки назван ИНН (ключ набора — название)",
      pre=seq(regds(key=("name",), subject=("inn",)), rowev([ROW0["name"]], ["address", "inn"]))),
    V("PR20", [], "у субъекта нет идентификатора одной из схем строки (ИНН) — совпадения по ОГРН достаточно",
      pre=seq(lambda W: W["ent_k_developer"]["identity"].pop("inn"), rowev([OGRN_DEV], ["address", "inn"]))),
    V("NR65", RI, "набор не объявляет субъект строки: его строка не подтверждает утверждение о сущности",
      pre=regds(subject=())),
    V("PR15", [], "субъект после слияния несёт идентификаторы влившейся сущности",
      pre=seq(add_entity("ent_k_trub", "prj_compliance", "ORGANIZATION", {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU",
                                                                         "ogrn": OGRN_TRUB, "inn": INN_TRUB}, CONF_CS, "MERGED",
                         "ent_k_developer", "2026-09-20T10:00:00Z"),
              rowev([OGRN_TRUB], ["address"]), obj50(type="STRING", value=ADDR_TRUB))),
    V("NR64", RI, "слияние позже утверждения не делает чужую строку своей",
      pre=seq(add_entity("ent_k_trub", "prj_compliance", "ORGANIZATION", {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU",
                                                                         "ogrn": OGRN_TRUB, "inn": INN_TRUB}, CONF_CS, "MERGED",
                         "ent_k_developer", "2026-09-27T10:00:00Z"),
              rowev([OGRN_TRUB], ["address"]), obj50(type="STRING", value=ADDR_TRUB))),

    # ---------------- the claim says what the row says ----------------
    V("NR70", RI, "утверждение говорит не то, что в ячейке", pre=obj50(type="STRING", value="г. Москва, ул. Лесная, д. 3")),
    V("NR71", RI, "процитирована колонка, не объявленная для предиката", pre=rowev([OGRN_DEV], ["name"])),
    V("NR72", RI, "колонка предиката скрыта, процитирована другая с тем же значением",
      pre=seq(regds(rows=rows_with(name=ROW0["address"])), rowev([OGRN_DEV], ["name"]))),
    V("NR73", RI, "тип литерала не равен типу колонки (дата как строка)",
      pre=seq(regds(columns=cols_with(address={"predicate": None}, registered_on={"predicate": "entity.registered_address"})),
              rowev([OGRN_DEV], ["registered_on"]), obj50(type="STRING", value=ROW0["registered_on"]))),
    V("NR74", RI, "ячейка предиката пуста",
      pre=seq(regds(rows=rows_with(address=None)), rowev([OGRN_DEV], ["address"]))),
    V("NR75", RI, "колонка-идентификатор: строковый литерал вместо идентификатора",
      pre=seq(regds(columns=cols_with(address={"identifier_scheme": "x.addr"})))),
    V("PR16", [], "колонка-идентификатор: номер дела из строки", pre=_case_claim),
    V("NR76", RI, "колонка-идентификатор: в утверждении другой номер дела",
      pre=seq(_case_claim, obj50(type="IDENTIFIER", scheme="ru.arbitr", value="А41-99999/2026"))),
    V("NR77", RI, "колонка-идентификатор: в утверждении другая схема идентификатора",
      pre=seq(_case_claim, obj50(type="IDENTIFIER", scheme="ru.sudrf", value="А41-12345/2026"))),
    V("PR17", [], "объект-сущность: ячейка называет её идентификатором", pre=_rival_claim()),
    V("NR78", RI, "объект-сущность: в ячейке идентификатор другой организации", pre=_rival_claim(rival=REGISTRY_ROWS[2]["ogrn"])),
    V("NR79", RI, "объект-сущность: колонка предиката не идентификатор",
      pre=_rival_claim(rival="АО «Трубопроводстрой»", col={"name": "rival", "type": "STRING", "marking": PUB, "predicate": "competitor.competes_with"})),
    V("NR7A", RI, "объект-сущность: идентификатор той же строки по другой схеме (ИНН как ОГРН)",
      pre=_rival_claim(rival=INN_TRUB, col=dict(RIVAL_COL, identifier_scheme="ru.inn2"))),

    # ---------------- after the independent review (S10R-03, -05, -07, -08, -09, -17) ----------------
    V("NR46", RI, "ключ — целая колонка со значением 1, row_key = [true]: true — не 1 (S10R-03)",
      pre=seq(regds(key=("employees",), rows=[dict(r, employees=n + 1) for n, r in enumerate(REGISTRY_ROWS)]), rowev([1], ["address", "ogrn"]),
              ev0(lambda ev: ev.__setitem__("row_key", [True])))),
    V("PR30", [], "ключ — целая колонка", pre=seq(regds(key=("employees",), rows=[dict(r, employees=n + 1) for n, r in enumerate(REGISTRY_ROWS)]),
                                                   rowev([1], ["address", "ogrn"]))),
    V("PR31", [], "ключ — булева и строковая колонки", pre=seq(regds(key=("active", "ogrn")), rowev([True, OGRN_DEV], ["address"]))),
    V("NR47", RI, "производитель посчитал хэш строки по ячейкам в своём порядке и привёл их в нём же — не порядок манифеста (S10R-08)",
      pre=regds(_producer_order)),
    V("NR3B", RI, "манифест объявляет в файле одну строку, а корень — двух; «единственная» строка предъявлена с путём из одного хэша (S10R-08)",
      pre=seq(regds(_two_rows_as_one), ev0(lambda ev: ev["proof"].__setitem__("index", 0)))),
    V("PR26", [], "объект-сущность: ячейка называет идентификатор сущности, влитой в объект ДО утверждения (S10R-09)",
      pre=_rival_merged("2026-09-20T10:00:00Z")),
    V("NR7B", RI, "объект-сущность: слияние ПОЗЖЕ утверждения — на момент утверждения ячейка называла другую организацию (S10R-09)",
      pre=_rival_merged("2026-09-27T10:00:00Z")),
    V("PR27", [], "колонка дат подтверждает литерал-дату (S10R-09)", pre=_birth_claim),
    V("NR7C", RI, "колонка дат: в утверждении другая дата", pre=seq(_birth_claim, obj50(type="DATE", value="1971-03-15"))),
    V("NR66", ["REF_UNRESOLVED"], "утверждение на строке о неизвестном субъекте: одна ошибка — неизвестный субъект (S10R-09)",
      pre=setk("c50", "subject", "ent_no_such_entity")),
    V("NR7D", ["REF_UNRESOLVED"], "утверждение на строке с неизвестной сущностью-объектом: одна ошибка (S10R-09)",
      pre=seq(_rival_claim(), setk("c50", "object", {"entity": "ent_no_such_entity"}))),
    V("PR28", [], "субъект утверждения сам влит в девелопера до утверждения: строка девелопера — о нём (правило «после слияния "
      "пишут о выжившем» — только у базы) (S10R-09)",
      pre=seq(add_entity("ent_k_dup", "prj_compliance", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент» (дубль)", "jurisdiction": "RU",
                                                                        "ogrn": REGISTRY_ROWS[3]["ogrn"], "inn": REGISTRY_ROWS[3]["inn"]}, CONF_CS,
                         "MERGED", "ent_k_developer", "2026-09-20T10:00:00Z"), setk("c50", "subject", "ent_k_dup"))),
    V("NR48", RI, "процитированная ячейка с именем, которого нет среди колонок манифеста: одна ошибка (S10R-09)",
      pre=ev0(lambda ev: ev["cells"].__setitem__(-1, {"name": "zzz", "value": 1, "salt": "0" * 64}))),
    V("NR1G", MI, "колонка объявлена для предиката, которого нет ни в реестре, ни в схеме tenant (S10R-17)",
      pre=mset(lambda m: m["columns"][2].__setitem__("predicate", "entity.no_such"))),
    V("NR1H", MI, "колонка объявлена для предиката схемы другого tenant… которого в этом tenant нет",
      pre=mset(lambda m: m["columns"][2].__setitem__("predicate", "x.no_such"))),
    V("NR1I", MI, "колонка объявлена для предиката схемы tenant, определённого ПОЗЖЕ получения версии",
      pre=seq(cls("sd_late", "sdf_late", root="THING", at="2026-09-06T00:00:00Z", attributes=[ATTR_NOTE]),
              mset(lambda m: m["columns"][2].__setitem__("predicate", "x.note")))),
    V("NR1J", MI, "колонка объявлена для предиката схемы ДРУГОГО tenant",
      pre=seq(cls("sd_alien", "sdf_alien", root="THING", tenant="tnt_other", attributes=[ATTR_NOTE]),
              mset(lambda m: m["columns"][2].__setitem__("predicate", "x.note")))),
    V("PR29", [], "колонка объявлена для предиката схемы tenant", pre=mset(lambda m: m["columns"][2].__setitem__("predicate", "x.max_length"))),

    # ---------------- the row files of a version, when the object store holds them (S10R-07) ----------------
    V("PRF1", [], "файлов версии в хранилище нет — версия регистрируется по манифесту",
      post=lambda d, ix, e: [e["content"].pop(k) for k in list(e["content"]) if k.startswith("sha256:") and e["content"][k][:5] == b'{"h":']),
    V("NRF1", MI, "байты файла строк подменены (адрес не сходится)",
      post=lambda d, ix, e: [e["content"].__setitem__(k, e["content"][k].replace("Заречн".encode(), "Заречм".encode()))
                             for k in list(e["content"]) if e["content"][k][:5] == b'{"h":']),
    V("NRF2", MI, "длина файла строк не та, что в манифесте", pre=mset(lambda m: m["files"][0].__setitem__("byte_length", m["files"][0]["byte_length"] + 1))),
    V("NRF3", MI, "в файле строк меньше, чем объявлено", pre=refile(lambda rows: rows[:-1])),
    V("NRF4", MI, "в файле лишняя строка", pre=refile(lambda rows: rows + [rows[-1]])),
    V("NRF5", MI, "строка файла не в канонической форме", pre=refile(lambda rows: [_json.dumps(rows[0], ensure_ascii=False).encode("utf-8")] + rows[1:])),
    V("NRF6", MI, "строка файла с лишним полем", pre=refile(lambda rows: [_set(rows[0], x=1)] + rows[1:])),
    V("NRF7", MI, "значение в файле не типа колонки", pre=refile(lambda rows: [_set(rows[0], v=rows[0]["v"][:7] + ["48"])] + rows[1:])),
    V("NRF8", MI, "в строке файла не столько значений, сколько колонок", pre=refile(lambda rows: [_set(rows[0], v=rows[0]["v"][:7])] + rows[1:])),
    V("NRF9", MI, "секрет строки короче 16 байт", pre=refile(lambda rows: [_set(rows[0], s=rows[0]["s"][:30])] + rows[1:])),
    V("NRFA", MI, "ключ строки в файле не равен значениям колонок ключа", pre=refile(lambda rows: [_set(rows[0], k=["1027700000000"])] + rows[1:])),
    V("NRFB", MI, "значение в файле изменено — хэш строки не сходится",
      pre=refile(lambda rows: [_set(rows[0], v=rows[0]["v"][:3] + ["г. Москва, ул. Выдуманная, д. 1"] + rows[0]["v"][4:])] + rows[1:])),
    V("PRF2", [], "строки файла не в порядке ключа: порядок не правило, правило — единственность ключа (S10R-28)",
      pre=refile(lambda rows: [rows[1], rows[0]] + rows[2:], fix_root=True)),
    V("NRFD", MI, "корень строк в манифесте не тот", pre=mset(lambda m: m["files"][0].__setitem__("rows_root", _flip(m["files"][0]["rows_root"])))),
    V("NRFE", MI, "файл строк не окончен переводом строки",
      pre=refile(lambda rows: b"".join(_canon(x).encode("utf-8") + b"\n" for x in rows)[:-1])),
    V("NRFF", MI, "пустое значение в колонке ключа (хэши согласованы)",
      pre=regds(rows=rows_with(2, ogrn=None), check=False)),
    V("NRFG", MI, "ключ повторяется в файле", pre=refile(lambda rows: [rows[0], rows[0]] + rows[2:], fix_root=True)),

    V("NRFL", MI, "поле хэша строки в файле неверно при верных значениях", pre=refile(lambda rows: [_set(rows[0], h=_flip(rows[0]["h"]))] + rows[1:])),
    V("NRFM", MI, "манифест объявляет в файле не столько строк, сколько в нём есть; корень — верный (S10R-21)",
      pre=regds(lambda W: _lie_rows(demo_registry()))),
    V("NRFN", MI, "манифест называет файл чужим адресом, а в хранилище под этим адресом лежат его байты (S10R-21)",
      pre=mset(lambda m: m["files"][0].__setitem__("object", "sha256:" + "0" * 64)),
      post=lambda d, ix, e: e["content"].__setitem__("sha256:" + "0" * 64, next(v for v in e["content"].values() if v[:5] == b'{"h":' and v.count(b"\n") == 4))),
    V("NRFO", MI, "один ключ в двух файлах версии с разным содержимым (S10R-22)",
      pre=regds(lambda W: _key_in_two_files())),
    V("NRFH", MI, "после последней строки файла — посторонние байты", pre=refile(lambda rows: b"".join(_canon(x).encode("utf-8") + b"\n" for x in rows) + b"tail")),
    V("NRFI", MI, "значение в файле не типа колонки, хэши согласованы", pre=regds(rows=rows_with(1, employees="1200"), check=False)),
    V("NRFJ", MI, "в строке файла меньше значений, чем колонок, хэши согласованы",
      pre=refile(lambda rows: [_rehash(_set(rows[0], v=rows[0]["v"][:7]))] + rows[1:], fix_root=True)),
    V("NRFK", MI, "секрет строки — 15 байт, хэши согласованы",
      pre=refile(lambda rows: [_rehash(_set(rows[0], s=rows[0]["s"][:30]))] + rows[1:], fix_root=True)),

    # ---------------- marking, time, tenant ----------------
    V("NR80", ["MARKING_BROADER_THAN_INPUT"], "процитирована колонка с персональными данными, а утверждение без этой категории",
      pre=rowev([OGRN_DEV], ["address", "director"])),
    V("PR18", [], "колонка с персональными данными процитирована в утверждении с этой категорией",
      pre=seq(rowev([OGRN_DEV], ["address", "director"]), setk("c50", "marking", CONF_CS_PD))),
    V("NR81", ["MARKING_BROADER_THAN_INPUT"], "процитирована колонка «для служебного пользования» в открытом утверждении",
      pre=seq(rowev([OGRN_DEV], ["address", "employees"]), setk("c50", "marking", PUB), setk("ent_k_developer", "marking", PUB))),
    V("NR82", ["MARKING_BROADER_THAN_INPUT"], "маркировка утверждения шире маркировки версии набора", pre=setk("s30", "marking", CONF_CS_PD)),
    V("NR83", ["TEMPORAL_ORDER_INVALID"], "утверждение записано раньше, чем получена версия набора", pre=setk("c50", "recorded_at", "2026-09-05T07:00:00Z")),
    V("NR84", ["CROSS_SCOPE_REFERENCE"], "строка версии набора другого tenant",
      pre=seq(setk("s30", "tenant_id", "tnt_other"), mset(lambda m: m.__setitem__("tenant_id", "tnt_other")))),
]

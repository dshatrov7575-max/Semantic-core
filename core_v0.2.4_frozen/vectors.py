"""Vectors for core-ontology/0.2: each negative vector must yield EXACTLY its expected error-code set;
each positive vector (expected == []) must be clean. pre(W) mutates the symbolic world before content
addresses/signatures are computed; post(ds, ix, env) tampers with the finished dataset, trust or content store.
"""
import copy
import hashlib

from fixtures import (world, finalize, SV, T, INN_DEV, OGRN_DEV, OGRN_TRUB, INN_TRUB, INN_LOMOV, OGRNIP_IP,
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

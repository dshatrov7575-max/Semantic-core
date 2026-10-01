"""Test world for core-ontology/0.2 + negative/positive vectors.

The world uses symbolic references ("@S:name" source, "@C:name" claim, {"$ev": [source, quote]} evidence).
finalize() computes every content address (source_id, claim_id, receipt_id), byte spans and Ed25519
signatures, so a mutated world stays consistent except for the one rule a vector targets.
Trust anchors (W["__trust__"]) and the content store are returned SEPARATELY from the dataset.
All persons, organisations and numbers are fictional.

python3 fixtures.py  -> data/world_valid.json, data/trust_anchors.json, data/vectors_manifest.json
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jcs import digest
from validator import inn_ok, ogrn_ok, ogrnip_ok

HERE = Path(__file__).resolve().parent
SV = "core-ontology/0.2"
T = "tnt_demo"


def _ctl(v, coef):
    return str(sum(c * int(x) for c, x in zip(coef, v)) % 11 % 10)


def inn10(p9):
    return p9 + _ctl(p9, [2, 4, 10, 3, 5, 9, 4, 6, 8])


def inn12(p10):
    a = p10 + _ctl(p10, [7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
    return a + _ctl(a, [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8])


def ogrn(p12):
    return p12 + str(int(p12) % 11 % 10)


def ogrnip(p14):
    return p14 + str(int(p14) % 13 % 10)


INN_DEV, OGRN_DEV = inn10("501200731"), ogrn("121500000731")
OGRN_TRUB, INN_TRUB = ogrn("110290001744"), inn10("290100174")
INN_LOMOV = inn12("6952031418")
INN_IP, OGRNIP_IP = inn12("5012887766"), ogrnip("32650120000412")
INN_NAMESAKE = inn12("7707123450")
assert all(map(inn_ok, (INN_DEV, INN_TRUB, INN_LOMOV, INN_IP, INN_NAMESAKE)))
assert ogrn_ok(OGRN_DEV) and ogrn_ok(OGRN_TRUB) and ogrnip_ok(OGRNIP_IP)

SEEDS = {"key_ts_1": hashlib.sha256(b"demo-seed:key_ts_1").digest(),
         "OTHER": hashlib.sha256(b"demo-seed:not-registered").digest()}
ARTIFACT = "sha256:" + hashlib.sha256("UMR-graph:s1:demo".encode()).hexdigest()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pub(seed):
    return b64u(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw())


def mk(level, *cats):
    return {"level": level, "categories": list(cats)}


PUB, INT = mk("PUBLIC"), mk("INTERNAL")
PUB_PD = mk("PUBLIC", "PERSONAL_DATA")
CONF_PD = mk("CONFIDENTIAL", "PERSONAL_DATA")
CONF_CS = mk("CONFIDENTIAL", "COMMERCIAL_SECRET")
CONF_CS_PD = mk("CONFIDENTIAL", "PERSONAL_DATA", "COMMERCIAL_SECRET")


def srch(scope, query, at, src=None):
    s = {"search_scope": scope, "query": query, "performed_at": at, "performed_by": "usr_bank_officer"}
    if src:
        s["result_source_id"] = "@S:" + src
    return s


def world():
    W = {}

    def add(name, rec):
        assert name not in W, name
        rec.setdefault("schema_version", SV)
        W[name] = rec

    # ---- projects: one per product ----
    for pid, prod, title, dm in [
        ("prj_ts_pumps", "TECHSENSE", "Насосная станция НС-2", INT),
        ("prj_conflict_land", "CONFLICTOLOGY", "Конфликт вокруг участка на ул. Заречной", CONF_PD),
        ("prj_wm_region", "WEB_MONITORING", "Мониторинг СМИ: Заречный район", PUB),
        ("prj_dossier", "DOSSIER", "Досье: участники застройки ул. Заречной", CONF_PD),
        ("prj_compliance", "COMPLIANCE", "Проверки заёмщиков банка", CONF_CS_PD),
        ("prj_wiki_whales", "SEMANTIC_WIKI", "База знаний по китам", PUB)]:
        add(pid, {"kind": "Project", "project_id": pid, "tenant_id": T, "product": prod, "title": title,
                  "created_at": "2026-09-01T09:00:00Z", "default_marking": dm})

    # ---- sources (content-addressed) ----
    def src(name, kind, title, text, observed, marking, uris=None, published=None):
        rec = {"kind": "Source", "tenant_id": T, "source_kind": kind, "media_type": "text/plain; charset=utf-8",
               "language": "ru", "title": title, "content_inline": text, "marking": marking,
               "observations": [{"observed_at": observed if n == 0 else "2026-09-07T00:00:00Z", "origin_uri": u,
                                 "observed_by": "svc_webmon"} for n, u in enumerate(uris or [f"urn:demo:{name}"])]}
        if published:
            rec["published_at"] = published
        add(name, rec)

    src("s1", "DOCUMENT", "Инструкция по эксплуатации насосной станции НС-2 (фрагмент)",
        "Насос Н-101 (модель НМ 16-100, изготовитель «НасосМаш») входит в состав насосной станции НС-2. "
        "Максимальное рабочее давление насоса Н-101 — 16 бар. "
        "При давлении выше 16 бар остановить насос Н-101 и сообщить дежурному инженеру.",
        "2026-09-02T08:00:00Z", INT)
    src("s2", "MEDIA_ARTICLE", "Жители Заречной улицы против застройки",
        "ООО «Заречье-Девелопмент» получило разрешение на строительство жилого комплекса на участке 50:12:0101001:245. "
        "Жители Заречной улицы выступили против застройки. Генеральный директор компании Аркадий Ломов заявил, "
        "что работы начнутся весной.",
        "2026-09-02T10:00:00Z", PUB,
        ["https://news.example/zarechye", "https://news.example/amp/zarechye", "https://agg.example/r/123"],
        "2026-09-02T07:30:00Z")
    src("s3", "SOCIAL_POST", "Пост инициативной группы «Заречная, 12»",
        "Инициативная группа «Заречная, 12» начала сбор подписей против застройки участка. Депутат городского совета "
        "Нина Грачёва поддержала жителей и направила запрос в администрацию.",
        "2026-09-03T12:00:00Z", PUB)
    src("s4", "REGISTRY_EXTRACT", "Выписка ЕГРЮЛ: ООО «Заречье-Девелопмент»",
        f"ООО «Заречье-Девелопмент», ОГРН {OGRN_DEV}, ИНН {INN_DEV}. Генеральный директор: Ломов Аркадий Семёнович, "
        f"ИНН {INN_LOMOV}, дата рождения 14.03.1971, с 12.02.2021. Учредители: Ломов Аркадий Семёнович — 60%; "
        f"ООО «Северный Трубопрокат» (ОГРН {OGRN_TRUB}) — 40%.",
        "2026-09-04T09:00:00Z", PUB_PD)
    src("s5", "REGISTRY_EXTRACT", "Выписка ЕГРН: 50:12:0101001:245",
        "Земельный участок с кадастровым номером 50:12:0101001:245, адрес: Московская обл., г. Заречный, "
        "ул. Заречная, уч. 12. Правообладатель: ООО «Заречье-Девелопмент», собственность.",
        "2026-09-04T09:30:00Z", PUB)
    src("s6", "MEDIA_ARTICLE", "Суд принял иск к застройщику",
        "Арбитражный суд Московской области принял к производству иск к ООО «Заречье-Девелопмент» о взыскании "
        "задолженности по договору подряда. Делу присвоен номер А41-12345/2026.",
        "2026-09-05T08:00:00Z", PUB)
    src("s7", "DOCUMENT", "Протокол подведения итогов аукциона № 0148300000126000017",
        f"Протокол подведения итогов электронного аукциона № 0148300000126000017 от 15.08.2026. "
        f"Победитель: ООО «Заречье-Девелопмент» (ИНН {INN_DEV}). Цена контракта: 12 500 000,00 руб.",
        "2026-09-05T09:00:00Z", PUB)
    src("s8", "SOCIAL_POST", "Telegram-канал ООО «Заречье-Девелопмент»",
        "Официальный канал ООО «Заречье-Девелопмент» в Telegram: @zarechye_dev. Новости строительства и ответы "
        "на вопросы жителей.",
        "2026-09-05T10:00:00Z", PUB)
    src("s9", "MEDIA_ARTICLE", "Интервью: Аркадий Ломов о планах компании",
        "Аркадий Семёнович Ломов родился 14 марта 1972 года в Твери. С 2021 года он руководит компанией "
        "«Заречье-Девелопмент».",
        "2026-09-05T11:00:00Z", PUB)
    src("s10", "DOCUMENT", "Статья «Синий кит»",
        "Синий кит — вид усатых китов. Длина синего кита достигает 30 метров, а масса — 150 тонн.",
        "2026-09-02T09:00:00Z", PUB)
    src("s11", "REGISTRY_EXTRACT", "Сведения о регистрации транспортного средства",
        "Сведения о регистрации транспортного средства: легковой автомобиль, VIN XTA210990Y1234567, "
        "владелец Ломов Аркадий Семёнович, дата регистрации 03.06.2024.",
        "2026-09-04T10:00:00Z", PUB_PD)
    src("s12", "REGISTRY_SEARCH_RESULT", "Поиск аккаунтов в социальных сетях: Ломов Аркадий Семёнович",
        f"Поиск по ФИО «Ломов Аркадий Семёнович» и ИНН {INN_LOMOV} в социальных сетях (VK, Telegram, OK) "
        f"выполнен 27.09.2026: аккаунтов не найдено.",
        "2026-09-27T11:00:00Z", CONF_PD)
    src("s13", "REGISTRY_EXTRACT", "Выписки ЕГРЮЛ/ЕГРИП: филиал и ИП",
        f"Филиал ООО «Северный Трубопрокат» в г. Заречный, ИНН {INN_TRUB}, КПП 290145001. "
        f"Индивидуальный предприниматель Ломова Ирина Петровна, ИНН {INN_IP}, ОГРНИП {OGRNIP_IP}, "
        f"дата рождения 02.11.1975.",
        "2026-09-04T11:00:00Z", PUB_PD)

    # ---- entities ----
    def ent(name, prj, etype, identity, display, marking, status="ACTIVE", merged_into=None, changed=None):
        rec = {"kind": "Entity", "entity_id": name, "project_id": prj, "entity_type": etype, "identity": identity,
               "display_name": display, "status": status, "created_at": "2026-09-05T12:00:00Z", "marking": marking}
        if merged_into:
            rec["merged_into"] = merged_into
        if changed:
            rec["status_changed_at"] = changed
        add(name, rec)

    dev_id = {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", "ogrn": OGRN_DEV, "inn": INN_DEV}
    lomov_full = {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович",
                  "birth_date": "1971-03-14", "inn": INN_LOMOV}
    # TechSense: equipment model (type) and installed instances
    ent("ent_ts_model", "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": "НМ 16-100"}, "Насос НМ 16-100", INT)
    ent("ent_ts_station", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "НС-2", "description": "насосная станция"}, "Насосная станция НС-2", INT)
    ent("ent_ts_pump", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "Н-101", "description": "насос"}, "Насос Н-101", INT)
    # Conflictology
    ent("ent_c_conflict", "prj_conflict_land", "CONFLICT", {"title": "Застройка участка на ул. Заречной", "started_on": "2026-09-02", "place": "г. Заречный"}, "Конфликт: застройка ул. Заречной", CONF_PD)
    ent("ent_c_developer", "prj_conflict_land", "ORGANIZATION", dict(dev_id), "ООО «Заречье-Девелопмент»", CONF_PD)
    ent("ent_c_initiative", "prj_conflict_land", "ORGANIZATION", {"name": "Инициативная группа «Заречная, 12»", "jurisdiction": "RU", "informal": True, "disambiguator": "zarechnaya-12"}, "Инициативная группа «Заречная, 12»", CONF_PD)
    ent("ent_c_lomov", "prj_conflict_land", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "disambiguator": "director-zarechye"}, "Ломов Аркадий", CONF_PD)
    ent("ent_c_grachyova", "prj_conflict_land", "PERSON", {"surname": "Грачёва", "given_name": "Нина", "disambiguator": "deputy-city-council"}, "Грачёва Нина", CONF_PD)
    # Web Monitoring
    ent("ent_w_developer", "prj_wm_region", "ORGANIZATION", dict(dev_id), "ООО «Заречье-Девелопмент»", PUB)
    ent("ent_w_initiative", "prj_wm_region", "ORGANIZATION", {"name": "Инициативная группа «Заречная, 12»", "jurisdiction": "RU", "informal": True, "disambiguator": "zarechnaya-12"}, "Инициативная группа «Заречная, 12»", PUB)
    # Dossier
    ent("ent_d_lomov", "prj_dossier", "PERSON", dict(lomov_full), "Ломов Аркадий Семёнович", CONF_PD)
    ent("ent_d_lomov_media", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "disambiguator": "from-s9"}, "Аркадий Ломов (из СМИ)", CONF_PD, "MERGED", "ent_d_lomov", "2026-09-06T15:00:00Z")
    ent("ent_d_developer", "prj_dossier", "ORGANIZATION", dict(dev_id), "ООО «Заречье-Девелопмент»", CONF_PD)
    ent("ent_d_trub", "prj_dossier", "ORGANIZATION", {"name": "ООО «Северный Трубопрокат»", "jurisdiction": "RU", "ogrn": OGRN_TRUB, "inn": INN_TRUB}, "ООО «Северный Трубопрокат»", CONF_PD)
    ent("ent_d_trub_branch", "prj_dossier", "ORGANIZATION", {"name": "Филиал ООО «Северный Трубопрокат» в г. Заречный", "jurisdiction": "RU", "legal_form": "BRANCH", "inn": INN_TRUB, "kpp": "290145001"}, "Филиал «Северного Трубопроката» (Заречный)", CONF_PD)
    ent("ent_d_ip", "prj_dossier", "PERSON", {"surname": "Ломова", "given_name": "Ирина", "patronymic": "Петровна", "birth_date": "1975-11-02", "inn": INN_IP, "ogrnip": OGRNIP_IP}, "ИП Ломова Ирина Петровна", CONF_PD)
    ent("ent_d_land", "prj_dossier", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:245", "address": "Московская обл., г. Заречный, ул. Заречная, уч. 12"}, "Участок 50:12:0101001:245", CONF_PD)
    ent("ent_d_car", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VEHICLE", "vin": "XTA210990Y1234567", "description": "легковой автомобиль"}, "Автомобиль VIN XTA210990Y1234567", CONF_PD)
    # Compliance
    ent("ent_k_developer", "prj_compliance", "ORGANIZATION", dict(dev_id), "ООО «Заречье-Девелопмент»", CONF_CS)
    ent("ent_k_lomov", "prj_compliance", "PERSON", dict(lomov_full), "Ломов Аркадий Семёнович", CONF_CS_PD)
    ent("ent_k_land", "prj_compliance", "REAL_ESTATE", {"cadastral_number": "50:12:0101001:245", "address": "Московская обл., г. Заречный, ул. Заречная, уч. 12"}, "Участок 50:12:0101001:245", CONF_CS)
    ent("ent_k_tender", "prj_compliance", "EVENT", {"title": "Электронный аукцион № 0148300000126000017", "date": "2026-08-15"}, "Аукцион № 0148300000126000017", CONF_CS)
    # SemanticWiki
    ent("ent_wk_blue", "prj_wiki_whales", "CONCEPT", {"label": "Синий кит", "lang": "ru", "namespace": "whales"}, "Синий кит", PUB)
    ent("ent_wk_baleen", "prj_wiki_whales", "CONCEPT", {"label": "Усатые киты", "lang": "ru", "namespace": "whales"}, "Усатые киты", PUB)

    # ---- claims ----
    def clm(name, prj, subj, pred, obj, evs, marking, recorded, by=None, q=None, vf=None, vt=None):
        rec = {"kind": "Claim", "project_id": prj, "subject": subj, "predicate": pred, "object": obj,
               "evidence": [{"$ev": list(e)} for e in evs],
               "produced_by": by or {"kind": "HUMAN", "actor_id": "usr_analyst1"},
               "recorded_at": recorded, "marking": marking}
        if q:
            rec["qualifiers"] = q
        if vf:
            rec["valid_from"] = vf
        if vt:
            rec["valid_to"] = vt
        add(name, rec)

    E = lambda x: {"entity": x}
    L = lambda **kw: {"literal": kw}
    PIPE = {"kind": "PIPELINE", "service_id": "svc_techsense", "run_id": "run_ts_0001"}
    t_ts = "2026-09-06T09:59:00Z"
    clm("c0", "prj_ts_pumps", "ent_ts_pump", "ts.instance_of", E("ent_ts_model"),
        [("s1", "Насос Н-101 (модель НМ 16-100, изготовитель «НасосМаш»)")], INT, t_ts, PIPE)
    clm("c1", "prj_ts_pumps", "ent_ts_pump", "ts.part_of", E("ent_ts_station"),
        [("s1", "входит в состав насосной станции НС-2")], INT, t_ts, PIPE)
    clm("c2", "prj_ts_pumps", "ent_ts_pump", "ts.has_parameter", L(type="QUANTITY", value="16", unit="bar"),
        [("s1", "Максимальное рабочее давление насоса Н-101 — 16 бар")], INT, t_ts, PIPE, q={"parameter": "max_working_pressure"})
    W["c2"]["evidence"][0]["graph_node"] = {"artifact_digest": ARTIFACT, "node_id": "n12"}
    clm("c3", "prj_ts_pumps", "ent_ts_pump", "ts.requires_action", L(type="STRING", value="остановить насос и сообщить дежурному инженеру"),
        [("s1", "При давлении выше 16 бар остановить насос Н-101 и сообщить дежурному инженеру")], INT, t_ts, PIPE,
        q={"condition": "давление > 16 бар"})
    t_c = "2026-09-06T12:00:00Z"
    clm("c4", "prj_conflict_land", "ent_c_developer", "conflict.party_to", E("ent_c_conflict"),
        [("s2", "получило разрешение на строительство жилого комплекса на участке 50:12:0101001:245")], CONF_PD, t_c, q={"role": "PARTY"})
    clm("c5", "prj_conflict_land", "ent_c_initiative", "conflict.party_to", E("ent_c_conflict"),
        [("s3", "Инициативная группа «Заречная, 12» начала сбор подписей против застройки участка")], CONF_PD, t_c, q={"role": "PARTY"})
    clm("c6", "prj_conflict_land", "ent_c_grachyova", "conflict.influences", E("ent_c_conflict"),
        [("s3", "Нина Грачёва поддержала жителей и направила запрос в администрацию")], CONF_PD, t_c,
        q={"mode": "EXPLICIT", "channel": "POLITICAL"})
    clm("c7", "prj_conflict_land", "ent_c_lomov", "conflict.influences", E("ent_c_conflict"),
        [("s2", "Генеральный директор компании Аркадий Ломов заявил, что работы начнутся весной")], CONF_PD, t_c,
        q={"mode": "EXPLICIT", "channel": "ADMINISTRATIVE"})
    clm("c7b", "prj_conflict_land", "ent_c_lomov", "rel.affiliated_with", E("ent_c_developer"),
        [("s2", "Генеральный директор компании Аркадий Ломов")], CONF_PD, t_c, q={"kind": "BUSINESS", "explicit": True})
    t_w = "2026-09-06T10:30:00Z"
    clm("c8", "prj_wm_region", "ent_w_developer", "wm.mentioned", L(type="STRING", value="Жители Заречной улицы против застройки"),
        [("s2", "Жители Заречной улицы выступили против застройки")], PUB, t_w, q={"sentiment": "NEGATIVE"})
    clm("c9", "prj_wm_region", "ent_w_initiative", "wm.mentioned", L(type="STRING", value="сбор подписей против застройки"),
        [("s3", "начала сбор подписей против застройки участка")], PUB, t_w, q={"sentiment": "NEUTRAL"})
    t_d = "2026-09-06T14:00:00Z"
    clm("c10", "prj_dossier", "ent_d_lomov", "corp.director_of", E("ent_d_developer"),
        [("s4", "Генеральный директор: Ломов Аркадий Семёнович"), ("s4", "с 12.02.2021")], CONF_PD, t_d,
        q={"title": "генеральный директор"}, vf="2021-02-12")
    clm("c11", "prj_dossier", "ent_d_lomov", "corp.founder_of", E("ent_d_developer"),
        [("s4", "Ломов Аркадий Семёнович — 60%")], CONF_PD, t_d, q={"share_bp": 6000})
    clm("c12", "prj_dossier", "ent_d_trub", "corp.founder_of", E("ent_d_developer"),
        [("s4", f"ООО «Северный Трубопрокат» (ОГРН {OGRN_TRUB}) — 40%")], CONF_PD, t_d, q={"share_bp": 4000})
    clm("c13", "prj_dossier", "ent_d_lomov", "person.birth_date", L(type="DATE", value="1971-03-14"),
        [("s4", "дата рождения 14.03.1971")], CONF_PD, t_d)
    clm("c14", "prj_dossier", "ent_d_lomov_media", "person.birth_date", L(type="DATE", value="1972-03-14"),
        [("s9", "родился 14 марта 1972 года")], CONF_PD, t_d)
    clm("c15", "prj_dossier", "ent_d_developer", "prop.owns", E("ent_d_land"),
        [("s5", "Правообладатель: ООО «Заречье-Девелопмент», собственность")], CONF_PD, t_d)
    clm("c16", "prj_dossier", "ent_d_trub_branch", "corp.branch_of", E("ent_d_trub"),
        [("s13", f"Филиал ООО «Северный Трубопрокат» в г. Заречный, ИНН {INN_TRUB}, КПП 290145001")], CONF_PD, t_d)
    clm("c17", "prj_dossier", "ent_d_lomov", "prop.owns", E("ent_d_car"),
        [("s11", "VIN XTA210990Y1234567, владелец Ломов Аркадий Семёнович, дата регистрации 03.06.2024")], CONF_PD, t_d, vf="2024-06-03")
    clm("c17b", "prj_dossier", "ent_d_ip", "person.sole_proprietor", L(type="IDENTIFIER", scheme="ru.ogrnip", value=OGRNIP_IP),
        [("s13", f"Индивидуальный предприниматель Ломова Ирина Петровна, ИНН {INN_IP}, ОГРНИП {OGRNIP_IP}")], CONF_PD, t_d)
    t_k = "2026-09-07T10:00:00Z"
    clm("c18", "prj_compliance", "ent_k_developer", "media.negative_mention", L(type="STRING", value="иск о взыскании задолженности по договору подряда"),
        [("s6", "принял к производству иск к ООО «Заречье-Девелопмент» о взыскании задолженности по договору подряда")],
        CONF_CS, t_k, q={"severity": "MEDIUM"})
    clm("c19", "prj_compliance", "ent_k_developer", "court.party_to_case", L(type="IDENTIFIER", scheme="ru.arbitr", value="А41-12345/2026"),
        [("s6", "иск к ООО «Заречье-Девелопмент»"), ("s6", "Делу присвоен номер А41-12345/2026")], CONF_CS, t_k, q={"role": "DEFENDANT"})
    clm("c20", "prj_compliance", "ent_k_developer", "tender.participated", E("ent_k_tender"),
        [("s7", "Победитель: ООО «Заречье-Девелопмент»"), ("s7", "Цена контракта: 12 500 000,00 руб.")], CONF_CS, t_k,
        q={"outcome": "WON", "contract_amount_minor": 1250000000, "currency": "RUB"})
    clm("c21", "prj_compliance", "ent_k_developer", "social.account", L(type="IDENTIFIER", scheme="telegram", value="@zarechye_dev"),
        [("s8", "Официальный канал ООО «Заречье-Девелопмент» в Telegram: @zarechye_dev")], CONF_CS, t_k)
    clm("c22", "prj_compliance", "ent_k_developer", "prop.owns", E("ent_k_land"),
        [("s5", "Правообладатель: ООО «Заречье-Девелопмент», собственность")], CONF_CS, t_k)
    clm("c23", "prj_compliance", "ent_k_lomov", "corp.director_of", E("ent_k_developer"),
        [("s4", "Генеральный директор: Ломов Аркадий Семёнович")], CONF_CS_PD, t_k, vf="2021-02-12")
    t_wk = "2026-09-03T09:00:00Z"
    clm("c24", "prj_wiki_whales", "ent_wk_blue", "wiki.is_a", E("ent_wk_baleen"),
        [("s10", "Синий кит — вид усатых китов")], PUB, t_wk)
    clm("c25", "prj_wiki_whales", "ent_wk_blue", "wiki.property", L(type="QUANTITY", value="30", unit="m"),
        [("s10", "Длина синего кита достигает 30 метров")], PUB, t_wk, q={"property": "max_length"})
    clm("c26", "prj_wiki_whales", "ent_wk_blue", "wiki.property", L(type="QUANTITY", value="150", unit="t"),
        [("s10", "масса — 150 тонн")], PUB, t_wk, q={"property": "max_mass"})

    # ---- reviews: declared decision time + system record time ----
    def rev(name, claim, status, at, rec_at, note=None):
        r = {"kind": "ClaimReview", "review_id": name, "claim_id": "@C:" + claim, "status": status,
             "reviewer": "usr_reviewer1", "reviewed_at": at, "recorded_at": rec_at}
        if note:
            r["note"] = note
        add(name, r)

    rev("rev_c18_a", "c18", "ACCEPTED", "2026-09-08T10:00:00Z", "2026-09-08T10:05:00Z")
    for c in ("c19", "c20", "c21", "c22", "c23"):
        rev(f"rev_{c}_a", c, "ACCEPTED", "2026-09-20T10:00:00Z", "2026-09-20T10:05:00Z")
    rev("rev_c20_d", "c20", "DISPUTED", "2026-09-28T10:00:00Z", "2026-09-28T10:05:00Z", "контрагент оспаривает итоги аукциона")
    rev("rev_c13_a", "c13", "ACCEPTED", "2026-09-07T09:00:00Z", "2026-09-07T09:05:00Z")

    # ---- Checks: one subject, many Checks; every finding carries its search trace ----
    add("chk_express_1", {"kind": "Check", "check_id": "chk_express_1", "project_id": "prj_compliance",
        "subject_entity_id": "ent_k_developer", "profile": "EXPRESS_NEGATIVE", "as_of": "2026-09-10",
        "requested_at": "2026-09-10T08:00:00Z", "requested_by": "usr_bank_officer", "status": "COMPLETED",
        "completed_at": "2026-09-10T12:00:00Z",
        "findings": [{"dimension": "NEGATIVE", "result": "FOUND", "risk": "MEDIUM", "claim_ids": ["@C:c18"],
                      "searches": [srch("Web Monitoring: СМИ", f"ИНН {INN_DEV}", "2026-09-10T09:00:00Z")]}],
        "overall_risk": "MEDIUM", "marking": CONF_CS_PD})
    fs = "2026-09-25T10:00:00Z"
    add("chk_full_1", {"kind": "Check", "check_id": "chk_full_1", "project_id": "prj_compliance",
        "subject_entity_id": "ent_k_developer", "profile": "FULL", "as_of": "2026-09-25",
        "requested_at": "2026-09-25T08:00:00Z", "requested_by": "usr_bank_officer", "status": "COMPLETED",
        "completed_at": "2026-09-26T15:00:00Z", "previous_check_id": "chk_express_1",
        "findings": [
            {"dimension": "NEGATIVE", "result": "FOUND", "risk": "MEDIUM", "claim_ids": ["@C:c18"], "searches": [srch("Web Monitoring: СМИ", f"ИНН {INN_DEV}", fs)]},
            {"dimension": "TENDERS", "result": "FOUND", "risk": "LOW", "claim_ids": ["@C:c20"], "searches": [srch("zakupki.gov.ru", f"ИНН {INN_DEV}", fs)]},
            {"dimension": "SOCIAL_MEDIA", "result": "FOUND", "risk": "NONE", "claim_ids": ["@C:c21"], "searches": [srch("соцсети: VK, Telegram, OK", "Заречье-Девелопмент", fs)]},
            {"dimension": "CORPORATE", "result": "FOUND", "risk": "NONE", "claim_ids": ["@C:c23"], "searches": [srch("ЕГРЮЛ", f"ОГРН {OGRN_DEV}", fs)]},
            {"dimension": "PROPERTY", "result": "FOUND", "risk": "NONE", "claim_ids": ["@C:c22"], "searches": [srch("ЕГРН", f"ИНН {INN_DEV}", fs)]},
            {"dimension": "COURT", "result": "FOUND", "risk": "MEDIUM", "claim_ids": ["@C:c19"], "searches": [srch("kad.arbitr.ru", f"ИНН {INN_DEV}", fs)]}],
        "overall_risk": "MEDIUM", "marking": CONF_CS_PD})
    add("chk_tenders_1", {"kind": "Check", "check_id": "chk_tenders_1", "project_id": "prj_compliance",
        "subject_entity_id": "ent_k_developer", "profile": "TENDERS_ONLY", "as_of": "2026-09-29",
        "requested_at": "2026-09-29T09:00:00Z", "requested_by": "usr_bank_officer", "status": "IN_PROGRESS",
        "previous_check_id": "chk_full_1", "findings": [], "marking": CONF_CS_PD})
    add("chk_social_lomov", {"kind": "Check", "check_id": "chk_social_lomov", "project_id": "prj_compliance",
        "subject_entity_id": "ent_k_lomov", "profile": "SOCIAL_ONLY", "as_of": "2026-09-27",
        "requested_at": "2026-09-27T10:00:00Z", "requested_by": "usr_bank_officer", "status": "COMPLETED",
        "completed_at": "2026-09-27T12:00:00Z",
        "findings": [{"dimension": "SOCIAL_MEDIA", "result": "NOT_FOUND", "risk": "NONE", "claim_ids": [],
                      "searches": [srch("соцсети: VK, Telegram, OK", f"ФИО + ИНН {INN_LOMOV}", "2026-09-27T11:00:00Z", "s12")]}],
        "overall_risk": "NONE", "marking": CONF_CS_PD})

    # ---- TechSense as artifact producer: signed receipt; the key lives in trust anchors, not in the data ----
    add("rcp_1", {"kind": "ArtifactReceipt", "project_id": "prj_ts_pumps",
        "producer": {"service_id": "svc_techsense", "version": "0.9.0"}, "run_id": "run_ts_0001",
        "artifact_digest": ARTIFACT, "artifact_schema_version": "umr-artifact/0.3", "semantic_profile_version": "ts-semantic/0.2",
        "input_source_ids": ["@S:s1"], "emitted_claim_ids": ["@C:c0", "@C:c1", "@C:c2", "@C:c3"],
        "issued_at": "2026-09-06T10:00:00Z", "key_id": "key_ts_1"})
    W["__trust__"] = {"trust_format": "core-trust/0.2", "keys": [
        {"tenant_id": T, "key_id": "key_ts_1", "service_id": "svc_techsense", "algorithm": "Ed25519",
         "public_key": pub(SEEDS["key_ts_1"]), "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z"}]}
    return W


ORDER = ["Project", "Source", "Entity", "Claim", "ClaimReview", "Check", "ArtifactReceipt"]


def finalize(W):
    """-> (dataset, index name->record position, trust anchors, content store {source_id: bytes})"""
    W = copy.deepcopy(W)
    trust = W.pop("__trust__")
    sid, cid, content = {}, {}, {}
    for n, r in W.items():
        if r["kind"] == "Source":
            b = r["content_inline"].encode("utf-8")
            r.setdefault("byte_length", len(b))
            r["source_id"] = "src:sha256:" + hashlib.sha256(b).hexdigest()
            sid[n] = r["source_id"]
            content[r["source_id"]] = b

    def res(x):
        if isinstance(x, str) and x.startswith("@S:"):
            return sid[x[3:]]
        if isinstance(x, str) and x.startswith("@C:"):
            return cid[x[3:]]
        if isinstance(x, list):
            return [res(v) for v in x]
        if isinstance(x, dict):
            if "$ev" in x:
                sname, quote = x["$ev"]
                data = W[sname]["content_inline"].encode("utf-8")
                qb = quote.encode("utf-8")
                start = data.find(qb)
                assert start >= 0, (sname, quote)
                ev = {"source_id": sid[sname], "span": {"start": start, "end": start + len(qb)},
                      "quote": quote, "quote_sha256": hashlib.sha256(qb).hexdigest()}
                ev.update({k: v for k, v in x.items() if k != "$ev"})
                return ev
            return {k: res(v) for k, v in x.items()}
        return x

    for n, r in W.items():
        if r["kind"] == "Claim":
            patch = r.pop("_ev_patch", None)
            r.update(res(dict(r)))
            if patch:
                patch(r["evidence"])
            r["claim_id"] = "clm:sha256:" + digest({k: v for k, v in r.items() if k != "claim_id"})
            cid[n] = r["claim_id"]
    for n, r in W.items():
        if r["kind"] not in ("Source", "Claim"):
            seed = r.pop("_sign_seed", None)
            r.update(res(dict(r)))
            if r["kind"] == "ArtifactReceipt":
                r["receipt_id"] = "rcp:sha256:" + digest({k: v for k, v in r.items() if k not in ("receipt_id", "signature")})
                r["signature"] = b64u(Ed25519PrivateKey.from_private_bytes(SEEDS[seed or r["key_id"]]).sign(r["receipt_id"].encode()))
    names = sorted(W, key=lambda n: (ORDER.index(W[n]["kind"]), n))
    ds = {"dataset_format": "core-dataset/0.2", "ontology_version": SV, "records": [W[n] for n in names]}
    return ds, {n: i for i, n in enumerate(names)}, trust, content

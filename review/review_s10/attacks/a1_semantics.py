#!/usr/bin/env python3
"""S10R / направление 1: утверждение на строке, которого строка не говорит. Живой путь (ac_loader, без валидатора) + валидатор."""
from common import *

ROWS = copy.deepcopy(REGISTRY_ROWS)
ADDR_TRUB = ROWS[1]["address"]
n = [0]
def ver(**kw):
    n[0] += 1
    return relabel(demo_registry(**kw), f"rev-a1-{n[0]}")
def ent(eid, identity, etype="ORGANIZATION", marking=CONF_CS, name="рец"):
    return {"kind": "Entity", "schema_version": "core-ontology/0.2", "entity_id": eid, "project_id": PRJ, "entity_type": etype, "identity": identity,
            "status": "ACTIVE", "created_at": utc(3), "marking": marking, "display_name": name}
sv = psql("SELECT DISTINCT body->>'schema_version' FROM ac.entities e, LATERAL (SELECT to_jsonb(e) AS body) x").stdout
E_ = [r for r in world()[0]["records"] if r["kind"] == "Entity" and r["entity_id"] == "ent_k_developer"][0]
print("сущность-образец:", json.dumps(E_, ensure_ascii=False)[:300])
def ent_like(eid, identity, etype="ORGANIZATION"):
    e = copy.deepcopy(E_); e.update(entity_id=eid, identity=identity, entity_type=etype, created_at=utc(3)); return e

# 1. контроль
dv = ver()
both("C0", "контроль: адрес девелопера по его строке", [source_rec(dv), mk_claim(dv.evidence([OGRN_DEV], ["address"]))], expect="accept")
# 2. чужая строка, набор с subject
both("A1", "адрес «Трубопроводстроя» приписан девелоперу (набор с subject)", [source_rec(dv),
     mk_claim(dv.evidence([OGRN_TRUB], ["address"]), obj={"literal": {"type": "STRING", "value": ADDR_TRUB}})], expect="refuse")
# 3. набор без subject
dv0 = ver(subject=())
both("A2", "набор БЕЗ subject: адрес «Трубопроводстроя» приписан девелоперу", [source_rec(dv0),
     mk_claim(dv0.evidence([OGRN_TRUB], ["address"]), obj={"literal": {"type": "STRING", "value": ADDR_TRUB}})], expect="refuse")
# 3b. набор без subject, субъект — физическое лицо без единого идентификатора строки (другой тип сущности)
both("A3", "набор БЕЗ subject: адрес организации приписан произвольной сущности проекта (ent_k_lomov, PERSON)", [source_rec(dv0),
     mk_claim(dv0.evidence([OGRN_TRUB], ["address"]), subj="ent_k_lomov", obj={"literal": {"type": "STRING", "value": ADDR_TRUB}},
              marking={"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]})], expect="refuse")
# 4. subject объявлен, но субъект без сильных идентификаторов схем строки
both("A4", "набор с subject: субъект — PERSON (нет ОГРН/ИНН строки)", [source_rec(dv),
     mk_claim(dv.evidence([OGRN_TRUB], ["address"]), subj="ent_k_lomov", obj={"literal": {"type": "STRING", "value": ADDR_TRUB}},
              marking={"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]})], expect="refuse")
# 5. subject = только inn; строка чужая по ОГРН (ключ), ИНН строки скрыт — цитируем только ключ
dvi = ver(subject=("inn",))
both("A5", "subject=(inn): ИНН строки скрыт листом, процитирован только ключ ogrn", [source_rec(dvi),
     mk_claim(dvi.evidence([OGRN_TRUB], ["address"]), obj={"literal": {"type": "STRING", "value": ADDR_TRUB}})], expect="refuse")
# 6. «грязная» строка: ОГРН чужой, ИНН субъекта; ОГРН — ключ (обязан быть процитирован), subject=(inn) — расхождение по ОГРН не видно
rows6 = copy.deepcopy(ROWS); rows6[1]["inn"] = INN_DEV; rows6 = rows6[1:]
dv6 = ver(subject=("inn",), rows=rows6)
both("A6", "subject=(inn): строка с ОГРН «Трубопроводстроя» и ИНН девелопера приписана девелоперу (ОГРН процитирован как ключ, но не субъект)",
     [source_rec(dv6), mk_claim(dv6.evidence([OGRN_TRUB], ["address", "inn"]), obj={"literal": {"type": "STRING", "value": ADDR_TRUB}})], expect="refuse")
# 7. колонка предиката = колонка другого смысла: два столбца объявлены для одного предиката
cols7 = copy.deepcopy(REGISTRY_COLUMNS) + [{"name": "prev_address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}]
rows7 = [dict(r, prev_address="г. Старый, ул. Прежняя, д. 0") for r in ROWS]
dv7 = ver(columns=cols7, rows=rows7)
both("A7", "две колонки объявлены для одного предиката: «прежний адрес» выдан за адрес регистрации (манифест так объявил)",
     [source_rec(dv7), mk_claim(dv7.evidence([OGRN_DEV], ["prev_address"]), obj={"literal": {"type": "STRING", "value": "г. Старый, ул. Прежняя, д. 0"}})])
# 8. предикат манифеста не из реестра предикатов / схема идентификатора не из реестра: манифест принимается?
cols8 = copy.deepcopy(REGISTRY_COLUMNS); cols8[2]["predicate"] = "no.such_predicate"; cols8[1]["identifier_scheme"] = "zz.nosuch"
dv8 = ver(columns=cols8, subject=("ogrn",))
both("A8", "манифест: колонка объявлена для несуществующего предиката и с несуществующей схемой идентификатора", [source_rec(dv8)])
# 9. объект-сущность = сам субъект строки: колонка ogrn объявлена предикатом связи
cols9 = copy.deepcopy(REGISTRY_COLUMNS); cols9[0]["predicate"] = "competitor.competes_with"
dv9 = ver(columns=cols9)
both("A9", "колонка-ключ субъекта объявлена предикатом связи: «девелопер конкурирует с девелопером»",
     [source_rec(dv9), mk_claim(dv9.evidence([OGRN_DEV], ["ogrn"]), predicate="competitor.competes_with", obj={"entity": "ent_k_developer"})])
# 10. перевёрнутая связь: строка «девелопер -> соперник X», утверждение «X конкурирует с девелопером»
RIV = {"name": "rival_ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn", "predicate": "competitor.competes_with"}
trub = ent_like("ent_rev_trub", {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU", "ogrn": OGRN_TRUB, "inn": INN_TRUB})
dv10 = ver(columns=copy.deepcopy(REGISTRY_COLUMNS) + [RIV], rows=[dict(r, rival_ogrn=OGRN_TRUB if i == 0 else None) for i, r in enumerate(ROWS)])
both("A10a", "контроль: «девелопер конкурирует с Трубопроводстроем» по строке девелопера",
     [source_rec(dv10), trub, mk_claim(dv10.evidence([OGRN_DEV], ["rival_ogrn"]), predicate="competitor.competes_with", obj={"entity": "ent_rev_trub"})], expect="accept")
both("A10b", "перевёрнуто: субъект — Трубопроводстрой, объект — девелопер, строка девелопера",
     [source_rec(dv10), trub, mk_claim(dv10.evidence([OGRN_DEV], ["rival_ogrn"]), subj="ent_rev_trub", predicate="competitor.competes_with", obj={"entity": "ent_k_developer"})], expect="refuse")
# 11. subject включает колонку объекта: subject=(ogrn, rival_ogrn) — строка «о двух», перевёрнутая связь проходит?
dv11 = ver(columns=copy.deepcopy(REGISTRY_COLUMNS) + [RIV], rows=[dict(r, rival_ogrn=OGRN_TRUB if i == 0 else None) for i, r in enumerate(ROWS)], subject=("inn", "rival_ogrn"))
both("A11", "subject=(inn, rival_ogrn): перевёрнутая связь — субъект Трубопроводстрой (без ИНН в строке? нет — совпал rival_ogrn)",
     [source_rec(dv11), trub, mk_claim(dv11.evidence([OGRN_DEV], ["rival_ogrn"]), subj="ent_rev_trub", predicate="competitor.competes_with", obj={"entity": "ent_rev_trub"})])
# 12. литерал другого типа с тем же текстом: INTEGER 48 против employees — предикат не объявлен
cols12 = copy.deepcopy(REGISTRY_COLUMNS); [c.__setitem__("predicate", "entity.registered_address") for c in cols12 if c["name"] == "name"]
dv12 = ver(columns=cols12)
both("A12", "название объявлено тем же предикатом, что и адрес: «адрес = название организации»",
     [source_rec(dv12), mk_claim(dv12.evidence([OGRN_DEV], ["name"]), obj={"literal": {"type": "STRING", "value": ROWS[0]["name"]}})])

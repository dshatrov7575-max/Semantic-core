"""ОШИБКА, P2. (а) Заглушки проходят контрольные цифры: ИНН/ОГРН/ОГРНИП/IMO из одних нулей, VIN из нулей, кадастровый
00:00:000000:0 — валидатор считает их настоящими сильными ключами (все «неизвестные ИНН» реестра склеятся в одну сущность
или дадут ложные дубли). (б) Ключ может быть пустым: PERSON с именем из невидимых символов, тег «-», событие ««»» —
для foreign_ids пустая нормальная форма отвергается (S11R2-09), для остальных ключей нет."""
from _h import *
from vectors import add_entity
from fixtures import CONF_PD, CONF_CS, INT
print("inn_ok('0000000000') =", VAL.inn_ok("0000000000"), "| inn_ok('000000000000') =", VAL.inn_ok("000000000000"),
      "| ogrn_ok('0'*13) =", VAL.ogrn_ok("0" * 13), "| ogrnip_ok('0'*15) =", VAL.ogrnip_ok("0" * 15), "| imo_ok('0000000') =", VAL.imo_ok("0000000"))
run(lambda W: W["ent_d_trub"]["identity"].update(inn="0000000000", ogrn="0000000000000"), label="организация: ИНН и ОГРН из нулей")
run(add_entity("ent_d_zero", "prj_dossier", "PERSON", {"surname": "Неизвестный", "given_name": "Н", "inn": "000000000000", "ogrnip": "0" * 15}), label="физлицо: ИНН и ОГРНИП из нулей")
run(add_entity("ent_d_ship", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VESSEL", "description": "судно", "imo": "0000000"}), label="судно: IMO 0000000")
run(add_entity("ent_d_car0", "prj_dossier", "MOVABLE_PROPERTY", {"subtype": "VEHICLE", "description": "авто", "vin": "0" * 17}), label="авто: VIN из нулей")
run(add_entity("ent_d_land0", "prj_dossier", "REAL_ESTATE", {"cadastral_number": "00:00:000000:0", "address": "-"}), label="участок 00:00:000000:0")
p = {"surname": "​", "given_name": "⁠", "birth_date": "1960-01-01"}
print("ключ ФИО невидимого имени:", repr(VAL.norm(p["surname"] + " " + p["given_name"])), "| ключ тега «-»:", repr(VAL.tag_norm("-")), "| ключ ««»»:", repr(VAL.norm("«»")))
run(add_entity("ent_d_inv", "prj_dossier", "PERSON", p), label="PERSON: имя из невидимых символов")
run(add_entity("ent_ts_dash", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "-"}, INT), label="EQUIPMENT: тег «-»")
run(add_entity("ent_k_ev", "prj_compliance", "EVENT", {"title": "«»", "date": "2026-01-01"}, CONF_CS), label="EVENT: название «»")

"""СПОРНОЕ РЕШЕНИЕ, P2 («примет противоречие»). Нет ни одного правила о связи субъекта с объектом и о согласии
утверждения с identity: организация — учредитель самой себя; филиал самого себя; филиал (ИНН головной в identity) —
«филиал» организации с ДРУГИМ ИНН; понятие — вид самого себя; А часть Б и Б часть А; учредители с долями 100 % + 100 %;
слияние двух физлиц с разными действительными ИНН (по правилу told_apart это заведомо разные люди), двух организаций с
разными ОГРН, двух участков с разными кадастровыми номерами. Ни ошибки, ни предупреждения."""
from _h import *
from vectors import add_entity, add_claim, setk
from fixtures import INT, INN_NAMESAKE, ogrn, inn10
run(setk("c12", "object", {"entity": "ent_d_trub"}), label="corp.founder_of: организация — учредитель самой себя")
run(setk("c16", "object", {"entity": "ent_d_trub_branch"}), label="corp.branch_of: филиал самого себя")
run(setk("c16", "object", {"entity": "ent_d_developer"}), label="corp.branch_of: в identity ИНН одной организации, объект — другая")
run(setk("c24", "object", {"entity": "ent_wk_blue"}), label="wiki.is_a: понятие — вид самого себя")
run(add_claim("cx1", "prj_ts_pumps", "ent_ts_station", "ts.part_of", {"entity": "ent_ts_pump"}, ("s1", "входит в состав насосной станции НС-2"), INT),
    label="ts.part_of: насос в станции И станция в насосе")
run(lambda W: (W["c11"]["qualifiers"].__setitem__("share_bp", 10000), W["c12"]["qualifiers"].__setitem__("share_bp", 10000)), label="доли учредителей 100 % + 100 %")
run(add_entity("ent_d_other", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14",
               "inn": INN_NAMESAKE}, status="MERGED", merged_into="ent_d_lomov", changed="2026-09-06T15:00:00Z"), label="слияние физлиц с разными действительными ИНН")
run(add_entity("ent_d_trub2", "prj_dossier", "ORGANIZATION", {"name": "ООО «Иное»", "jurisdiction": "RU", "ogrn": ogrn("102770000001"), "inn": inn10("770700001")},
               status="MERGED", merged_into="ent_d_trub", changed="2026-09-06T15:00:00Z"), label="слияние организаций с разными ОГРН и ИНН")
run(add_entity("ent_d_land2", "prj_dossier", "REAL_ESTATE", {"cadastral_number": "77:01:0001001:1", "address": "Москва"},
               status="MERGED", merged_into="ent_d_land", changed="2026-09-06T15:00:00Z"), label="слияние участков с разными кадастровыми номерами")

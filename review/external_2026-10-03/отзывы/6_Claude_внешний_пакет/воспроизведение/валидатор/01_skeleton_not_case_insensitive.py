"""ОШИБКА, P1. «Скелет» имени не сворачивает регистр у латинских B/H/M/T (и греческих Β/Ζ/Η/Μ/Ν): заглавная буква
переводится в кириллического двойника ДО casefold, строчная — нет. Точный ключ (casefold) считает строки равными,
скелет (который по описанию = точный ключ + доп. свёртки) — разными. Итог: «Siemens»/«SIEMENS», «Tom Hanks»/«TOM HANKS»
— две сущности в одном проекте без ошибки и без предупреждения (PERSON, EQUIPMENT_MODEL, EVENT, CONFLICT, неформальная
организация — все типы, чей ключ строится через norm())."""
from _h import *
from vectors import add_entity
from fixtures import CONF_PD, CONF_CS, INT

def pair(etype, a, b, prj, marking):
    def pre(W):
        add_entity("ent_x_a", prj, etype, a, marking)(W)
        add_entity("ent_x_b", prj, etype, b, marking)(W)
    R, _, _ = run(pre, show=False)
    return R.codes(), [w["code"] for w in R.warnings if w["code"] == "POSSIBLE_DUPLICATE"]

for a, b in [("Siemens", "SIEMENS"), ("Tom Hanks", "TOM HANKS"), ("Bosch", "BOSCH"), ("Иванов", "ИВАНОВ")]:
    print(f"{a!r:12} {b!r:12} точный ключ равен: {VAL.base_key(a) == VAL.base_key(b)};  скелет равен: {VAL.norm(a) == VAL.norm(b)}"
          f"   ({VAL.norm(a)!r} / {VAL.norm(b)!r})")
dob = "1956-07-09"
print("PERSON  Hanks Tom / HANKS TOM, одна дата рождения:",
      pair("PERSON", {"surname": "Hanks", "given_name": "Tom", "birth_date": dob}, {"surname": "HANKS", "given_name": "TOM", "birth_date": dob}, "prj_dossier", CONF_PD))
print("MODEL   Siemens S7-1200 / SIEMENS S7-1200:",
      pair("EQUIPMENT_MODEL", {"manufacturer": "Siemens", "model": "S7-1200"}, {"manufacturer": "SIEMENS", "model": "S7-1200"}, "prj_ts_pumps", INT))
print("EVENT   Meeting hq / MEETING HQ, одна дата:",
      pair("EVENT", {"title": "Meeting hq", "date": "2026-09-01"}, {"title": "MEETING HQ", "date": "2026-09-01"}, "prj_compliance", CONF_CS))
print("ORG неформальная  Team Alpha / TEAM ALPHA, один disambiguator:",
      pair("ORGANIZATION", {"name": "Team Alpha", "jurisdiction": "RU", "informal": True, "disambiguator": "grp"},
           {"name": "TEAM ALPHA", "jurisdiction": "RU", "informal": True, "disambiguator": "grp"}, "prj_compliance", CONF_CS))
print("контроль: PERSON Иванов Пётр / ИВАНОВ ПЁТР (кириллица) ->",
      pair("PERSON", {"surname": "Иванов", "given_name": "Пётр", "birth_date": dob}, {"surname": "ИВАНОВ", "given_name": "ПЁТР", "birth_date": dob}, "prj_dossier", CONF_PD))
print("контроль: CONCEPT (точный ключ) Moby Dick / MOBY DICK ->",
      pair("CONCEPT", {"label": "Moby Dick", "lang": "en"}, {"label": "MOBY DICK", "lang": "en"}, "prj_wiki_whales", FX.PUB))

"""СПОРНОЕ РЕШЕНИЕ, P2: работает как задумано, но «одна сущность — один раз» на реальных данных не удержится.
Каждая пара ниже — один и тот же объект мира; все принимаются без ошибки и без предупреждения."""
from _h import *
from vectors import add_entity, seq
from fixtures import CONF_PD, CONF_CS, PUB, INN_DEV, INN_NAMESAKE

def both(label, *adds, pre0=None):
    def pre(W):
        if pre0:
            pre0(W)
        for f in adds:
            f(W)
    R, _, _ = run(pre, show=False)
    print(f"{label}: ошибки={R.codes()} предупреждения={[w['code'] for w in R.warnings if w['code'] == 'POSSIBLE_DUPLICATE']}")

def P(eid, s, g, p=None, **kw):
    i = {"surname": s, "given_name": g, **({"patronymic": p} if p else {}), **kw}
    return add_entity(eid, "prj_dossier", "PERSON", i)
D = {"birth_date": "1980-05-05"}
both("Наталья / Наталия", P("ent_x1", "Иванова", "Наталья", **D), P("ent_x2", "Иванова", "Наталия", **D))
both("с отчеством / без отчества", P("ent_x1", "Иванов", "Пётр", "Ильич", **D), P("ent_x2", "Иванов", "Пётр", **D))
both("порядок: фамилия и имя переставлены", P("ent_x1", "Иванов", "Пётр", **D), P("ent_x2", "Пётр", "Иванов", **D))
both("инициалы", P("ent_x1", "Иванов", "Пётр", "Ильич", **D), P("ent_x2", "Иванов", "П.", "И.", **D))
both("двойная фамилия: «-» / « - » / пробел", P("ent_x1", "Салтыков-Щедрин", "Михаил", **D), P("ent_x2", "Салтыков - Щедрин", "Михаил", **D),
     P("ent_x3", "Салтыков Щедрин", "Михаил", **D))
both("транслитерация", P("ent_x1", "Иванов", "Пётр", **D), P("ent_x2", "Ivanov", "Petr", **D))
both("запятая после фамилии", P("ent_x1", "Иванов", "Пётр", **D), P("ent_x2", "Иванов,", "Пётр", **D))
both("три записи одного человека: с датой рождения / с disambiguator / только с ИНН",
     P("ent_x1", "Седов", "Пётр", "Ильич", birth_date="1960-01-01"), P("ent_x2", "Седов", "Пётр", "Ильич", disambiguator="abc"),
     P("ent_x3", "Седов", "Пётр", "Ильич", inn=INN_NAMESAKE))
O = lambda eid, **i: add_entity(eid, "prj_dossier", "ORGANIZATION", {"name": "ООО «Заречье-Девелопмент»", "jurisdiction": "RU", **i})
both("та же организация ещё раз как «филиал» (тот же ИНН + любой КПП)", O("ent_x1", legal_form="BRANCH", inn=INN_DEV, kpp="501201001"))
both("та же организация ещё раз как «неформальная»", O("ent_x1", informal=True, disambiguator="abc"))
both("одна по ОГРН, вторая по ИНН", O("ent_x1", inn=INN_DEV), pre0=lambda W: W["ent_d_developer"]["identity"].pop("inn"))
E = lambda eid, place: add_entity(eid, "prj_compliance", "EVENT", {"title": "Сход жителей", "date": "2026-09-01", "place": place}, CONF_CS)
both("событие: место «г. Заречный» / «Заречный»", E("ent_x1", "г. Заречный"), E("ent_x2", "Заречный"))
both("понятие «Синий кит»: lang ru / rus", add_entity("ent_x1", "prj_wiki_whales", "CONCEPT", {"label": "Синий кит", "lang": "rus", "namespace": "whales"}, PUB))

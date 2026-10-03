"""ОШИБКА, P2 (остаток RS-12). Снятие «ударений» — список блоков (_MARKS), а не категория Mn/Me: бреве U+0306 и
диерезис U+0308 сохраняются НА ЛЮБОЙ букве (а не только й/ё), титло U+0483, знаки иврита/арабского и др. не снимаются.
Таблица двойников не содержит самых частых для имён СНГ пар: латинские i/I ↔ кириллические і/І (украинские, белорусские,
казахские имена, набранные в русской раскладке), j/ј, s/ѕ, h/һ. Для тегов оборудования цифры-двойники (О/0, З/3,
I/l/1) не дают даже предупреждения POSSIBLE_DUPLICATE."""
import unicodedata
from _h import *
from vectors import add_entity
from fixtures import CONF_PD, INT

def pair(etype, a, b, prj="prj_dossier", marking=CONF_PD):
    def pre(W):
        add_entity("ent_x_a", prj, etype, a, marking)(W)
        add_entity("ent_x_b", prj, etype, b, marking)(W)
    R, _, _ = run(pre, show=False)
    return (R.codes() or "ПРИНЯТЫ ОБЕ"), [w["code"] for w in R.warnings if w["code"] == "POSSIBLE_DUPLICATE"]

P = lambda s: {"surname": s, "given_name": "Аркадий", "birth_date": "1980-05-05"}
print("— комбинируемые знаки (фамилия «Ломов» против «Ломо+знак+в»)")
for cp in (0x0301, 0x0306, 0x0308, 0x0483, 0x0489, 0x0591, 0x064E, 0x2DE0, 0xA66F):
    print(f"  U+{cp:04X} {unicodedata.category(chr(cp))} {unicodedata.name(chr(cp))[:38]:38} ->", pair("PERSON", P("Ломов"), P("Ломо" + chr(cp) + "в")))
print("— двойники")
for a, b in [("Зiнченко", "Зінченко"), ("Iваненко", "Іваненко"), ("Jovanović", "Јovanović"), ("Smith", "Ѕmith"), ("Ломов", "Лoмoв")]:
    print(f"  {a!r} / {b!r} ->", pair("PERSON", P(a), P(b)))
print("— теги оборудования на одной площадке")
for a, b in [("О-101", "0-101"), ("З-12", "3-12"), ("Н-1О1", "Н-101"), ("Н-l01", "Н-101"), ("НС-2", "HC-2")]:
    print(f"  {a!r} / {b!r} ->", pair("EQUIPMENT", {"site_id": "site_zz", "tag": a}, {"site_id": "site_zz", "tag": b}, "prj_ts_pumps", INT))

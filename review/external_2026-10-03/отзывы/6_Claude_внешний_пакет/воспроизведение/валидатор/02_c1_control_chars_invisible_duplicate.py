"""ОШИБКА, P1. Фаза 0 запрещает «управляющие символы в структурных полях», но проверяет только U+0000–U+001F и U+007F.
Управляющие C1 (U+0080–U+009F, категория Cc, невидимы) проходят в identity, не удаляются ни точным ключом, ни скелетом
(они не Cf и не в списке _IGNORABLE) — и дают вторую сущность с тем же видимым именем. U+0085 к тому же режет слово."""
import unicodedata
from _h import *
from vectors import add_entity
from fixtures import CONF_PD, INT, INN_DEV

def pair(etype, a, b, prj, marking):
    def pre(W):
        add_entity("ent_x_a", prj, etype, a, marking)(W)
        add_entity("ent_x_b", prj, etype, b, marking)(W)
    R, _, _ = run(pre, show=False)
    return R.codes(), [w["code"] for w in R.warnings if w["code"] == "POSSIBLE_DUPLICATE"]

P = lambda s: {"surname": s, "given_name": "Аркадий", "birth_date": "1980-05-05"}
for cp in (0x0080, 0x0086, 0x009F, 0x0085):
    s = "Ломо" + chr(cp) + "в"
    print(f"U+{cp:04X} категория {unicodedata.category(chr(cp))}: PERSON «Ломов»/«Ломо<U+{cp:04X}>в», та же дата рождения ->",
          pair("PERSON", P("Ломов"), P(s), "prj_dossier", CONF_PD), " ключи:", repr(VAL.base_key(s)), repr(VAL.norm(s)))
print("EQUIPMENT тег «Н-101» / «Н-101<U+0086>» на одной площадке ->",
      pair("EQUIPMENT", {"site_id": "site_zz", "tag": "Н-101"}, {"site_id": "site_zz", "tag": "Н-101\u0086"}, "prj_ts_pumps", INT))
print("контроль U+001F (C0) в фамилии ->", pair("PERSON", P("Ломов"), P("Ломо\u001fв"), "prj_dossier", CONF_PD))
print("контроль U+200B (Cf) в фамилии ->", pair("PERSON", P("Ломов"), P("Ломо​в"), "prj_dossier", CONF_PD))

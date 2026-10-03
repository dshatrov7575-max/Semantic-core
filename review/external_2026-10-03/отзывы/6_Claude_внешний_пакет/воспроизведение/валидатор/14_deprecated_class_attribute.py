"""ОШИБКА, P2 (схема своего времени). Предикат выведенной из употребления связи (LinkDef deprecated) после вывода
неизвестен — PREDICATE_UNKNOWN. Атрибут выведенного из употребления КЛАССА остаётся действующим предикатом: новое
утверждение, записанное после вывода класса, принимается."""
from _h import *
from vectors import nextv, xclaim, lit, seq, T_LATE
run(seq(nextv("sd_whale_v2", "sd_whale_v3", "DEPRECATE_CLASS", at=T_LATE, deprecated=True),
        xclaim("cx", "ent_wk_blue", "x.itis_tsn", lit(type="IDENTIFIER", scheme="x.itis", value="999"),
               quote=("s20", "номер в каталоге ITIS — 180528"), recorded="2026-09-05T10:00:00Z")),
    label=f"класс выведен {T_LATE}, утверждение с его атрибутом записано 2026-09-05")
run(seq(nextv("sd_belongs", "sd_belongs2", "DEPRECATE_LINK", at=T_LATE, deprecated=True),
        xclaim("cx", "ent_wk_blue", "x.belongs_to", {"entity": "ent_wk_baleen"}, recorded="2026-09-05T10:00:00Z")),
    label="контроль: связь выведена, утверждение с ней после вывода")

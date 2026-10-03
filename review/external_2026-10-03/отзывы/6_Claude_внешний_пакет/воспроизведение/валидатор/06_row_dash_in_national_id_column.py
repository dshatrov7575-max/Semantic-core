"""ОШИБКА, P2 (отвергает законное). Исправление S11R2-09 («прочерк в колонке идентификатора — не идентификатор, строка
субъекту не противоречит») работает только для схем, которые нормализуются id_norm. Для ru.inn / ru.ogrn / ru.ogrnip /
vin / imo значение берётся «как записано», «-» не пусто — и строка, верно названная по ОГРН, отвергается как «не о
субъекте», если в колонке ИНН стоит прочерк или пробел (обычная заглушка реестров)."""
from _h import *
from vectors import regds, rows_with, rowev, seq
from fixtures import OGRN_DEV

for v in ("-", " ", "0", "", None):
    R, _, _ = run(seq(regds(rows=rows_with(0, inn=v)), rowev([OGRN_DEV], ["address", "inn"])), show=False)
    print(f"ИНН в строке = {v!r:5} ->", [(e["code"], e["msg"][:95]) for e in R.errors] or "принято")

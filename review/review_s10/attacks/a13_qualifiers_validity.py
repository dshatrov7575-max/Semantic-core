#!/usr/bin/env python3
"""S10R / направление 1: утверждение говорит БОЛЬШЕ, чем строка: уточнения (qualifiers) и срок действия (valid_from/valid_to) стражем
строки не сверяются ни с чем. Для узлов графа (цикл 4, S4R-01) то же самое запрещено: уточнения = узлу, срока действия нет."""
from common import *
CASE = {"name": "case_no", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.arbitr", "predicate": "court.party_to_case"}
dv = relabel(demo_registry(columns=copy.deepcopy(REGISTRY_COLUMNS) + [CASE], rows=[dict(r, case_no="А41-12345/2026" if i == 0 else None) for i, r in enumerate(REGISTRY_ROWS)]),
             "rev-a13 " + utc(0))
src = source_rec(dv)
lit = {"literal": {"type": "IDENTIFIER", "scheme": "ru.arbitr", "value": "А41-12345/2026"}}
ev = dv.evidence([OGRN_DEV], ["case_no"])
print("строка говорит только: ОГРН девелопера, номер дела А41-12345/2026 (роли в деле в наборе нет вовсе)")
for role in ("DEFENDANT", "PLAINTIFF", "THIRD_PARTY"):
    both("Q-" + role[:3], f"«девелопер — {role} по делу А41-12345/2026» на этой строке", [src, mk_claim(copy.deepcopy(ev), predicate="court.party_to_case", obj=lit, qualifiers={"role": role})], expect="refuse")
ev2 = dv.evidence([OGRN_DEV], ["address"])
both("V-1", "«адрес регистрации действует с 1990-01-01 по 1991-12-31» (организация зарегистрирована в 2021 — колонка registered_on той же строки)",
     [src, mk_claim(copy.deepcopy(ev2), valid_from="1990-01-01", valid_to="1991-12-31")], expect="refuse")

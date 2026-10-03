"""СПОРНОЕ РЕШЕНИЕ, P2 (D6). Утверждение с атрибутом класса допустимо, только если субъект — экземпляр класса, то есть
оно выводится из утверждения schema.is_a. Маркировка атрибутного утверждения с маркировкой этого членства не
сверяется: открытое «x.max_length = 30 м» принимается при членстве CONFIDENTIAL и само раскрывает принадлежность классу
(для класса вроде «фигурант проверки» это и есть закрытое сведение)."""
from _h import *
from vectors import setk
from fixtures import mk
R, ds, ix = run(setk("c41", "marking", mk("CONFIDENTIAL")), label="членство CONFIDENTIAL, атрибут класса PUBLIC")
print("c41:", ds["records"][ix["c41"]]["predicate"], ds["records"][ix["c41"]]["marking"], "| c42:", ds["records"][ix["c42"]]["predicate"], ds["records"][ix["c42"]]["marking"])

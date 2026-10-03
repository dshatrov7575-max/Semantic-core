"""ОШИБКА, P2. Литерал QUANTITY — десятичная строка без канонической формы: «30», «30.0», «30.00» — три разных литерала
(разные claim_id). Для однозначного предиката валидатор объявляет «источники расходятся» (CONTRADICTION_SINGLE_VALUED)
между 30 м и 30.0 м; «-0» и «-0.0» принимаются как значения."""
from _h import *
from vectors import add_claim
from fixtures import PUB
def pre(W):
    add_claim("c42b", "prj_wiki_whales", "ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": "30.0", "unit": "m"}},
              ("s10", "Длина синего кита достигает 30 метров"), PUB, recorded="2026-09-03T09:40:00Z")(W)
    W["c42b"]["schema_version"] = "core-ontology/0.3"
R, _, _ = run(pre, show=False)
print("ошибки:", R.codes(), "| предупреждения:", [(w["code"], w["msg"]) for w in R.warnings if "x.max_length" in w["msg"]])
for v in ("-0", "-0.0", "30.000"):
    R, _, _ = run(lambda W: W["c25"]["object"]["literal"].__setitem__("value", v), show=False)
    print(f"QUANTITY value={v!r}:", R.codes() or "принято")

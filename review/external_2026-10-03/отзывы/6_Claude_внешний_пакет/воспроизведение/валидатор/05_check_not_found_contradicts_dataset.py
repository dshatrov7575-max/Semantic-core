"""СПОРНОЕ РЕШЕНИЕ, P1. «FOUND ⇔ есть утверждения» проверяется только по списку claim_ids самой Проверки. Завершённая
Проверка с итогом NOT_FOUND / риск NONE принимается, хотя в том же проекте есть утверждение того же измерения о том же
субъекте со статусом ACCEPTED на момент завершения. «Не выявлено» подтверждается лишь текстом следа поиска — данные,
которые его опровергают, лежат в том же наборе, и валидатор их не сопоставляет."""
from _h import *

R, ds, ix = run(show=False)
k, c = ds["records"][ix["chk_express_1"]], ds["records"][ix["c18"]]
print("эталон:", k["findings"][0]["result"], k["findings"][0]["risk"], "| c18:", c["predicate"], "о", c["subject"],
      "| ACCEPTED записано", ds["records"][ix["rev_c18_a"]]["recorded_at"], "| Проверка завершена", k["completed_at"])
def pre(W):
    k = W["chk_express_1"]
    k["findings"][0].update(result="NOT_FOUND", risk="NONE", claim_ids=[])
    k["overall_risk"] = "NONE"
run(pre, label="NEGATIVE: NOT_FOUND/NONE при принятом негативном утверждении о субъекте")
def pre2(W):
    pre(W)
    W["chk_full_1"].pop("previous_check_id")
    k = W["chk_full_1"]
    for f in k["findings"]:
        f.update(result="NOT_FOUND", risk="NONE", claim_ids=[])
    k["overall_risk"] = "NONE"
run(pre2, label="FULL: все шесть измерений NOT_FOUND при пяти принятых утверждениях")

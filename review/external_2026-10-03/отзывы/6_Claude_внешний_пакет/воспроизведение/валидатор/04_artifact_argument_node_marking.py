"""ОШИБКА, P1 (D6 «производное не шире входов»). У утверждения конвейера литерал и уточнение берутся из узлов-аргументов
графа (ACTION.text, QUANTITY.value, CONDITION.text). Валидатор требует, чтобы маркировка утверждения покрывала только
источник ФРАГМЕНТА (якорь узла-отношения). Якоря узлов-аргументов могут лежать в другом, более закрытом входе артефакта
— это не проверяется. Итог: текст из источника RESTRICTED дословно попадает в утверждение INTERNAL, которое этот
источник даже не называет."""
from _h import *
from vectors import add_source
from fixtures import mk

SECRET = "вскрыть пломбу 7-Б и подать резервное питание с фидера 12"
def pre(W):
    add_source("s_secret", "ДСП. Аварийный регламент НС-2: " + SECRET + "; уставка 16 бар.",
               marking=mk("RESTRICTED", "COMMERCIAL_SECRET"), observed="2026-09-02T08:00:00Z")(W)
    a = W["__artifacts__"]["umr_ns2"]
    a["inputs"].append("@S:s_secret")
    W["rcp_1"]["input_source_ids"].append("@S:s_secret")
    for n in a["nodes"]:
        if n["id"] == "n5":                                   # ACTION: text and anchor come from the secret source
            n["text"], n["anchor"] = SECRET, {"$anchor": ["s_secret", SECRET]}
    W["c3"]["object"] = {"literal": {"type": "STRING", "value": SECRET}}
R, ds, ix = run(pre, label="литерал из RESTRICTED-источника")
c = ds["records"][ix["c3"]]
src = {r["source_id"]: r for r in ds["records"] if r["kind"] == "Source"}
print("утверждение c3:", c["marking"], "| литерал:", c["object"]["literal"]["value"])
print("источники его доказательств:", [(src[e["source_id"]]["title"][:30], src[e["source_id"]]["marking"]["level"]) for e in c["evidence"]])
print("литерал есть в байтах процитированного источника:", SECRET in src[c["evidence"][0]["source_id"]]["content_inline"])

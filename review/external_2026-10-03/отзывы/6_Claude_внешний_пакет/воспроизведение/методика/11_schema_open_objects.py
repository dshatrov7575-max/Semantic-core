"""Схема: где объекты НЕ закрыты, где нет ограничения типа (любой JSON), якорные шаблоны у свободного текста. Запуск из core/."""
import json
S = json.load(open("core.schema.json", encoding="utf-8"))
print("$defs:", len(S["$defs"]), list(S["$defs"])[:80])
opens, anyv, pats = [], [], []
def walk(n, path):
    if isinstance(n, dict):
        is_obj = n.get("type") == "object" or "properties" in n
        if is_obj and n.get("additionalProperties", True) is not False and n.get("unevaluatedProperties", True) is not False:
            opens.append((path, {k: n[k] for k in ("additionalProperties", "propertyNames", "maxProperties") if k in n}))
        if "pattern" in n:
            pats.append((path, n["pattern"]))
        for k, v in n.items():
            walk(v, path + "/" + k)
    elif isinstance(n, list):
        for i, v in enumerate(n): walk(v, path + "/" + str(i))
walk(S, "")
print("\nobjects not closed:")
for p, x in opens: print("  ", p, json.dumps(x, ensure_ascii=False)[:300])
print("\npatterns on properties named like free text (content_inline, quote, note, value, text, row_key):")
for p, pat in pats:
    last = p.split("/")[-1]
    if last in ("content_inline", "quote", "note", "value", "text", "row_key") or "/value" in p or "/text" in p:
        print("  ", p, pat)
# свойства без type/enum/$ref/const/oneOf/anyOf — «любой JSON»
def walk2(n, path):
    if isinstance(n, dict):
        if "properties" in n:
            for k, v in n["properties"].items():
                if isinstance(v, dict) and not ({"type", "enum", "$ref", "const", "oneOf", "anyOf", "allOf"} & v.keys()):
                    anyv.append((path + "/properties/" + k, v))
                elif v is True:
                    anyv.append((path + "/properties/" + k, v))
        for k, v in n.items(): walk2(v, path + "/" + k)
    elif isinstance(n, list):
        for i, v in enumerate(n): walk2(v, path + "/" + str(i))
walk2(S, "")
print("\nproperties accepting any JSON:")
for p, v in anyv: print("  ", p, v)

"""Свидетели для выживших автоматических мутантов: вход, на котором мутант отвечает иначе, чем оригинал
(=> мутант НЕ эквивалентен, это непроверенное условие). Запуск из core/."""
import sys, importlib.util, copy
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("am", "../findings/06_auto_mutator.py"); am = importlib.util.module_from_spec(spec); spec.loader.exec_module(am)
import validator as O
from vectors import build, V, setid, setk, seq
def mut(idx):
    code, info = am.mutant_code(idx); return am.load(code), info
def show(idx, what, fo, fm):
    print(f"#{idx}: {what}\n    оригинал: {fo!r}\n    мутант:   {fm!r}   -> {'РАЗНОЕ: не эквивалентен' if fo != fm else 'одинаково'}")
def codes(mod, vec):
    ds, tr, ct = build(vec); r = mod.validate(ds, tr, ct); return r.codes()

# 437: U+3164 в таблице невидимых
M, i = mut(437); show(437, "base_key('Ло\\u3164мов') == base_key('Ломов')", O.base_key("Лоㅤмов") == O.base_key("Ломов"), M.base_key("Лоㅤмов") == M.base_key("Ломов"))
# 1879: строчная капитель ʏ U+028F -> у
M, i = mut(1879); show(1879, "norm('К\\u028Fзнецов') == norm('Кузнецов')", O.norm("Кʏзнецов") == O.norm("Кузнецов"), M.norm("Кʏзнецов") == M.norm("Кузнецов"))
# 1221: ОГРНИП с остатком от деления на 13, равным 10..12
M, i = mut(1221)
n = next(x for x in range(30000000000000, 30000000001000) if x % 13 == 11); v = f"{n}{n % 13 % 10}"
show(1221, f"ogrnip_ok('{v}')  (остаток {n % 13})", O.ogrnip_ok(v), M.ogrnip_ok(v))
import fixtures
vals = [x for x in vars(fixtures).values() if isinstance(x, str) and x.isdigit() and len(x) == 15]
print("    ОГРНИП в фикстурах:", [(x, int(x[:14]) % 13) for x in vals], "— остаток >= 10 не встречается" if all(int(x[:14]) % 13 < 10 for x in vals) else "")
# 146: тег с разделителем на конце
M, i = mut(146); show(146, "tag_norm('Н-101-') == tag_norm('Н-101')", O.tag_norm("Н-101-") == O.tag_norm("Н-101"), M.tag_norm("Н-101-") == M.tag_norm("Н-101"))
# 129: overall_risk NONE при находке LOW
M, i = mut(129)
def risk(W):
    k = W["chk_express_1"]; 
    f = next(f for f in k["findings"] if f["result"] == "FOUND") if any(f["result"] == "FOUND" for f in k["findings"]) else None
    W["__dbg__"] = None
import json
ds, tr, ct = build()
ck = [r for r in ds["records"] if r["kind"] == "Check" and r["status"] == "COMPLETED"]
print("    завершённые Проверки эталона:", [(c["check_id"], c["overall_risk"], [f["risk"] for f in c["findings"]]) for c in ck])
def post(d, ix, e):
    for r in d["records"]:
        if r["kind"] == "Check" and r["status"] == "COMPLETED" and r["overall_risk"] == "LOW":
            r["overall_risk"] = "NONE"; return
        if r["kind"] == "Check" and r["status"] == "COMPLETED" and r["overall_risk"] == "NONE":
            r["overall_risk"] = "LOW"; return
vec = V("W129", [], "", post=post)
show(129, "overall_risk NONE<->LOW при неизменных находках", codes(O, vec), codes(M, vec))
# 157: идентификатор-литерал из ASCII-не-цифр / из полноширинных цифр
M, i = mut(157)
for val in ("3040000000000ab", "３０４" + "000000000000"):
    show(157, f"_ascii_digits({val!r})", O._ascii_digits(val), M._ascii_digits(val))
# 1186: U+D7FF
M, i = mut(1186); show(1186, "_bad_str('\\ud7ff')", O._bad_str("퟿"), M._bad_str("퟿"))

# ---- границы времени (целевой прогон)
from vectors import add_entity, _qualify
M, i = mut(1014)
vec = V("W1014", [], "уточнение и слияние в одну и ту же секунду",
        pre=seq(add_entity("ent_d_lomov_x", "prj_dossier", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "birth_date": "1971-03-14"},
                           status="MERGED", merged_into="ent_d_lomov", changed="2026-09-06T11:00:00Z"),
                _qualify("idd_xx", "prj_dossier", "ent_d_lomov_x", disambiguator="zzz")))
show(1014, "уточнение (decided_at 11:00:00) сущности, слитой в ту же секунду", codes(O, vec), codes(M, vec))
M, i = mut(817)
def sur(d, ix, e):
    next(r for r in d["records"] if r["kind"] == "Entity")["display_name"] = "x\ud800y"
vec = V("W817", [], "", post=sur)
show(817, "одиночный суррогат U+D800 (нижняя граница диапазона) в display_name", codes(O, vec), codes(M, vec))

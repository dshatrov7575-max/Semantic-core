#!/usr/bin/env python3
"""RS re-review v0.2.1: attacks on the normative validator (clean-room, core/ only read).
Usage: CORE=<path to core> python3 validator_attacks.py
Each line: id | verdict | codes | warnings | description.  FINDING = the rule is bypassed or a legit case is refused.
"""
import copy
import os
import subprocess
import sys
import tempfile
import json
from pathlib import Path

CORE = Path(os.environ.get("CORE", Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(CORE))
from validator import validate  # noqa: E402
from vectors import build, add_entity, seq  # noqa: E402
from fixtures import CONF_PD, INT, PUB, CONF_CS  # noqa: E402

rows = []


def run(aid, desc, pre=None, post=None, want=None, finding_if=None):
    ds, tr, ct = build({"pre": pre, "post": post})
    r = validate(ds, tr, ct)
    codes, warns = r.codes(), sorted({w["code"] for w in r.warnings} - {"CONTRADICTION_SINGLE_VALUED"})
    verdict = "FINDING" if finding_if and finding_if(codes, warns) else "ok"
    rows.append((aid, verdict, codes, warns, desc))
    print(f"{aid:<8} {verdict:<8} errors={codes} warnings={warns} | {desc}", flush=True)
    return r


LOMOV = {"surname": "Ломов", "given_name": "Аркадий", "patronymic": "Семёнович", "birth_date": "1971-03-14"}


def person(name, **ov):
    ident = dict(LOMOV, **ov)
    return add_entity(name, "prj_dossier", "PERSON", ident, CONF_PD)


silent = lambda c, w: "ENTITY_DUPLICATE_IN_PROJECT" not in c and not w  # noqa: E731
dup = lambda c, w: "ENTITY_DUPLICATE_IN_PROJECT" in c  # noqa: E731
only_warn = lambda c, w: not c and "POSSIBLE_DUPLICATE" in w  # noqa: E731

print("== B1: skeleton bypasses (второе лицо Ломова без ИНН, та же дата рождения; ожидается ENTITY_DUPLICATE_IN_PROJECT)")
run("B1-00", "контроль: «Ломов» без ИНН с той же ФИО+датой", pre=person("ent_xx"), finding_if=silent)
run("B1-01", "ударение U+0301 (комбинирующий акут): «Ломо́в»", pre=person("ent_xx", surname="Ломо́в"), finding_if=silent)
run("B1-02", "латинская ë U+00EB в отчестве: «Семëнович»", pre=person("ent_xx", patronymic="Семëнович"), finding_if=silent)
run("B1-03", "армянская օ U+0585: «Лօмов»", pre=person("ent_xx", surname="Лօмов"), finding_if=silent)
run("B1-04", "латинская капитель ᴏ U+1D0F: «Лᴏмов»", pre=person("ent_xx", surname="Лᴏмов"), finding_if=silent)
run("B1-05", "греческая лунная сигма Ϲ U+03F9: «Ϲемёнович»", pre=person("ent_xx", patronymic="Ϲемёнович"), finding_if=silent)
run("B1-06", "чероки Ꭺ U+13AA: «Ꭺркадий»", pre=person("ent_xx", given_name="Ꭺркадий"), finding_if=silent)
run("B1-07", "пустой шрифт Брайля U+2800 внутри фамилии", pre=person("ent_xx", surname="Ло⠀мов"), finding_if=silent)
run("B1-08", "контроль: греческая ο U+03BF (заявлено закрытым RR-03k)", pre=person("ent_xx", surname="Лοмов"), finding_if=silent)
run("B1-09", "контроль: U+034F CGJ (заявлено закрытым RR-03h)", pre=person("ent_xx", surname="Ло͏мов"), finding_if=silent)

print("== B2: оборудование и понятия (RR-02 понижение до предупреждения)")
eq = lambda name, tag: add_entity(name, "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": tag}, INT)  # noqa: E731
run("B2-01", "ложное слияние: разные теги «К-1/12» и «К-11/2» (разделители выброшены) -> ошибка без обхода",
    pre=seq(eq("ent_e1", "К-1/12"), eq("ent_e2", "К-11/2")), finding_if=dup)
run("B2-02", "ложное слияние: «TT-10-1» (контур 10, датчик 1) и «TT-101»",
    pre=seq(eq("ent_e1", "TT-10-1"), eq("ent_e2", "TT-101")), finding_if=dup)
run("B2-03", "настоящий дубль насоса Н-101 латинской H: только предупреждение",
    pre=eq("ent_e1", "H-101"), finding_if=only_warn)
run("B2-04", "дубль насоса Н-101 с комбинирующим U+0301: ни ошибки, ни предупреждения",
    pre=eq("ent_e1", "Н́-101"), finding_if=silent)
run("B2-05", "дубль насоса: надстрочные цифры «Н-1⁰¹» — только предупреждение",
    pre=eq("ent_e1", "Н-1⁰¹"), finding_if=only_warn)
cp = lambda name, label, dis=None: add_entity(name, "prj_wiki_whales", "CONCEPT",  # noqa: E731
                                            dict({"label": label, "lang": "ru", "namespace": "whales"}, **({"disambiguator": dis} if dis else {})), PUB)
run("B2-06", "дубль понятия «Синий кит» с латинской C: только предупреждение", pre=cp("ent_c1", "Cиний кит"), finding_if=only_warn)
run("B2-07", "дубль понятия «Синий кит.» (точка): ни ошибки, ни предупреждения", pre=cp("ent_c1", "Синий кит."), finding_if=silent)
run("B2-08", "омоним: у существующего «Синий кит» нет пометки, новому пометка не помогает (надо менять старую — в БД identity неизменяема)",
    pre=cp("ent_c1", "синий кит", "colour-name"), finding_if=dup)
model = lambda name, m: add_entity(name, "prj_ts_pumps", "EQUIPMENT_MODEL", {"manufacturer": "НасосМаш", "model": m}, INT)  # noqa: E731
run("B2-09", "ложное слияние моделей «ЦНС 10²» и «ЦНС 102» (NFKC в ключе уровня ошибки, RR-02d не исправлен)",
    pre=seq(model("ent_m1", "ЦНС 10²"), model("ent_m2", "ЦНС 102")), finding_if=dup)

print("== B3: квалификаторы и уровни идентичности")
run("B3-01", "конфликт с местом «Заречный» вместо «г. Заречный» — второй конфликт",
    pre=add_entity("ent_cf2", "prj_conflict_land", "CONFLICT",
                   {"title": "Застройка участка на ул. Заречной", "started_on": "2026-09-02", "place": "Заречный"}, CONF_PD), finding_if=silent)
run("B3-02", "тот же Ломов в проекте конфликта: уже есть с disambiguator, добавлен с датой рождения — ключи не встречаются",
    pre=add_entity("ent_cl2", "prj_conflict_land", "PERSON", {"surname": "Ломов", "given_name": "Аркадий", "birth_date": "1971-03-14"}, CONF_PD),
    finding_if=silent)
run("B3-03", "неформальная группа: то же название, другой disambiguator — вторая сущность без предупреждения",
    pre=add_entity("ent_ig2", "prj_conflict_land", "ORGANIZATION",
                   {"name": "Инициативная группа «Заречная, 12»", "jurisdiction": "RU", "informal": True, "disambiguator": "zarechnaya12"}, CONF_PD),
    finding_if=silent)

ig = lambda name, nm: add_entity(name, "prj_conflict_land", "ORGANIZATION",  # noqa: E731
                                 {"name": nm, "jurisdiction": "RU", "informal": True, "disambiguator": "zarechnaya-12"}, CONF_PD)
run("B3-04", "контроль: неформальная группа с латинскими a/e/o в названии и тем же disambiguator — дубль найден",
    pre=ig("ent_ig3", "Инициaтивная группa «Зaречнaя, 12»"), finding_if=silent)
run("B3-05", "неформальная группа: ударение U+0301 в названии («Заре́чная»), тот же disambiguator — дубль не найден",
    pre=ig("ent_ig3", "Инициативная группа «Заре\u0301чная, 12»"), finding_if=silent)


def chain(W):
    W["ent_d_lomov2"] = copy.deepcopy(W["ent_d_lomov"])
    W["ent_d_lomov2"].update(entity_id="ent_d_lomov2", identity={"surname": "Ломов", "given_name": "Аркадий", "disambiguator": "later-card"})
    W["ent_d_lomov"].update(status="MERGED", merged_into="ent_d_lomov2", status_changed_at="2026-09-20T10:00:00Z")


print("== B4: время слияния (RR-01, RR-13)")
run("B4-01", "цепочка слияний: дубль слит в Ломова 06.09, Ломов позже (20.09) слит в новую карточку — законная история отвергнута",
    pre=chain, finding_if=lambda c, w: "ENTITY_MERGE_INVALID" in c)


def merge_before_birth(W):
    add_entity("ent_d_new", "prj_dossier", "PERSON", {"surname": "Петров", "given_name": "Пётр", "disambiguator": "target-born-later"}, CONF_PD)(W)
    W["ent_d_new"]["created_at"] = "2026-09-25T00:00:00Z"
    add_entity("ent_d_old", "prj_dossier", "PERSON", {"surname": "Петров", "given_name": "Пётр", "disambiguator": "old-card"}, CONF_PD,
               "MERGED", "ent_d_new", "2026-09-06T00:00:00Z")(W)


run("B4-02", "слияние 06.09 в сущность, созданную 25.09 (цель не существовала в момент слияния) — принято",
    pre=merge_before_birth, finding_if=lambda c, w: not c)


def retire_at(ts):
    def f(W):
        W["ent_k_lomov"].update(status="RETIRED", status_changed_at=ts)
    return f


run("B4-03", "контроль: субъект закрытой Проверки выведен ровно в момент закрытия -> ошибка (строго позже)", pre=retire_at("2026-09-27T12:00:00Z"),
    finding_if=lambda c, w: "CHECK_SUBJECT_INVALID" not in c)
run("B4-04", "контроль: выведен через секунду после закрытия -> принято (RR-01 закрыт)", pre=retire_at("2026-09-27T12:00:01Z"),
    finding_if=lambda c, w: bool(c))
run("B4-05", "status_changed_at в будущем (2099) принят валидатором (в БД время ставит база)", pre=retire_at("2099-01-01T00:00:00Z"),
    finding_if=lambda c, w: bool(c))

print("== B5: доверие по tenant (RR-06)")


def other_tenant_broken(d, ix, e):
    k = dict(e["trust"]["keys"][0], tenant_id="tnt_other", key_id="key_other")
    k["not_before"], k["not_after"] = k["not_after"], k["not_before"]
    e["trust"]["keys"].append(k)


run("B5-01", "битая запись ДРУГОГО tenant в реестре: набор tnt_demo целиком получает ошибку TRUST_CONFIG_INVALID (загрузчик откажет)",
    post=other_tenant_broken, finding_if=lambda c, w: "TRUST_CONFIG_INVALID" in c)

print("== B6: литералы (RR-11)")
run("B6-01", "ОГРНИП-литерал с верной контрольной суммой, но чужой (не ОГРНИП субъекта) — принят",
    pre=lambda W: W["c17b"]["object"]["literal"].__setitem__("value", "304500116000157"), finding_if=lambda c, w: not c)

print("== B7: CLI (RR-05)")
with tempfile.TemporaryDirectory() as tmp:
    ds, tr, ct = build()
    p = Path(tmp) / "ds.json"
    p.write_text(json.dumps(ds, ensure_ascii=False), encoding="utf-8")
    (Path(tmp) / "file").write_text("x")
    for aid, args, desc in [("B7-01", [str(p), "--content-dir", str(Path(tmp) / "nope")], "--content-dir на несуществующий каталог"),
                            ("B7-02", [str(p), "--content-dir", str(Path(tmp) / "file")], "--content-dir указывает на файл"),
                            ("B7-03", [str(p), "--trust"], "--trust без значения")]:
        r = subprocess.run([sys.executable, str(CORE / "validator.py"), *args], capture_output=True, text=True)
        tb = "Traceback" in r.stderr
        last = (r.stderr.strip().splitlines() or [""])[-1]
        rows.append((aid, "FINDING" if tb else "ok", [], [], desc))
        print(f"{aid:<8} {'FINDING' if tb else 'ok':<8} exit={r.returncode} traceback={tb} {last[:90]} | {desc}")

n = sum(1 for r in rows if r[1] == "FINDING")
print(f"\nvalidator_attacks={len(rows)} findings={n}")


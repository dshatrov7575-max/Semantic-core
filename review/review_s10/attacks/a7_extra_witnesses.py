#!/usr/bin/env python3
"""S10R / направление 7: для выживших мутантов рецензента (a7_extra_mutants.py) — вход-свидетель, на котором мутант и валидатор расходятся.
Есть свидетель => это правило действует, а вектора на него нет. Нет свидетеля => мутант эквивалентен (в находку не идёт)."""
from common import *
import mutants as MU
import a7_extra_mutants as XM
E_DEV = next(r for r in world()[0]["records"] if r["kind"] == "Entity" and r["entity_id"] == "ent_k_developer")
E_LOM = next(r for r in world()[0]["records"] if r["kind"] == "Entity" and r["entity_id"] == "ent_k_lomov")
def mutant(mid):
    m = next(x for x in XM.X if x[0] == mid); return MU.load(MU.SRC.replace(m[2], m[3])), m[1]
def run(mod, records):
    ds, tr, ct = world(); ds["records"] = ds["records"] + copy.deepcopy(records)
    rep = mod.validate(ds, tr, ct)
    return "ПРИНЯТО" if not rep.errors else "ОТКАЗ " + ",".join(rep.codes())
def show(mid, desc, records):
    mod, what = mutant(mid); a, b = run(VAL, records), run(mod, records)
    print(f"{mid} «{what}»\n   свидетель: {desc}\n   валидатор: {a}\n   мутант:    {b}\n   => {'РАСХОДЯТСЯ: правило действует, вектора нет' if a != b else 'различия не найдено'}\n")
def ent(eid, identity, status="ACTIVE", into=None, at=None, etype="ORGANIZATION", like=E_DEV):
    e = copy.deepcopy(like); e.update(entity_id=eid, identity=identity, entity_type=etype, status=status, created_at="2026-09-02T00:00:00Z")
    e.pop("merged_into", None); e.pop("status_changed_at", None)
    if into: e.update(merged_into=into, status_changed_at=at)
    return e
OBS, REC = "2026-09-05T08:00:00Z", "2026-09-26T09:00:00Z"
RIV = {"name": "rival_ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn", "predicate": "competitor.competes_with"}
OG2 = REGISTRY_ROWS[2]["ogrn"]; IN2 = REGISTRY_ROWS[2]["inn"]
def rival_world(merge_at):
    dv = relabel(demo_registry(columns=copy.deepcopy(REGISTRY_COLUMNS) + [RIV], rows=[dict(r, rival_ogrn=OG2 if i == 0 else None) for i, r in enumerate(REGISTRY_ROWS)]), "rev-x01")
    a = ent("ent_rev_trub", {"name": "АО «Трубопроводстрой»", "jurisdiction": "RU", "ogrn": OGRN_TRUB, "inn": INN_TRUB})
    b = ent("ent_rev_alfa", {"name": "ООО «Альфа-Сервис»", "jurisdiction": "RU", "ogrn": OG2, "inn": IN2}, "MERGED", "ent_rev_trub", merge_at)
    c = mk_claim(dv.evidence([OGRN_DEV], ["rival_ogrn"]), predicate="competitor.competes_with", obj={"entity": "ent_rev_trub"}, recorded=REC)
    return [source_rec(dv, observed=OBS), a, b, c]
show("X01", "объект утверждения — выжившая сущность, ячейка называет ОГРН сущности, влитой в неё ДО утверждения (2026-09-20)", rival_world("2026-09-20T10:00:00Z"))
show("X02", "то же, но слияние ПОЗЖЕ утверждения (2026-09-27): на момент утверждения ячейка называет другую организацию", rival_world("2026-09-27T10:00:00Z"))
# X03: колонка дат подтверждает литерал-дату (person.birth_date)
inn_l = E_LOM["identity"].get("inn")
cols = [{"name": "inn", "type": "STRING", "marking": {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}, "identifier_scheme": "ru.inn"},
        {"name": "born", "type": "DATE", "marking": {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}, "predicate": "person.birth_date"}]
dp = DatasetVersion("dst_rev_persons", T, "rev-x03", cols, ["inn"], [{"inn": inn_l, "born": "1970-05-17"}], subject=("inn",))
cm = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}
c3 = mk_claim(dp.evidence([inn_l], ["born"]), subj="ent_k_lomov", predicate="person.birth_date", obj={"literal": {"type": "DATE", "value": "1970-05-17"}}, marking=cm, recorded=REC)
show("X03", "набор лиц: колонка born (DATE) объявлена для person.birth_date; утверждение — дата рождения литералом DATE", [source_rec(dp, observed=OBS, marking=cm), c3])
dv = demo_registry()
c4 = mk_claim(dv.evidence([OGRN_DEV], ["address"]), subj="ent_no_such_entity", recorded=REC)
show("X04", "утверждение на строке о несуществующем субъекте (REF_UNRESOLVED у обоих; у мутанта ещё и внутренняя ошибка)", [c4])
dr = relabel(demo_registry(columns=copy.deepcopy(REGISTRY_COLUMNS) + [RIV], rows=[dict(r, rival_ogrn=OGRN_TRUB if i == 0 else None) for i, r in enumerate(REGISTRY_ROWS)]), "rev-x05")
c5 = mk_claim(dr.evidence([OGRN_DEV], ["rival_ogrn"]), predicate="competitor.competes_with", obj={"entity": "ent_no_such_entity"}, recorded=REC)
show("X05", "утверждение на строке с несуществующей сущностью-объектом", [source_rec(dr, observed=OBS), c5])
m6 = ent("ent_rev_dup", {"name": "ООО «Заречье-Девелопмент» (дубль)", "jurisdiction": "RU", "ogrn": OG2, "inn": IN2}, "MERGED", "ent_k_developer", "2026-09-20T10:00:00Z")
c6 = mk_claim(dv.evidence([OGRN_DEV], ["address"]), subj="ent_rev_dup", recorded=REC)
show("X06", "субъект утверждения сам слит в девелопера ДО утверждения; строка — девелопера", [m6, c6])
e7 = dv.evidence([OGRN_DEV], ["address"]); e7["cells"][-1] = {"name": "zzz", "value": 1, "salt": "0" * 64}
show("X07", "процитированная ячейка с именем, которого нет среди колонок манифеста", [mk_claim(e7, recorded=REC)])

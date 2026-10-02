#!/usr/bin/env python3
"""Рецензия цикла 9: атаки на валидатор (снимок). Запуск: python3 val_attacks_s9.py > val_attacks_s9.out"""
import sys, time, copy
from pathlib import Path
SNAP = Path(__file__).resolve().parent.parent / "snapshot" / "core"
sys.path.insert(0, str(SNAP))
import vectors as VX
from vectors import V, build, add_entity, _classdef, _linkdef, _identifierdef, _schemachange, _add_schema_world, _isa_claim_world, T
from validator import validate
PUB = VX.PUB; INT = VX.INT; CONF_PD = VX.CONF_PD

def run(title, pre=None, post=None):
    ds, tr, ct = build(V("X", [], title, pre=pre, post=post))
    r = validate(ds, tr, ct)
    msgs = [f"{e['code']}: {e['msg']}" for e in r.errors]
    print(f"{title}\n    -> codes={r.codes()}" + ("" if not msgs else "\n       " + "\n       ".join(m[:150] for m in msgs[:4])))
    return r

def seq(*fs):
    def f(W):
        for g in fs: g(W)
    return f
def put(name, rec):
    return lambda W: W.__setitem__("zz_" + name, rec)
def isa(key, subj, cls, **kw):
    return lambda W: _isa_claim_world(W, "zz_" + key, subj, cls, **kw)
def other_tenant_project(W):
    W["prj_other"] = {"kind": "Project", "schema_version": VX._SV9, "project_id": "prj_other", "tenant_id": "tnt_other",
                      "product": "DOSSIER", "title": "Чужой проект", "created_at": "2026-09-01T09:00:00Z", "default_marking": PUB}

t0 = time.time()
print("== A. собственные векторы цикла 9 (контроль) ==")
for v in VX.VECTORS:
    if v["id"] in ("P801","P802","N801","N802","N803","N810","N811","N820","N830","N831","N832"):
        ds, tr, ct = build(v); got = validate(ds, tr, ct).codes()
        print(f"{v['id']} expected={v['expected']} got={got} {'OK' if got == v['expected'] else 'MISMATCH'}")

print("\n== B. THING ==")
run("B1 сущность THING (валидатор)", pre=add_entity("ent_thing1", "prj_wiki_whales", "THING", {"label": "Акулы", "lang": "ru"}, PUB))
run("B2 is_a сущности THING на класс THING",
    pre=seq(add_entity("ent_thing1", "prj_wiki_whales", "THING", {"label": "Акулы", "lang": "ru"}, PUB),
            put("cls_t", _classdef("thing_cls", root_type="THING")),
            isa("cl_t", "ent_thing1", "sdf_thing_cls", project_id="prj_wiki_whales", source_key="s2")))

print("\n== C. иерархия ==")
run("C1 самоссылка parent=self", pre=put("c1", _classdef("selfp", parent="selfp")))
run("C2 цикл A->B->A", pre=seq(put("ca", _classdef("cyc_a", parent="cyc_b")), put("cb", _classdef("cyc_b", parent="cyc_a"))))
def chain(n):
    def f(W):
        W["zz_k0"] = _classdef("ch0")
        for i in range(1, n): W[f"zz_k{i}"] = _classdef(f"ch{i}", parent=f"ch{i-1}")
    return f
t = time.time(); run("C3 цепочка 400 классов (валидна)", pre=chain(400)); print(f"    time={time.time()-t:.1f}s")

print("\n== D. tenant ==")
run("D1 is_a на класс чужого tenant (класс tnt_other, проект tnt_demo)",
    pre=seq(_add_schema_world, put("cf", {**_classdef("foreign_cls"), "tenant_id": "tnt_other"}), isa("cl", "ent_c_developer", "sdf_foreign_cls")))
def bad_lit_tenant(W):
    _add_schema_world(W); _isa_claim_world(W, "zz_cl", "ent_c_developer", "sdf_org_sub")
    W["zz_cl"]["object"]["literal"]["tenant_id"] = "tnt_someone_else"
run("D2 CLASS_REF.tenant_id = tnt_someone_else, класс и проект в tnt_demo", pre=bad_lit_tenant)
run("D3 SchemaChange tenant=tnt_other на ClassDef tenant=tnt_demo",
    pre=seq(_add_schema_world, put("sx", {**_schemachange("foreign_chg", "sdf_org_sub"), "tenant_id": "tnt_other"})))
run("D4 LinkDef tenant=tnt_other, domain/range в tnt_demo (правило CROSS_SCOPE у LinkDef)",
    pre=seq(_add_schema_world, put("lx", {**_linkdef("xt", "org_sub", "person_vip"), "tenant_id": "tnt_other"})))
run("D5 два tenant хотят один class_id sdf_org_sub",
    pre=seq(_add_schema_world, lambda W: W.__setitem__("zz_dup", {**_classdef("org_sub"), "tenant_id": "tnt_other"})))
run("D6 одинаковый id sdf_same у ClassDef и LinkDef (разные виды)",
    pre=seq(_add_schema_world, put("cs", _classdef("same")), put("ls", {**_linkdef("z", "org_sub", "person_vip"), "link_id": "sdf_same"})))

print("\n== E. время и версии ==")
run("E1 ClassDef created_at=2099, is_a recorded_at=2026-10-02 (класс «создан» позже утверждения)",
    pre=seq(_add_schema_world, lambda W: W["cls_org_sub"].__setitem__("created_at", "2099-01-01T00:00:00Z"), isa("cl", "ent_c_developer", "sdf_org_sub")))
run("E2 ClassDef created_at=1970", pre=seq(_add_schema_world, lambda W: W["cls_org_sub"].__setitem__("created_at", "1970-01-01T00:00:00Z")))
run("E3 SchemaChange recorded_at раньше created_at цели (2001 г.)",
    pre=seq(_add_schema_world, lambda W: W["scx_add_org"].__setitem__("recorded_at", "2001-01-01T00:00:00Z")))
run("E4 вторая версия класса: тот же class_id, version=2",
    pre=seq(_add_schema_world, put("v2", {**_classdef("org_sub", version=2), "name": "Новое имя"})))
run("E5 первая и единственная запись класса сразу version=7", pre=put("v7", _classdef("v7only", version=7)))

print("\n== F. декоративные поля ==")
run("F1 ClassDef без SchemaChange", pre=put("c", _classdef("lonely")))
run("F2 SchemaChange ADD_LINK с target_kind=ClassDef", pre=seq(_add_schema_world, put("sx", _schemachange("addlink_on_class", "sdf_org_sub", "ClassDef", "ADD_LINK"))))
run("F3 SchemaChange CHANGE_IDENTIFIER_STRENGTH на LinkDef", pre=seq(_add_schema_world, put("sx", _schemachange("x2", "sdf_lnk_sub_to_vip", "LinkDef", "CHANGE_IDENTIFIER_STRENGTH"))))
run("F4 is_a на абстрактный класс", pre=seq(put("ab", _classdef("abs_org", is_abstract=True)), isa("cl", "ent_c_developer", "sdf_abs_org")))
A = lambda aid, pred, **kw: {"attr_id": aid, "predicate_id": pred, "cardinality": "ONE", "required": True, **kw}
run("F5 attributes: predicate_id не существует + дубль attr_id", pre=put("c", _classdef("attrs", attributes=[A("inn", "no.such_predicate"), A("inn", "another.nothing")])))
run("F6 attributes: предикат вне домена root_type (person.birth_date у ORGANIZATION)", pre=put("c", _classdef("attrs2", attributes=[A("bd", "person.birth_date")])))
run("F7 наследник объявляет inherited=true для атрибута, которого у родителя нет",
    pre=seq(put("p", _classdef("par")), put("c", _classdef("chi", parent="par", attributes=[A("ghost", "corp.director_of", inherited=True)]))))
run("F8 required-атрибут класса, is_a есть, утверждения по атрибуту нет",
    pre=seq(put("c", _classdef("needs", attributes=[A("addr", "entity.registered_address")])), isa("cl", "ent_c_developer", "sdf_needs")))
run("F9 LinkDef: predicate_id не зарегистрирован (no.such_thing)", pre=seq(_add_schema_world, put("l", _linkdef("q", "org_sub", "person_vip", predicate_id="no.such_thing"))))
run("F10 LinkDef: inverse_predicate_id не зарегистрирован", pre=seq(_add_schema_world, put("l", _linkdef("q", "org_sub", "person_vip", inverse_predicate_id="no.such_inverse"))))
run("F11 LinkDef: symmetric=true при domain!=range и с inverse", pre=seq(_add_schema_world, put("l", _linkdef("q", "org_sub", "person_vip", symmetric=True, inverse_predicate_id="corp.director_of"))))
run("F12 LinkDef corp.director_of domain=org_sub(ORGANIZATION) — в реестре предикатов домен PERSON; и два LinkDef на один предикат с ONE/MANY",
    pre=seq(_add_schema_world, put("l1", _linkdef("d1", "org_sub", "org_sub", predicate_id="corp.director_of", cardinality="ONE")),
            put("l2", _linkdef("d2", "person_vip", "person_vip", predicate_id="corp.director_of", cardinality="MANY"))))
run("F13 IdentifierDef: два определения одной (tenant, scheme, root_type), STRONG и WEAK",
    pre=seq(put("i1", _identifierdef("dupa", scheme="ext.same")), put("i2", _identifierdef("dupb", scheme="ext.same", strength="WEAK"))))
run("F14 IdentifierDef: переопределение встроенной ru.inn как WEAK c validation_regex '.*'",
    pre=put("i", _identifierdef("inn", scheme="ru.inn", strength="WEAK", validation_regex=".*")))
run("F15 IdentifierDef: невалидное регулярное выражение '([' и катастрофическое '(a+)+$'",
    pre=seq(put("i1", _identifierdef("badre", validation_regex="([")), put("i2", _identifierdef("redos", normalization_regex="(a+)+$"))))
run("F16 IdentifierDef applies_to_root_type='PLANET' (какое правило отвергает?)", pre=put("i", _identifierdef("pl", root_type="PLANET")))

print("\n== G. маркировки ==")
def pub_claim_on_restricted_class(W):
    W["zz_cr"] = _classdef("secret_cls", root_type="CONCEPT", marking={"level": "RESTRICTED", "categories": ["COMMERCIAL_SECRET"]}, label_ru="Секретная таксономия")
    add_entity("ent_pub_concept", "prj_wiki_whales", "CONCEPT", {"label": "Тестовое понятие рецензии", "lang": "ru"}, PUB)(W)
    _isa_claim_world(W, "zz_cl", "ent_pub_concept", "sdf_secret_cls", project_id="prj_wiki_whales")
    W["zz_cl"]["marking"] = PUB
    W["zz_cl"]["object"]["literal"]["label"] = "Секретная таксономия"
r = run("G1 PUBLIC-утверждение is_a на RESTRICTED-класс (с label класса в литерале)", pre=pub_claim_on_restricted_class)
run("G2 наследник PUBLIC у родителя RESTRICTED", pre=seq(put("p", _classdef("secret_par", marking={"level": "RESTRICTED", "categories": []})), put("c", _classdef("pub_child", parent="secret_par", marking=PUB))))
print(f"\ntotal {time.time()-t0:.0f}s")

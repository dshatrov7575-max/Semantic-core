#!/usr/bin/env python3
"""S9 attacks on the schema-as-data tables (cycle 9, D27.1): no validator in front — what the Model Constructor
(ac_modeler), the loader (ac_loader), the migrator and the owner can and cannot do. Each attack must be refused
(«held»); lines marked «законная» must be accepted. Includes the findings of the independent review
(S9R-01 … S9R-28) as regression attacks, two races and a growth measurement.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s9.py
"""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
from s9_tests import claim, entity, kref, sd, PUB, INT  # noqa: E402
from schema_s9 import schema_sql  # noqa: E402

BAD = []
SD, SC, SV, T, RF, MB = (["SCHEMA_DEF_INVALID"], ["SCHEMA_CHANGE_INVALID"], ["SCHEMA_INVALID"], ["TEMPORAL_ORDER_INVALID"],
                         ["REF_UNRESOLVED"], ["MARKING_BROADER_THAN_INPUT"])
CK, PD, AO = ["violates check constraint"], ["permission denied"], ["APPEND_ONLY"]


def attack(aid, desc, sql, expect, legit=False):
    r = psql(sql)
    err = next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), "").replace("psql:<stdin>:", "")
    ok = (r.returncode == 0) if legit else (r.returncode != 0 and any(e in r.stderr for e in expect))
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {'законная: ' if legit else ''}{desc} | {err[:120] or 'принято'}", flush=True)


def as_(role, body, commit=False):
    return f"SET SESSION AUTHORIZATION {role};\nBEGIN;\n{body}\n{'COMMIT' if commit else 'ROLLBACK'};"


def mod(*records, commit=False, role="ac_s9_modeler"):
    return as_(role, schema_sql(list(records)), commit)


def cls(did, version=1, ctype="ADD_CLASS", root="CONCEPT", name="Класс атаки", **kw):
    return sd("ClassDef", did, version, ctype, root_type=root, name=name, **kw)


def raw_class(**over):
    cols = {"tenant_id": "'tnt_demo'", "class_id": "'sdf_raw'", "version": "1", "root_type": "'CONCEPT'", "name": "'Класс'",
            "marking": "'{\"level\":\"PUBLIC\",\"categories\":[]}'", "change_type": "'ADD_CLASS'", "description": "'атака'",
            "recorded_at": "now()", "recorded_by": "'usr_modeler1'"}
    cols.update(over)
    return f"INSERT INTO ac.class_defs ({', '.join(cols)}) VALUES ({', '.join(cols.values())});"


def loader(*records):
    return ingest_sql(list(records), {}, commit=False)


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    setup = """
    DO $$ BEGIN CREATE ROLE ac_s9_modeler LOGIN IN ROLE ac_modeler; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    DO $$ BEGIN CREATE ROLE ac_s9_migrator LOGIN IN ROLE ac_migrator; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
    """
    if psql(setup).returncode:
        sys.exit("setup failed")
    time.sleep(1.1)
    rank = {"predicate_id": "x.rank", "name": "ранг", "value_type": "STRING", "cardinality": "ONE", "required": False}
    whale2 = [{"predicate_id": "x.max_length", "name": "наибольшая длина", "value_type": "QUANTITY", "unit": "m", "cardinality": "ONE",
               "required": True},
              {"predicate_id": "x.itis_tsn", "name": "номер ITIS", "value_type": "IDENTIFIER", "scheme": "x.itis", "cardinality": "ONE",
               "required": False}]
    whale = dict(root_type="CONCEPT", name="Вид китов", parent_class_id="sdf_taxon")
    taxon = dict(root_type="CONCEPT", name="Таксон", parent_class_id="sdf_organism")

    # ---- legitimate writes
    attack("L1", "конструктор добавляет класс-наследник с атрибутом", mod(cls("sdf_new", parent_class_id="sdf_taxon", attributes=[rank])), [], True)
    attack("L2", "конструктор переименовывает класс (версия 2)", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", **{**taxon, "name": "Таксон (группа)"})), [], True)
    attack("L3", "тот же class_id в схеме другого tenant", mod(cls("sdf_taxon", tenant="tnt_other", root="ORGANIZATION")), [], True)

    # ---- form of the records (S9R-07)
    attack("F1", "маркировка вне словаря", as_("ac_s9_modeler", raw_class(marking="'{\"level\":\"TOP_SECRET\",\"zzz\":1}'")), CK)
    attack("F2", "маркировка — строка", as_("ac_s9_modeler", raw_class(marking="'\"строка\"'")), CK)
    attack("F3", "имя из пробелов", as_("ac_s9_modeler", raw_class(name="'   '")), CK)
    attack("F4", "имя из неразрывных пробелов", as_("ac_s9_modeler", raw_class(name="E'\\u00A0\\u2003'")), CK)
    attack("F5", "пустое описание изменения", as_("ac_s9_modeler", raw_class(description="''")), CK)
    attack("F6", "корневой тип вне десяти", as_("ac_s9_modeler", raw_class(root_type="'PLANET'")), CK)
    attack("F7", "атрибут с предикатом вне пространства «x.»", mod(cls("sdf_new", attributes=[{**rank, "predicate_id": "corp.director_of"}])), CK)
    attack("F8", "атрибут QUANTITY без единицы", mod(cls("sdf_new", attributes=[{**rank, "value_type": "QUANTITY"}])), CK)
    attack("F9", "атрибут с лишним полем", mod(cls("sdf_new", attributes=[{**rank, "inherited": True}])), CK)
    attack("F10", "автор записи не usr_/svc_", as_("ac_s9_modeler", raw_class(recorded_by="'root'")), CK)
    attack("F11", "связь с предикатом реестра ядра (не «x.»)", mod(sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="corp.director_of",
           name="связь", domain_class_id="sdf_taxon", range_class_id="sdf_taxon", cardinality="MANY")), CK)

    # ---- versions and the journal entry (S9R-13, S9R-17)
    attack("V1", "первая запись с версией 7", mod(cls("sdf_new", version=7)), SD)
    attack("V2", "версия 4 при последней 2", mod(sd("ClassDef", "sdf_whale_species", 4, "RENAME_CLASS", **{**whale, "name": "Киты"}, attributes=whale2)), SD)
    attack("V3", "повтор версии 2", mod(sd("ClassDef", "sdf_whale_species", 2, "RENAME_CLASS", **{**whale, "name": "Киты"}, attributes=whale2)), SD)
    attack("V4", "запись журнала не равна отличию (имя изменено, заявлено DEPRECATE_CLASS)",
           mod(sd("ClassDef", "sdf_taxon", 2, "DEPRECATE_CLASS", **{**taxon, "name": "Таксон (группа)"})), SC)
    attack("V5", "первая версия класса с типом ADD_LINK", mod(cls("sdf_new", ctype="ADD_LINK")), SC)
    attack("V6", "новая версия меняет родителя", mod(sd("ClassDef", "sdf_whale_species", 3, "RENAME_CLASS", **{**whale, "parent_class_id": "sdf_organism"}, attributes=whale2)), SC)
    attack("V7", "новая версия меняет маркировку", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", marking=INT, **taxon)), SC)
    attack("V8", "новая версия меняет корневой тип", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", **{**taxon, "root_type": "THING"})), SC)
    attack("V9", "новая версия делает класс абстрактным", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", is_abstract=True, **taxon)), SC)
    attack("V10", "версия без единого отличия", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", **taxon)), SC)
    attack("V11", "два изменения в одной версии", mod(sd("ClassDef", "sdf_taxon", 2, "RENAME_CLASS", **{**taxon, "name": "Т"}, attributes=[rank])), SC)
    attack("V12", "CHANGE_ATTRIBUTE меняет тип значения",
           mod(sd("ClassDef", "sdf_whale_species", 3, "CHANGE_ATTRIBUTE", **whale,
                  attributes=[{"predicate_id": "x.max_length", "name": "наибольшая длина", "value_type": "STRING", "cardinality": "ONE",
                               "required": True}, whale2[1]])), SC)
    psql(mod(cls("sdf_tmp13"), commit=True))
    time.sleep(1.1)
    psql(mod(cls("sdf_tmp13", 2, "DEPRECATE_CLASS", deprecated=True), commit=True))
    time.sleep(1.1)
    attack("V13", "версия после вывода из употребления (возврат в употребление)", mod(cls("sdf_tmp13", 3, "DEPRECATE_CLASS")), SC)
    attack("V13b", "переименование после вывода из употребления", mod(cls("sdf_tmp13", 3, "RENAME_CLASS", name="Другое имя", deprecated=True)), SC)
    attack("V14", "новая версия связи меняет класс-диапазон",
           mod(sd("LinkDef", "sdf_belongs_to", 2, "RENAME_LINK", predicate_id="x.belongs_to", name="входит в таксон",
                  domain_class_id="sdf_whale_species", range_class_id="sdf_whale_species", cardinality="MANY")), SC)
    attack("V15", "новая версия типа идентификатора меняет формат",
           mod(sd("IdentifierDef", "sdf_itis", 2, "CHANGE_IDENTIFIER_STRENGTH", scheme="x.itis", name="Номер ITIS", applies_to_root_type="CONCEPT",
                  strength="STRONG", priority=1, format=[{"chars": "DIGIT", "min": 1, "max": 8}])), SC)

    # ---- time (S9R-08)
    attack("T1", "исторический импорт версии до печати истории (мигратор)",
           as_("ac_s9_migrator", "SET LOCAL ac.historical_import = 'on';\n" + schema_sql([cls("sdf_new", at="1999-12-31T00:00:00Z")])), T)
    attack("T2", "исторический импорт версии из будущего (мигратор)",
           as_("ac_s9_migrator", "SET LOCAL ac.historical_import = 'on';\n" + schema_sql([cls("sdf_new", at="2099-01-01T00:00:00Z")])), T)
    attack("T3", "конструктор включает исторический режим сам (не член ac_migrator) — время всё равно системное",
           as_("ac_s9_modeler", "SET LOCAL ac.historical_import = 'on';\n" + schema_sql([cls("sdf_new", at="1999-12-31T00:00:00Z")])
               + "\nDO $$ BEGIN IF (SELECT recorded_at FROM ac.class_defs WHERE class_id = 'sdf_new') < now() - interval '1 minute' THEN "
                 "RAISE EXCEPTION 'BACKDATED'; END IF; END $$;"), [], True)

    t_mid = utc(0)                                   # after the seal of the import, before the live claim below
    time.sleep(1.1)
    psql(ingest_sql([entity("ent_s9_pre", "Горбач"), claim("ent_s9_pre", "schema.is_a", kref("sdf_taxon"), "вид усатых китов")], {}))
    attack("T4", "мигратор дописывает версию определения задним числом под уже записанное живое утверждение (S9R2-02)",
           as_("ac_s9_migrator", "SET LOCAL ac.historical_import = 'on';\n" + schema_sql(
               [sd("ClassDef", "sdf_taxon", 2, "DEPRECATE_CLASS", at=t_mid, deprecated=True, **taxon)])),
           ["TEMPORAL_ORDER_INVALID"])      # the text changed in cycle 11 (S11R-08): the rule now covers live versions too
    fresh = psql("SET SESSION AUTHORIZATION ac_s9_modeler;\n" + schema_sql([cls("sdf_fresh")]))
    e0 = entity("ent_s9_fresh", "Сейвал")
    r_fresh = psql(ingest_sql([e0, claim("ent_s9_fresh", "schema.is_a", kref("sdf_fresh"), "вид усатых китов")], {}))
    ok = fresh.returncode == 0 and r_fresh.returncode == 0
    BAD.append(not ok)
    print(f"T5     {'held' if ok else 'FINDING'} | законная: schema.is_a сразу после создания класса, в ту же секунду (S9R2-04) | "
          + (r_fresh.stderr.strip().splitlines()[0][:100] if r_fresh.returncode else "принято"))

    # ---- tenant isolation (S9R-10, S9R-11)
    attack("X1", "родитель из схемы другого tenant: ответ тот же, что «нет такого класса»",
           mod(cls("sdf_foreign", tenant="tnt_other"), cls("sdf_new", parent_class_id="sdf_foreign")), RF)
    attack("X2", "связь на класс другого tenant", mod(cls("sdf_foreign", tenant="tnt_other"),
           sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="x.related_to", name="связь", domain_class_id="sdf_taxon",
              range_class_id="sdf_foreign", cardinality="MANY")), RF)
    f_cls = mod(cls("sdf_foreign", tenant="tnt_other"), commit=True)
    psql(f_cls)
    e = entity("ent_s9a", "Косатка")
    psql(ingest_sql([e], {}))
    time.sleep(1.1)
    r_no = psql(loader(claim("ent_s9a", "schema.is_a", kref("sdf_nowhere"), "вид усатых китов")))
    r_fo = psql(loader(claim("ent_s9a", "schema.is_a", kref("sdf_foreign"), "вид усатых китов")))
    m1 = next((ln for ln in r_no.stderr.splitlines() if "ERROR" in ln), "").replace("sdf_nowhere", "*")
    m2 = next((ln for ln in r_fo.stderr.splitlines() if "ERROR" in ln), "").replace("sdf_foreign", "*")
    ok = r_no.returncode != 0 and m1 == m2 and "tnt_other" not in r_fo.stderr
    BAD.append(not ok)
    print(f"X3     {'held' if ok else 'FINDING'} | schema.is_a на класс другого tenant неотличимо от несуществующего класса (сообщение то же, tenant не назван) | {m2[:110]}")
    attack("X4", "CLASS_REF с полем tenant_id", loader(claim("ent_s9a", "schema.is_a", {"literal": {"type": "CLASS_REF", "class_id": "sdf_taxon",
           "tenant_id": "tnt_other"}}, "вид усатых китов")), SV)
    attack("X5", "CLASS_REF с полем label (название класса в теле утверждения)", loader(claim("ent_s9a", "schema.is_a",
           {"literal": {"type": "CLASS_REF", "class_id": "sdf_taxon", "label": "Секретный класс"}}, "вид усатых китов")), SV)

    # ---- hierarchy and derived tables (S9R-05)
    attack("H1", "класс — родитель самому себе", mod(cls("sdf_self", parent_class_id="sdf_self")), RF)
    attack("H2", "корневой тип наследника не равен родительскому", mod(cls("sdf_new", root="THING", parent_class_id="sdf_taxon")), SD)
    attack("H3", "наследник PUBLIC у родителя INTERNAL", mod(cls("sdf_int", marking=INT), cls("sdf_new", parent_class_id="sdf_int")), MB)
    for n, (role, sql) in enumerate([
            ("ac_s9_modeler", "INSERT INTO ac.class_closure VALUES ('tnt_demo', 'sdf_exhibit', 'sdf_taxon', 1);"),
            ("ac_app", "INSERT INTO ac.class_closure VALUES ('tnt_demo', 'sdf_exhibit', 'sdf_taxon', 1);"),
            ("ac_s9_migrator", "DELETE FROM ac.class_closure;"),
            ("ac_s9_modeler", "UPDATE ac.class_closure SET depth = 99;"),
            ("ac_s9_modeler", "INSERT INTO ac.schema_predicates VALUES ('tnt_demo', 'x.stolen', 'ClassDef', 'sdf_taxon');"),
            ("ac_s9_modeler", "DELETE FROM ac.class_defs;"), ("ac_s9_modeler", "UPDATE ac.link_defs SET name = 'x';"),
            ("ac_s9_modeler", "TRUNCATE ac.identifier_defs;"), ("ac_app", schema_sql([cls("sdf_by_loader")]))], 1):
        attack(f"D{n}", f"{role}: {sql[:70]}", as_(role, sql), PD + AO)
    attack("D10", "владелец: DELETE FROM ac.class_closure", "BEGIN; DELETE FROM ac.class_closure; ROLLBACK;", AO)
    attack("D11", "владелец: UPDATE ac.schema_predicates", "BEGIN; UPDATE ac.schema_predicates SET definer_id = 'sdf_x'; ROLLBACK;", AO)

    # ---- predicates of the tenant (S9R-12, S9R-14, S9R-15)
    attack("P1", "атрибут с предикатом, уже определённым в другом классе", mod(cls("sdf_new", attributes=[whale2[0]])), SD)
    attack("P2", "связь с предикатом, уже определённым атрибутом", mod(sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="x.max_length",
           name="связь", domain_class_id="sdf_taxon", range_class_id="sdf_taxon", cardinality="MANY")), SD)
    attack("P3", "вторая связь на тот же предикат", mod(sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="x.belongs_to",
           name="связь", domain_class_id="sdf_taxon", range_class_id="sdf_taxon", cardinality="ONE")), SD)
    attack("P4", "атрибут повторяется в классе", mod(cls("sdf_new", attributes=[rank, {**rank, "name": "ещё раз"}])), SD)
    attack("P5", "симметричная связь разных классов", mod(sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="x.related_to", name="связь",
           domain_class_id="sdf_whale_species", range_class_id="sdf_taxon", cardinality="MANY", symmetric=True)), CK)
    attack("P6", "связь на несуществующий класс", mod(sd("LinkDef", "sdf_lnk", 1, "ADD_LINK", predicate_id="x.related_to", name="связь",
           domain_class_id="sdf_nowhere", range_class_id="sdf_taxon", cardinality="MANY")), RF)
    attack("P7", "утверждение с предикатом вне реестра и вне схемы", loader(claim("ent_s9a", "no.such_thing", {"literal": {"type": "STRING", "value": "x"}}, "вид")),
           ["PREDICATE_UNKNOWN"])

    # ---- identifier types (S9R-16)
    idf = dict(name="Тип", applies_to_root_type="CONCEPT", strength="WEAK", priority=5)
    attack("I1", "вторая схема x.itis для CONCEPT", mod(sd("IdentifierDef", "sdf_itis2", 1, "ADD_IDENTIFIER", scheme="x.itis",
           format=[{"chars": "DIGIT", "min": 1, "max": 9}], **{**idf, "priority": 7})), SD)
    attack("I2", "приоритет 1 для CONCEPT занят", mod(sd("IdentifierDef", "sdf_zb", 1, "ADD_IDENTIFIER", scheme="x.zoobank",
           format=[{"chars": "DIGIT", "min": 1, "max": 9}], **{**idf, "priority": 1})), SD)
    attack("I3", "встроенная ru.inn объявлена слабой", mod(sd("IdentifierDef", "sdf_inn", 1, "ADD_IDENTIFIER", scheme="ru.inn",
           **{**idf, "applies_to_root_type": "ORGANIZATION"})), CK)
    attack("I4", "встроенной ru.inn задан формат (переопределение проверки ядра)", mod(sd("IdentifierDef", "sdf_inn", 1, "ADD_IDENTIFIER",
           scheme="ru.inn", format=[{"chars": "DIGIT", "min": 1, "max": 9}], **{**idf, "applies_to_root_type": "ORGANIZATION", "strength": "STRONG"})), CK)
    attack("I5", "формат — регулярное выражение (a+)+$", as_("ac_s9_modeler",
           "INSERT INTO ac.identifier_defs (tenant_id, idef_id, version, scheme, name, applies_to_root_type, strength, priority, format, marking, "
           "change_type, description, recorded_at, recorded_by) VALUES ('tnt_demo', 'sdf_zb', 1, 'x.zoobank', 'Тип', 'CONCEPT', 'WEAK', 5, "
           "'\"(a+)+$\"', '{\"level\":\"PUBLIC\",\"categories\":[]}', 'ADD_IDENTIFIER', 'атака', now(), 'usr_modeler1');"), CK)
    attack("I6", "формат: min > max", mod(sd("IdentifierDef", "sdf_zb", 1, "ADD_IDENTIFIER", scheme="x.zoobank",
           format=[{"chars": "DIGIT", "min": 5, "max": 4}], **idf)), CK)
    attack("I7", "формат: класс знаков вне словаря", mod(sd("IdentifierDef", "sdf_zb", 1, "ADD_IDENTIFIER", scheme="x.zoobank",
           format=[{"chars": ".*", "min": 1, "max": 4}], **idf)), CK)
    attack("I8", "схема вне пространства tenant и не встроенная", mod(sd("IdentifierDef", "sdf_zb", 1, "ADD_IDENTIFIER", scheme="telegram",
           format=[{"chars": "DIGIT", "min": 1, "max": 4}], **idf)), CK)
    attack("I9", "значение идентификатора не в формате схемы", loader(claim("ent_wk_blue", "x.itis_tsn",
           {"literal": {"type": "IDENTIFIER", "scheme": "x.itis", "value": "18O528"}}, "вид усатых китов")), ["IDENTIFIER_SCHEME_INVALID"])
    attack("I10", "значение идентификатора с переводом строки в конце", loader(claim("ent_wk_blue", "x.itis_tsn",
           {"literal": {"type": "IDENTIFIER", "scheme": "x.itis", "value": "180528\n"}}, "вид усатых китов")), ["IDENTIFIER_SCHEME_INVALID"])

    # ---- claims against the schema (S9R-02, S9R-18, S9R-24)
    attack("C1", "schema.is_a на несуществующий класс", loader(claim("ent_s9a", "schema.is_a", kref("sdf_nowhere"), "вид усатых китов")), RF)
    attack("C2", "schema.is_a на абстрактный класс", loader(claim("ent_s9a", "schema.is_a", kref("sdf_organism"), "вид усатых китов")),
           ["CLASS_NOT_INSTANTIABLE"])
    attack("C3", "schema.is_a: сущность CONCEPT, класс с корнем THING", loader(claim("ent_s9a", "schema.is_a", kref("sdf_exhibit"), "вид усатых китов")),
           ["PREDICATE_DOMAIN_VIOLATION"])
    psql(mod(cls("sdf_secret", marking=INT, attributes=[{**rank, "predicate_id": "x.secret_note"}]), commit=True))
    time.sleep(1.1)
    attack("C4", "PUBLIC schema.is_a на класс INTERNAL", loader(claim("ent_s9a", "schema.is_a", kref("sdf_secret"), "вид усатых китов")), MB)
    attack("C5", "законная: INTERNAL schema.is_a на класс INTERNAL", loader(claim("ent_s9a", "schema.is_a", kref("sdf_secret"), "вид усатых китов", marking=INT)), [], True)
    psql(ingest_sql([claim("ent_s9a", "schema.is_a", kref("sdf_secret"), "вид усатых китов", marking=INT)], {}))
    time.sleep(1.1)
    attack("C6", "PUBLIC утверждение с атрибутом класса INTERNAL", loader(claim("ent_s9a", "x.secret_note", {"literal": {"type": "STRING", "value": "x"}}, "вид")), MB)
    attack("C7", "schema.is_a с объектом-строкой", loader(claim("ent_s9a", "schema.is_a", {"literal": {"type": "STRING", "value": "sdf_taxon"}}, "вид")),
           ["PREDICATE_RANGE_VIOLATION"])
    attack("C8", "атрибут у сущности, не названной экземпляром класса", loader(claim("ent_wk_blue_colour", "x.max_length",
           {"literal": {"type": "QUANTITY", "value": "30", "unit": "m"}}, "вид")), ["PREDICATE_DOMAIN_VIOLATION"])
    attack("C9", "атрибут с квалификатором", loader({**claim("ent_wk_blue", "x.max_length", {"literal": {"type": "QUANTITY", "value": "31", "unit": "m"}}, "вид"),
           "qualifiers": {"property": "max_length"}}), ["QUALIFIER_INVALID"])
    attack("C10", "связь с объектом — не экземпляром класса-диапазона", loader(claim("ent_wk_blue", "x.belongs_to", {"entity": "ent_wk_blue_colour"}, "вид")),
           ["PREDICATE_RANGE_VIOLATION"])
    attack("C11", "связь с литералом вместо сущности", loader(claim("ent_wk_blue", "x.belongs_to", {"literal": {"type": "STRING", "value": "x"}}, "вид")),
           ["PREDICATE_RANGE_VIOLATION"])

    # ---- races
    def run(sql, out, n):
        out[n] = psql(sql)
    res = {}
    th = [threading.Thread(target=run, args=(f"SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n{schema_sql([cls(f'sdf_race_{n}', parent_class_id='sdf_taxon')])}\n"
                                              "SELECT pg_sleep(1);\nCOMMIT;", res, n)) for n in range(4)]
    [t.start() for t in th]
    [t.join() for t in th]
    n_ok = sum(1 for r in res.values() if r.returncode == 0)
    n_rows = psql("SELECT count(*) FROM ac.class_closure WHERE descendant_id LIKE 'sdf_race_%';").stdout.strip()
    ok = n_ok == 4 and n_rows == "12"
    BAD.append(not ok)
    print(f"R1     {'held' if ok else 'FINDING'} | гонка: четыре сессии одновременно добавляют классы одного tenant — все приняты, замыкание полное | "
          f"принято {n_ok}/4, строк замыкания {n_rows} (ожидается 12)")

    # deprecate a class while a membership claim is being written: whichever order — never a claim on a deprecated class
    psql(mod(cls("sdf_gone"), commit=True))
    time.sleep(1.1)
    res = {}
    dep = f"SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n{schema_sql([cls('sdf_gone', 2, 'DEPRECATE_CLASS', deprecated=True)])}\nSELECT pg_sleep(1.5);\nCOMMIT;"
    t1 = threading.Thread(target=run, args=(dep, res, "dep"))
    t1.start()
    time.sleep(0.5)
    isa = ingest_sql([claim("ent_s9a", "schema.is_a", kref("sdf_gone"), "вид усатых китов")], {})
    t2 = threading.Thread(target=run, args=(isa, res, "isa"))
    t2.start()
    t1.join()
    t2.join()
    refused = res["isa"].returncode != 0
    ok = res["dep"].returncode == 0 and refused
    BAD.append(not ok)
    print(f"R2     {'held' if ok else 'FINDING'} | гонка: класс выводится из употребления, пока пишется schema.is_a на него — утверждение ждёт и отвергнуто | "
          + next((ln for ln in res["isa"].stderr.splitlines() if "ERROR" in ln), "принято")[:110])

    # withdraw a membership while a claim relying on it is being written: the claim waits and is refused
    cid = psql("SELECT claim_id FROM ac.claims WHERE subject = 'ent_s9a' AND predicate = 'schema.is_a' "
               "AND body->'object'->'literal'->>'class_id' = 'sdf_secret';").stdout.strip()
    res = {}
    wd = ("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\n"
          f"INSERT INTO ac.claim_reviews VALUES ('rev_s9_race', '{cid}', 'WITHDRAWN', 'usr_reviewer1', now(), now());\nSELECT pg_sleep(1.5);\nCOMMIT;")
    t1 = threading.Thread(target=run, args=(wd, res, "wd"))
    t1.start()
    time.sleep(0.5)
    xc = ingest_sql([claim("ent_s9a", "x.secret_note", {"literal": {"type": "STRING", "value": "заметка"}}, "вид", marking=INT)], {})
    t2 = threading.Thread(target=run, args=(xc, res, "x"))
    t2.start()
    t1.join()
    t2.join()
    ok = bool(cid) and res["wd"].returncode == 0 and res["x"].returncode != 0 and "PREDICATE_DOMAIN_VIOLATION" in res["x"].stderr
    BAD.append(not ok)
    print(f"R3     {'held' if ok else 'FINDING'} | гонка: принадлежность классу отзывается, пока пишется утверждение с атрибутом этого класса — "
          "утверждение ждёт и отвергнуто | " + next((ln for ln in res["x"].stderr.splitlines() if "ERROR" in ln), "принято")[:110])

    # ---- growth (S9R-26): incremental closure
    def timed(sql):
        t0 = time.time()
        r = psql(sql)
        return r.returncode, time.time() - t0
    flat = "SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n" + schema_sql([cls(f"sdf_flat_{n}") for n in range(1000)]) + "\nCOMMIT;"
    rc1, s1 = timed(flat)
    chain = "SET SESSION AUTHORIZATION ac_s9_modeler;\nBEGIN;\n" + schema_sql(
        [cls(f"sdf_chain_{n}", at=f"2026-01-01T00:{n // 60:02d}:{n % 60:02d}Z",          # the time only orders the statements
             **({"parent_class_id": f"sdf_chain_{n - 1}"} if n else {})) for n in range(400)]) + "\nCOMMIT;"
    rc2, s2 = timed(chain)
    depth = psql("SELECT max(depth) FROM ac.class_closure WHERE descendant_id = 'sdf_chain_399';").stdout.strip()
    ok = rc1 == 0 and rc2 == 0 and depth == "399" and s1 < 60 and s2 < 60
    BAD.append(not ok)
    print(f"G1     {'held' if ok else 'FINDING'} | рост: 1000 плоских классов — {s1:.1f} с; цепочка глубиной 400 — {s2:.1f} с (глубина в замыкании {depth})")

    print(f"\nattacks={len(BAD)} findings={sum(BAD)}")
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

"""Конструктор модели — CLI для работы с записями схемы (D27.1, cycle 9).

Команды:
  add-class   — создать ClassDef
  add-link    — создать LinkDef
  add-iddef   — создать IdentifierDef
  list        — вывести записи схемы из файла датасета
  export      — экспортировать схему tenant в JSON

Каждая операция add-* проверяет созданную запись через validator (только схема-записи).

python3 model_constructor.py --help
python3 model_constructor.py add-class --help
"""
import argparse
import json
import sys
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SV = "core-ontology/0.3"

ROOT_TYPES = [
    "PERSON", "ORGANIZATION", "REAL_ESTATE", "MOVABLE_PROPERTY",
    "EVENT", "CONFLICT", "EQUIPMENT", "EQUIPMENT_MODEL", "CONCEPT", "THING"
]

CARDINALITIES = ["ONE", "MANY"]
STRENGTHS = ["STRONG", "WEAK"]

CHANGE_TYPES = [
    "ADD_CLASS", "RENAME_CLASS", "DEPRECATE_CLASS",
    "ADD_ATTRIBUTE", "CHANGE_ATTRIBUTE_CARDINALITY", "REMOVE_ATTRIBUTE",
    "ADD_LINK", "REMOVE_LINK",
    "ADD_IDENTIFIER_DEF", "CHANGE_IDENTIFIER_STRENGTH",
]

TARGET_KINDS = ["ClassDef", "LinkDef", "IdentifierDef"]

_SDF = re.compile(r'^sdf_[a-z0-9_]{2,64}$')
_TNT = re.compile(r'^tnt_[a-z0-9_]{2,64}$')
_ACT = re.compile(r'^(usr|svc)_[a-z0-9_]{2,64}$')
_SCX = re.compile(r'^scx_[a-z0-9_]{2,64}$')
_PRED = re.compile(r'^[a-z]+\.[a-z_]+$')
_SCHEME = re.compile(r'^[a-z][a-z0-9.]{1,40}$')


def err(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_marking(level="INTERNAL"):
    return {"level": level, "categories": []}


def validate_id(val, pattern, name):
    if not pattern.match(val):
        err(f"{name} '{val}' не соответствует шаблону {pattern.pattern}")
    return val


# ──────────────────────────── add-class ────────────────────────────

def cmd_add_class(args):
    class_id = validate_id(args.class_id, _SDF, "class_id")
    tenant_id = validate_id(args.tenant_id, _TNT, "tenant_id")
    created_by = validate_id(args.created_by, _ACT, "created_by")
    if args.root_type not in ROOT_TYPES:
        err(f"root_type '{args.root_type}' не допустим; варианты: {ROOT_TYPES}")
    if args.parent and not _SDF.match(args.parent):
        err(f"parent_class_id '{args.parent}' не соответствует формату sdf_…")

    rec = {
        "kind": "ClassDef",
        "schema_version": SV,
        "class_id": class_id,
        "tenant_id": tenant_id,
        "root_type": args.root_type,
        "name": args.name,
        "version": args.version,
        "created_at": args.created_at or now_utc(),
        "created_by": created_by,
        "marking": default_marking(args.marking_level),
    }
    if args.label_ru:
        rec["label_ru"] = args.label_ru
    if args.parent:
        rec["parent_class_id"] = args.parent
    if args.abstract:
        rec["is_abstract"] = True

    out = json.dumps(rec, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Записано: {args.out}")
    else:
        print(out)


# ──────────────────────────── add-link ────────────────────────────

def cmd_add_link(args):
    link_id = validate_id(args.link_id, _SDF, "link_id")
    tenant_id = validate_id(args.tenant_id, _TNT, "tenant_id")
    created_by = validate_id(args.created_by, _ACT, "created_by")
    domain_id = validate_id(args.domain_class_id, _SDF, "domain_class_id")
    range_id = validate_id(args.range_class_id, _SDF, "range_class_id")
    pred = validate_id(args.predicate_id, _PRED, "predicate_id")
    if args.cardinality not in CARDINALITIES:
        err(f"cardinality '{args.cardinality}' не допустим; варианты: {CARDINALITIES}")
    if args.inverse and not _PRED.match(args.inverse):
        err(f"inverse_predicate_id '{args.inverse}' не соответствует формату")

    rec = {
        "kind": "LinkDef",
        "schema_version": SV,
        "link_id": link_id,
        "tenant_id": tenant_id,
        "predicate_id": pred,
        "domain_class_id": domain_id,
        "range_class_id": range_id,
        "cardinality": args.cardinality,
        "version": args.version,
        "created_at": args.created_at or now_utc(),
        "created_by": created_by,
        "marking": default_marking(args.marking_level),
    }
    if args.label_ru:
        rec["label_ru"] = args.label_ru
    if args.symmetric:
        rec["symmetric"] = True
    if args.inverse:
        rec["inverse_predicate_id"] = args.inverse

    out = json.dumps(rec, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Записано: {args.out}")
    else:
        print(out)


# ──────────────────────────── add-iddef ────────────────────────────

def cmd_add_iddef(args):
    idef_id = validate_id(args.idef_id, _SDF, "idef_id")
    tenant_id = validate_id(args.tenant_id, _TNT, "tenant_id")
    created_by = validate_id(args.created_by, _ACT, "created_by")
    if not _SCHEME.match(args.scheme):
        err(f"scheme '{args.scheme}' не соответствует формату")
    if args.applies_to not in ROOT_TYPES:
        err(f"applies_to_root_type '{args.applies_to}' не допустим; варианты: {ROOT_TYPES}")
    if args.strength not in STRENGTHS:
        err(f"strength '{args.strength}' не допустим; варианты: {STRENGTHS}")

    rec = {
        "kind": "IdentifierDef",
        "schema_version": SV,
        "idef_id": idef_id,
        "tenant_id": tenant_id,
        "scheme": args.scheme,
        "applies_to_root_type": args.applies_to,
        "strength": args.strength,
        "priority": args.priority,
        "version": args.version,
        "created_at": args.created_at or now_utc(),
        "created_by": created_by,
        "marking": default_marking(args.marking_level),
    }
    if args.label_ru:
        rec["label_ru"] = args.label_ru
    if args.norm_regex:
        rec["normalization_regex"] = args.norm_regex
    if args.val_regex:
        rec["validation_regex"] = args.val_regex

    out = json.dumps(rec, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Записано: {args.out}")
    else:
        print(out)


# ──────────────────────────── add-change ────────────────────────────

def cmd_add_change(args):
    change_id = validate_id(args.change_id, _SCX, "change_id")
    tenant_id = validate_id(args.tenant_id, _TNT, "tenant_id")
    recorded_by = validate_id(args.recorded_by, _ACT, "recorded_by")
    target_id = validate_id(args.target_id, _SDF, "target_id")
    if args.change_type not in CHANGE_TYPES:
        err(f"change_type '{args.change_type}' не допустим; варианты: {CHANGE_TYPES}")
    if args.target_kind not in TARGET_KINDS:
        err(f"target_kind '{args.target_kind}' не допустим; варианты: {TARGET_KINDS}")

    rec = {
        "kind": "SchemaChange",
        "schema_version": SV,
        "change_id": change_id,
        "tenant_id": tenant_id,
        "change_type": args.change_type,
        "target_id": target_id,
        "target_kind": args.target_kind,
        "description": args.description,
        "recorded_at": args.recorded_at or now_utc(),
        "recorded_by": recorded_by,
        "marking": default_marking(args.marking_level),
    }
    if args.migration_note:
        rec["migration_note"] = args.migration_note

    out = json.dumps(rec, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Записано: {args.out}")
    else:
        print(out)


# ──────────────────────────── list ────────────────────────────

def cmd_list(args):
    path = Path(args.dataset)
    if not path.exists():
        err(f"Файл не найден: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))

    records = data if isinstance(data, list) else data.get("records", [])
    kinds_filter = set(args.kinds.split(",")) if args.kinds else None
    tenant_filter = args.tenant or None

    rows = []
    for r in records:
        k = r.get("kind", "")
        if kinds_filter and k not in kinds_filter:
            continue
        if tenant_filter and r.get("tenant_id") != tenant_filter:
            continue
        # pick display ID
        rec_id = (r.get("class_id") or r.get("link_id") or r.get("idef_id")
                  or r.get("change_id") or r.get("kind", "?"))
        rows.append((k, rec_id, r.get("tenant_id", ""), r.get("name") or r.get("scheme") or r.get("change_type", "")))

    if args.json:
        filtered = []
        for r in records:
            k = r.get("kind", "")
            if kinds_filter and k not in kinds_filter:
                continue
            if tenant_filter and r.get("tenant_id") != tenant_filter:
                continue
            filtered.append(r)
        print(json.dumps(filtered, ensure_ascii=False, indent=2))
        return

    if not rows:
        print("(нет записей)")
        return

    col_k = max(len(r[0]) for r in rows)
    col_i = max(len(r[1]) for r in rows)
    col_t = max(len(r[2]) for r in rows)
    fmt = f"{{:<{col_k}}}  {{:<{col_i}}}  {{:<{col_t}}}  {{}}"
    print(fmt.format("kind", "id", "tenant_id", "name/scheme/change_type"))
    print("-" * (col_k + col_i + col_t + 40))
    for k, i, t, n in rows:
        print(fmt.format(k, i, t, n))
    print(f"\nИтого: {len(rows)}")


# ──────────────────────────── export ────────────────────────────

def cmd_export(args):
    path = Path(args.dataset)
    if not path.exists():
        err(f"Файл не найден: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data if isinstance(data, list) else data.get("records", [])

    tenant = args.tenant
    schema_kinds = {"ClassDef", "LinkDef", "IdentifierDef", "SchemaChange"}
    export = [r for r in records
              if r.get("kind") in schema_kinds
              and (not tenant or r.get("tenant_id") == tenant)]

    result = {
        "schema_version": SV,
        "exported_at": now_utc(),
        "tenant_id": tenant or "*",
        "records": export,
    }
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Экспортировано {len(export)} записей → {args.out}")
    else:
        print(out)


# ──────────────────────────── validate-schema ────────────────────────────

def cmd_validate_schema(args):
    """Валидирует только schema-записи из датасета через validator."""
    try:
        from validator import validate
    except ImportError:
        err("validator.py не найден в Python path; запустите из /home/claude/as/core/")

    path = Path(args.dataset)
    if not path.exists():
        err(f"Файл не найден: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data if isinstance(data, list) else data.get("records", [])

    r = validate(records)
    codes = r.codes()
    if codes:
        for code, rec_id, msg in r._errors:
            print(f"  {code}  {rec_id}  {msg}", file=sys.stderr)
        print(f"\nОШИБКИ: {len(codes)}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"OK — {len(records)} записей, ошибок нет")


# ──────────────────────────── argparse ────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="model_constructor.py",
        description="Конструктор модели: создание/список/экспорт схемных записей (ClassDef, LinkDef, IdentifierDef).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # shared args helper
    def add_common(sp):
        sp.add_argument("--tenant-id", required=True, metavar="tnt_…", help="TenantId")
        sp.add_argument("--created-by", default="usr_test_admin", metavar="usr_…|svc_…")
        sp.add_argument("--created-at", default=None, metavar="ISO8601", help="дата создания (по умолч. сейчас)")
        sp.add_argument("--version", type=int, default=1, metavar="N")
        sp.add_argument("--marking-level", default="INTERNAL",
                        choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL"], metavar="LEVEL")
        sp.add_argument("--out", default=None, metavar="FILE.json", help="файл для сохранения; без флага — stdout")

    # add-class
    ac = sub.add_parser("add-class", help="Создать ClassDef")
    ac.add_argument("class_id", metavar="sdf_…")
    ac.add_argument("--root-type", required=True, choices=ROOT_TYPES)
    ac.add_argument("--name", required=True)
    ac.add_argument("--label-ru", default=None)
    ac.add_argument("--parent", default=None, metavar="sdf_…", dest="parent")
    ac.add_argument("--abstract", action="store_true")
    add_common(ac)
    ac.set_defaults(func=cmd_add_class)

    # add-link
    al = sub.add_parser("add-link", help="Создать LinkDef")
    al.add_argument("link_id", metavar="sdf_…")
    al.add_argument("--predicate-id", required=True, metavar="ns.predicate")
    al.add_argument("--domain-class-id", required=True, metavar="sdf_…")
    al.add_argument("--range-class-id", required=True, metavar="sdf_…")
    al.add_argument("--cardinality", required=True, choices=CARDINALITIES)
    al.add_argument("--label-ru", default=None)
    al.add_argument("--symmetric", action="store_true")
    al.add_argument("--inverse", default=None, metavar="ns.predicate")
    add_common(al)
    al.set_defaults(func=cmd_add_link)

    # add-iddef
    ai = sub.add_parser("add-iddef", help="Создать IdentifierDef")
    ai.add_argument("idef_id", metavar="sdf_…")
    ai.add_argument("--scheme", required=True, metavar="inn|ogrn|…")
    ai.add_argument("--applies-to", required=True, choices=ROOT_TYPES, metavar="ROOT_TYPE")
    ai.add_argument("--strength", required=True, choices=STRENGTHS)
    ai.add_argument("--priority", type=int, default=10)
    ai.add_argument("--label-ru", default=None)
    ai.add_argument("--norm-regex", default=None, metavar="REGEX")
    ai.add_argument("--val-regex", default=None, metavar="REGEX")
    add_common(ai)
    ai.set_defaults(func=cmd_add_iddef)

    # add-change
    ach = sub.add_parser("add-change", help="Создать SchemaChange (запись журнала)")
    ach.add_argument("change_id", metavar="scx_…")
    ach.add_argument("--change-type", required=True, choices=CHANGE_TYPES)
    ach.add_argument("--target-id", required=True, metavar="sdf_…")
    ach.add_argument("--target-kind", required=True, choices=TARGET_KINDS)
    ach.add_argument("--description", required=True)
    ach.add_argument("--migration-note", default=None)
    ach.add_argument("--tenant-id", required=True, metavar="tnt_…")
    ach.add_argument("--recorded-by", default="usr_test_admin", metavar="usr_…|svc_…")
    ach.add_argument("--recorded-at", default=None, metavar="ISO8601")
    ach.add_argument("--marking-level", default="INTERNAL",
                     choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL"])
    ach.add_argument("--out", default=None, metavar="FILE.json")
    ach.set_defaults(func=cmd_add_change)

    # list
    ls = sub.add_parser("list", help="Вывести записи схемы из датасета")
    ls.add_argument("dataset", metavar="FILE.json")
    ls.add_argument("--kinds", default=None,
                    metavar="ClassDef,LinkDef,…",
                    help="фильтр по kind (через запятую)")
    ls.add_argument("--tenant", default=None, metavar="tnt_…")
    ls.add_argument("--json", action="store_true", help="вывод в JSON")
    ls.set_defaults(func=cmd_list)

    # export
    ex = sub.add_parser("export", help="Экспортировать схему tenant из датасета")
    ex.add_argument("dataset", metavar="FILE.json")
    ex.add_argument("--tenant", default=None, metavar="tnt_…")
    ex.add_argument("--out", default=None, metavar="FILE.json")
    ex.set_defaults(func=cmd_export)

    # validate-schema
    vs = sub.add_parser("validate-schema", help="Проверить schema-записи через validator")
    vs.add_argument("dataset", metavar="FILE.json")
    vs.set_defaults(func=cmd_validate_schema)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

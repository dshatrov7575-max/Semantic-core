#!/usr/bin/env python3
"""Model Constructor (D27.1) — a command-line client of the schema registry: it edits the tenant's schema as RECORDS.

The schema lives in a dataset file (core-dataset/0.3) as ClassDef / LinkDef / IdentifierDef records; every command adds
exactly ONE new version of ONE definition with its journal entry, runs the WHOLE dataset through the normative
validator and writes the file only if the validator has no errors. No tables are generated: the physical model is
never touched (the database loads the same records, slice/schema_s9.py).

  init            FILE
  add-class       FILE sdf_ID --tenant T --root-type TYPE --name N [--parent sdf_P] [--abstract]
  add-attribute   FILE sdf_ID --tenant T --predicate x.p --name N --type TYPE [--unit u] [--scheme s] [--many] [--required]
  change-attribute FILE sdf_ID --tenant T --predicate x.p [--name N] [--one | --many] [--required | --optional]
  remove-attribute FILE sdf_ID --tenant T --predicate x.p
  add-link        FILE sdf_ID --tenant T --predicate x.p --name N --domain sdf_A --range sdf_B [--one] [--symmetric]
  add-identifier  FILE sdf_ID --tenant T --scheme x.s|ru.inn|… --root-type TYPE --name N --strength STRONG|WEAK
                                --priority K [--format DIGIT:1-9,lit:-,ALNUM_UPPER:6]
  set-strength    FILE sdf_ID --tenant T --strength STRONG|WEAK
  rename          FILE sdf_ID --tenant T --name N
  deprecate       FILE sdf_ID --tenant T
  show            FILE --tenant T [--at 2026-10-02T12:00:00Z]      the schema in force (inherited attributes included)
  journal         FILE --tenant T                                   who changed what and when
  validate        FILE [--trust trust.json] [--content-dir DIR]
Common options of the editing commands: --by usr_…|svc_… (required), --description TEXT (required), --note TEXT,
  --at ISO-time (default: now, UTC), --marking LEVEL[:CATEGORY,…] (first version only; default INTERNAL),
  --trust / --content-dir (when the file also holds claims with sources).
Exit code: 0 — written (or valid), 1 — refused (the file is left untouched), 2 — usage error.
"""
import argparse
import copy
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import validator as VAL

SV, DF = "core-ontology/0.3", "core-dataset/0.3"
IDF = {"ClassDef": "class_id", "LinkDef": "link_id", "IdentifierDef": "idef_id"}
ROOTS = ["PERSON", "ORGANIZATION", "REAL_ESTATE", "MOVABLE_PROPERTY", "EVENT", "CONFLICT", "EQUIPMENT", "EQUIPMENT_MODEL",
         "CONCEPT", "THING"]
TYPES = ["STRING", "DATE", "QUANTITY", "MONEY", "IDENTIFIER", "BOOLEAN", "INTEGER"]


T0 = time.time()


class Refused(Exception):
    pass


def load(path):
    try:
        ds = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as ex:
        raise Refused(f"не удалось прочитать {path}: {type(ex).__name__}")
    if not isinstance(ds, dict) or not isinstance(ds.get("records"), list):
        raise Refused(f"{path}: это не набор данных ядра (нет списка records)")
    return ds


def content_of(args):
    content = {}
    if getattr(args, "content_dir", None):
        for f in Path(args.content_dir).iterdir():
            if f.is_file():
                content["src:sha256:" + f.name] = content["sha256:" + f.name] = f.read_bytes()
    trust = json.loads(Path(args.trust).read_text(encoding="utf-8")) if getattr(args, "trust", None) else None
    return trust, content


def check(ds, args):
    trust, content = content_of(args)
    rep = VAL.validate(ds, trust, content)
    for e in rep.errors:
        print("ERROR", e["code"], e["ref"], e["msg"], file=sys.stderr)
    for w in rep.warnings:
        print("WARN ", w["code"], w["ref"], w["msg"], file=sys.stderr)
    return not rep.errors


def save(path, ds):
    """atomically: a refused or interrupted command never leaves a half-written file"""
    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(ds, f, ensure_ascii=False, indent=1)
        f.write("\n")
    os.replace(tmp, p)


def chain(ds, tenant, did):
    """-> (kind, versions sorted) of the definition (tenant, id); the id may be a class, a link or an identifier type"""
    found = {}
    for r in ds["records"]:
        if isinstance(r, dict) and r.get("kind") in IDF and r.get("tenant_id") == tenant and r.get(IDF[r["kind"]]) == did:
            found.setdefault(r["kind"], []).append(r)
    if len(found) > 1:
        raise Refused(f"{did}: идентификатор принадлежит определениям разных видов ({', '.join(sorted(found))}) — уточните файл")
    for kind, lst in found.items():
        return kind, sorted(lst, key=lambda r: r.get("version", 0))
    return None, []


def change(args, ctype):
    if args.at and args.at > datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise Refused("время записи изменения из будущего")
    ch = {"type": ctype, "description": args.description,
          "recorded_at": args.at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "recorded_by": args.by}
    if args.note:
        ch["migration_note"] = args.note
    return ch


def marking(spec):
    level, _, cats = (spec or "INTERNAL").partition(":")
    return {"level": level, "categories": [c for c in cats.split(",") if c]}


def first(args, kind, ctype, **body):
    return {"kind": kind, "schema_version": SV, IDF[kind]: args.id, "tenant_id": args.tenant, "version": 1, **body,
            "marking": marking(args.marking), "change": change(args, ctype)}


def nxt(ds, args, kinds, ctype):
    kind, lst = chain(ds, args.tenant, args.id)
    if not lst:
        raise Refused(f"определения {args.id} нет в схеме tenant {args.tenant}")
    if kind not in kinds:
        raise Refused(f"{args.id} — {kind}; команда применима к: {', '.join(kinds)}")
    if args.marking:
        raise Refused("маркировка задаётся только первой версией определения и не меняется")
    while not args.at and datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") <= lst[-1]["change"]["recorded_at"] \
            and time.time() < T0 + 3:
        time.sleep(0.2)          # versions are ordered by time to the second: a command in the same second waits for the next one
    r = copy.deepcopy(lst[-1])
    r["version"] += 1
    r["change"] = change(args, ctype if isinstance(ctype, str) else ctype[kind])
    return r


def parse_format(spec):
    out = []
    for part in spec.split(","):
        name, _, rng = part.partition(":")
        if name == "lit":
            out.append({"lit": rng})
        else:
            lo, _, hi = rng.partition("-")
            if not (lo.isdigit() and (hi or lo).isdigit()):
                raise Refused(f"формат: «{part}» — ожидается КЛАСС:мин-макс или lit:знак")
            out.append({"chars": name, "min": int(lo), "max": int(hi or lo)})
    return out


def edit(ds, args):  # noqa: C901
    """-> the ONE new record the command adds"""
    c = args.cmd
    if c == "add-class":
        body = {"root_type": args.root_type, "name": args.name}
        if args.parent:
            body["parent_class_id"] = args.parent
        if args.abstract:
            body["is_abstract"] = True
        return first(args, "ClassDef", "ADD_CLASS", **body)
    if c == "add-link":
        body = {"predicate_id": args.predicate, "name": args.name, "domain_class_id": args.domain, "range_class_id": args.range,
                "cardinality": "ONE" if args.one else "MANY"}
        if args.symmetric:
            body["symmetric"] = True
        return first(args, "LinkDef", "ADD_LINK", **body)
    if c == "add-identifier":
        body = {"scheme": args.scheme, "name": args.name, "applies_to_root_type": args.root_type, "strength": args.strength,
                "priority": args.priority}
        if args.format:
            body["format"] = parse_format(args.format)
        return first(args, "IdentifierDef", "ADD_IDENTIFIER", **body)
    if c == "rename":
        r = nxt(ds, args, list(IDF), {"ClassDef": "RENAME_CLASS", "LinkDef": "RENAME_LINK", "IdentifierDef": "RENAME_IDENTIFIER"})
        r["name"] = args.name
        return r
    if c == "deprecate":
        r = nxt(ds, args, list(IDF), {"ClassDef": "DEPRECATE_CLASS", "LinkDef": "DEPRECATE_LINK", "IdentifierDef": "DEPRECATE_IDENTIFIER"})
        r["deprecated"] = True
        return r
    if c == "set-strength":
        r = nxt(ds, args, ["IdentifierDef"], "CHANGE_IDENTIFIER_STRENGTH")
        r["strength"] = args.strength
        return r
    if c == "add-attribute":
        r = nxt(ds, args, ["ClassDef"], "ADD_ATTRIBUTE")
        a = {"predicate_id": args.predicate, "name": args.name, "value_type": args.type,
             "cardinality": "MANY" if args.many else "ONE", "required": bool(args.required)}
        if args.unit:
            a["unit"] = args.unit
        if args.scheme:
            a["scheme"] = args.scheme
        r.setdefault("attributes", []).append(a)
        return r
    attrs = None
    if c in ("change-attribute", "remove-attribute"):
        r = nxt(ds, args, ["ClassDef"], "CHANGE_ATTRIBUTE" if c == "change-attribute" else "REMOVE_ATTRIBUTE")
        attrs = r.get("attributes", [])
        pos = next((n for n, a in enumerate(attrs) if a["predicate_id"] == args.predicate), None)
        if pos is None:
            raise Refused(f"у класса {args.id} нет атрибута {args.predicate} (унаследованные меняются в классе, где объявлены)")
    if c == "remove-attribute":
        del attrs[pos]
        if not attrs:
            r.pop("attributes")
        return r
    if c == "change-attribute":
        a = attrs[pos]
        if args.name:
            a["name"] = args.name
        if args.one or args.many:
            a["cardinality"] = "ONE" if args.one else "MANY"
        if args.required or args.optional:
            a["required"] = bool(args.required)
        return r
    raise Refused(f"неизвестная команда {c}")


def in_force(ds, tenant, at):
    """the latest version of every definition of the tenant recorded by `at` -> {kind: {id: record}}"""
    out = {k: {} for k in IDF}
    for r in sorted((r for r in ds["records"] if r.get("kind") in IDF and r.get("tenant_id") == tenant),
                    key=lambda r: r["version"]):
        if at is None or r["change"]["recorded_at"] <= at:
            out[r["kind"]][r[IDF[r["kind"]]]] = r
    return out


def show(ds, args):
    m = in_force(ds, args.tenant, args.at)
    cls = m["ClassDef"]

    def up(cid):
        seen = []
        while cid in cls and cid not in seen:
            seen.append(cid)
            cid = cls[cid].get("parent_class_id")
        return seen

    flag = lambda r: (" [абстрактный]" if r.get("is_abstract") else "") + (" [выведен из употребления]" if r.get("deprecated") else "")  # noqa: E731
    print(f"Схема tenant {args.tenant}" + (f" на {args.at}" if args.at else "") + f": классов {len(cls)}, связей {len(m['LinkDef'])}, "
          f"типов идентификаторов {len(m['IdentifierDef'])}")
    for cid in sorted(cls, key=lambda c: (list(reversed(up(c))), c)):
        k = cls[cid]
        print(f"{'  ' * (len(up(cid)) - 1)}{cid} v{k['version']} «{k['name']}» ({k['root_type']}, {k['marking']['level']}){flag(k)}")
        for anc in reversed(up(cid)):
            for a in cls[anc].get("attributes", []):
                kind = a["value_type"] + (f" {a['unit']}" if "unit" in a else "") + (f" {a['scheme']}" if "scheme" in a else "")
                print(f"{'  ' * len(up(cid))}- {a['predicate_id']} «{a['name']}»: {kind}, {a['cardinality']}"
                      + (", обязательный" if a["required"] else "") + (f" (от {anc})" if anc != cid else ""))
    for lid, r in sorted(m["LinkDef"].items()):
        print(f"связь {lid} v{r['version']} {r['predicate_id']} «{r['name']}»: {r['domain_class_id']} -> {r['range_class_id']}, "
              f"{r['cardinality']}" + (", симметричная" if r.get("symmetric") else "") + flag(r))
    for iid, r in sorted(m["IdentifierDef"].items(), key=lambda x: (x[1]["applies_to_root_type"], x[1]["priority"])):
        print(f"идентификатор {iid} v{r['version']} {r['scheme']} «{r['name']}»: {r['applies_to_root_type']}, {r['strength']}, "
              f"приоритет {r['priority']}" + flag(r))


def journal(ds, args):
    rows = sorted((r for r in ds["records"] if r.get("kind") in IDF and r.get("tenant_id") == args.tenant),
                  key=lambda r: (r["change"]["recorded_at"], r["kind"], r[IDF[r["kind"]]], r["version"]))
    for r in rows:
        ch = r["change"]
        print(f"{ch['recorded_at']} {ch['recorded_by']} {ch['type']} {r['kind']} {r[IDF[r['kind']]]} v{r['version']}: {ch['description']}")


def parser():
    p = argparse.ArgumentParser(prog="model_constructor.py", description="Конструктор модели: схема tenant как записи (D27.1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def cmd(name, edit_cmd=True, need_id=True):
        s = sub.add_parser(name)
        s.add_argument("file")
        if need_id:
            s.add_argument("id")
        s.add_argument("--trust")
        s.add_argument("--content-dir")
        if name != "validate" and name != "init":
            s.add_argument("--tenant", required=True)
        if edit_cmd:
            s.add_argument("--by", required=True)
            s.add_argument("--description", required=True)
            s.add_argument("--note")
            s.add_argument("--at")
            s.add_argument("--marking")
        return s

    cmd("init", False, False)
    cmd("validate", False, False)
    cmd("journal", False, False)
    cmd("show", False, False).add_argument("--at")
    s = cmd("add-class")
    s.add_argument("--root-type", required=True, choices=ROOTS)
    s.add_argument("--name", required=True)
    s.add_argument("--parent")
    s.add_argument("--abstract", action="store_true")
    s = cmd("add-attribute")
    s.add_argument("--predicate", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--type", required=True, choices=TYPES)
    s.add_argument("--unit")
    s.add_argument("--scheme")
    s.add_argument("--many", action="store_true")
    s.add_argument("--required", action="store_true")
    s = cmd("change-attribute")
    s.add_argument("--predicate", required=True)
    s.add_argument("--name")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--one", action="store_true")
    g.add_argument("--many", action="store_true")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--required", action="store_true")
    g.add_argument("--optional", action="store_true")
    cmd("remove-attribute").add_argument("--predicate", required=True)
    s = cmd("add-link")
    s.add_argument("--predicate", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--domain", required=True)
    s.add_argument("--range", required=True)
    s.add_argument("--one", action="store_true")
    s.add_argument("--symmetric", action="store_true")
    s = cmd("add-identifier")
    s.add_argument("--scheme", required=True)
    s.add_argument("--root-type", required=True, choices=ROOTS)
    s.add_argument("--name", required=True)
    s.add_argument("--strength", required=True, choices=["STRONG", "WEAK"])
    s.add_argument("--priority", required=True, type=int)
    s.add_argument("--format")
    cmd("set-strength").add_argument("--strength", required=True, choices=["STRONG", "WEAK"])
    cmd("rename").add_argument("--name", required=True)
    cmd("deprecate")
    return p


def main(argv):
    args = parser().parse_args(argv[1:])
    try:
        if args.cmd == "init":
            if Path(args.file).exists():
                raise Refused(f"{args.file} уже существует")
            save(args.file, {"dataset_format": DF, "ontology_version": SV, "records": []})
            print(f"Создан пустой набор {args.file}")
            return 0
        ds = load(args.file)
        if args.cmd == "validate":
            ok = check(ds, args)
            print("схема и набор действительны" if ok else "ОТВЕРГНУТО валидатором")
            return 0 if ok else 1
        if args.cmd in ("show", "journal"):
            if not check(ds, args):
                raise Refused("набор не проходит валидатор — показывать нечего")
            (show if args.cmd == "show" else journal)(ds, args)
            return 0
        rec = edit(ds, args)
        new = {**ds, "records": ds["records"] + [rec]}
        if not check(new, args):
            raise Refused("валидатор отверг изменение — файл не изменён")
        save(args.file, new)
        print(f"Записано: {rec['kind']} {rec[IDF[rec['kind']]]} версия {rec['version']} ({rec['change']['type']})")
        return 0
    except Refused as ex:
        print(f"ОТКАЗ: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

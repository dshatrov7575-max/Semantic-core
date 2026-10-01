#!/usr/bin/env python3
"""Renders ac.equipment_card (JSON) as a readable Markdown card in the owner's style (as render_s3.py): facts only,
an empty section is one line «Сведений нет.», after each section only the sources cited in it, dates ДД.ММ.ГГГГ,
no internal identifiers or English codes in the text. Each fact also says how it was obtained: extracted by the
TechSense service (version, date of the run, the link to the graph node checked on read) or entered by an analyst.

Usage: PGHOST=... PGDATABASE=... python3 slice/render_s4.py ent_ts_pump [as_of] [reader]
"""
import json
import subprocess
import sys

from render_s3 import ddmmyyyy, bold_dates, marking_text

SERVICE = {"svc_techsense": "TechSense"}


def call(sql, user):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=f"SET SESSION AUTHORIZATION {user};\n{sql}",
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def how(p):
    if p is None:
        return "происхождение не установлено"
    if p["kind"] == "HUMAN":
        return "внесено аналитиком"
    nodes_ok = p.get("nodes") and all(n["span_in_anchor"] for n in p["nodes"])
    return (f"извлечено автоматически службой {SERVICE.get(p['service_id'], p['service_id'])} (версия {p['version']}) "
            f"{ddmmyyyy(p['issued_at'])}; "
            + ("привязка к графу разбора проверена" if nodes_ok and p.get("artifact_stored") else "ПРИВЯЗКА К ГРАФУ НЕ ПОДТВЕРЖДЕНА"))


def section(n, s, prod, out):
    out.append(f"\n## {n}. {s['title']}\n")
    if not s.get("facts"):
        out.append(s.get("empty", "Сведений нет."))
        return
    sources, origin = {}, {}

    def cite(claims):
        marks = []
        for c in claims:
            for e in c["evidence"]:
                qs = sources.setdefault(e["source_title"], [])
                if e["quote"] not in qs:
                    qs.append(e["quote"])
                k = list(sources).index(e["source_title"]) + 1
                marks.append(k)
                origin.setdefault(how(prod.get(c["claim_id"])), set()).add(k)
        return "".join(f"[{m}]" for m in sorted(set(marks)))

    for f in s["facts"]:
        out.append(bold_dates(f["text"]) + " " + cite(f["claims"]) + "\n")
        if f.get("note"):
            out.append(bold_dates(f["note"]) + " " + cite(f.get("other_claims", [])) + "\n")
    out.append("\nИсточники:\n")
    for i, (title, quotes) in enumerate(sources.items(), 1):
        out.append(f"{i}. «{title}»: " + "; ".join(f"«{q}»" for q in quotes) + ".")
    out.append("\nКак получено: " + "; ".join(f"{', '.join(f'[{k}]' for k in sorted(ks))} — {h}" for h, ks in origin.items()) + ".")


def card(eid, as_of=None, user="ac_rd_ts"):
    d = call(f"SELECT ac.equipment_card('prj_ts_pumps', '{eid}'{', ' + repr(as_of) + '::timestamptz' if as_of else ''});", user)
    i = d["identity"]
    ident = ([f"позиция (тег) {i['tag']}"] if "tag" in i
             else [f"изготовитель {i['manufacturer']}", f"модель {i['model']}"])
    out = [f"# Карточка {'оборудования' if d['entity_type'] == 'EQUIPMENT' else 'модели оборудования'}: {d['display_name']}\n",
           "Идентификация: " + ", ".join(ident) + (f", {i['description']}" if i.get("description") else "") + ".\n",
           f"Сведения на {ddmmyyyy(d['as_of'])}{' (предварительно: сведения за последние минуты ещё поступают)' if d.get('provisional') else ''}. "
           f"Гриф: {marking_text(d['marking'])}.\n"]
    if d.get("also_known_as"):
        out.append("Объединённые записи: " + "; ".join(a["display_name"] for a in d["also_known_as"]) + ".\n")
    if d.get("model_disputed"):
        out.append("Сведения о модели расходятся (см. раздел «Модель»); данные модели приведены для модели, указанной в этом разделе.\n")
    for n, s in enumerate(d["sections"], 1):
        section(n, s, d.get("production", {}), out)
    out.append(f"\n\nКонтрольная сумма: `{d['digest']}`")
    return "\n".join(out)


if __name__ == "__main__":
    print(card(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None, sys.argv[3] if len(sys.argv) > 3 else "ac_rd_ts"))

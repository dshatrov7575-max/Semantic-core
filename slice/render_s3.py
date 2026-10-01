#!/usr/bin/env python3
"""Renders S3 projections (JSON from ac.dossier / ac.check_report) as readable Markdown in the owner's dossier style:
facts only; an empty chapter is one line «Сведений нет.»; after each chapter only the sources cited in it (one item per
source, its quotes together, including sources named in a discrepancy note); numbering to the second level; dates as
ДД.ММ.ГГГГ, the date of a dated fact in bold; no internal identifiers or English codes in the text; a draft (open or
cancelled Check) is marked as such. Reads as reader ac_rd_full (s3_tests.py creates it).

Usage: PGHOST=... PGDATABASE=... python3 slice/render_s3.py dossier prj_dossier ent_d_lomov [as_of]
       PGHOST=... PGDATABASE=... python3 slice/render_s3.py report chk_full_1
"""
import json
import re
import subprocess
import sys

RISK = {"NONE": "отсутствует", "LOW": "низкий", "MEDIUM": "средний", "HIGH": "высокий"}
LEVEL = {"PUBLIC": "открытые сведения", "INTERNAL": "для служебного пользования", "CONFIDENTIAL": "конфиденциально",
         "RESTRICTED": "строго ограниченный доступ"}
CATEGORY = {"PERSONAL_DATA": "персональные данные", "COMMERCIAL_SECRET": "коммерческая тайна", "OFFICIAL_USE": "служебная информация"}
PROFILE = {"FULL": "полная", "EXPRESS_NEGATIVE": "экспресс-проверка негативных сведений", "TENDERS_ONLY": "государственные закупки",
           "SOCIAL_ONLY": "социальные сети"}
STATUS = {"COMPLETED": "завершена", "IN_PROGRESS": "не завершена (черновик)", "REQUESTED": "не начата (черновик)",
          "CANCELLED": "отменена (черновик, выводы не сделаны)"}


def call(sql, user="ac_rd_full"):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=f"SET SESSION AUTHORIZATION {user};\n{sql}",
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def ddmmyyyy(iso):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", iso or "")
    return f"{m.group(3)}.{m.group(2)}.{m.group(1)}" if m else (iso or "")


def bold_dates(s):
    return re.sub(r"(\d{2}\.\d{2}\.\d{4})", r"**\1**", s)


def marking_text(m):
    cats = [CATEGORY.get(c, c) for c in m.get("categories", [])]
    return LEVEL.get(m["level"], m["level"]) + (f" ({', '.join(cats)})" if cats else "")


def chapter(n, title, facts, empty_text, out, lead=None):
    out.append(f"\n## {n}. {title}\n")
    if lead:
        out.append(lead + "\n")
    if not facts:
        out.append(empty_text)
        return
    sources = {}                                   # title -> [quotes], in order of first citation

    def cite(claims):
        marks = []
        for c in claims:
            for e in c["evidence"]:
                qs = sources.setdefault(e["source_title"], [])
                if e["quote"] not in qs:
                    qs.append(e["quote"])
                marks.append(list(sources).index(e["source_title"]) + 1)
        return "".join(f"[{m}]" for m in sorted(set(marks)))

    for f in facts:
        out.append(bold_dates(f["text"]) + " " + cite(f["claims"]) + "\n")
        if f.get("note"):
            out.append(bold_dates(f["note"]) + " " + cite(f.get("other_claims", [])) + "\n")
    out.append("\nИсточники:\n")
    for i, (title, quotes) in enumerate(sources.items(), 1):
        out.append(f"{i}. «{title}»: " + "; ".join(f"«{q}»" for q in quotes) + ".")


def dossier(p, e, as_of=None):
    d = call(f"SELECT ac.dossier('{p}', '{e}'{', ' + repr(as_of) + '::timestamptz' if as_of else ''});")
    out = [f"# Досье: {d['display_name']}\n",
           f"Сведения на {ddmmyyyy(d['as_of'])}{' (предварительно: сведения за последние минуты ещё поступают)' if d.get('provisional') else ''}. "
           f"Гриф: {marking_text(d['marking'])}.\n"]
    if d.get("also_known_as"):
        out.append("Объединённые записи: " + "; ".join(a["display_name"] for a in d["also_known_as"]) + ".\n")
    for n, s in enumerate(d["sections"], 1):
        chapter(n, s["title"], s.get("facts"), s.get("empty", "Сведений нет."), out)
    out.append(f"\n\nКонтрольная сумма: `{d['digest']}`")
    return "\n".join(out)


def report(k):
    d = call(f"SELECT ac.check_report('{k}');")
    draft = d.get("draft")
    head = [f"# {'ЧЕРНОВИК. ' if draft else ''}Отчёт о Проверке: {d['subject']['display_name']}\n",
            f"Вид Проверки: {PROFILE.get(d['profile'], d['profile'])}. Состояние: {STATUS.get(d['status'], d['status'])}. "
            f"Сведения на {ddmmyyyy(d['as_of'])}."
            + (f" Итоговый риск: {RISK[d['overall_risk']]}." if d.get("overall_risk") else "")
            + f" Гриф: {marking_text(d['marking'])}."]
    if d.get("previous"):
        pv = d["previous"]
        head.append(f"Предыдущая Проверка ({PROFILE.get(pv['profile'], pv['profile'])}) на {ddmmyyyy(pv['as_of'])}: "
                    f"итоговый риск {RISK.get(pv['overall_risk'], '—')}.")
    out = head
    for n, dim in enumerate(d["dimensions"], 1):
        s = dim.get("searches", [])
        lead = ("Поиск: " + "; ".join(f"{x.get('scope') or 'источник не указан'}, запрос «{x.get('query') or '—'}», "
                                      f"{ddmmyyyy(x['performed_at'])}" + (f", результат — «{x['result_source']['title']}»"
                                                                          if x.get("result_source") else "") for x in s) + "."
                if s else "Поиск не выполнялся.")
        if dim.get("risk"):
            lead += f" Риск: {RISK[dim['risk']]}."
        chapter(n, dim["title"], dim.get("facts"), dim.get("text", "Не выявлено."), out, lead)
    out.append(f"\n\nКонтрольная сумма: `{d['digest']}`")
    return "\n".join(out)


if __name__ == "__main__":
    kind = sys.argv[1]
    print(dossier(*sys.argv[2:]) if kind == "dossier" else report(sys.argv[2]))

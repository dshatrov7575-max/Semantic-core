#!/usr/bin/env python3
"""Renders ac.custody (JSON) as a short readable note «сохранность оригиналов» in the owner's style: full sentences,
dates ДД.ММ.ГГГГ, no internal identifiers or English codes.
Usage: PGHOST=... PGDATABASE=... python3 slice/render_s5b.py <claim_id> [as_of] [reader]
"""
import json
import subprocess
import sys

from render_s3 import ddmmyyyy, marking_text

STATUS = {"OK": "цел", "CORRUPT": "повреждён", "MISSING": "утрачен", "UNCHECKED": "ещё не проверялся"}
KIND = {"text/html": "страница сайта", "application/pdf": "документ PDF", "image/png": "изображение", "image/jpeg": "изображение"}


def call(sql, user):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=f"SET SESSION AUTHORIZATION {user};\n{sql}",
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def size(n):
    return f"{n} байт" if n < 1024 else f"{n / 1024:.1f} КБ".replace(".", ",") if n < 1024 * 1024 else f"{n / 1048576:.1f} МБ".replace(".", ",")


def custody(cid, as_of=None, user="ac_rd_wm"):
    d = call(f"SELECT ac.custody('{cid}'{', ' + repr(as_of) + '::timestamptz' if as_of else ''});", user)
    out = ["# Сохранность оригиналов\n", f"Утверждение: {d['text']}\n",
           f"Сведения на {ddmmyyyy(d['as_of'])}. Гриф: {marking_text(d['marking'])}.\n"]
    for n, s in enumerate(d["sources"], 1):
        out.append(f"\n## {n}. «{s['title']}»\n")
        out.append(f"Текст источника ({size(s['text_bytes'])}) хранится в базе; цитаты сверяются с ним при каждом чтении.\n")
        for o in s["observations"]:
            line = f"**{ddmmyyyy(o['observed_at'])}** получено по адресу {o['origin_uri']}."
            og = o.get("original")
            if og:
                kind = KIND.get(og["media_type"].split(";")[0], og["media_type"].split(";")[0])
                line += (f" Оригинал ({kind}, {size(og['byte_length'])}) сохранён {ddmmyyyy(og['stored_at'])}; состояние — {STATUS[og['status']]}"
                         + (f", последняя проверка {ddmmyyyy(og['last_checked_at'])}, всего проверок — {og['checks']}." if og.get("last_checked_at") else "."))
            else:
                line += " Оригинал не сохранялся."
            out.append(line + "\n")
    out.append(f"\nКонтрольная сумма: `{d['digest']}`")
    return "\n".join(out)


if __name__ == "__main__":
    print(custody(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None, sys.argv[3] if len(sys.argv) > 3 else "ac_rd_wm"))

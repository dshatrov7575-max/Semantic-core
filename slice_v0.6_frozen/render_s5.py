#!/usr/bin/env python3
"""Renders ac.wm_feed (JSON) as a readable Markdown feed in the owner's style: one numbered item per publication
(an article fetched several times is one item), date of publication in bold, the mention as a full sentence with its
quote, where and how many times the article was received; an item without a publication is marked as a single
source. No internal identifiers or English codes in the text.

Usage: PGHOST=... PGDATABASE=... python3 slice/render_s5.py ent_w_developer [as_of] [reader]
"""
import json
import subprocess
import sys

from render_s3 import ddmmyyyy, marking_text


def call(sql, user):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=f"SET SESSION AUTHORIZATION {user};\n{sql}",
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def feed(eid, as_of=None, user="ac_rd_wm", project="prj_wm_region"):
    d = call(f"SELECT ac.wm_feed('{project}', '{eid}'{', ' + repr(as_of) + '::timestamptz' if as_of else ''});", user)
    out = [f"# Лента упоминаний: {d['display_name']}\n",
           f"Сведения на {ddmmyyyy(d['as_of'])}{' (предварительно: сведения за последние минуты ещё поступают)' if d.get('provisional') else ''}. "
           f"Гриф: {marking_text(d['marking'])}.\n"]
    if not d["items"]:
        out.append("Упоминаний не выявлено.")
    for n, it in enumerate(d["items"], 1):
        when = it.get("published_at") or it.get("first_seen")
        head = f"«{it['title']}»" + (f", {it['outlet']}" if it.get("outlet") else "")
        out.append(f"\n## {n}. {head}, **{ddmmyyyy(when)}**\n")
        for m in it["mentions"]:
            quotes = []
            for c in m["claims"]:
                for e in c["evidence"]:
                    if e["quote"] not in quotes:
                        quotes.append(e["quote"])
            out.append(m["text"] + " Цитата: " + "; ".join(f"«{q}»" for q in quotes) + ".\n")
        if it.get("renditions"):
            urls = [u for r in it["renditions"] for u in r["urls"]]
            n = len(it["renditions"])
            out.append(("Упоминание подтверждено " + ("одной версией" if n == 1 else f"{n} версиями") + " одного текста статьи "
                        f"(разные адреса и байты), впервые получена {ddmmyyyy(it['first_seen'])}: ") + "; ".join(urls) + ".")
        else:
            out.append(f"Отдельный материал (публикация не заведена), получен {ddmmyyyy(it.get('first_seen'))}.")
    out.append(f"\n\nКонтрольная сумма: `{d['digest']}`")
    return "\n".join(out)


if __name__ == "__main__":
    print(feed(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None, sys.argv[3] if len(sys.argv) > 3 else "ac_rd_wm"))

#!/usr/bin/env python3
"""Builds ПРИМЕР_ЛЕНТЫ_S5.md: reload the world (the article of news.example fetched three times with different bytes),
add a live re-fetch with other whitespace and an edited version of the article with its own mention, then render the
feed of the developer. Usage: PGHOST=... PGDATABASE=<scratch db> python3 slice/make_examples_s5.py"""
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s5_tests as T  # noqa: E402
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
from render_s5 import feed  # noqa: E402


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    T.sql1(T.SETUP)
    ds, _, _ = build()
    pub = next(p for p in ds["records"] if p["kind"] == "Publication")
    S2 = next(s["content_inline"] for s in ds["records"] if s["kind"] == "Source"
              and VAL.text_digest_of(s["content_inline"].encode()) == pub["text_digest"] and "\n" not in s["content_inline"])
    time.sleep(1.1)
    rf = T.source(S2.replace(". ", ".  ", 2), "https://news.example/zarechye?utm_campaign=autumn", utc(0))
    assert psql(ingest_sql([rf], {})).returncode == 0
    time.sleep(1.1)
    assert psql(ingest_sql([T.mention(rf["source_id"], rf["content_inline"], "Жители Заречной улицы выступили против застройки", utc(0))], {})).returncode == 0
    edited = S2.replace("выступили против застройки", "выступили против стройки")
    ed = T.source(edited, "https://news.example/zarechye", utc(0))
    assert psql(ingest_sql([ed], {})).returncode == 0
    time.sleep(1.1)
    assert psql(ingest_sql([T.mention(ed["source_id"], edited, "Жители Заречной улицы выступили против стройки", utc(0))], {})).returncode == 0
    time.sleep(1.1)
    text = ("# Пример ленты упоминаний (S5)\n\nПостроена базой (`ac.wm_feed`) из эталонного мира и живых записей: статья news.example "
            "получена четыре раза с разными байтами (лишние пробелы и перевод строки, невидимый символ, мобильная версия, метки "
            "перехода) — это одна позиция; в ней перечислены три версии, на которые ссылаются упоминания; отредактированная версия "
            "статьи без своей записи публикации — отдельный материал. "
            "Отрисовано `slice/render_s5.py`.\n\n---\n\n" + feed("ent_w_developer"))
    out = HERE / "ПРИМЕР_ЛЕНТЫ_S5.md"
    out.write_text(text + "\n", encoding="utf-8")
    print("written", out, len(out.read_bytes()), "bytes")


if __name__ == "__main__":
    main()

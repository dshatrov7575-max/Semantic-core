#!/usr/bin/env python3
"""Builds ПРИМЕР_СОХРАННОСТИ_S5.md: the world + one live fetch with its original kept in the object store (S3 protocol,
emulator); the original of the live fetch is then damaged inside the store and the scrubber records it.
Usage: PGHOST=... PGDATABASE=<scratch db> python3 slice/make_examples_s5b.py"""
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s5b_tests as T  # noqa: E402
import s5_tests as S5  # noqa: E402
import s3_tests as S3  # noqa: E402
from vectors import build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
from object_store import object_key  # noqa: E402
import gateway as GW  # noqa: E402
from render_s5b import custody  # noqa: E402


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    S5.sql1(S3.SETUP)
    S5.sql1(S5.SETUP)
    ds, _, content = build()
    with tempfile.TemporaryDirectory() as tmp:
        srv, store = T.start_emulator(Path(tmp))
        try:
            s2 = next(s for s in ds["records"] if s["kind"] == "Source" and any("original" in o for o in s["observations"]))
            og = next(o["original"] for o in s2["observations"] if "original" in o)
            store.put("tnt_demo", content[og["object"]])
            c8 = next(c for c in ds["records"] if c["kind"] == "Claim" and c["predicate"] == "wm.mentioned" and c["recorded_at"] == "2026-09-06T10:30:00Z")
            text = s2["content_inline"].replace(". ", ".   ", 1)
            raw = ("<!doctype html><html><body><article>" + text + "</article></body></html>").encode("utf-8")
            time.sleep(1.1)
            orig = GW.register(store, "tnt_demo", raw, "text/html; charset=utf-8")
            src = S5.source(text, "https://news.example/zarechye?utm_medium=rss", utc(0))
            src["observations"][0]["original"] = orig
            assert psql(ingest_sql([src], {})).returncode == 0
            time.sleep(1.1)
            m = S5.mention(src["source_id"], text, "Жители Заречной улицы выступили против застройки", utc(0))
            assert psql(ingest_sql([m], {})).returncode == 0
            time.sleep(1.1)
            (Path(tmp) / "originals" / object_key("tnt_demo", orig["object"])).write_bytes(raw[:-10])
            GW.scrub(store)
            time.sleep(1.1)
            text_out = ("# Пример: сохранность оригиналов (S5, часть 2)\n\nПостроено базой (`ac.custody`), отрисовано `slice/render_s5b.py`. "
                        "Оригиналы лежат в объектном хранилище (протокол S3); у второго утверждения оригинал намеренно повреждён внутри "
                        "хранилища, и плановая проверка это записала.\n\n---\n\n" + custody(c8["claim_id"]) + "\n\n---\n\n" + custody(m["claim_id"]))
        finally:
            srv.terminate()
    out = HERE / "ПРИМЕР_СОХРАННОСТИ_S5.md"
    out.write_text(text_out + "\n", encoding="utf-8")
    print("written", out, len(out.read_bytes()), "bytes")


if __name__ == "__main__":
    main()

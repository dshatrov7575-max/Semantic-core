#!/usr/bin/env python3
"""Рецензия цикла 9: (а) валидатор на «мусорной» маркировке/пустом имени ClassDef; (б) TRUNCATE под ac_loader (review09f)."""
import sys, subprocess, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "snapshot" / "core"))
import vectors as VX
from validator import validate
for title, kw in [("marking={level:TOP_SECRET,zzz:1}", {"marking": {"level": "TOP_SECRET", "zzz": 1}}), ("marking='строка'", {"marking": "строка"}),
                  ("marking={}", {"marking": {}}), ("name='   '", {"name": "   "}), ("label_ru=''", {"label_ru": ""})]:
    c = VX._classdef("zz_m"); c.update(kw)
    r = validate(*VX.build(VX.V("X", [], "", pre=lambda W, c=c: W.__setitem__("zz_m", c))))
    print(f"валидатор, ClassDef {title}: {r.codes()}")
for t in ("TRUNCATE ac.class_defs;", "TRUNCATE ac.class_closure;"):
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input="SET SESSION AUTHORIZATION ac_loader;\n" + t, capture_output=True, text=True, env={**os.environ, "PGDATABASE": "review09f"})
    print(f"[review09f/ac_loader] {t} => {r.stderr.strip() or 'OK'}")

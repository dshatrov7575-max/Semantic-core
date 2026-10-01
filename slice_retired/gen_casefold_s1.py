#!/usr/bin/env python3
"""Regenerates casefold_s1.sql: a PostgreSQL case-folding table equal to Python str.casefold() (normative, used by
validator.base_key) for every code point where casefold() or PostgreSQL lower() changes the character.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=... python3 slice/gen_casefold_s1.py"""
import subprocess
from pathlib import Path

pg = {int(x) for x in subprocess.run(["psql", "-XAtc", "SELECT cp FROM generate_series(1, 1114111) cp "
                                      "WHERE (cp < 55296 OR cp > 57343) AND lower(chr(cp)) <> chr(cp)"],
                                     capture_output=True, text=True, check=True).stdout.split()}
py = {cp for cp in range(1, 0x110000) if not 0xD800 <= cp <= 0xDFFF and chr(cp).casefold() != chr(cp)}
cps = sorted(pg | py)


def lit(s):
    return "'" + s.replace("'", "''") + "'"


rows = ",\n".join(f"({lit(chr(c))},{lit(chr(c).casefold())})" for c in cps)
sql = f"""-- Generated from Python str.casefold() (the validator's normative case folding) for every code point where
-- casefold() or PostgreSQL lower() changes the character: {len(cps)} rows. Regenerate: slice/gen_casefold_s1.py.
CREATE TABLE ac.casefold_map (ch text PRIMARY KEY, folded text NOT NULL);
INSERT INTO ac.casefold_map VALUES
{rows};
CREATE OR REPLACE FUNCTION ac.casefold(s text) RETURNS text STABLE LANGUAGE sql AS $$
  SELECT coalesce(string_agg(coalesce(m.folded, c.ch), '' ORDER BY c.n), '')
  FROM regexp_split_to_table(s, '') WITH ORDINALITY AS c(ch, n) LEFT JOIN ac.casefold_map m ON m.ch = c.ch $$;
"""
(Path(__file__).resolve().parent / "casefold_s1.sql").write_text(sql, encoding="utf-8")
print("rows", len(cps))

#!/usr/bin/env python3
"""Раунд 2 (г): нормальная форма идентификатора строки — validator.row_id против ac.row_id на экзотических значениях
(Юникод, пробелы, кадастровые с нулями, пустая строка, символы, не назначенные в Юникоде 14.0, но известные PostgreSQL).
Расхождение функций — ещё не находка: дальше для расхождений проверяется сквозной путь (мир -> валидатор и база)."""
import json, random, sys, unicodedata
from rv import *

SCHEMES = ["ru.cadastral", "lei", "ru.inn", "vin", "imo", "x.reg", "ru.ogrn"]
FIXED = ["", " ", "-", "./_-", "0", "00", "0:0", "00:000", "50:12:0101001:245", "050:012:0101001:0245", "50:12:0101001:245 ", " 50:12", "50:12:",
         ":50", "50::12", "5０:12", "٥٠:١٢", "50:12\n", "1" * 18, "1" * 19, "0" * 18 + ":1", "0" * 19 + ":1", "9" * 18 + ":0009", "+1:2", "1e3:2",
         "5493-0012-3456", "5493 0012 3456", "5493AB123456", "５４９３ＡＢ", "ǅ", "ß", "ẞ", "İ", "ı", "K", "Å", "ﬁ", "㎏", "①", "½", "ǆ", "­5493", "54​93",
         "54 93", "54 93", "54　93", "54–93", "54−93", "54‐ 93", "Á", "Å", "\U0001E030", "\U0001E030-1",
         "\U0001E04D", "a\U0001E06Db", "\U0001F600", "ꟲ", "᷺", "x\x00y"[:1] + "y", "a\tb", "a\nb", "a\rb", "a b", "a/b", "a.b", "a_b", "a—b", "a‑b",
         "A" * 300, "ʼ", "'", "«a»", "Ⅰ", "µ", "μ", "ς", "σ", "Σ", "ё", "Ё", "е"]
rnd = random.Random(11)
POOL = list("0123456789:abAB -_./") + [" ", "​", "０", "Ａ", "ß", "İ", "́", "\U0001E030", "\U0001E031", "‐", "−", "\t", "ǅ", "ﬃ", "Ⅷ"]
vals = FIXED + ["".join(rnd.choice(POOL) for _ in range(rnd.randint(1, 12))) for _ in range(3000)]
pairs = [(s, v) for s in SCHEMES for v in vals]
sql = "SELECT jsonb_agg(ac.row_id(x->>0, x->>1) ORDER BY o) FROM jsonb_array_elements($q$" + json.dumps(pairs, ensure_ascii=False) + "$q$::jsonb) WITH ORDINALITY a(x, o);"
r = psql(sql)
if r.returncode:
    sys.exit(first_err(r))
db = json.loads(r.stdout)
bad = []
for (s, v), d in zip(pairs, db):
    try:
        sch, val = VAL.row_id(s, v)
        py = sch + "|" + val
    except Exception as ex:   # noqa: BLE001
        py = f"EXC {type(ex).__name__}"
    if py != d:
        bad.append((s, v, py, d))
print(f"пар (схема, значение): {len(pairs)}; расхождений validator.row_id / ac.row_id: {len(bad)}")
kinds = {}
for s, v, py, d in bad:
    k = "не назначен в Юникоде 14.0" if any(unicodedata.category(ch) == "Cn" for ch in v) else "исключение" if py.startswith("EXC") else "прочее"
    kinds.setdefault(k, []).append((s, v, py, d))
for k, lst in kinds.items():
    print(f"  {k}: {len(lst)}; примеры: " + "; ".join(f"{s} {v!r}: py={py!r} db={d!r}" for s, v, py, d in lst[:4]))
json.dump(bad, open(Path(__file__).parent / "out" / "b21_mismatch.json", "w"), ensure_ascii=False)
report("G1", bool(kinds.get("прочее") or kinds.get("исключение")), "расхождение нормальной формы на назначенных символах")

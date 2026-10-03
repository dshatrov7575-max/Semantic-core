#!/usr/bin/env python3
"""S10R / направление 7: правила нового кода без вектора. Дополнительные мутанты рецензента прогоняются ТОЙ ЖЕ машиной (core/mutants.py:
базовый мир + все векторы); выживший мутант = правило, которое не проверяет ни один вектор."""
from common import *
import mutants as MU
from multiprocessing import Pool
X = [
 ("X01", "объект-сущность: слияния объекта не учитываются",
  '                                         group_keys(obj_ent, t_rec) if obj_ent is not None else None)',
  '                                         ent_keys(obj_ent["entity_type"], obj_ent["identity"]) if obj_ent is not None else None)'),
 ("X02", "объект-сущность: слияние объекта ПОЗЖЕ утверждения учитывается",
  '                                         group_keys(obj_ent, t_rec) if obj_ent is not None else None)',
  '                                         group_keys(obj_ent, "9999") if obj_ent is not None else None)'),
 ("X03", "литерал: сверяется только строковая колонка (DATE/INTEGER/BOOLEAN никогда не подтверждают)",
  '        elif lit["type"] == col["type"] and lit["value"] == v:', '        elif lit["type"] == col["type"] == "STRING" and lit["value"] == v:'),
 ("X04", "субъект: неизвестный субъект не пропускается (subj_keys is None)",
  '    if m.get("subject") and subj_keys is not None:', '    if m.get("subject"):'),
 ("X05", "объект-сущность: неизвестный объект не пропускается (obj_keys is None)",
  '            if obj_keys is None or (scheme[col["name"]], v) in obj_keys:', '            if (scheme[col["name"]], v) in (obj_keys or ()):'),
 ("X06", "группа субъекта: ветка «субъект сам слит к моменту утверждения» (владелец = merged_into)",
  '        owner = e["merged_into"] if merged_by(e, t) else e["entity_id"]', '        owner = e["entity_id"]'),
 ("X07", "маркировка колонок: условие cell[name] in cols", 'if "salt" in cell and cell["name"] in cols and not dominates(', 'if "salt" in cell and not dominates('),
 ("X08", "тип ячейки: целое — любое число (нет отдельного правила диапазона)", 'COLUMN_PY = {"STRING": str, "INTEGER": int, "BOOLEAN": bool, "DATE": str}',
  'COLUMN_PY = {"STRING": str, "INTEGER": (int, float), "BOOLEAN": bool, "DATE": str}'),
 ("X09", "доказательство-строка у источника с негодным манифестом: молча пропускается и у обычного источника — нет: проверяется только вид",
  '                    continue                            # a broken manifest is reported at the source\n', '                    pass\n                    continue\n'),
 ("X10", "строка без subject в манифесте, но m[subject] пуст: m.get('subject') -> 'subject' in m", '    if m.get("subject") and subj_keys is not None:', '    if "subject" in m and subj_keys is not None:'),
 ("X11", "ключ: набор с ключом определяется по m['key'] — заменить на наличие row_key в доказательстве", '    if m["key"]:\n        if any(k not in quoted', '    if m["key"] and "row_key" in ev:\n        if any(k not in quoted'),
 ("X12", "литерал-идентификатор у колонки-идентификатора: ветка identifier_scheme раньше обычной", '        elif "identifier_scheme" in col:\n', '        elif "identifier_scheme" in col and lit["type"] == "IDENTIFIER":\n'),
]
def init():
    MU.CASES = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
def one(m):
    if MU.SRC.count(m[2]) != 1: return (m[0], f"PATTERN x{MU.SRC.count(m[2])}", m[1])
    return MU.run_one(m)
if __name__ == "__main__":
    only = sys.argv[1:]
    with Pool(2, initializer=init) as pool:
        rows = pool.map(one, [m for m in X if not only or m[0] in only], chunksize=1)
    for r in rows: print(f"{r[0]:<5} {r[1]:<34} {r[2]}", flush=True)
    print("\nвыжило:", sum(1 for r in rows if r[1] == "SURVIVED"), "из", len(rows))

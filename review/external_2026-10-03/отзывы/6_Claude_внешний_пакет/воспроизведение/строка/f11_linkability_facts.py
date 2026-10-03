"""Факты о связываемости (заявлено и выполняется): неизменная строка — те же листья во всех версиях набора;
изменилась одна ячейка — новые листья всех ячеек; тот же ключ набора в другом наборе — другие листья.
Не заявлено: секрет не зависит от ИМЁН и МАРКИРОВОК колонок — при переименовании/перемаркировке соли прежние."""
from _h import *
K = os.urandom(32)
def leaves(dv, key=OGRN_DEV):
    _, kv, s, h, vals = dv.rows[dv.where[canon([key])]]
    return {n: cell_leaf(cell_salt(s, n), n, v).hex() for n, v in zip(dv.names, vals)}, s
mk = lambda did="dst_a", rows=REGISTRY_ROWS, cols=REGISTRY_COLUMNS: DatasetVersion(did, T, "v", cols, ["ogrn"], rows, subject=("ogrn", "inn"), dataset_key=K)
a, sa = leaves(mk())
b, sb = leaves(mk(rows=[dict(REGISTRY_ROWS[0], employees=49)] + REGISTRY_ROWS[1:]))
c, sc = leaves(mk(did="dst_b"))
print("та же строка, новая версия: совпало листьев", sum(a[n] == leaves(mk())[0][n] for n in a), "из", len(a))
print("изменена одна ячейка (employees): совпало листьев", sum(a[n] == b[n] for n in a), "из", len(a))
print("тот же ключ набора, другой dataset_id: совпало листьев", sum(a[n] == c[n] for n in a), "из", len(a))
cols2 = copy.deepcopy(REGISTRY_COLUMNS)
next(x for x in cols2 if x["name"] == "employees")["marking"] = CONF_PD            # в новой версии колонка закрыта
next(x for x in cols2 if x["name"] == "name")["name"] = "full_name"               # и одна колонка переименована
rows2 = [{("full_name" if k == "name" else k): v for k, v in r.items()} for r in REGISTRY_ROWS]
d, sd = leaves(mk(rows=rows2, cols=cols2))
print("перемаркировка employees + переименование name: секрет строки тот же:", sa == sd, "| лист employees тот же:", a["employees"] == d["employees"])

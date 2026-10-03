"""Проверено, держит: набор без subject; строка без идентификаторов субъекта; набор без ключа; чужая строка;
честный HMAC при известных прочих ячейках; в доказательстве нет секрета строки."""
from _h import *
def case(tag, key=("ogrn",), subject=("ogrn", "inn"), rows=None, quote=("address",), rowkey=None, cols=None):
    def pre(W):
        dv = demo_registry(rows=rows, key=key, subject=subject, columns=cols)
        set_ds(W, dv)
        k = rowkey(dv) if callable(rowkey) else (rowkey or [OGRN_DEV])
        W["c50"]["evidence"] = [{"$row": ["s30", k, list(quote)]}]
    R, ds, ix, content = run(pre)
    show(tag, R)
    return ds["records"][ix["c50"]]["evidence"][0]
case("набор без subject", subject=())
r = copy.deepcopy(REGISTRY_ROWS); r[0]["inn"] = None; r[0]["ogrn"] = OGRN_DEV
case("subject = (inn), ячейка inn пуста, процитирована", subject=("inn",), rows=r, quote=("address", "inn"))
case("subject = (inn), ячейка inn скрыта", subject=("inn",), quote=("address",))
case("чужая строка (ОГРН «Трубопроводстроя») об адресе девелопера", rowkey=[OGRN_TRUB])
ev = case("набор без ключа: строка названа хэшем, процитированы ogrn и address", key=(), quote=("address", "ogrn"),
          rowkey=lambda dv: next(x[0] for x in dv.rows if x[4][0] == OGRN_DEV))
print("   в доказательстве row_key:", "row_key" in ev, "| поля:", sorted(ev), "| поля ячеек:", sorted({k for c in ev["cells"] for k in c}))
# секрет строки в доказательстве не раскрывается: по соли процитированной ячейки соли остальных не вывести
dv = demo_registry(); pos = dv.where[canon([OGRN_DEV])]; secret = dv.rows[pos][2]
blob = json.dumps(dv.evidence([OGRN_DEV], ["address"]))
print("секрет строки встречается в доказательстве:", secret.hex() in blob, "| соль director встречается:", cell_salt(secret, "director").hex() in blob)

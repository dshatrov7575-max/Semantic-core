"""F03. «Прочерк и пустая строка — не идентификатор» (архитектура v0.10 §3, S11R2-09) выполняется только для схем,
нормализуемых id_norm. Для ru.inn / ru.ogrn / ru.ogrnip / vin / imo заглушка в колонке субъекта считается
идентификатором, расходящимся с идентификатором субъекта: честное утверждение отвергается, пока колонку не скрыть."""
from _h import *
def pre(blank, col, quote, scheme=None):
    def f(W):
        cols = copy.deepcopy(REGISTRY_COLUMNS); rows = copy.deepcopy(REGISTRY_ROWS); subj = ("ogrn", "inn")
        if col == "lei":
            cols.append({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"}); subj = ("ogrn", "inn", "lei")
            for r in rows: r["lei"] = None
            W["ent_k_developer"]["identity"]["foreign_ids"] = [{"scheme": "lei", "value": "549300abcd12"}]
        rows[0][col] = blank
        set_ds(W, demo_registry(rows=rows, columns=cols, subject=subj))
        W["c50"]["evidence"] = [{"$row": ["s30", [OGRN_DEV], quote]}]
    return f
for col in ("lei", "inn"):
    for blank in ("-", "", "—", "н/д", " "):
        for quote in (["address", col], ["address"]):
            R, ds, ix, content = run(pre(blank, col, quote))
            msg = "ПРИНЯТО" if not R.errors else "ОТКАЗ: " + R.errors[0]["msg"][:95]
            dbr = ""
            if col == "inn" and blank == "-":
                dbr = " | база: " + (db_load(ds, FX.finalize(FX.world())[2], content) or "ПРИНЯТО")[:120]
            print(f"колонка {col:3} = {blank!r:6} процитировано {str(quote):20} -> {msg}{dbr}")

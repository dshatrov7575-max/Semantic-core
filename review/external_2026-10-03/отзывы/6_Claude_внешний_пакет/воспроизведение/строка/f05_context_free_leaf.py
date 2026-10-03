"""F05. Лист и хэш строки не привязаны к контексту (tenant, набор, версия, маркировка/тип/роль колонки, число колонок):
всё это живёт только в манифесте, а манифест — самозаявленный Source. Одно и то же доказательство побайтно годно
под другим манифестом с тем же rows_root: (а) с пониженной маркировкой колонки; (б) с другим числом и именами
скрытых колонок. Файлы строк и ключ набора для регистрации такого манифеста не нужны."""
from _h import *
dv1 = demo_registry()
ev_pd = dv1.evidence([OGRN_DEV], ["address", "director"])       # получено читателем с категорией ПД по версии v1

def world_with(manifest, ev, marking=CONF_CS):
    def f(W):
        W["s30"]["content_inline"] = canon(manifest)
        W["__datasets__"] = {}                                    # файлов строк в хранилище нет
        W["c50"]["marking"] = marking
        sid = "src:sha256:" + hashlib.sha256(canon(manifest).encode("utf-8")).hexdigest()
        W["c50"]["evidence"] = [dict(copy.deepcopy(ev), source_id=sid)]
    return f

def attempt(tag, manifest, ev):
    def pre(W):
        world_with(manifest, ev)(W)
    R, ds, ix, content = run(pre)
    show(tag + " | валидатор", R)
    if not R.errors:
        why = db_load(ds, FX.finalize(FX.world())[2], content)
        print("      база:", why or "ПРИНЯТО", "| досье читателя ac_rd_cs (без категории ПД):",
              json.dumps([e["cells"] for e in dossier_rows()] if not why else None, ensure_ascii=False))

# исходная версия: директор — CONFIDENTIAL + PERSONAL_DATA; утверждение CONFIDENTIAL + COMMERCIAL_SECRET
attempt("v1, процитирован director", dv1.manifest, ev_pd)
# (а) тот же манифест, те же files/rows_root, директор объявлен PUBLIC
m2 = copy.deepcopy(dv1.manifest); m2["version_label"] = "2026-09-01-open"
next(c for c in m2["columns"] if c["name"] == "director")["marking"] = PUB
attempt("(а) манифест-двойник: director PUBLIC, те же rows_root", m2, ev_pd)
# (б) двойник с 5 колонками вместо 8: хвост дерева (director..employees) выдан за один лист колонки «tail»
ev_a = dv1.evidence([OGRN_DEV], ["address"])
L = [bytes.fromhex(c["leaf"]) if "leaf" in c else cell_leaf(bytes.fromhex(c["salt"]), c["name"], c["value"]) for c in ev_a["cells"]]
tail = merkle_root(L[4:8])
m3 = copy.deepcopy(dv1.manifest); m3["version_label"] = "2026-09-01-five"
m3["columns"] = m3["columns"][:4] + [{"name": "tail", "type": "STRING", "marking": PUB}]
ev3 = copy.deepcopy(ev_a); ev3["cells"] = ev3["cells"][:4] + [{"name": "tail", "leaf": tail.hex()}]
attempt("(б) манифест-двойник: 5 колонок, внутренний узел дерева ячеек выдан за лист", m3, ev3)
print("row_sha256 одинаков во всех трёх:", ev_pd["row_sha256"] == ev3["row_sha256"] == ev_a["row_sha256"])

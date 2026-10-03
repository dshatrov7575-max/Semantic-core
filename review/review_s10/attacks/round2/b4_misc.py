#!/usr/bin/env python3
"""S10R раунд 2 / новое: ac.dataset_reset, ac.row_profile_expr, ac.dataset_info, ac.support_key, ac.claim_provenance, правило конверта."""
from r2common import *
from s10_tests import copy_file
import threading
stamp = utc(0)
COLS = "file_no, row_no, row_hash, row_secret"
def reg(dv, **kw):
    r = db_try([source_rec(dv, **kw)], commit=True); assert r.returncode == 0, first_err(r); return dv
def copy_(dv, tbl, path, user="ac_loader"):
    cols = COLS + ", " + ", ".join('"c_%s"' % c["name"] for c in dv.columns)
    with open(path, "rb") as fh:
        return subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", f"SET SESSION AUTHORIZATION {user}", "-c", f"COPY {tbl} ({cols}) FROM STDIN"], stdin=fh, capture_output=True, text=True)
L = lambda q, u="ac_loader": verdict(psql(q, u))[:120]
print("== 1. ac.dataset_reset")
d = reg(relabel(demo_registry(), "rev-b4 reset " + stamp)); tbl = psql(f"SELECT ac.dataset_open('{T}', '{d.source_id}');", "ac_loader").stdout.strip()
f = copy_file(d); copy_(d, tbl, f); copy_(d, tbl, f)
print("   двойная загрузка: seal —", L(f"SELECT ac.dataset_seal('{T}', '{d.source_id}');"))
print("   reset читателем —", L(f"SELECT ac.dataset_reset('{T}', '{d.source_id}');", "ac_rd_full"), "| reset загрузчиком —", L(f"SELECT ac.dataset_reset('{T}', '{d.source_id}');"))
print("   повторная загрузка:", copy_(d, tbl, f).returncode, "| seal —", L(f"SELECT ac.dataset_seal('{T}', '{d.source_id}');"))
print("   reset запечатанной —", L(f"SELECT ac.dataset_reset('{T}', '{d.source_id}');"), "| reset неоткрытой —", L(f"SELECT ac.dataset_reset('{T}', 'src:sha256:{'0' * 64}');"))
print("   строк в запечатанной таблице после попыток:", psql(f"SELECT count(*) FROM {tbl}").stdout.strip())
# гонка reset ↔ seal: печать идёт, сброс в это время
d2 = reg(relabel(demo_registry(), "rev-b4 reset-race " + stamp)); tbl2 = psql(f"SELECT ac.dataset_open('{T}', '{d2.source_id}');", "ac_loader").stdout.strip(); copy_(d2, tbl2, copy_file(d2))
res = {}
t1 = threading.Thread(target=lambda: res.__setitem__("seal", L(f"BEGIN; SELECT ac.dataset_seal('{T}', '{d2.source_id}'); SELECT pg_sleep(2); COMMIT;")))
t2 = threading.Thread(target=lambda: res.__setitem__("reset", L(f"SELECT ac.dataset_reset('{T}', '{d2.source_id}');")))
t1.start(); time.sleep(0.7); t2.start(); t1.join(); t2.join()
print("   гонка: печать (держит транзакцию 2 с) и сброс —", res, "| строк:", psql(f"SELECT count(*) || ', запечатана: ' || (SELECT sealed_at IS NOT NULL FROM ac.dataset_tables WHERE source_id = '{d2.source_id}') FROM {tbl2}").stdout.strip())
print("== 2. ac.row_profile_expr: значения, текст которых не тот, что хэшировался")
def try_date(val_manifest, val_table, col="registered_on"):
    rows = copy.deepcopy(REGISTRY_ROWS); rows[0][col] = val_manifest
    dv = reg(relabel(demo_registry(rows=rows, check=False) if val_manifest is not None else demo_registry(rows=rows), f"rev-b4 prof {val_table} {stamp}"))
    i = [c["name"] for c in dv.columns].index(col)
    def mut(rs):
        for x in rs:
            if x[4][0] == OGRN_DEV: x[4][i] = val_table
    t = psql(f"SELECT ac.dataset_open('{T}', '{dv.source_id}');", "ac_loader").stdout.strip(); cp = copy_(dv, t, copy_file(dv, mut))
    return ("COPY: " + cp.stderr.strip()[:60]) if cp.returncode else L(f"SELECT ac.dataset_seal('{T}', '{dv.source_id}');")
for man, tab in [("0044-03-15", "0044-03-15 BC"), (None, "infinity"), (None, "-infinity"), ("0001-01-01", "0001-01-01 BC"), ("9999-12-31", "9999-12-31"), ("0001-01-01", "0001-01-01")]:
    print(f"   манифест {man!r}, в таблице {tab!r}: seal —", try_date(man, tab)[:100])
print("== 3. ac.dataset_info")
CONF_PD = {"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA"]}
p1 = reg(relabel(demo_registry(rows=REGISTRY_ROWS[:3]), "rev-b4 закрытая предыдущая " + stamp), marking=CONF_PD)
p2 = reg(relabel(demo_registry(previous=p1.source_id), "rev-b4 открытая следующая " + stamp))
for who in ("ac_rd_none", "ac_rd_cs", "ac_rd_full"):
    a = psql(f"SELECT ac.dataset_info('{PRJ}', '{p1.source_id}');", who); b = psql(f"SELECT ac.dataset_info('{PRJ}', '{p2.source_id}');", who); g = psql(f"SELECT ac.dataset_info('{PRJ}', 'src:sha256:{'ab' * 32}');", who)
    print(f"   {who}: закрытая версия — {first_err(a)[:40] if a.returncode else 'выдана'}; несуществующая — {first_err(g)[:40]}; открытая — " +
          (first_err(b)[:40] if b.returncode else "выдана, previous = " + str(json.loads(b.stdout).get("previous"))[:30] + "…"))
info = json.loads(psql(f"SELECT ac.dataset_info('{PRJ}', '{p2.source_id}');", "ac_rd_cs").stdout)
print("   читателю без PERSONAL_DATA через открытую версию назван адрес закрытой версии (её он читать не может):", info.get("previous") == p1.source_id)
print("   поля:", sorted(info), "| колонки с маркировкой выше допуска названы:", [c["name"] for c in info["columns"] if c["marking"]["categories"]])
print("== 4. ac.support_key: семейство — это dataset_id, который набор объявляет о себе сам")
ev = None
def claim_on(v):
    e = v.evidence([OGRN_DEV], ["address"]); return mk_claim(e)
ids = []
for i in (1, 2):
    v = demo_registry(); v.manifest["dataset_id"] = f"dst_registry_demo_copy{i}"; relabel(v, f"rev-b4 тот же реестр под другим именем {i} {stamp}"); reg(v); ids.append(v)
time.sleep(1.2)
r = db_try([claim_on(v) for v in ids], commit=True)
print("   тот же реестр (те же строки) зарегистрирован под двумя другими dataset_id, то же утверждение на каждой:", verdict(r)[:40])
print("   поддержек адреса девелопера:", psql("SELECT string_agg(val || ' -> ' || n, '; ') FROM (SELECT c.body->'object'->'literal'->>'value' AS val, count(DISTINCT ac.support_key(e.tenant_id, e.source_id, now())) AS n "
      "FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) WHERE c.subject = 'ent_k_developer' AND c.predicate = 'entity.registered_address' GROUP BY 1) x").stdout.strip())
print("   ключи поддержки:", psql("SELECT string_agg(DISTINCT ac.support_key(e.tenant_id, e.source_id, now()), ', ') FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) WHERE e.kind = 'ROW' AND c.subject = 'ent_k_developer'").stdout.strip()[:200])
other = DatasetVersion("dst_registry_demo", T, "rev-b4 ДРУГОЙ источник с тем же dataset_id " + stamp, [{"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
        {"name": "addr", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}], ["ogrn"], [{"ogrn": OGRN_DEV, "addr": REGISTRY_ROWS[0]["address"]}], subject=("ogrn",))
print("   независимый набор (другие колонки, другой производитель) с тем же dataset_id = dst_registry_demo:", verdict(db_try([source_rec(other)], commit=True))[:30],
      "— его поддержка сольётся с реестром: ключ", psql(f"SELECT ac.support_key('{T}', '{other.source_id}', now())").stdout.strip())
print("== 5. ac.claim_provenance для доказательств-строк")
print("  ", psql("SELECT count(*) || ' строк-доказательств, verified: ' || count(*) FILTER (WHERE verified) || ', пример quote: ' || left(min(quote), 90) FROM ac.claim_provenance p JOIN ac.claim_evidence e USING (claim_id, ord) WHERE e.kind = 'ROW'").stdout.strip())
print("   читатель:", L("SELECT count(*) FROM ac.claim_provenance;", "ac_rd_full"))
print("== 6. Правило конверта")
ds, tr, ct = world()
def env(desc, fn):
    d = copy.deepcopy(ds); fn(d); rep = VAL.validate(d, tr, ct); print(f"   {desc}: {py_verdict(rep)[:90]}")
env("конверт 0.3, записи 0.4 (NR1F)", lambda d: d.__setitem__("ontology_version", "core-ontology/0.3"))
def strip(d):
    d["ontology_version"] = "core-ontology/0.3"
    for r in d["records"]:
        if r.get("schema_version") == "core-ontology/0.4": r.pop("schema_version")
env("конверт 0.3, у записей 0.4 пометка schema_version снята", strip)
env("конверт core-ontology/0.2", lambda d: d.__setitem__("ontology_version", "core-ontology/0.2"))
env("конверт 0.4, запись версии набора помечена 0.3", lambda d: [r.__setitem__("schema_version", "core-ontology/0.3") for r in d["records"] if r.get("source_kind") == "DATASET_VERSION"])

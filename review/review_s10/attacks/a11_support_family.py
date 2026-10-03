#!/usr/bin/env python3
"""S10R / D27.4 «поддержка факта считается по семейству набора»: в срезе ac.support_key про наборы не знает —
N версий одного реестра дают N «независимых» поддержек и перевешивают два действительно независимых документа."""
from common import *
from s10_tests import copy_file
import time
stamp = utc(0)
W_ADDR = "г. Москва, ул. Иная, д. 5"
def doc(text):
    b = text.encode()
    return {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest(), "source_kind": "DOCUMENT",
            "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "Справка рецензента", "byte_length": len(b), "content_inline": text,
            "marking": PUB, "observations": [{"observed_at": utc(2), "origin_uri": "urn:review:s10:doc:" + hashlib.sha256(b).hexdigest()[:8], "observed_by": "svc_dataset_loader"}]}
def span_claim(d, quote, value):
    b = d["content_inline"].encode(); st = b.index(quote.encode()); en = st + len(quote.encode())
    return mk_claim({"source_id": d["source_id"], "span": {"start": st, "end": en}, "quote_sha256": hashlib.sha256(b[st:en]).hexdigest()},
                    obj={"literal": {"type": "STRING", "value": value}})
def fact():
    r = psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer');", "ac_rd_full")
    if r.returncode: return first_err(r)
    out = []
    for s in json.loads(r.stdout).get("sections", []):
        for f in s.get("facts", []):
            if "адрес" in f.get("text", "").lower() or W_ADDR in json.dumps(f, ensure_ascii=False):
                out.append(f["text"] + (" || ПРИМЕЧАНИЕ: " + f["note"] if f.get("note") else ""))
    return out
def supports():
    return psql("SELECT string_agg(val || ' -> поддержек: ' || n, '; ') FROM (SELECT c.body->'object'->'literal'->>'value' AS val, count(DISTINCT ac.support_key(e.tenant_id, e.source_id, now())) AS n "
                "FROM ac.claims c JOIN ac.claim_evidence e USING (claim_id) WHERE c.subject = 'ent_k_developer' AND c.predicate = 'entity.registered_address' GROUP BY 1) x").stdout.strip()
print("0. исходно:", fact(), "\n   ", supports())
d1 = doc(f"Справка банка от {stamp}. Юридический адрес заёмщика: {W_ADDR}. Подготовил отдел сопровождения.")
d2 = doc(f"Выписка контрагента от {stamp}. Адрес регистрации: {W_ADDR}. Сведения получены от нотариуса.")
r = db_try([d1, d2], commit=True); assert r.returncode == 0, first_err(r)
time.sleep(1.2)
r = db_try([span_claim(d1, W_ADDR, W_ADDR), span_claim(d2, W_ADDR, W_ADDR)], commit=True); print("1. два независимых документа называют другой адрес:", verdict(r))
print("  ", fact(), "\n   ", supports())
vs = []
for i in (2, 3):
    v = relabel(demo_registry(), f"rev-a11 переиздание {i} {stamp}"); r = db_try([source_rec(v)], commit=True); assert r.returncode == 0, first_err(r); vs.append(v)
time.sleep(1.2)
ev = demo_registry().evidence([OGRN_DEV], ["address"])
cl = []
for v in vs:
    e = copy.deepcopy(ev); e["source_id"] = v.source_id; cl.append(mk_claim(e))
r = db_try(cl, commit=True); print("2. тот же реестр зарегистрирован ещё двумя версиями (те же строки), то же доказательство предъявлено каждой:", verdict(r))
print("  ", fact(), "\n   ", supports())
print("   семейство одно:", psql("SELECT count(DISTINCT dataset_id) || ' набор, ' || count(*) || ' версий' FROM ac.datasets WHERE source_id IN (" + ",".join(f"'{x}'" for x in [demo_registry().source_id] + [v.source_id for v in vs]) + ")").stdout.strip())
print("   ac.claim_provenance для доказательства-строки (quote / verified):", psql("SELECT coalesce(quote, 'NULL') || ' / ' || coalesce(verified::text, 'NULL') FROM ac.claim_provenance p JOIN ac.claim_evidence e USING (claim_id, ord) WHERE e.kind = 'ROW' LIMIT 1").stdout.strip())

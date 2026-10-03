#!/usr/bin/env python3
"""S10R / манифест, «previous» и порядок прихода: источник-previous без байтов."""
from common import *
import time

def plain_source(text, kind="DOCUMENT", with_bytes=True):
    b = text.encode("utf-8")
    s = {"kind": "Source", "schema_version": "core-ontology/0.2", "tenant_id": T, "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest(),
         "source_kind": kind, "media_type": "text/plain; charset=utf-8", "language": "ru", "title": "рецензент: обычный документ",
         "byte_length": len(b), "marking": PUB,
         "observations": [{"observed_at": utc(2), "origin_uri": "urn:review:s10:doc", "observed_by": "svc_dataset_loader"}]}
    if with_bytes:
        s["content_inline"] = text
    return s

def src_sql(s, with_bytes):
    """INSERT источника загрузчиком; байты — только если with_bytes"""
    full = ingest_sql([dict(s, content_inline=s.get("content_inline", "x"))], {}, commit=True)
    if not with_bytes:
        full = "\n".join(l for l in full.splitlines() if "INSERT INTO ac.source_bytes" not in l)
    return full

print("== 1. previous называет ДОКУМЕНТ, байты которого в базу не приходят; версия пришла первой")
doc = plain_source("Документ рецензента без байтов, порядок 1. " + utc(0), with_bytes=False)
v = relabel(demo_registry(previous=doc["source_id"]), "rev-a2-1")
rep = validate_with([doc, source_rec(v)])
print("   валидатор (оба источника в наборе записей):", py_verdict(rep))
r1 = psql(src_sql(source_rec(v), True)); print("   база: версия с previous ->", verdict(r1))
r2 = psql(src_sql(doc, False)); print("   база: затем источник-документ БЕЗ байтов ->", verdict(r2))
print("   в базе теперь:", psql(f"SELECT d.version_label, d.previous = s.source_id AS previous_known, s.body->>'source_kind', "
      f"(SELECT count(*) FROM ac.source_bytes b WHERE b.source_id = s.source_id) AS bytes FROM ac.datasets d JOIN ac.sources s ON s.source_id = d.previous "
      f"WHERE d.source_id = '{v.source_id}'").stdout.strip())

print("== 2. тот же случай, обратный порядок: документ без байтов пришёл первым")
doc2 = plain_source("Документ рецензента без байтов, порядок 2. " + utc(0), with_bytes=False)
v2 = relabel(demo_registry(previous=doc2["source_id"]), "rev-a2-2")
print("   валидатор:", py_verdict(validate_with([doc2, source_rec(v2)])))
print("   база: документ без байтов ->", verdict(psql(src_sql(doc2, False))))
print("   база: затем версия с previous ->", verdict(psql(src_sql(source_rec(v2), True))))

print("== 3. previous — запись DATASET_VERSION того же набора, манифест которой в базу не пришёл; версия первой")
pv = relabel(demo_registry(rows=REGISTRY_ROWS[:3]), "rev-a2-3prev-" + utc(0))
ps = source_rec(pv); ps_nb = {k: x for k, x in ps.items() if k != "content_inline"}
v3 = relabel(demo_registry(previous=pv.source_id), "rev-a2-3")
print("   валидатор (previous без байтов):", py_verdict(validate_with([ps_nb, source_rec(v3)])))
print("   база: версия ->", verdict(psql(src_sql(source_rec(v3), True))))
print("   база: затем запись previous без байтов ->", verdict(psql(src_sql(ps, False))))

print("== 4. контроль: документ С байтами после версии — база отвергает (как заявлено S10-09)")
doc4 = plain_source("Документ рецензента с байтами. " + utc(0))
v4 = relabel(demo_registry(previous=doc4["source_id"]), "rev-a2-4")
print("   валидатор:", py_verdict(validate_with([doc4, source_rec(v4)])))
print("   база: версия ->", verdict(psql(src_sql(source_rec(v4), True))))
print("   база: затем документ с байтами ->", verdict(psql(src_sql(doc4, True))))

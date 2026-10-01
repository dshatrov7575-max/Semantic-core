"""Second reference instruction for S4 (not part of the core world): valve К-1/12 of station НС-2.
Shared by the adapter tests (adapter/tests_adapter.py) and the database tests (slice/s4_tests.py, attacks_s4.py)."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
from jcs import canon_bytes  # noqa: E402

SV = "core-ontology/0.2"
INT = {"level": "INTERNAL", "categories": []}

VALVE_TITLE = "Инструкция по эксплуатации задвижки К-1/12 насосной станции НС-2 (фрагмент)"
VALVE_TEXT = ("Задвижка К-1/12 (электропривод, модель ЗКС 80-16, изготовитель «АрмаТех») входит в состав насосной станции НС-2. "
              "Номинальное давление задвижки К-1/12 — 1,6 МПа. "
              "При утечке через сальник закрыть задвижку К-1/12 и вызвать слесаря. "
              "Задвижка установлена на напорном трубопроводе Т-3.")


def make_source(text, title, observed_at, tenant="tnt_demo", marking=INT, uri="urn:demo:valve"):
    b = text.encode("utf-8")
    return {"kind": "Source", "schema_version": SV, "tenant_id": tenant, "source_kind": "DOCUMENT",
            "media_type": "text/plain; charset=utf-8", "language": "ru", "title": title, "content_inline": text,
            "marking": marking, "observations": [{"observed_at": observed_at, "origin_uri": uri, "observed_by": "svc_techsense"}],
            "byte_length": len(b), "source_id": "src:sha256:" + hashlib.sha256(b).hexdigest()}


def anchor(text, sid, quote):
    b, qb = text.encode("utf-8"), quote.encode("utf-8")
    start = b.find(qb)
    assert start >= 0, quote
    return {"source_id": sid, "start": start, "end": start + len(qb)}


def valve_artifact(sid, run_id="run_ts_0002", version="0.9.0", station_tag="НС-2", extra_nodes=(), tweak=None):
    """-> canonical bytes of the simplified UMR graph of VALVE_TEXT"""
    A = lambda q: anchor(VALVE_TEXT, sid, q)  # noqa: E731
    art = {
        "artifact_format": "umr-artifact/0.3", "semantic_profile": "ts-semantic/0.2",
        "producer": {"service_id": "svc_techsense", "version": version}, "run_id": run_id, "inputs": [sid],
        "nodes": [
            {"id": "v1", "type": "ENTITY", "entity_type": "EQUIPMENT", "anchor": A("Задвижка К-1/12"),
             "identity": {"site_id": "site_ns2", "tag": "К-1/12", "description": "задвижка"}},
            {"id": "v2", "type": "ENTITY", "entity_type": "EQUIPMENT_MODEL", "anchor": A("модель ЗКС 80-16"),
             "identity": {"manufacturer": "АрмаТех", "model": "ЗКС 80-16"}},
            {"id": "v3", "type": "ENTITY", "entity_type": "EQUIPMENT", "anchor": A("насосной станции НС-2"),
             "identity": {"site_id": "site_ns2", "tag": station_tag, "description": "насосная станция"}},
            {"id": "v4", "type": "QUANTITY", "value": "1.6", "unit": "MPa", "anchor": A("1,6 МПа")},
            {"id": "v5", "type": "ACTION", "text": "закрыть задвижку и вызвать слесаря",
             "anchor": A("закрыть задвижку К-1/12 и вызвать слесаря")},
            {"id": "v6", "type": "CONDITION", "text": "утечка через сальник", "anchor": A("При утечке через сальник")},
            {"id": "v7", "type": "ENTITY", "entity_type": "EQUIPMENT", "anchor": A("напорном трубопроводе Т-3"),
             "identity": {"site_id": "site_ns2", "tag": "Т-3", "description": "напорный трубопровод"}},
            {"id": "r1", "type": "RELATION", "role": "instance-of", "args": ["v1", "v2"],
             "anchor": A("Задвижка К-1/12 (электропривод, модель ЗКС 80-16, изготовитель «АрмаТех»)")},
            {"id": "r2", "type": "RELATION", "role": "part-of", "args": ["v1", "v3"],
             "anchor": A("Задвижка К-1/12 (электропривод, модель ЗКС 80-16, изготовитель «АрмаТех») входит в состав насосной станции НС-2")},
            {"id": "r3", "type": "RELATION", "role": "has-parameter", "args": ["v1", "v4"], "parameter": "nominal_pressure",
             "anchor": A("Номинальное давление задвижки К-1/12 — 1,6 МПа")},
            {"id": "r4", "type": "RELATION", "role": "requires-action", "args": ["v1", "v5"], "condition": "v6",
             "anchor": A("При утечке через сальник закрыть задвижку К-1/12 и вызвать слесаря")},
            {"id": "r5", "type": "RELATION", "role": "installed-on", "args": ["v1", "v7"],
             "anchor": A("Задвижка установлена на напорном трубопроводе Т-3")},
            *extra_nodes]}
    if tweak:
        tweak(art)
    return canon_bytes(art)

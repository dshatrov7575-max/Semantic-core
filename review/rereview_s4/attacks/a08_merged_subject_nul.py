"""S4R: (1) claims on the MERGED entity itself (what the adapter would have to emit instead of the survivor);
(2) NUL inside an anchored fragment / in ACTION text (DB stricter than validator)."""
from harness import run, art
from vectors import add_entity, seq
INT = {"level": "INTERNAL", "categories": []}
merged = add_entity("ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101", "description": "насос"},
                    INT, status="MERGED", merged_into="ent_ts_pump", changed="2026-09-05T13:00:00Z")
def to_lat(W):
    W["__artifacts__"]["umr_ns2"]["nodes"][0]["identity"]["tag"] = "H-101"
    for c in ("c0", "c1", "c2", "c3"):
        W[c]["subject"] = "ent_ts_pump_lat"
run("узел 'H-101', утверждения о СЛИТОЙ ent_ts_pump_lat (после слияния)", pre=seq(merged, to_lat))
def to_lat_survivor(W):
    W["__artifacts__"]["umr_ns2"]["nodes"][0]["identity"]["tag"] = "H-101"
run("узел 'H-101', утверждения о выжившей ent_ts_pump (как делает адаптер)", pre=seq(merged, to_lat_survivor))
NUL = chr(0)
def nul_text(W):
    W["__artifacts__"]["umr_ns2"]["nodes"].append({"id": "n60", "type": "ACTION", "text": "a" + NUL + "b", "anchor": {"$anchor": ["s1", "Насос Н-101"]}})
run("ACTION-узел с U+0000 в тексте (свободный текст)", pre=nul_text)

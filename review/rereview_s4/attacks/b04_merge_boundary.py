"""Final check: merge exactly at the claims' recorded_at (2026-09-06T09:59:00Z) and one second later -- parity."""
from harness import run
from vectors import add_entity, seq
INT = {"level": "INTERNAL", "categories": []}
def node_lat(W):
    W["__artifacts__"]["umr_ns2"]["nodes"][0]["identity"]["tag"] = "H-101"
for t in ("2026-09-06T09:59:00Z", "2026-09-06T09:59:01Z"):
    m = add_entity("ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101", "description": "насос"},
                   INT, status="MERGED", merged_into="ent_ts_pump", changed=t)
    run(f"слияние 'H-101' в {t}, утверждения 09:59:00 о ent_ts_pump, узел 'H-101'", pre=seq(m, node_lat))

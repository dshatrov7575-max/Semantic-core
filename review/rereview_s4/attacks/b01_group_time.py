"""S4R-11 candidate: the merge group is taken from the FINAL state, not at the claim's recorded_at.
Claims c0..c3 are recorded 2026-09-06T09:59; the alias is merged LATER (2026-09-07)."""
from harness import run
from vectors import add_entity, seq
INT = {"level": "INTERNAL", "categories": []}
late = add_entity("ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101", "description": "насос"},
                  INT, status="MERGED", merged_into="ent_ts_pump", changed="2026-09-07T00:00:00Z")
def node_lat(W):
    W["__artifacts__"]["umr_ns2"]["nodes"][0]["identity"]["tag"] = "H-101"
run("слияние ПОСЛЕ записи: утверждения о ent_ts_pump, узел называет 'H-101' (ещё отдельная сущность на момент записи)", pre=seq(late, node_lat))
def subj_alias(W):
    for c in ("c0", "c1", "c2", "c3"):
        W[c]["subject"] = "ent_ts_pump_lat"
run("слияние ПОСЛЕ записи: утверждения о ent_ts_pump_lat ('H-101'), узел называет 'Н-101' (другая сущность на момент записи)", pre=seq(late, subj_alias))
# control: no merge at all -> must be rejected
alone = add_entity("ent_ts_pump_lat", "prj_ts_pumps", "EQUIPMENT", {"site_id": "site_ns2", "tag": "H-101", "description": "насос"}, INT)
run("контроль: 'H-101' не слит, узел 'H-101', утверждения о ent_ts_pump", pre=seq(alone, node_lat))

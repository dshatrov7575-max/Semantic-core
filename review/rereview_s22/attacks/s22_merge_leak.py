#!/usr/bin/env python3
"""S22-01: projections name entities through ac.ent_name(), which follows merged_into to the survivor WITHOUT
checking the survivor's marking; merges do not re-check that claim markings dominate the survivor.
Live role ac_loader merges a CS-marked plot into a RESTRICTED+PD plot; readers then see the RESTRICTED name.
S22-02: the same merge changes the report of a CLOSED Check (chk_full_1) retroactively (text + digest)."""
from common import reload, ok, err, js, verdict

reload()
CLAIM = "clm:sha256:b7eb45057e47ac116f0cdc06e7146268e9795a0868fb0fd442ced23f5b5262bc"  # developer prop.owns ent_k_land
SECRET = "СЕКРЕТНО: дача Ломова А.С., пос. Жуковка"

before_rep = js("SELECT ac.check_report('chk_full_1');", "ac_rd_full")
before_dos = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_cs")
print("cs-reader dossier before:", [f["text"] for s in before_dos["sections"] for f in s.get("facts", []) if "владеет" in f["text"]])

ok(f"""BEGIN;
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, created_at, marking, display_name)
VALUES ('ent_k_secret_plot', 'prj_compliance', 'REAL_ESTATE', '{{"cadastral_number": "50:12:0101001:999"}}', 'ACTIVE', now(),
        '{{"level": "RESTRICTED", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}}', '{SECRET}');
UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_k_secret_plot' WHERE entity_id = 'ent_k_land';
COMMIT;""", "ac_loader")
print("ac_loader: merge ent_k_land (CONFIDENTIAL/CS) -> ent_k_secret_plot (RESTRICTED/PD+CS) COMMIT")

dos = js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_cs")
txt = [f["text"] for s in dos["sections"] for f in s.get("facts", []) if "владеет" in f["text"]]
print("cs-reader (CONFIDENTIAL, {COMMERCIAL_SECRET}) dossier after:", txt)
prov = js(f"SELECT ac.provenance('{CLAIM}');", "ac_rd_cs")
print("cs-reader provenance text:", prov["text"])
rep = js("SELECT ac.check_report('chk_full_1');", "ac_rd_full")
rtxt = [f["text"] for d in rep["dimensions"] for f in d.get("facts", []) if "владеет" in f["text"]]
print("full-reader (CONFIDENTIAL) report chk_full_1:", rtxt)
print("direct dossier of the survivor for cs-reader:", err("SELECT ac.dossier('prj_compliance', 'ent_k_secret_plot');", "ac_rd_cs"))
verdict("S22-01", any(SECRET in t for t in txt) or SECRET in prov["text"] or any(SECRET in t for t in rtxt),
        "имя сущности уровня RESTRICTED/PERSONAL_DATA попало в досье/провенанс/отчёт читателей CONFIDENTIAL без ПД")
print("chk_full_1 digest before:", before_rep["digest"])
print("chk_full_1 digest after: ", rep["digest"], "| status", rep["status"], "completed_at", rep["completed_at"])
verdict("S22-02", before_rep["digest"] != rep["digest"],
        "отчёт ЗАКРЫТОЙ Проверки chk_full_1 изменился после слияния, выполненного после её завершения")

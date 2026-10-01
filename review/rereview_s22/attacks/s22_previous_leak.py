#!/usr/bin/env python3
"""S22-03: check_report() prints the previous Check (check_id, as_of, overall_risk, profile) without checking the
reader's clearance against the previous Check's marking; checks_guard does not require the new Check's marking to
dominate the previous one. A reader without PERSONAL_DATA learns the result of a PD-marked Check it cannot open."""
from common import reload, ok, err, js, verdict

reload()
print("cs-reader opens chk_full_1 directly:", err("SELECT ac.check_report('chk_full_1');", "ac_rd_cs"))
body = ('{"check_id": "chk_cs_only", "project_id": "prj_compliance", "subject_entity_id": "ent_k_developer", '
        '"status": "IN_PROGRESS", "marking": {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}}')
ok(f"""BEGIN;
INSERT INTO ac.checks VALUES ('chk_cs_only', 'prj_compliance', 'ent_k_developer', 'TENDERS_ONLY', 'IN_PROGRESS', now(), NULL, NULL,
  current_date, NULL, 'chk_full_1', '{{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}}', '{body}');
COMMIT;""", "ac_loader")
rep = js("SELECT ac.check_report('chk_cs_only');", "ac_rd_cs")
print("cs-reader report chk_cs_only.previous:", rep.get("previous"))
verdict("S22-03", bool(rep.get("previous")) and rep["previous"].get("overall_risk") is not None,
        "читатель без PERSONAL_DATA видит итог (overall_risk/профиль/дату) закрытой для него Проверки chk_full_1")

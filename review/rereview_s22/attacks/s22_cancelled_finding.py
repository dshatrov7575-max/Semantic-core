#!/usr/bin/env python3
"""S22-04: check_findings has no CHECK_CLOSED guard. After a Check is CANCELLED, ac_loader still inserts a
NOT_FOUND finding; the closed Check's report changes and shows «Не выявлено.» with NO search trace."""
from common import reload, ok, err, js, verdict

reload()
M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
ok(f"""BEGIN;
INSERT INTO ac.checks VALUES ('chk_express_2', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'IN_PROGRESS', now(), NULL, NULL,
  current_date, NULL, NULL, '{M}', jsonb_build_object('check_id', 'chk_express_2', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));
COMMIT;""", "ac_loader")
ok("""BEGIN;
UPDATE ac.checks SET status = 'CANCELLED', body = jsonb_set(body, '{status}', '"CANCELLED"') WHERE check_id = 'chk_express_2';
COMMIT;""", "ac_loader")
before = js("SELECT ac.check_report('chk_express_2');", "ac_rd_full")
print("after cancel:", before["status"], before.get("cancelled_at"), [(d["dimension"], d.get("result"), d.get("text")) for d in before["dimensions"]])
r = err("""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_express_2', 'NEGATIVE', 'NOT_FOUND', 'NONE');
COMMIT;""", "ac_loader")
print("ac_loader inserts finding into CANCELLED Check:", r)
after = js("SELECT ac.check_report('chk_express_2');", "ac_rd_full")
dims = [(d["dimension"], d.get("result"), d.get("text"), d.get("searches")) for d in after["dimensions"]]
print("report after:", dims)
bad = [d for d in after["dimensions"] if d.get("text") == "Не выявлено." and not d.get("searches")]
verdict("S22-04", before["digest"] != after["digest"] and bool(bad),
        "в отменённую (закрытую) Проверку дописан итог; отчёт изменён, «Не выявлено.» без следа поиска")

# open Check: the same «Не выявлено.» without a search trace (draft)
ok("""BEGIN; INSERT INTO ac.check_findings VALUES ('chk_tenders_1', 'TENDERS', 'NOT_FOUND', 'NONE'); COMMIT;""", "ac_loader")
op = js("SELECT ac.check_report('chk_tenders_1');", "ac_rd_full")
bad2 = [d for d in op["dimensions"] if d.get("text") == "Не выявлено." and not d.get("searches")]
verdict("S22-04b", bool(bad2), "открытая Проверка: «Не выявлено.» в проекции без следа поиска (черновик не помечен)")

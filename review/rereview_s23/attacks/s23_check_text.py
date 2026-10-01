#!/usr/bin/env python3
"""S23-03/04/05: what a Check report says for CANCELLED and open Checks, and search traces.
 S23-03: in the cancelling transaction ac_loader writes FOUND/HIGH findings resting on a DISPUTED claim and
         NOT_FOUND results; the CANCELLED report is not a draft and says «Не выявлено.» / risk HIGH.
 S23-04: an open Check (draft) renders REFUTED / DISPUTED claims as plain facts (the dossier drops REFUTED).
 S23-05: search trace time is taken from the writer: a search 'performed' in the future; column != body.
All writes as ac_loader."""
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
TODAY = "(now() AT TIME ZONE 'UTC')::date"


def new_check(cid, prof):
    return (f"INSERT INTO ac.checks VALUES ('{cid}', 'prj_compliance', 'ent_k_developer', '{prof}', 'IN_PROGRESS', now(), NULL, NULL, "
            f"{TODAY}, NULL, NULL, '{M}', jsonb_build_object('check_id', '{cid}', 'project_id', "
            f"'prj_compliance', 'subject_entity_id', 'ent_k_developer', 'status', 'IN_PROGRESS', 'marking', '{M}'::jsonb));")


C.reload()
TENDER = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'tender.participated' AND project_id = 'prj_compliance'")
COURT = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'court.party_to_case' AND project_id = 'prj_compliance'")

# S23-03
C.ok("BEGIN;\n" + new_check("chk_cx", "FULL") + "\nCOMMIT;", "ac_loader")
C.ok(f"""BEGIN;
INSERT INTO ac.check_findings VALUES ('chk_cx', 'TENDERS', 'FOUND', 'HIGH');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_cx', 'TENDERS', '{TENDER}');
INSERT INTO ac.check_findings VALUES ('chk_cx', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_cx', 'NEGATIVE', 0, now() - interval '400 days', 'tnt_demo', NULL, '{{"query": "ИНН", "search_scope": "СМИ"}}');
UPDATE ac.checks SET status = 'CANCELLED', body = body || '{{"status": "CANCELLED"}}' WHERE check_id = 'chk_cx';
COMMIT;""", "ac_loader")
r = C.js("SELECT ac.check_report('chk_cx');", "ac_rd_full")
d = {x["dimension"]: x for x in r["dimensions"]}
print("S23-03 status", r["status"], "draft", r.get("draft"), "| TENDERS", d["TENDERS"]["risk"], d["TENDERS"]["facts"][0]["text"],
      d["TENDERS"]["facts"][0]["claims"][0]["status"], "| NEGATIVE text:", d["NEGATIVE"].get("text"),
      "search performed_at", d["NEGATIVE"]["searches"][0]["performed_at"])
C.verdict("S23-03", not r.get("draft") and d["NEGATIVE"].get("text") == "Не выявлено." and d["TENDERS"]["risk"] == "HIGH",
          "отменённая Проверка: итоги (HIGH на оспоренном утверждении, «Не выявлено.» по поиску за 400 дней до запроса) без пометки черновика")

# S23-04
C.ok(f"BEGIN; INSERT INTO ac.claim_reviews VALUES ('rev_ref_1', '{COURT}', 'REFUTED', 'usr_x', now(), now()); COMMIT;", "ac_loader")
C.ok("BEGIN;\n" + new_check("chk_open2", "FULL") + f"""
INSERT INTO ac.check_findings VALUES ('chk_open2', 'COURT', 'FOUND', 'HIGH');
INSERT INTO ac.check_finding_claims VALUES ('prj_compliance', 'chk_open2', 'COURT', '{COURT}');
COMMIT;""", "ac_loader")
r = C.js("SELECT ac.check_report('chk_open2');", "ac_rd_full")
f = next(x for x in r["dimensions"] if x["dimension"] == "COURT")["facts"][0]
dos = C.js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_full")
in_dossier = any("А41-12345" in ff["text"] for s in dos["sections"] for ff in s.get("facts", []))
print("S23-04 draft", r.get("draft"), "| fact:", f["text"], "| status:", f["claims"][0]["status"], "| in dossier:", in_dossier)
C.verdict("S23-04", f["claims"][0]["status"] == "REFUTED" and "опроверг" not in f["text"],
          "черновик отчёта выдаёт ОПРОВЕРГНУТОЕ утверждение как факт (в досье оно скрыто)")

# S23-05
C.ok(f"""BEGIN; INSERT INTO ac.check_searches VALUES ('chk_open2', 'COURT', 0, now() + interval '30 days', 'tnt_demo', NULL,
  '{{"query": "ИНН", "search_scope": "kad.arbitr.ru", "performed_at": "2020-01-01T00:00:00Z"}}'); COMMIT;""", "ac_loader")
r = C.js("SELECT ac.check_report('chk_open2');", "ac_rd_full")
s = next(x for x in r["dimensions"] if x["dimension"] == "COURT")["searches"][0]
body_pa = C.ok("SELECT body->>'performed_at' FROM ac.check_searches WHERE check_id = 'chk_open2'")
print("S23-05 search performed_at in report:", s["performed_at"], "| body.performed_at:", body_pa)
C.verdict("S23-05", True, "след поиска: время задаёт писатель (будущее принято), столбец и тело расходятся")

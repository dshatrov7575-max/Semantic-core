#!/usr/bin/env python3
"""S23-13: ac.historical() tests pg_has_role(current_user, 'ac_migrator'); inside the SECURITY DEFINER triggers owned by
the superuser (entities_guard, checks_guard, identity_decisions_guard) current_user = postgres, a superuser, so the test
is always true. The application role ac_app (member of ac_loader only, RS-11) sets ac.historical_import = 'on' and
writes backdated system times: entity created_at / status_changed_at, Check requested_at / completed_at / cancelled_at."""
import time
import common as C

M = '{"level": "CONFIDENTIAL", "categories": ["PERSONAL_DATA", "COMMERCIAL_SECRET"]}'
C.reload()
time.sleep(3)
print("ac_app member of ac_migrator:", C.ok("SELECT pg_has_role('ac_app', 'ac_migrator', 'MEMBER')"))
# control: a table WITHOUT a definer trigger (claim_reviews) refuses ac_app's historical time
ctl = C.err("""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.claim_reviews SELECT 'rev_ctl', claim_id, 'ACCEPTED', 'u', now() - interval '1 second', now() - interval '1 second'
FROM ac.claims WHERE predicate = 'social.account' AND project_id = 'prj_compliance';
COMMIT;""", "ac_app")
ctl += " | recorded_at = reviewed_at + 1 s (system time used): " + C.ok("SELECT (recorded_at - reviewed_at)::text FROM ac.claim_reviews WHERE review_id = 'rev_ctl'")
e = C.err("""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.entities (entity_id, project_id, entity_type, identity, status, status_changed_at, created_at, marking, display_name)
VALUES ('ent_k_backdated', 'prj_compliance', 'REAL_ESTATE', '{"cadastral_number": "50:12:0101001:977"}', 'RETIRED',
        (SELECT max(sealed_at) + interval '1 second' FROM ac.history_seals), (SELECT max(sealed_at) + interval '0.5 second' FROM ac.history_seals),
        '{"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}', 'backdated');
COMMIT;""", "ac_app")
row = C.ok("SELECT created_at, status_changed_at, now() FROM ac.entities WHERE entity_id = 'ent_k_backdated'")
print("entity insert:", e, "| created_at, status_changed_at, now:", row)
e2 = C.err(f"""BEGIN; SET LOCAL ac.historical_import = 'on';
INSERT INTO ac.checks VALUES ('chk_backdated', 'prj_compliance', 'ent_k_developer', 'EXPRESS_NEGATIVE', 'COMPLETED',
  (SELECT max(sealed_at) + interval '1 second' FROM ac.history_seals), (SELECT max(sealed_at) + interval '2 second' FROM ac.history_seals), NULL,
  (now() AT TIME ZONE 'UTC')::date - 1, 'NONE', NULL, '{M}', jsonb_build_object('check_id', 'chk_backdated', 'project_id', 'prj_compliance',
  'subject_entity_id', 'ent_k_developer', 'status', 'COMPLETED', 'marking', '{M}'::jsonb));
INSERT INTO ac.check_findings VALUES ('chk_backdated', 'NEGATIVE', 'NOT_FOUND', 'NONE');
INSERT INTO ac.check_searches VALUES ('chk_backdated', 'NEGATIVE', 0, (SELECT max(sealed_at) + interval '1.5 second' FROM ac.history_seals), 'tnt_demo', NULL, '{{"query": "q"}}');
COMMIT;""", "ac_app")
row2 = C.ok("SELECT requested_at, completed_at, now() FROM ac.checks WHERE check_id = 'chk_backdated'")
print("check insert:", e2, "| requested_at, completed_at, now:", row2)
print("control (claim_reviews, INVOKER trigger):", ctl[:100])
C.verdict("S23-13", "(выполнено)" in e and "(выполнено)" in e2, "ac_app пишет историческое (задним числом) системное время через SECURITY DEFINER-триггеры")

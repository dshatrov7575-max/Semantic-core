#!/usr/bin/env python3
"""Сколько вызовов функций базы приходится на одно доказательство-строку в досье (pg_stat_xact_user_functions).
Usage: PGDATABASE=review11_m python3 a44_profile.py   (после a43_currency_cost.py)"""
from rv import *
cid = one("SELECT c.claim_id FROM ac.claims c WHERE c.subject = 'ent_r_m1' ORDER BY recorded_at DESC LIMIT 1")
Q = ("SELECT string_agg(funcname || '×' || calls || ' (' || round(total_time::numeric, 1) || ' мс)', ', ' ORDER BY total_time DESC) "
     "FROM pg_stat_xact_user_functions WHERE schemaname = 'ac'")
for label, sql in (("один ac.evidence_json", f"SELECT length(ac.evidence_json('{cid}', now())::text)"),
                   ("одно досье (у сущности одно утверждение на строке)", f"SET LOCAL SESSION AUTHORIZATION ac_rd_measure;\nSELECT length(ac.dossier('{PRJ}', 'ent_r_m1')::text);\nRESET SESSION AUTHORIZATION")):
    r = psql(f"SET track_functions = 'all';\nBEGIN;\n{sql};\n{Q};\nCOMMIT;")
    print(f"{label}:\n   ", r.stdout.strip().splitlines()[-1] if r.returncode == 0 else first_err(r))

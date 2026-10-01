#!/usr/bin/env python3
"""S23-06: existence / project oracle through error texts of check_report and provenance.
A reader with NO clearance for prj_compliance tells an existing Check / claim from a non-existent one and learns
its project_id. Also: what a reader with a partial clearance gets (sanity of the filters)."""
import common as C

C.reload()
cid = C.ok("SELECT claim_id FROM ac.claims WHERE predicate = 'media.negative_mention' AND project_id = 'prj_compliance'")
fake_c = "clm:sha256:" + "0" * 64
for who in ("ac_rd_public", "ac_rd_none"):
    a = C.err("SELECT ac.check_report('chk_full_1');", who)
    b = C.err("SELECT ac.check_report('chk_does_not_exist');", who)
    c = C.err(f"SELECT ac.provenance('{cid}');", who)
    d = C.err(f"SELECT ac.provenance('{fake_c}');", who)
    print(who, "| existing Check:", a, "\n   | missing Check:", b, "\n   | existing claim:", c, "\n   | missing claim:", d)
    C.verdict("S23-06/" + who, a != b or c != d, "ответ отличает существующую Проверку/утверждение от несуществующего и называет проект")

# dossier: existing entity of a project the reader has no clearance for vs a missing one (expected: identical)
a = C.err("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_public")
b = C.err("SELECT ac.dossier('prj_compliance', 'ent_k_nothing');", "ac_rd_public")
C.verdict("S23-06/dossier", a != b, "досье: существующая vs несуществующая сущность: " + a)

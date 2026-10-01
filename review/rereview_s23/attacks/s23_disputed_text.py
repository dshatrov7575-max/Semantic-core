#!/usr/bin/env python3
"""S23-12: text of projections. (a) the dossier states a DISPUTED claim as a plain fact (only alternative values get
«(сведения оспорены)»); (b) the rendered report of an open Check carries no draft marker and prints «— —»."""
import json, os, subprocess, sys
import common as C

C.reload()
d = C.js("SELECT ac.dossier('prj_compliance', 'ent_k_developer');", "ac_rd_full")
f = [x for s in d["sections"] for x in s.get("facts", []) if any(c["status"] == "DISPUTED" for c in x["claims"])]
print("dossier fact with DISPUTED claim:", [(x["text"], [c["status"] for c in x["claims"]], x.get("note")) for x in f])
C.verdict("S23-12a", any("оспор" not in x["text"] and not x.get("note") for x in f), "оспоренное утверждение подано в досье как факт")
out = subprocess.run([sys.executable, os.path.join(os.environ["SLICE"], "render_s3.py"), "report", "chk_tenders_1"],
                     capture_output=True, text=True).stdout
print(out[:400])
C.verdict("S23-12b", "черновик" not in out.lower() and "— —" in out, "текст открытой Проверки: нет пометки «черновик», «риск — —», «Поиск: .»")

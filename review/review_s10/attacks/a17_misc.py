#!/usr/bin/env python3
"""S10R / мелочи: (1) набор без subject — чужая строка в досье с verified = true; (2) ac.claim_provenance не видит доказательств-строк;
(3) README ядра не обновлён; (4) шаблон predicate манифеста против идентификаторов предикатов реестра."""
from common import *
import re, time
ADDR_TRUB = REGISTRY_ROWS[1]["address"]
dv0 = relabel(demo_registry(subject=()), "rev-a17 без subject " + utc(0))
r = db_try([source_rec(dv0, title="Реестр без объявленного субъекта строки (рецензент)")], commit=True); assert r.returncode == 0, first_err(r)
time.sleep(1.2)
c = mk_claim(dv0.evidence([OGRN_TRUB], ["address"]), obj={"literal": {"type": "STRING", "value": ADDR_TRUB}})
r = db_try([c], commit=True); print("1. адрес «Трубопроводстроя» (строка с ОГРН", OGRN_TRUB + ") записан как адрес девелопера:", verdict(r))
d = json.loads(psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer');", "ac_rd_full").stdout)
for s in d.get("sections", []):
    for f in s.get("facts", []):
        for cl in f.get("claims", []) + f.get("other_claims", []):
            for e in cl["evidence"]:
                if e.get("source_id") == dv0.source_id:
                    print("   в досье девелопера: verified =", e["verified"], "| row_key =", e["row_key"], "| ячейки:", json.dumps(e["cells"], ensure_ascii=False))
print("2. ac.claim_provenance:", psql("SELECT (SELECT count(*) FROM ac.claim_evidence) || ' доказательств в базе, из них строк ' || (SELECT count(*) FROM ac.claim_evidence WHERE kind = 'ROW') "
      "|| '; в представлении провенанса ' || (SELECT count(*) FROM ac.claim_provenance) || ', из них о строках ' || (SELECT count(*) FROM ac.claim_provenance p JOIN ac.claim_evidence e USING (claim_id, ord) WHERE e.kind = 'ROW')").stdout.strip())
rd = (SNAP / "core" / "README.md").read_text(encoding="utf-8")
import vectors, mutants
print("3. README ядра: заголовок —", rd.splitlines()[0], "| о векторах:", re.search(r"\| `vectors.py` \| ([^|]*)", rd).group(1)[:60], "| о мутантах:", re.search(r"\| `mutants.py` \| ([^|]*)", rd).group(1)[:60])
print("   на деле: векторов", len(vectors.VECTORS), ", мутантов", len(mutants.M), ", слов «набор данных»/DATASET/ROW в README:", sum(rd.count(w) for w in ("DATASET_VERSION", "ROW", "dataset.py", "манифест")))
print("   fixtures.demo_registry: docstring —", repr(__import__("fixtures").demo_registry.__doc__[:90]), "; код выводит секрет из ВСЕХ значений строки (json.dumps(vals))")
pat = re.compile(r"^[a-z]+\.[a-z_]+\Z")
ids = [p["id"] for p in VAL.PREDICATES["predicates"]]
print("4. предикатов реестра:", len(ids), "; не проходят шаблон predicate манифеста:", [i for i in ids if not pat.match(i)] or "нет",
      "| типы литералов реестра без типа колонки (не могут опираться на строку):", sorted({t for p in VAL.PREDICATES["predicates"] for t in p["range"].get("literal", [])} - {"STRING", "INTEGER", "BOOLEAN", "DATE", "IDENTIFIER"}))

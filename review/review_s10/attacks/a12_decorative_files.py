#!/usr/bin/env python3
"""S10R / правило 3 (декоративное поле): files[].object и files[].byte_length манифеста не читает ни одно правило.
Манифест с адресами файлов, которых нет нигде, и с произвольной длиной принимается валидатором и базой; утверждение на строке — тоже."""
from common import *
dv = demo_registry()
m = copy.deepcopy(dv.manifest); m["version_label"] = "rev-a12 " + utc(0)
for i, f in enumerate(m["files"]):
    f["object"] = "sha256:" + ("%02x" % (0xde + i)) * 32; f["byte_length"] = 1
class X: pass
x = X(); x.manifest = m; x.manifest_bytes = canon(m).encode(); x.source_id = "src:sha256:" + hashlib.sha256(x.manifest_bytes).hexdigest()
ev = dv.evidence([OGRN_DEV], ["address"]); ev["source_id"] = x.source_id
print("адреса файлов в манифесте:", [f["object"][:20] + "…" for f in m["files"]], "длины:", [f["byte_length"] for f in m["files"]])
both("D1", "манифест с несуществующими адресами файлов и длиной 1 + утверждение на «строке» такой версии", [source_rec(x), mk_claim(ev)], expect="refuse")
import validator, inspect
src = inspect.getsource(validator)
seg = src[src.index("def parse_manifest"):src.index("# ---------- schema as data")]
print("упоминаний в правилах валидатора (parse_manifest … row_evidence_error): object =", seg.count('"object"'), ", byte_length =", seg.count('"byte_length"'))
ddl = (SNAP / "slice" / "ddl_s10.sql").read_text()
body = ddl[ddl.index("CREATE FUNCTION ac.row_evidence_error"):]
print("упоминаний в ddl_s10.sql после проверки формы манифеста: object =", body.count("'object'"), ", byte_length =", body.count("'byte_length'"))
print("есть ли в базе версии s30 её файлы строк как объекты хранилища:", psql("SELECT count(*) FROM ac.originals o WHERE o.object IN (SELECT f->>'object' FROM ac.datasets d, jsonb_array_elements(d.manifest->'files') f)").stdout.strip() or "таблицы ac.originals нет / 0")

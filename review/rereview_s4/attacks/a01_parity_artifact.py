"""S4R parity attacks on artifact parsing and graph_says: validator vs database on the same input."""
import copy
from harness import run, art
TAB = chr(9)

def node(a, nid):
    return next(n for n in a["nodes"] if n["id"] == nid)

run("baseline")
# 1. control character in a structural field of an ENTITY node (description) -- validator prescan rejects
run("TAB в description узла n1", pre=art(lambda a: node(a, "n1")["identity"].__setitem__("description", "насос" + TAB + "x")))
# 1b. control character in the TAG itself; strong key may still equal Н-101
run("TAB в теге узла n1 ('Н-101'+TAB)", pre=art(lambda a: node(a, "n1")["identity"].__setitem__("tag", "Н-101" + TAB)))
run("TAB внутри тега ('Н'+TAB+'101')", pre=art(lambda a: node(a, "n1")["identity"].__setitem__("tag", "Н" + TAB + "101")))
# 2. NonEmpty maxLength 2000 for ACTION text of an unused node
run("ACTION-узел с текстом 2001 символ", pre=art(lambda a: a["nodes"].append(
    {"id": "n50", "type": "ACTION", "text": "я" * 2001, "anchor": {"$anchor": ["s1", "Насос Н-101"]}})))
run("description узла 2001 символ", pre=art(lambda a: node(a, "n1")["identity"].__setitem__("description", "я" * 2001)))
# 3. literal variants (both should reject)
run("QUANTITY 16.0 вместо 16", pre=lambda W: W["c2"]["object"]["literal"].__setitem__("value", "16.0"))
run("STRING с lang", pre=lambda W: W["c3"]["object"]["literal"].__setitem__("lang", "ru"))
# 4. tag spelling variants in the node (strong key derivation on NODE identities, SQL vs Python)
for t in ["н-101", "Н101", "Н 101", "H-101", "Н‐101", "Н-１０１", "Н" + chr(0xA0) + "101", "Н-1О1", "Н-101" + chr(0x301), "Н–101", "Н/101", "Н_101", "Н.101", " Н-101"]:
    run(f"тег узла {t!r}", pre=art(lambda a, t=t: node(a, "n1")["identity"].__setitem__("tag", t)))
# 5. model spelling variants
for m in ["HM 16-100", "НМ16-100", "НМ 16–100", "нм 16-100", "НМ 16-1ОО", "НМ 16-100" + chr(0x301)]:
    run(f"модель узла {m!r}", pre=art(lambda a, m=m: node(a, "n2")["identity"].__setitem__("model", m)))
run("изготовитель 'HacocMaш' (латиница)", pre=art(lambda a: node(a, "n2")["identity"].__setitem__("manufacturer", "HacocMaш")))

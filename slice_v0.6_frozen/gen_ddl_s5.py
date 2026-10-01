#!/usr/bin/env python3
"""Generates ddl_s5.sql from ddl_s5.src.sql: the whitespace class of ac.pub_norm is taken from validator._PUB_WS."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "core"))
import validator as VAL  # noqa: E402
import unicodedata as _ud  # noqa: E402
assert _ud.unidata_version == VAL.UNICODE_VERSION, "generate only with the validator's pinned Unicode version"

BS = chr(92)
cls = "[" + "".join(f"{BS}u{ord(c):04X}" for c in sorted(VAL._PUB_WS)) + "]+"
import unicodedata  # noqa: E402

# code points unassigned (Cn) in the validator's Unicode version, as ranges; surrogates are not text
cn, start = [], None
for cp in range(0x110000 + 1):
    is_cn = cp < 0x110000 and not (0xD800 <= cp <= 0xDFFF) and unicodedata.category(chr(cp)) == "Cn"
    if is_cn and start is None:
        start = cp
    elif not is_cn and start is not None:
        cn.append((start, cp - 1))
        start = None


def esc(cp):
    return f"{BS}u{cp:04X}" if cp <= 0xFFFF else f"{BS}U{cp:08X}"


cn_cls = "[" + "".join(esc(a) if a == b else f"{esc(a)}-{esc(b)}" for a, b in cn) + "]"
src = (HERE / "ddl_s5.src.sql").read_text(encoding="utf-8")
assert src.count("@@WS@@") == 1 and src.count("@@CN@@") == 1
(HERE / "ddl_s5.sql").write_text(src.replace("@@WS@@", cls).replace("@@CN@@", cn_cls), encoding="utf-8")
print("ddl_s5.sql:", len(cls), "chars in the whitespace class;", len(cn), f"unassigned ranges (Unicode {unicodedata.unidata_version})")

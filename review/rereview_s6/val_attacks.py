#!/usr/bin/env python3
"""S6 review: validator attacks on the ORIGINAL rule (0.2.6). Read-only on core/."""
import copy, hashlib, sys
sys.path.insert(0, "/home/claude/as/core")
import validator as VAL
from vectors import build

ds0, trust, content0 = build()
base = VAL.validate(ds0, trust, content0)
print("base world errors:", base.codes())

def world():
    return copy.deepcopy(ds0), dict(content0)

def src_with_original(ds):
    for r in ds["records"]:
        if r["kind"] == "Source":
            for o in r["observations"]:
                if "original" in o:
                    return r, o
def run(name, mut):
    ds, content = world()
    s, o = src_with_original(ds)
    try:
        mut(ds, content, s, o)
        rep = VAL.validate(ds, trust, content)
        print(f"{name:<34} -> errors={sorted(set(rep.codes()))}")
    except Exception as e:
        print(f"{name:<34} -> EXCEPTION {type(e).__name__}: {e}")

def setv(k, v):
    return lambda ds, c, s, o: o["original"].__setitem__(k, v)

run("V01 media_type trailing \\n", setv("media_type", "text/html\n"))
run("V02 media_type upper", setv("media_type", "Text/HTML"))
run("V03 media_type 2 spaces charset", setv("media_type", "text/html;  charset=utf-8"))
run("V04 byte_length True", lambda ds, c, s, o: (c.__setitem__("sha256:" + hashlib.sha256(b"x").hexdigest(), b"x"),
                                              o["original"].update(object="sha256:" + hashlib.sha256(b"x").hexdigest(), byte_length=True)))
L = len(content0[src_with_original(ds0)[1]["original"]["object"]])
run("V05 byte_length float n.0", setv("byte_length", float(L)))
run("V06 byte_length 2**63", setv("byte_length", 2 ** 63))
run("V07 object is list", setv("object", ["x"]))
run("V08 original is string", lambda ds, c, s, o: o.__setitem__("original", "sha256:" + "0" * 64))
run("V09 content value is str", lambda ds, c, s, o: c.__setitem__(o["original"]["object"], "text"))
run("V10 content missing", lambda ds, c, s, o: c.pop(o["original"]["object"]))
run("V11 content 1 byte flipped", lambda ds, c, s, o: c.__setitem__(o["original"]["object"], c[o["original"]["object"]][:-1] + b"?"))
run("V12 extra key in original", setv("stored_at", "2026-01-01T00:00:00Z"))

# V13 tenant confusion: `content` has no tenant dimension. A source of ANOTHER tenant names the object that was
# stored only for tnt_demo. The validator accepts; the database (registry is per tenant) refuses.
def other_tenant(ds, c, s, o):
    tenants = sorted({r["tenant_id"] for r in ds["records"] if r["kind"] == "Source"})
    print("   tenants in the world:", tenants)
    for r in ds["records"]:
        if r["kind"] == "Source" and r["tenant_id"] != s["tenant_id"]:
            r["observations"][0]["original"] = dict(o["original"])
            print("   attached original of", s["tenant_id"], "to a source of", r["tenant_id"])
            return
    print("   (no second tenant in the reference world)")
run("V13 cross-tenant original", other_tenant)

# V14 the same object under two different media types and under a source it has nothing to do with
def unrelated(ds, c, s, o):
    for r in ds["records"]:
        if r["kind"] == "Source" and r is not s:
            r["observations"][0]["original"] = dict(o["original"], media_type="application/pdf")
            return
run("V14 unrelated source, other type", unrelated)

# V15 original that IS the text bytes / an artifact (address spaces overlap in `content`)
def alias(ds, c, s, o):
    k = next(k for k in c if k.startswith("sha256:") and k != o["original"]["object"]) if any(
        k.startswith("sha256:") and k != o["original"]["object"] for k in c) else None
    print("   other sha256: keys in content:", [x[:20] for x in c if x.startswith("sha256:")][:5], "| key kinds:", sorted({x.split(":")[0] for x in c}))
    if k:
        o["original"].update(object=k, byte_length=len(c[k]))
run("V15 alias artifact as original", alias)

# V13b: build a second tenant by copying the source with the original under tnt_zz (content is NOT per tenant)
def second_tenant(ds, c, s, o):
    t = copy.deepcopy(s); t["tenant_id"] = "tnt_zz"
    ds["records"].append(t)
run("V13b same source+original in tnt_zz", second_tenant)

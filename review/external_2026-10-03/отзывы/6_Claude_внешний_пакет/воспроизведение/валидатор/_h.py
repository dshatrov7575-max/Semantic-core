"""Harness: build the reference world, mutate it, validate. Used by every finding script."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core"))
import validator as VAL
from fixtures import world, finalize
import fixtures as FX
import vectors as VX

def run(pre=None, post=None, show=True, label=""):
    W = world()
    if pre:
        pre(W)
    ds, ix, trust, content = finalize(W)
    env = {"trust": trust, "content": content}
    if post:
        post(ds, ix, env)
    R = VAL.validate(ds, env["trust"], env["content"])
    if show:
        print(f"[{label}] errors={[(e['code'], e['ref'][:40], e['msg'][:110]) for e in R.errors]}")
        print(f"[{label}] warnings={[(w['code'], w['msg'][:90]) for w in R.warnings]}")
    return R, ds, ix

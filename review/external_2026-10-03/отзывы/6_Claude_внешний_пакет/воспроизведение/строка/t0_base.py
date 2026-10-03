from _h import *
R, ds, ix, content = run()
show("базовый мир", R)
c50 = ds["records"][ix["c50"]]
print(json.dumps(c50["evidence"][0], ensure_ascii=False)[:900])

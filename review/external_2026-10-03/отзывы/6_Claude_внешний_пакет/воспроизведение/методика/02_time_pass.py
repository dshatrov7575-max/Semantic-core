"""Время одного прохода всех векторов. Запуск из core/."""
import sys, time; sys.path.insert(0,'.')
from vectors import VECTORS, build
import validator
t=time.time(); CASES=[(None,*build())]+[(v,*build(v)) for v in VECTORS]; t1=time.time()
ts=[]
bad=0
for v,ds,tr,ct in CASES:
    s=time.time(); r=validator.validate(ds,tr,ct); ts.append((time.time()-s, v['id'] if v else 'BASE'))
    if v and r.codes()!=v['expected']: bad+=1
print("build %.1fs validate-all %.1fs mismatches %d"%(t1-t, time.time()-t1, bad))
ts.sort(reverse=True); print(ts[:8]); print("median", ts[len(ts)//2])

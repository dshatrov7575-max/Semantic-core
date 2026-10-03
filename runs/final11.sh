#!/bin/bash
# cycle 11: final runs, resumable (a container restart loses background processes — run this script again)
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres
A=/home/claude/as; D=$A/runs/final11; mkdir -p $D/mut
pg_isready -q -h $PGHOST -p $PGPORT || su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /home/claude/pg_ac/data -l /home/claude/pg_ac/server.log -o '-p 5436 -k /home/claude/pg_ac' start" >/dev/null 2>&1
sleep 3
cd $A/core
if [ ! -f $D/tests.done ]; then python3 tests.py > $A/slice/RUN_TESTS_CORE_v0.4.stdout.txt 2>&1 && touch $D/tests.done; fi
python3 - <<'PY' > $D/batches.txt
import mutants
ids=[m[0] for m in mutants.M]
for i in range(0,len(ids),30): print(" ".join(ids[i:i+30]))
PY
n=0
while read -r ids; do
  n=$((n+1)); f=$D/mut/batch_$(printf %02d $n).out
  if ! grep -q "^mutants=" "$f" 2>/dev/null; then python3 mutants.py $ids > "$f" 2>&1; fi
done < $D/batches.txt
if [ ! -f $D/mut.done ]; then
  cat $D/mut/batch_*.out | grep -E "^M[0-9A-Za-z]+ " > $A/slice/RUN_MUTANTS_CORE_v0.4.stdout.txt
  python3 - <<'PY' >> $A/slice/RUN_MUTANTS_CORE_v0.4.stdout.txt
import mutants
rows=[l.split(None,2) for l in open('/home/claude/as/slice/RUN_MUTANTS_CORE_v0.4.stdout.txt',encoding='utf-8') if l.strip()]
ids=[r[0] for r in rows]
k=sum(1 for r in rows if r[1]=='KILLED'); e=sum(1 for r in rows if r[1]=='EQUIVALENT'); b=len(rows)-k-e
print(f"\nmutants={len(mutants.M)} run={len(rows)} distinct={len(set(ids))} killed={k} equivalent={e} survived/broken={b}  (прогон пачками по 30: runs/final11.sh)")
PY
  touch $D/mut.done
fi
cd $A
if [ ! -f $D/reg.started ]; then rm -f runs/v10/*.done runs/v10_summary.txt; touch $D/reg.started; fi
if [ ! -f $D/reg.done ]; then ./run_v10.sh && touch $D/reg.done; fi
echo ALLDONE > $D/all.done

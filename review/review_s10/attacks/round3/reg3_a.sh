#!/bin/bash
# Раунд 2: воспроизведение заявленного и регрессия прежних срезов на снимке 2 (базы review10_3*).
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres
cd /home/claude/as/review/review_s10/snapshot3
O=../attacks/round3/out
createdb review10_3s 2>/dev/null; createdb review10_3t 2>/dev/null; createdb review10_3r 2>/dev/null
for i in 1 2 3; do PGDATABASE=review10_3s python3 slice/s10_tests.py > $O/s10_tests_$i.txt 2>&1; echo "exit=$?" >> $O/s10_tests_$i.txt; done
PGDATABASE=review10_3t python3 slice/attacks_s10.py 1500 > $O/attacks_s10.txt 2>&1; echo "exit=$?" >> $O/attacks_s10.txt
echo DONE > $O/reg_a.done

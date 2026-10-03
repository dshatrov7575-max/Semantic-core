#!/bin/bash
# Регрессия прежних срезов на снимке (возобновляемая): каждому скрипту — свой вывод и код возврата.
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=review11_r
S=/home/claude/as/review/review_s11/snapshot; O=/home/claude/as/review/review_s11/attacks/out/reg; mkdir -p $O
psql -X -d postgres -Atc "select 1 from pg_database where datname='review11_r'" | grep -q 1 || createdb review11_r
cd $S
for t in slice/s11_tests.py slice/attacks_s11.py slice/attacks_s1.py slice/regression_rs_db_attacks.py slice/regression_s22.py slice/regression_s23_races.py slice/regression_s24.py slice/s3_tests.py slice/s4_tests.py slice/attacks_s4.py slice/s5_tests.py slice/attacks_s5.py slice/regression_s5_races.py slice/parity_s5.py slice/s5b_tests.py slice/attacks_s5b.py slice/s9_tests.py slice/attacks_s9.py slice/s10_tests.py "slice/attacks_s10.py 600" adapter/tests_adapter.py store/store_tests.py; do
  n=$(echo $t | tr '/ ' '__'); [ -f $O/$n.rc ] && continue
  s=$(date +%s); python3 $t > $O/$n.out 2>&1; rc=$?; echo "$rc $(( $(date +%s)-s ))s" > $O/$n.rc
done
echo DONE > $O/ALL_DONE

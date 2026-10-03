#!/bin/bash
# Раунд 3: тесты ядра и регрессия прежних срезов на DDL snapshot3 (копия /tmp/claude-0/s11/r3), возобновляемо.
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=review11_r3 PYTHONDONTWRITEBYTECODE=1
S=/tmp/claude-0/s11/r3; O=/home/claude/as/review/review_s11/round3/attacks/out/reg; mkdir -p $O
cd $S
for t in slice/s11_tests.py slice/attacks_s11.py slice/attacks_s1.py slice/regression_rs_db_attacks.py slice/regression_s22.py slice/regression_s23_races.py slice/regression_s24.py slice/s3_tests.py slice/s4_tests.py slice/attacks_s4.py slice/s5_tests.py slice/attacks_s5.py slice/regression_s5_races.py slice/parity_s5.py slice/s5b_tests.py slice/attacks_s5b.py slice/s9_tests.py slice/attacks_s9.py slice/s10_tests.py "slice/attacks_s10.py 600" adapter/tests_adapter.py store/store_tests.py; do
  n=$(echo $t | tr '/ ' '__'); [ -f $O/$n.rc ] && continue
  s=$(date +%s); python3 $t > $O/$n.out 2>&1; rc=$?; echo "$rc $(( $(date +%s)-s ))s" > $O/$n.rc
done
[ -f $O/core_tests.rc ] || { (cd core && python3 tests.py > $O/core_tests.out 2>&1; echo $? > $O/core_tests.rc); }
echo DONE > $O/ALL_DONE

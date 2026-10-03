#!/bin/bash
# Раунд 2: воспроизведение заявленного и регрессия прежних срезов на снимке 2 (базы review10_3*).
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres
cd /home/claude/as/review/review_s10/snapshot3
O=../attacks/round3/out
createdb review10_3s 2>/dev/null; createdb review10_3t 2>/dev/null; createdb review10_3r 2>/dev/null
for f in attacks_s1 s3_tests s4_tests s5_tests s5b_tests attacks_s4 attacks_s5 attacks_s5b attacks_s9 regression_s22 regression_s24 regression_s23_races regression_s5_races; do
  PGDATABASE=review10_3r python3 slice/load_s1.py > /dev/null 2>&1
  PGDATABASE=review10_3r python3 slice/$f.py > $O/reg_$f.txt 2>&1; echo "exit=$?" >> $O/reg_$f.txt
done
PGDATABASE=review10_3r python3 slice/load_s1.py > /dev/null 2>&1
PGDATABASE=review10_3r SLICE=$PWD/slice python3 slice/regression_rs_db_attacks.py > $O/reg_regression_rs_db_attacks.txt 2>&1; echo "exit=$?" >> $O/reg_regression_rs_db_attacks.txt
PGDATABASE=review10_3r python3 slice/load_s1.py > /dev/null 2>&1
PGDATABASE=review10_3r python3 slice/s9_tests.py > $O/reg_s9_tests.txt 2>&1; echo "exit=$?" >> $O/reg_s9_tests.txt
(cd adapter && python3 tests_adapter.py > ../$O/reg_tests_adapter.txt 2>&1; echo "exit=$?" >> ../$O/reg_tests_adapter.txt)
(cd store && PGDATABASE=review10_3r python3 store_tests.py > ../$O/reg_store_tests.txt 2>&1; echo "exit=$?" >> ../$O/reg_store_tests.txt)
cd /home/claude/as/review/review_s10/attacks/round2
export S10_SNAP=/home/claude/as/review/review_s10/snapshot3
PGDATABASE=review10_3f python3 /home/claude/as/review/review_s10/snapshot3/slice/load_s1.py > /dev/null 2>&1
PGDATABASE=review10_3f python3 a8_fuzz_manifest_r2.py 3000 3003 > ../round3/out/a8_fuzz_manifest.txt 2>&1
PGDATABASE=review10_3f python3 a9_fuzz_row_r2.py 3000 3003 > ../round3/out/a9_fuzz_row.txt 2>&1
echo DONE > ../round3/out/reg_b.done

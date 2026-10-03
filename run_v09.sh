#!/bin/bash
# Regression of the whole slice on the v0.9 DDL (cycle 10): every acceptance / attack / race / parity script, sequentially.
# Usage: ./run_v09.sh [fast]   (fast: without the long sweeps DB_VECTORS_S1 and S5 exhaustive parity)
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=ac_v09
cd /home/claude/as || exit 1
dropdb --if-exists ac_v09 2>/dev/null; createdb ac_v09
S=slice
run() {  # name, command...
  local out=$1; shift
  "$@" > "$out" 2>&1
  echo "$(date +%H:%M:%S) rc=$? $out :: $(tail -1 "$out" | cut -c1-150)" >> runs/v09_summary.txt
}
: > runs/v09_summary.txt
run $S/RUN_LOAD_S1.stdout.txt        python3 $S/load_s1.py
run $S/RUN_KEYS_PARITY.stdout.txt    python3 $S/keys_parity_s1.py
run $S/RUN_S1.stdout.txt             python3 $S/attacks_s1.py
run $S/RUN_RS_REGRESSION.stdout.txt  python3 $S/regression_rs_db_attacks.py
run $S/RUN_S22_REGRESSION.stdout.txt python3 $S/regression_s22.py
run $S/RUN_S23_RACES.stdout.txt      python3 $S/regression_s23_races.py
run $S/RUN_S24_REGRESSION.stdout.txt python3 $S/regression_s24.py
run $S/RUN_S3.stdout.txt             python3 $S/s3_tests.py
run $S/RUN_S4.stdout.txt             python3 $S/s4_tests.py
run $S/RUN_S4_ATTACKS.stdout.txt     python3 $S/attacks_s4.py
run $S/RUN_S5.stdout.txt             python3 $S/s5_tests.py
run $S/RUN_S5_ATTACKS.stdout.txt     python3 $S/attacks_s5.py
run $S/RUN_S5_RACES.stdout.txt       python3 $S/regression_s5_races.py
run $S/RUN_S5_PARITY.stdout.txt      python3 $S/parity_s5.py
run $S/RUN_S5B.stdout.txt            python3 $S/s5b_tests.py
run $S/RUN_S5B_ATTACKS.stdout.txt    python3 $S/attacks_s5b.py
run $S/RUN_S9.stdout.txt             python3 $S/s9_tests.py
run $S/RUN_S9_ATTACKS.stdout.txt     python3 $S/attacks_s9.py
run $S/RUN_S10.stdout.txt            python3 $S/s10_tests.py
run $S/RUN_S10_ATTACKS.stdout.txt    python3 $S/attacks_s10.py 3000
run $S/RUN_ADAPTER.stdout.txt        python3 adapter/tests_adapter.py
run store/RUN_STORE.stdout.txt       python3 store/store_tests.py
if [ "$1" != "fast" ]; then
  run $S/RUN_S5_EXHAUSTIVE.stdout.txt python3 $S/parity_s5_exhaustive.py
  run $S/DB_VECTORS_S1.stdout.txt     python3 $S/db_vectors_s1.py
fi
echo done >> runs/v09_summary.txt

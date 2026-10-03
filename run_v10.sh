#!/bin/bash
# Regression of the whole slice on the v0.10 DDL (cycle 11): every acceptance / attack / race / parity script, sequentially.
# Resumable: a finished step leaves runs/v10/<name>.done and is skipped on the next start (a container restart kills
# background processes). Usage: ./run_v10.sh [fast] [fresh]   (fast: without the long sweeps; fresh: forget finished steps)
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=ac_v10
cd /home/claude/as || exit 1
pg_isready -q -h $PGHOST -p $PGPORT || { su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /home/claude/pg_ac/data -l /home/claude/pg_ac/server.log -o '-p 5436 -k /home/claude/pg_ac' start" >/dev/null 2>&1; sleep 4; }
mkdir -p runs/v10
case " $* " in *" fresh "*) rm -f runs/v10/*.done runs/v10_summary.txt;; esac
psql -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = 'ac_v10'" | grep -q 1 || createdb ac_v10
S=slice
run() {  # output file, command...
  local out=$1; shift
  local mark=runs/v10/$(basename "$out").done
  [ -f "$mark" ] && return
  "$@" > "$out" 2>&1
  local rc=$?
  echo "$(date +%H:%M:%S) rc=$rc $out :: $(tail -1 "$out" | cut -c1-150)" >> runs/v10_summary.txt
  # a step is «done» only if it SUCCEEDED (external review 03.10: the mark used to be set after a failed step, and a
  # repeated start skipped it); a failed step is run again next time and fails the whole script
  if [ $rc -eq 0 ]; then touch "$mark"; else FAILED=$((FAILED + 1)); fi
}
FAILED=0
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
run $S/RUN_S11.stdout.txt            python3 $S/s11_tests.py
run $S/RUN_S11_ATTACKS.stdout.txt    python3 $S/attacks_s11.py
run $S/RUN_ADAPTER.stdout.txt        python3 adapter/tests_adapter.py
run store/RUN_STORE.stdout.txt       python3 store/store_tests.py
case " $* " in *" fast "*) ;; *)
  run $S/RUN_S5_EXHAUSTIVE.stdout.txt python3 $S/parity_s5_exhaustive.py
  run $S/DB_VECTORS_S1.stdout.txt     python3 $S/db_vectors_s1.py;;
esac
echo "done failed=$FAILED code=$(cat core/validator.py slice/*.sql | sha256sum | cut -c1-16)" >> runs/v10_summary.txt
[ "$FAILED" -eq 0 ]

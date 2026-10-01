#!/bin/bash
# S24 re-review rerun. Usage: PGDATABASE=review026 SLICE=/home/claude/s24/slice ./run_all.sh
# Race scripts of S23 (s23_race_*.py) are excluded: their harness waits for T1 while T2 holds a lock and hangs
# under serialisation; the races are covered by slice/regression_s23_races.py.
set -u
export PGHOST=${PGHOST:-/home/claude/pg_ac} PGPORT=${PGPORT:-5436} PGUSER=${PGUSER:-postgres}
export PGDATABASE=${PGDATABASE:?set PGDATABASE to a scratch database}
export SLICE=${SLICE:-/home/claude/s24/slice}
A=/home/claude/s24/s23_attacks_adapted
cd "$SLICE/.." || exit 1
for s in attacks_s1.py s3_tests.py regression_s22.py regression_s23_races.py keys_parity_s1.py; do
  echo "### slice/$s"; timeout 600 python3 "slice/$s" 2>&1 | grep -E 'RESULT|=[0-9]+ ' ; done
for s in s23_01_validator.py s23_observation_backdate.py s23_previous_open.py s23_historical_escalation.py s23_check_text.py \
         s23_oracle.py s23_projection_dos.py s23_disputed_text.py s23_asof.py s23_s22_bypass.py; do
  echo "### $s"; (cd "$A" && timeout 120 python3 "$s" 2>&1 | grep -E '^(S23|B-)[^:]*: (FINDING|held)|CHECK_PREVIOUS_INVALID' | head -5); done
echo "### s24_qualifier_parity.py"; timeout 300 python3 /home/claude/as/review/rereview_s24/attacks/s24_qualifier_parity.py 2>&1

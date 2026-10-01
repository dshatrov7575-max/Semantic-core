#!/bin/bash
# S23 re-review: rerun every attack against a slice snapshot.
# Usage: PGDATABASE=review025 SLICE=/home/claude/s23/slice ./run_all.sh
# Every script reloads the reference world into $PGDATABASE (must be a scratch DB) and creates reader roles.
# Lines "S23-NN: FINDING" = the defect is present; "held" = the rule held.
set -u
export PGHOST=${PGHOST:-/home/claude/pg_ac} PGPORT=${PGPORT:-5436} PGUSER=${PGUSER:-postgres}
export PGDATABASE=${PGDATABASE:?set PGDATABASE to a scratch database}
export SLICE=${SLICE:-/home/claude/s23/slice}
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
for s in s23_previous_open.py s23_01_validator.py s23_observation_backdate.py s23_race_review.py s23_race_merge.py s23_race_rows.py \
         s23_historical_escalation.py s23_check_text.py s23_oracle.py s23_projection_dos.py s23_disputed_text.py s23_asof.py \
         s23_s22_bypass.py; do
  echo "### $s"
  python3 "$s" 2>&1 | grep -E '^(S23|B-)[^:]*: (FINDING|held)'
done
python3 -c "import common as C; C.reload()"   # leave the scratch DB with the clean reference world

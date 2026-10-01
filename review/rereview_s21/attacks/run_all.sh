#!/bin/bash
# Rerun all S2.1 attacks against any slice version.
# Usage: PGDATABASE=review022 SLICE=/home/claude/s21/slice ./run_all.sh
set -u
export PGHOST=${PGHOST:-/home/claude/pg_ac} PGPORT=${PGPORT:-5436} PGUSER=${PGUSER:-postgres}
export PGDATABASE=${PGDATABASE:-review022}
export SLICE=${SLICE:-/home/claude/s21/slice}
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "### 0. load reference world"
python3 "$SLICE/load_s1.py" | tail -2
echo "### 1. parity fuzz (SQL vs Python identity normalisation)"
python3 "$HERE/parity_fuzz.py" 2>/dev/null | grep -m1 "^cases="
echo "### 2. author + reviewer regression suites"
python3 "$SLICE/attacks_s1.py" 2>&1 | tail -2
python3 "$SLICE/regression_rs_db_attacks.py" 2>&1 | grep -cE 'held|ok' | xargs echo "regression held/ok rows:"
echo "### 3. S21-01 halfwidth duplicate (expect count=2 => FINDING)"
python3 "$SLICE/load_s1.py" >/dev/null
psql -X -q -At -f "$HERE/s21_01_halfwidth_dupe.sql" 2>/dev/null | grep -m1 EQUIPMENT
echo "### 4. P0 fix confirmation battery"
"$HERE/s21_probe.sh" 2>&1 | grep -E '^---|ERROR|CHECK_'

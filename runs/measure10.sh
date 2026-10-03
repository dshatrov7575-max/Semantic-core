#!/bin/bash
# cycle 10: measurement of the massive profile (synthetic register, 1M and 8M rows)
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres PGDATABASE=ac_s10m
cd /home/claude/as/slice
dropdb --if-exists ac_s10m; createdb ac_s10m
python3 load_s1.py > /dev/null 2>&1 || { echo "world load failed"; exit 1; }
for n in 1000000 8000000; do
  python3 dataset_s10.py measure $n /home/claude/ds_measure/$n || exit 1
  rm -rf /home/claude/ds_measure/$n/objects /home/claude/ds_measure/$n/rows.copy
done
psql -Atc "SELECT 'db_size_mb=' || pg_database_size('ac_s10m') / 1048576"

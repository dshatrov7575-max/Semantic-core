#!/bin/bash
# long runs, sequential, detached: mutants, DB vector coverage, exhaustive parity of id_norm
export PGHOST=/home/claude/pg_ac PGPORT=5436 PGUSER=postgres
cd /home/claude/as/core && python3 mutants.py > /home/claude/as/review/mutants_v0.2.3_final.txt 2>&1
cd /home/claude/as/slice && PGDATABASE=ac_vec python3 db_vectors_s1.py > DB_VECTORS_S1.stdout.txt 2>&1
echo done > /home/claude/as/run_long.done

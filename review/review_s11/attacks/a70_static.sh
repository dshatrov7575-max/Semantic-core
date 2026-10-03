#!/bin/bash
# Мёртвый и декоративный код в новом (цикл 11): статические проверки по снимку.
S=/home/claude/as/review/review_s11/snapshot
echo "1) мёртвая конструкция в ac.row_evidence_error (ddl_s10.sql):"; grep -n "IF true THEN" $S/slice/ddl_s10.sql
echo "2) ac.row_currency читает поле previous?"; awk '/CREATE FUNCTION ac.row_currency/,/^END \$\$;/' $S/slice/ddl_s10.sql | grep -c "previous"
echo "3) номера мутантов цикла: MS04, MS05 отсутствуют:"; grep -o '"MS0[0-9]"' $S/core/mutants.py | tr '\n' ' '; echo
echo "4) векторы цикла 11:"; grep -o 'V("[NP]S0[0-9]"' $S/core/vectors.py | tr '\n' ' '; echo
echo "5) файл вывода исследования в снимке:"; ls -la $S/research/dataset_delta_bench.out
echo "6) предел числа файлов манифеста:"; grep -n "100000" $S/slice/ddl_s10.sql | head -2
echo "7) стражи изоляции в чтении:"; grep -n "require_read_committed" $S/slice/ddl_s9.sql $S/slice/ddl_s5b.sql; grep -n "lock_keys" $S/slice/ddl_s5b.sql | tail -3

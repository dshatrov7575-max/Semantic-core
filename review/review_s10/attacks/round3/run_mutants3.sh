#!/bin/bash
# Мутанты MR.. пачками по 15 с возобновлением: готовая пачка (файл out/mut_NN.txt с итоговой строкой) не перезапускается.
cd /home/claude/as/review/review_s10/snapshot3/core
O=../../attacks/round3/out
[ -s $O/core_tests.txt ] && grep -q "ALL PASS\|FAIL" $O/core_tests.txt || python3 tests.py > $O/core_tests.txt 2>&1
ids=($(grep -o '"MR[0-9A-Z]*"' mutants.py | tr -d '"' | sort -u))
n=0
for ((i=0; i<${#ids[@]}; i+=15)); do
  n=$((n+1)); f=$O/mut_$(printf %02d $n).txt
  grep -q "^mutants=" $f 2>/dev/null && continue
  python3 mutants.py ${ids[@]:i:15} > $f 2>&1
done
cat $O/mut_??.txt | grep "^MR" > $O/mutants_MR.txt
echo DONE >> $O/mutants_MR.txt

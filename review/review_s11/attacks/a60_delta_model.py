#!/usr/bin/env python3
"""Проверка исследования о дельтах версий (research/dataset_delta_bench.py).
1) перезапуск модели автора с другими зёрнами — разброс чисел (в таблице отчёта один прогон);
2) аналитика: доля неизменных файлов при одних правках = (1-u)^C;
3) «корзины» автора: число корзин округляется ВНИЗ до степени двойки — средний файл до 2 раз больше заявленного C;
   честные корзины (N/C корзин, хэш по модулю) — другие числа;
4) третий способ, которого в исследовании нет: границы файлов по содержимому (граница там, где hash(ключа) mod C == 0,
   строки остаются в порядке ключа) — устойчив к вставкам и удалениям, порядок по ключу сохраняется;
5) предел манифеста: files <= 100000 (ac.manifest_error) против «125 тыс. файлов» из вывода 3.
Usage: python3 a60_delta_model.py [N=1000000]"""
import hashlib, math, random, statistics, sys
sys.path.insert(0, "/home/claude/as/review/review_s11/snapshot/research")
import dataset_delta_bench as B

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000


def h32(k):
    return int.from_bytes(hashlib.blake2b(str(k).encode(), digest_size=4).digest(), "big")


def files_buckets_honest(rows, c, n0):
    nb = max(1, round(n0 / c))
    b = {}
    for r in rows:
        b.setdefault(h32(r[0]) % nb, []).append(r)
    return {tuple(v) for v in b.values()}


def files_content_defined(rows, c, n0):
    out, cur = set(), []
    for r in rows:
        cur.append(r)
        if h32(r[0]) % c == 0:
            out.add(tuple(cur)); cur = []
    if cur:
        out.add(tuple(cur))
    return out


def share(cut, base, nv):
    old, new = cut(base), cut(nv)
    same = old & new
    return len(same) / len(new), sum(len(f) for f in same) / len(nv), len(nv) / len(new)


base = [(k, 0) for k in range(N)]
print(f"N = {N}")
print("\n1) модель автора, 5 зёрен: доля общих ФАЙЛОВ, позиционная резка, только правки")
for u, c in ((0.001, 4096), (0.001, 512), (0.001, 64), (0.005, 512), (0.01, 64)):
    vals = []
    for seed in range(5):
        nv = B.new_version(base, u, 0, 0, random.Random(seed))
        vals.append(share(lambda r: B.files_positional(r, c), base, nv)[0])
    print(f"   u={u:.2%} C={c:<5} прогоны: {' '.join(f'{v:.1%}' for v in vals)} | аналитика (1-u)^C = {(1 - u) ** c:.1%}")

print("\n3-4) u=0,1 % a=0,05 % d=0,05 %: доля общих файлов (средний размер файла в строках)")
nv = B.new_version(base, 0.001, 0.0005, 0.0005, random.Random(20261003))
for c in (4096, 512, 64):
    r = {name: share(cut, base, nv) for name, cut in (
        ("позиционно", lambda x: B.files_positional(x, c)), ("корзины автора", lambda x: B.files_bucketed(x, c, N)),
        ("корзины честные", lambda x: files_buckets_honest(x, c, N)), ("границы по содержимому", lambda x: files_content_defined(x, c, N)))}
    print(f"   C={c:<5} " + " | ".join(f"{k}: файлов {v[0]:.1%}, строк {v[1]:.1%} (ср. файл {v[2]:.0f})" for k, v in r.items()) + f" | аналитика (1-0,002)^C = {0.998 ** c:.1%}")
print("\n   u=0,01 % a=0,005 % d=0,005 %")
nv = B.new_version(base, 0.0001, 0.00005, 0.00005, random.Random(20261003))
for c in (4096, 512, 64):
    r = {name: share(cut, base, nv) for name, cut in (
        ("корзины автора", lambda x: B.files_bucketed(x, c, N)), ("корзины честные", lambda x: files_buckets_honest(x, c, N)),
        ("границы по содержимому", lambda x: files_content_defined(x, c, N)))}
    print(f"   C={c:<5} " + " | ".join(f"{k}: файлов {v[0]:.1%}, строк {v[1]:.1%} (ср. файл {v[2]:.0f})" for k, v in r.items()) + f" | аналитика (1-0,0002)^C = {0.9998 ** c:.1%}")

print("\n5) манифест: 8 млн строк / 64 = %d файлов; предел ac.manifest_error: files <= 100000" % (8_000_000 // 64))

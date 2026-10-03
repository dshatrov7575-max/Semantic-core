#!/usr/bin/env python3
"""Сколько файлов строк новая версия набора может взять у предыдущей «по хэшу» (D27.2: «новая версия ссылается на
неизменившиеся файлы — дельты ЕГРЮЛ не множат объём»)?

Файл версии неизменен, если в нём те же строки с теми же значениями. Модель: N строк с ключами; новая версия — те же
строки, из которых доля u изменена (в случайных местах), доля a добавлена (новые ключи в случайных местах порядка) и
доля d удалена. Два способа резать строки на файлы:
  позиционный  — подряд по ключу по C строк (так режет производитель цикла 10): вставка или удаление сдвигает все
                 следующие файлы;
  по корзинам  — файл = корзина hash(ключа) mod (N/C), в среднем C строк: вставки и удаления локальны, порядок по
                 ключу внутри набора теряется;
  по содержимому — строки в порядке ключа, файл кончается на строке с hash(ключа) mod C = 0: вставки и удаления
                 локальны, порядок по ключу сохранён.
Печатается доля файлов и доля строк, которые новая версия берёт у предыдущей без перезаписи (среднее по 5 зёрнам),
и аналитическая оценка доли нетронутых файлов (1-u-a-d)^C.
"""
import hashlib
import random
import sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000


def files_positional(rows, c):
    return {tuple(rows[i:i + c]) for i in range(0, len(rows), c)}


def _h(k):
    return int.from_bytes(hashlib.blake2b(str(k).encode(), digest_size=8).digest(), "big")


def files_bucketed(rows, c, n0):
    """Файл = корзина hash(ключа) mod (N/C): в среднем ровно C строк (в первой редакции число корзин округлялось до
    степени двойки вниз и корзины выходили почти вдвое крупнее заявленного — находка рецензии S11R-16)."""
    nb = max(1, n0 // c)
    b = {}
    for r in rows:
        b.setdefault(_h(r[0]) % nb, []).append(r)
    return {tuple(v) for v in b.values()}


def files_content_defined(rows, c):
    """Границы по содержимому: строки остаются в порядке ключа, файл кончается на строке, у которой hash(ключа) mod C = 0.
    В среднем C строк; вставка или удаление задевает один файл, порядок по ключу сохранён."""
    out, cur = set(), []
    for r in rows:
        cur.append(r)
        if _h(r[0]) % c == 0:
            out.add(tuple(cur))
            cur = []
    if cur:
        out.add(tuple(cur))
    return out


def new_version(rows, u, a, d, rnd):
    out = []
    for k, ver in rows:
        x = rnd.random()
        if x < d:
            continue
        out.append((k, ver + 1) if x < d + u else (k, ver))
    out += [(k + 0.5, 0) for k in rnd.sample(range(len(rows)), int(len(rows) * a))]
    out.sort()
    return out


SEEDS = (20261003, 1, 2, 3, 4)


def main():
    base = [(k, 0) for k in range(N)]
    print(f"N = {N} строк; среднее по {len(SEEDS)} зёрнам; доля ФАЙЛОВ / доля СТРОК новой версии, взятых у предыдущей без перезаписи\n")
    print(f"{'изменено':>9} {'добавлено':>10} {'удалено':>8} | {'файл':>5} | {'позиционно':>15} | {'корзины':>15} | {'по содержимому':>15} | {'(1-u-a-d)^C':>11}")
    for u, a, d in ((0.001, 0, 0), (0.005, 0, 0), (0.01, 0, 0), (0.001, 0.0005, 0.0005), (0.005, 0.002, 0.002), (0.0001, 0.00005, 0.00005)):
        for c in (4096, 512, 64):
            cuts = (lambda r: files_positional(r, c), lambda r: files_bucketed(r, c, N), lambda r: files_content_defined(r, c))
            acc = [[0.0, 0.0] for _ in cuts]
            for seed in SEEDS:
                nv = new_version(base, u, a, d, random.Random(seed))
                for i, cut in enumerate(cuts):
                    old, new = cut(base), cut(nv)
                    same = old & new
                    acc[i][0] += len(same) / len(new) / len(SEEDS)
                    acc[i][1] += sum(len(f) for f in same) / len(nv) / len(SEEDS)
            cells = " | ".join(f"{x:>6.1%} / {y:>6.1%}" for x, y in acc)
            print(f"{u:>9.2%} {a:>10.3%} {d:>8.3%} | {c:>5} | {cells} | {(1 - u - a - d) ** c:>11.1%}")
        print()


if __name__ == "__main__":
    main()

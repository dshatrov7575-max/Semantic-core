"""Разбор вывода автора DB_VECTORS_S1.stdout.txt: что стоит за «отвергнуто базой»."""
import re, sys, collections
P = "/home/claude/proj/АС_АРХИВ_ДЛЯ_КРИТИКИ_2026-10-03/прогоны/DB_VECTORS_S1.stdout.txt"
rows = []
for ln in open(P, encoding="utf-8"):
    parts = [x.strip() for x in ln.rstrip("\n").split(" | ")]
    if len(parts) >= 3 and re.fullmatch(r"[A-Z]+[0-9A-Za-z]*", parts[0]) and parts[2] in ("REJECTED", "ACCEPTED", "N/A"):
        rows.append((parts[0], parts[1].split(","), parts[2], " | ".join(parts[3:])))
c = collections.Counter(r[2] for r in rows)
print("rows", len(rows), dict(c))
same = other_code = constraint = other = 0
oc = collections.Counter(); cons = collections.Counter(); oth = []
pairs = collections.Counter()
for vid, exp, res, msg in rows:
    if res != "REJECTED": continue
    m = re.search(r"ERROR:\s+([A-Z][A-Z_]{3,}):", msg) or re.search(r"ERROR:\s+([A-Z][A-Z_]{5,})\b", msg)
    if m and m.group(1) in exp: same += 1
    elif m:
        other_code += 1; oc[m.group(1)] += 1; pairs[(",".join(exp), m.group(1))] += 1
    elif re.search(r"violates (check|unique|foreign key|not-null|exclusion) constraint|duplicate key|null value", msg):
        constraint += 1; cons[re.search(r"(check|unique|foreign key|not-null|exclusion) constraint|duplicate key|null value", msg).group()] += 1
    else:
        other += 1; oth.append((vid, exp, msg[:160]))
print("rejected: same code", same, "| other named code", other_code, "| bare constraint", constraint, "| other", other)
print("other named codes:", oc.most_common())
print("constraints:", cons.most_common())
print("expected -> actual (other code), top:")
for (e, a), n in pairs.most_common(45): print("  %3d  %s -> %s" % (n, e, a))
print("other (ни код, ни ограничение):")
for o in oth: print("  ", o)
print("ACCEPTED by expected code:", collections.Counter(",".join(r[1]) for r in rows if r[2] == "ACCEPTED").most_common())
print("N/A:", [(r[0], r[1], r[3]) for r in rows if r[2] == "N/A"])

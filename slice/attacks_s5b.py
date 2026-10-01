#!/usr/bin/env python3
"""S5 part 2 attacks on the registry of originals in the database (no validator, no gateway in front): what the
application role (ac_loader) and the storage role (ac_storage) can and cannot do. Each attack must be refused.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s5b.py
"""
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
from ingest_s4 import ingest_sql, psql, utc, q  # noqa: E402
from s5_tests import source  # noqa: E402

BAD = []
A1, A2, A3 = ("sha256:" + c * 64 for c in "abc")


def attack(aid, desc, sql, expect, legit=False):
    r = psql(sql)
    err = r.stderr.strip().splitlines()[0] if r.stderr.strip() else ""
    ok = (r.returncode == 0) if legit else (r.returncode != 0 and any(e in r.stderr for e in expect))
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {'законная: ' if legit else ''}{desc} | {err[:110] or 'принято'}", flush=True)


def as_(role, body):
    return f"SET SESSION AUTHORIZATION {role};\nBEGIN;\n{body}\nROLLBACK;"


def reg(addr, n=100, tenant="tnt_demo", check="OK"):
    s = f"INSERT INTO ac.objects (tenant_id, object_address, byte_length) VALUES ('{tenant}', '{addr}', {n});\n"
    if check:
        s += f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('{tenant}', '{addr}', '{check}');\n"
    return s


def obs(addr, n=100, mt="text/html", tenant="tnt_demo"):
    s = source("Текст страницы для проверки оригиналов.", "https://news.example/a", utc(0))
    s["observations"][0]["original"] = {"object": addr, "media_type": mt, "byte_length": n}
    return ingest_sql([s], {}, commit=False)


def main():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    # committed setup as the gateway would do: A1 intact, A2 later found corrupt, A3 in another tenant
    setup = ("SET SESSION AUTHORIZATION ac_storage;\nBEGIN;\n" + reg(A1) + reg(A2) + reg(A3, tenant="tnt_other") + "COMMIT;\n"
             "SELECT pg_sleep(0.1);\nINSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo', '" + A2 + "', 'CORRUPT');")
    if psql(setup).returncode:
        sys.exit("setup failed")
    time.sleep(1.1)
    O, PD = ["ORIGINAL_INVALID"], ["permission denied"]

    attack("L1", "шлюз регистрирует объект с проверкой", as_("ac_storage", reg("sha256:" + "d" * 64)).replace("ROLLBACK;", "COMMIT;"), [], True)
    attack("L2", "наблюдение называет зарегистрированный целый оригинал", obs(A1), [], True)

    attack("D601", "приложение объявляет объект сохранённым", as_("ac_loader", reg("sha256:" + "e" * 64)), PD)
    attack("D602", "приложение пишет результат проверки", as_("ac_loader", f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo', '{A2}', 'OK');"), PD)
    attack("D603", "шлюз регистрирует объект без успешной проверки чтением",
           as_("ac_storage", reg("sha256:" + "f" * 64, check=None)).replace("ROLLBACK;", "COMMIT;"), O)
    attack("D603b", "шлюз регистрирует объект с проверкой «повреждён»",
           as_("ac_storage", reg("sha256:" + "f" * 64, check="CORRUPT")).replace("ROLLBACK;", "COMMIT;"), O)
    attack("D604", "шлюз задаёт время сохранения", as_("ac_storage", "INSERT INTO ac.objects (tenant_id, object_address, byte_length, stored_at) "
           f"VALUES ('tnt_demo', 'sha256:{'1' * 64}', 5, '2000-01-01');"), PD)
    attack("D604b", "шлюз задаёт время проверки", as_("ac_storage", "INSERT INTO ac.object_checks (tenant_id, object_address, result, checked_at) "
           f"VALUES ('tnt_demo', '{A2}', 'OK', '2000-01-01');"), PD)
    attack("D605", "шлюз меняет длину объекта", as_("ac_storage", f"UPDATE ac.objects SET byte_length = 1 WHERE object_address = '{A1}';"), PD + ["APPEND_ONLY"])
    attack("D605b", "шлюз удаляет запись проверки", as_("ac_storage", f"DELETE FROM ac.object_checks WHERE object_address = '{A2}';"), PD + ["APPEND_ONLY"])
    attack("D605c", "роль миграции стирает запись «повреждён»", as_("ac_migrator", f"DELETE FROM ac.object_checks WHERE object_address = '{A2}';"), PD + ["APPEND_ONLY"])
    attack("D606", "шлюз читает тексты источников", as_("ac_storage", "SELECT count(*) FROM ac.source_bytes;"), PD)
    attack("D606b", "шлюз читает утверждения", as_("ac_storage", "SELECT count(*) FROM ac.claims;"), PD)
    attack("D606c", "шлюз пишет наблюдение", as_("ac_storage", "INSERT INTO ac.source_observations (tenant_id, source_id, observed_at, origin_uri, observed_by) "
           "VALUES ('tnt_demo', 'src:sha256:' || repeat('0', 64), now(), 'https://x.example/', 'svc_x');"), PD)
    attack("D607", "наблюдение называет незарегистрированный оригинал", obs("sha256:" + "9" * 64), O + ["observation_original_fk"])
    attack("D608", "наблюдение называет объект другого tenant", obs(A3), O + ["observation_original_fk"])
    attack("D609", "длина оригинала не та, что зарегистрирована", obs(A1, n=99), O)
    attack("D610", "оригинал без типа содержимого", obs(A1).replace("$ac_q$text/html$ac_q$", "NULL"), ["observation_original_whole"])
    attack("D611", "тип содержимого не по форме", obs(A1, mt="TEXT/HTML; x"), ["check constraint"])
    attack("D612", "проверка незарегистрированного объекта", as_("ac_storage", "INSERT INTO ac.object_checks (tenant_id, object_address, result) "
           f"VALUES ('tnt_demo', 'sha256:{'8' * 64}', 'OK');"), ["foreign key"])
    attack("D613", "результат проверки вне списка", as_("ac_storage", f"INSERT INTO ac.object_checks (tenant_id, object_address, result) VALUES ('tnt_demo', '{A1}', 'FINE');"),
           ["check constraint"])
    attack("D614", "наблюдение называет оригинал, признанный повреждённым", obs(A2), O)
    attack("D615", "адрес объекта не sha256", as_("ac_storage", reg("md5:abc")), ["check constraint"])
    attack("D616", "объект нулевой длины", as_("ac_storage", reg("sha256:" + "7" * 64, n=0)), ["check constraint"])
    print(f"\nattacks={len(BAD)} findings={sum(BAD)}")
    print("S5B_ATTACKS=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

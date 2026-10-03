#!/usr/bin/env python3
"""Builds the ЯДРО_v0.10 bundles (text packages with an unpack one-liner) and SHA256SUMS into /home/claude/out10."""
import hashlib
from pathlib import Path

ROOT = Path("/home/claude/as")
OUT = Path("/home/claude/out10")
OUT.mkdir(exist_ok=True)
UNPACK = ("python3 -c \"import re,sys,os;t=open(sys.argv[1],encoding='utf-8').read();[(os.makedirs(os.path.dirname(n) or '.',exist_ok=True),"
          "open(n,'w',encoding='utf-8').write(b)) for n,b in re.findall(r'=== FILE: (\\S+) ===\\n(.*?)\\n=== END ===',t,re.S)]\" <этот_файл>")

S = "slice/"
BUNDLES = [
    ("ЯДРО_v0.10_1_онтология.md", "онтология core-ontology/0.4 (цикл 10 ч.1, D27.2/D27.4): валидатор, схема, реестр, производитель версии набора данных, эталонный мир, Конструктор модели",
     ["core/README.md", "core/validator.py", "core/core.schema.json", "core/predicates.json", "core/jcs.py", "core/jcs.mjs", "core/dataset.py", "core/fixtures.py",
      "core/model_constructor.py"]),
    ("ЯДРО_v0.10_2_тесты.md", "вектора (681, из них 39 цикла 11), приёмка T1–T9, мутанты (535, из них 27 цикла 11)",
     ["core/vectors.py", "core/tests.py", "core/mutants.py"]),
    ("ЯДРО_v0.10_3_срез_и_проекции.md", "срез PostgreSQL S1-S3 и проекции S3 (ac.claim_evidence: вид доказательства SPAN/ROW), тесты и регрессии",
     [S + f for f in ("ddl_s1.sql", "unicode_s1.sql", "gen_unicode_s1.py", "keys_s1.sql", "proj_s3.sql", "attacks_s1.py",
                      "s3_tests.py", "render_s3.py", "regression_rs_db_attacks.py", "regression_s22.py", "regression_s23_races.py",
                      "regression_s24.py", "db_vectors_s1.py", "keys_parity_s1.py", "parity_exhaustive_s1.py",
                      "ПРИМЕР_ДОСЬЕ_S3.md", "ПРИМЕР_ОТЧЁТА_S3.md")]),
    ("ЯДРО_v0.10_4_TechSense_S4.md", "S4: адаптер TechSense, артефакт в базе, карточка оборудования, тесты и атаки (без изменений с v0.6)",
     ["adapter/techsense_umr.py", "adapter/samples.py", "adapter/tests_adapter.py",
      S + "ddl_s4.sql", S + "proj_s4.sql", S + "ingest_s4.py", S + "s4_tests.py", S + "attacks_s4.py", S + "render_s4.py",
      S + "make_examples_s4.py", S + "ПРИМЕР_КАРТОЧКИ_S4.md"]),
    ("ЯДРО_v0.10_5_WebMonitoring_S5.md", "S5 ч.1: публикации Web Monitoring, лента упоминаний, паритет, гонки, тесты и атаки (без изменений с v0.6)",
     [S + f for f in ("ddl_s5.src.sql", "gen_ddl_s5.py", "ddl_s5.sql", "proj_s5.sql", "s5_tests.py", "attacks_s5.py", "parity_s5.py",
                      "parity_s5_exhaustive.py", "regression_s5_races.py", "render_s5.py", "make_examples_s5.py", "ПРИМЕР_ЛЕНТЫ_S5.md")]),
    ("ЯДРО_v0.10_6_ObjectStorage_S5b.md", "S5 ч.2 (D26): объектное хранилище оригиналов, шлюз, реестр в базе, проекция «сохранность» (без изменений с v0.7)",
     ["store/object_store.py", "store/s3_emulator.py", "store/gateway.py", "store/store_tests.py",
      S + "ddl_s5b.sql", S + "s5b_tests.py", S + "attacks_s5b.py", S + "render_s5b.py",
      S + "make_examples_s5b.py", S + "ПРИМЕР_СОХРАННОСТИ_S5.md"]),
    ("ЯДРО_v0.10_7_Схема_S9.md", "S9 (D27.1): схема как данные в PostgreSQL — определения с версиями, замыкание, страж утверждений, проекции «модель» и «пробелы схемы», загрузчик, приёмка и атаки",
     [S + f for f in ("ddl_s9.sql", "schema_s9.py", "load_s1.py", "s9_tests.py", "attacks_s9.py")]),
    ("ЯДРО_v0.10_10_Наборы_S10.md", "S10 (D27.2/D27.4, часть 1): версии наборов данных и доказательство-строка в PostgreSQL — каталог, страж, широкие таблицы с печатью, чтение по допуску, поиск по идентификатору; производитель и загрузчик; приёмка, атаки, измерение",
     [S + f for f in ("ddl_s10.sql", "dataset_s10.py", "s10_tests.py", "attacks_s10.py")] + ["runs/measure10.sh"]),
    ("ЯДРО_v0.10_11_Изоляция_и_строки_S11.md", "S11 (цикл 11): запись только в READ COMMITTED, схема ключей entity:, «о ком строка», актуальность строки — страж изоляции на всех таблицах, тесты, атаки, исследование о дельтах версий",
     [S + f for f in ("ddl_s11.sql", "s11_tests.py", "attacks_s11.py")] + ["run_v10.sh", "runs/final11.sh", "research/dataset_delta_bench.py", "research/dataset_delta_bench.out", "research/ИССЛЕДОВАНИЕ_2026-10-03_дельты_версий.md"]),
    ("ЯДРО_v0.10_8_прогоны.md", "выводы прогонов v0.10 (онтология, срез, хранилище; исчерпывающий паритет символов — без изменений с v0.4)",
     [S + f for f in ("RUN_TESTS_CORE_v0.4.stdout.txt", "RUN_MUTANTS_CORE_v0.4.stdout.txt", "RUN_S11.stdout.txt", "RUN_S11_ATTACKS.stdout.txt", "RUN_S10.stdout.txt", "RUN_S10_ATTACKS.stdout.txt", "RUN_S10_MEASURE.stdout.txt", "RUN_S9.stdout.txt", "RUN_S9_ATTACKS.stdout.txt",
                      "RUN_ADAPTER.stdout.txt",
                      "RUN_S5.stdout.txt", "RUN_S5_ATTACKS.stdout.txt", "RUN_S5_RACES.stdout.txt", "RUN_S5_PARITY.stdout.txt",
                      "RUN_S5_EXHAUSTIVE.stdout.txt", "RUN_S5B.stdout.txt", "RUN_S5B_ATTACKS.stdout.txt",
                      "RUN_S4.stdout.txt", "RUN_S4_ATTACKS.stdout.txt", "RUN_S1.stdout.txt", "RUN_S3.stdout.txt",
                      "RUN_S22_REGRESSION.stdout.txt", "RUN_S23_RACES.stdout.txt", "RUN_S24_REGRESSION.stdout.txt",
                      "RUN_RS_REGRESSION.stdout.txt", "RUN_LOAD_S1.stdout.txt", "RUN_KEYS_PARITY.stdout.txt",
                      "DB_VECTORS_S1.stdout.txt", "EXHAUSTIVE_PARITY.stdout.txt", "EXHAUSTIVE_PARITY_id_norm.stdout.txt")]
     + ["store/RUN_STORE.stdout.txt", "runs/v10_summary.txt"]),
    ("ЯДРО_v0.10_9_рецензия_S11.md", "независимая рецензия цикла 11: раунды 1–4 — ВОЗВРАТ, раунд 5 — ПРИНЯТО С ЗАМЕЧАНИЯМИ; отчёты, ответы автора, скрипты рецензента",
     sorted(str(p.relative_to(ROOT)) for d in ["review/review_s11", "review/review_s11/attacks"] + [f"review/review_s11/round{n}{x}" for n in (2, 3, 4, 5) for x in ("", "/attacks", "/attacks/out")]
            if (ROOT / d).is_dir()
            for p in (ROOT / d).iterdir()
            if p.is_file() and p.suffix in (".py", ".out", ".md", ".sh", ".sql", ".txt") and p.stat().st_size < 150_000)),
]


def main():
    sums = []
    for name, title, files in BUNDLES:
        parts = [f"# {name[:-3]} — {title}\n",
                 f"Пакет ЯДРО_v0.10 (Главный-1, 2026-10-03). Каждый файл — между строками '=== FILE: <путь> ===' и '=== END ==='. "
                 "Распаковка в текущий каталог:\n", "```bash", UNPACK, "```\n"]
        for f in files:
            text = (ROOT / f).read_text(encoding="utf-8")
            assert "\n=== END ===" not in text, f
            parts.append(f"=== FILE: {f} ===\n{text.rstrip(chr(10))}\n=== END ===\n")
        body = "\n".join(parts)
        (OUT / name).write_text(body, encoding="utf-8")
        print(f"{name}: {len(files)} files, {len(body.encode())} bytes")
    for extra in (ROOT / "docs/АРХИТЕКТУРА_ЯДРА_v0.10.md",):
        (OUT / extra.name).write_bytes(extra.read_bytes())
    for p in sorted(OUT.iterdir()):
        if p.name.endswith(".md") and not p.name.startswith("АС_"):
            sums.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
    (OUT / "ЯДРО_v0.10_SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print("\n".join(sums))


if __name__ == "__main__":
    main()

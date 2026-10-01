# ЯДРО — онтология core-ontology/0.2.3 (исполняемая)

Нормативный текст — `АРХИТЕКТУРА_ЯДРА_v0.4.md` (правила 0.2.3; формат записей core-ontology/0.2 с совместимыми расширениями: `disambiguator` у CONCEPT, запись `IdentityDecision`). Здесь — код, который его проверяет.

| Файл | Что это |
|---|---|
| `core.schema.json` | JSON Schema 2020-12: набор данных (8 видов записей) и реестр доверия |
| `predicates.json` | реестр предикатов (24) и профилей Проверки — данные, не код |
| `validator.py` | единственный нормативный валидатор (фазы 0–2, 36 кодов ошибок, 2 кода предупреждений) |
| `jcs.py`, `jcs.mjs` | RFC 8785 JCS, UTF-8, целочисленный профиль (Python — норматив, Node — для производителей на JS) |
| `fixtures.py` | тестовый мир на все 6 продуктов + реестр доверия + хранилище байтов |
| `vectors.py` | 291 вектор (241 негативный, 50 позитивных граничных) |
| `tests.py` | приёмка T1–T7 (≈3 мин) |
| `mutants.py` | мутационный прогон: 251 мутант (≈30 мин на 2 ядрах) |

Установка: `pip install jsonschema cryptography` (Python ≥ 3.11), Node ≥ 18 для T6.

```bash
python3 tests.py        # ALL PASS
python3 mutants.py      # killed + equivalent = всего, survived = 0
python3 validator.py world.json --trust trust.json --content-dir DIR   # DIR: файлы с именем = hex из source_id
```

Правило: новое правило добавляется только вместе с негативным вектором и мутантом, которого этот вектор убивает.

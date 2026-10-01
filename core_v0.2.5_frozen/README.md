# ЯДРО — онтология core-ontology/0.2.5 (исполняемая)

Нормативный текст — `АРХИТЕКТУРА_ЯДРА_v0.6.md` (правила 0.2.5; формат записей core-ontology/0.2 + запись `Publication`). Здесь — код, который его проверяет.

| Файл | Что это |
|---|---|
| `core.schema.json` | JSON Schema 2020-12: набор данных (9 видов записей, с `Publication`), реестр доверия, **артефакт `umr-artifact/0.3`** (`$defs.UmrArtifact`) |
| `predicates.json` | реестр предикатов (24), профилей Проверки и **ролей артефактов** (`artifact_formats`: роль графа → предикат) — данные, не код |
| `validator.py` | единственный нормативный валидатор (фазы 0–2, 39 кодов ошибок, 2 кода предупреждений); хранилище объектов `content` — байты источников по `source_id` и артефактов по `artifact_digest` |
| `jcs.py`, `jcs.mjs` | RFC 8785 JCS, UTF-8, целочисленный профиль (Python — норматив, Node — для производителей на JS) |
| `fixtures.py` | тестовый мир на все 6 продуктов + реестр доверия + хранилище байтов + артефакт TechSense (инструкция НС-2) + статья news.example в трёх версиях байтов и её публикация |
| `vectors.py` | 358 векторов (299 негативных, 59 позитивных граничных) |
| `tests.py` | приёмка T1–T8 (≈5 мин; T8 — закреплённая версия Unicode 14.0.0) |
| `mutants.py` | мутационный прогон: 314 мутантов (≈45 мин на 2 ядрах) |

Адаптер TechSense — `../adapter/techsense_umr.py` (приёмка `../adapter/tests_adapter.py`).

Установка: `pip install jsonschema cryptography` (Python ≥ 3.11), Node ≥ 18 для T6.

```bash
python3 tests.py        # ALL PASS
python3 mutants.py      # killed + equivalent = всего, survived = 0
python3 validator.py world.json --trust trust.json --content-dir DIR   # DIR: файлы с именем = hex адреса (источники и артефакты)
```

Правило: новое правило добавляется только вместе с негативным вектором и мутантом, которого этот вектор убивает.

#!/usr/bin/env python3
"""S10R / направление 8: отступления от проекта D27.2–D27.4 (и D27.6), которые в снимке нигде не названы отступлениями.
Каждая строка — факт, проверенный запуском (текст проекта: docs/АС_МНЕНИЕ_2026-10-02_v001_модель_данных.md)."""
from common import *
import hmac
dv = demo_registry()
snap_txt = "".join(p.read_text(encoding="utf-8", errors="replace") for d in ("core", "slice") for p in (SNAP / d).glob("*") if p.suffix in (".py", ".sql", ".md"))
print("слово «отступлен…» в коде и текстах снимка (core, slice):", snap_txt.count("тступлен"), "раз; README ядра описывает онтологию:",
      (SNAP / "core" / "README.md").read_text(encoding="utf-8").splitlines()[0])
q = lambda s: psql(s).stdout.strip()
print("\n1. D27.4 «соль колонки = HMAC(секрет строки, имя колонки)»")
secret = dv.rows[0][2]; s_impl = cell_salt(secret, "address")
print("   соль в реализации == sha256(0x03‖секрет‖имя):", s_impl == hashlib.sha256(b"\x03" + secret + b"address").digest(), "| == HMAC-SHA256(секрет, имя):", s_impl == hmac.new(secret, b"address", "sha256").digest())
print("\n2. D27.4 «шлюз пишет ac.dataset_row_checks; страж ROW берёт блокировку по ключу строки и требует запись проверки с тем же row_sha256»")
print("   таблица ac.dataset_row_checks:", q("SELECT coalesce(to_regclass('ac.dataset_row_checks')::text, 'нет')"),
      "| упоминаний row_checks / lock_keys / pg_advisory в ddl_s10.sql:", sum((SNAP / "slice" / "ddl_s10.sql").read_text().count(w) for w in ("row_checks", "lock_keys", "pg_advisory")),
      "| роль ac_gateway в ddl_s10.sql:", (SNAP / "slice" / "ddl_s10.sql").read_text().count("ac_gateway"))
print("   следствие: утверждение на строке принимается для версии, строки которой никто не читал и не сверял (см. a12_decorative_files.py)")
print("\n3. D27.2 «маркировка набора = максимум по его колонкам»")
print("   версия s30 мира: маркировка источника", q(f"SELECT marking FROM ac.sources WHERE source_id = '{dv.source_id}'"), "| маркировки колонок:",
      q(f"SELECT string_agg(DISTINCT c->'marking'->>'level' || coalesce(' ' || (c->'marking'->'categories'->>0), ''), ', ') FROM ac.datasets, jsonb_array_elements(manifest->'columns') c WHERE source_id = '{dv.source_id}'"))
print("   правила «источник не уже максимума колонок» нет ни в валидаторе, ни в базе (манифест с колонкой RESTRICTED при PUBLIC-источнике принят: a8, операция 5/32)")
print("\n4. D27.4 «поддержка факта считается по семейству набора (ac.support_key расширяется)» — не сделано и не названо частью 2: см. a11_support_family.py")
print("   ac.support_key двух версий одного набора различны:", q("SELECT count(DISTINCT ac.support_key(tenant_id, source_id, now())) || ' ключей на ' || count(*) || ' версий набора ' || dataset_id FROM ac.datasets GROUP BY dataset_id ORDER BY count(*) DESC LIMIT 1"))
print("\n5. D27.3 «у набора без ключа ключ = хэш канонической формы строки»; D27.4 «строка хэшируется по ключу и содержимому… пара (ключ, row_sha256) ищется в любой версии семейства»")
a = DatasetVersion("dst_rev_nokey", T, "v1", REGISTRY_COLUMNS, [], REGISTRY_ROWS[:1]); b = DatasetVersion("dst_rev_nokey", T, "v2", REGISTRY_COLUMNS, [], REGISTRY_ROWS[:1])
print("   одна и та же строка в двух версиях (производитель по умолчанию, секрет os.urandom): хэш строки v1 == v2:", a.rows[0][3] == b.rows[0][3],
      "— «имя» строки без ключа меняется от версии к версии при неизменном содержимом")
print("   доказательство привязано к месту: proof =", sorted(dv.evidence([OGRN_DEV], ['address'])['proof']), "(номер файла и номер строки в файле версии)")
print("\n6. D27.3 «индекс идентификаторов — только для наборов, помеченных „индексируемый“»")
print("   поле в манифесте:", "indexable" in json.dumps(dv.manifest), "| индексов по колонкам-идентификаторам запечатанных версий:",
      q("SELECT count(*) FROM pg_indexes WHERE schemaname = 'acd' AND indexdef LIKE '%IS NOT NULL%'"), "| ac.dataset_find обходит версии циклом: запросов на один поиск =",
      q("SELECT count(*) FROM ac.datasets x JOIN ac.dataset_tables t USING (tenant_id, source_id), jsonb_array_elements(x.manifest->'columns') c WHERE t.sealed_at IS NOT NULL AND c->>'identifier_scheme' = 'ru.inn'"))
print("\n7. D27.6 «широкие таблицы PostgreSQL — под RLS»; D27.2 «секционирование + BRIN»")
print("   таблиц в acd с включённой RLS:", q("SELECT count(*) FILTER (WHERE relrowsecurity) || ' из ' || count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'acd' AND relkind IN ('r','p')"),
      "| индексов BRIN:", q("SELECT count(*) FROM pg_indexes WHERE schemaname = 'acd' AND indexdef LIKE '%USING brin%'"))
print("\n8. D27.2 «колоночные файлы в объектном хранилище»: файл строк —", repr(dv.files[0][1][:60].decode()), "… (JSON-строки, секрет строки «s» открытым текстом)")
print("\n9. D27.4 «литерал утверждения = ровно процитированные колонки — страж сверяет литерал с цитатой»: сверяется одна колонка предиката; уточнения и срок действия — нет (a13)")
print("\n10. D27.4 доказательство несёт «leaves = хэши остальных колонок» — все n листьев, а не путь в дереве ячеек: размер доказательства строки шириной 512 колонок =",
      len(canon(DatasetVersion('dst_w', T, 'w', [{'name': 'c%d' % i, 'type': 'INTEGER', 'marking': PUB} for i in range(512)], ['c0'], [{('c%d' % i): i for i in range(512)}]).evidence([0], []))), "знаков")

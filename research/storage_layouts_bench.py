#!/usr/bin/env python3
"""Измерение: сколько места занимает ОДИН И ТОТ ЖЕ набор ЕГРЮЛ-подобных записей в разных раскладках
PostgreSQL 16 и в колоночном сжатом виде. Цель — заменить оценку «в 2–3 раза больше» цифрами.

Раскладки:
  A  wide      — широкая типизированная таблица (одна строка на организацию), индексы по ОГРН/ИНН/названию/региону
  B  eav       — типизированный EAV (как SMW SQLStore3 / XWiki): таблица id + таблицы значений по типу, индексы (s,p) и (p,v)
  C  jsonb     — документ на организацию (jsonb) + GIN(jsonb_path_ops) + btree по ИНН и названию
  D  claims    — раскладка «хранилище утверждений» ядра: ТЕ ЖЕ колонки и те же PK/UNIQUE, что у ac.claims
                 и ac.claim_evidence (ddl_s1.sql), одно утверждение на атрибут, одно доказательство на утверждение
  E  bulk      — «массивный профиль» предложения D27: A + происхождение на уровне НАБОРА ДАННЫХ
                 (source_id набора + номер строки в нём), т.е. +12 байт на строку
  D2 claims   — то же ядро, но одно утверждение на ЗАПИСЬ (вся строка — литерал-объект), одно доказательство
  F  columnar* — ПРИБЛИЖЕНИЕ колоночного файла (Parquet/ClickHouse): каждая колонка A выгружена текстом и сжата
                 zlib-6 и xz-6 ПО СТОЛБЦАМ. Это не Parquet (pip недоступен в среде): нет словарного кодирования
                 и типовых кодеков, поэтому оценка СВЕРХУ для реального Parquet/ZSTD.

Все размеры — pg_total_relation_size (данные + индексы + TOAST). Запросы — лучшее из 3 на прогретом кэше.
Запуск: python3 storage_layouts_bench.py [N_ORGS] [--unique]   (по умолчанию 200000). Пишет storage_layouts_bench[_unique].out и .json.
После рецензии (R-09…R-12): индекс (subject, predicate) у D; раскладка D2; размеры «только данные» отдельно от «с индексами»;
режим --unique с уникальными названиями/адресами (словарная синтетика сжимается лучше реальных данных).
"""
import json, os, subprocess, sys, time, zlib, lzma
from pathlib import Path

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
UNIQUE = "--unique" in sys.argv          # R-11/R-12: уникальные названия/адреса (высокая энтропия)
N = int(ARGS[0]) if ARGS else 200_000
ATTRS = 26                       # атрибутов на организацию (см. список в SQL ниже)
DB = "bench_layouts"
HERE = Path(__file__).resolve().parent
OUT = HERE / ("storage_layouts_bench_unique.out" if UNIQUE else "storage_layouts_bench.out")
LOG = []


def say(s=""):
    print(s, flush=True); LOG.append(s)


def psql(sql, db=DB, tuples=True, timeout=3600):
    args = ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db]
    if tuples:
        args += ["-At"]
    r = subprocess.run(args, input=sql, text=True, capture_output=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:2000])
    return r.stdout.strip()


def size(rel, data_only=False):
    return int(psql(f"select {'pg_table_size' if data_only else 'pg_total_relation_size'}('{rel}')"))


def sizes(rels, data_only=False):
    return sum(size(r, data_only) for r in rels)


def ms(sql, runs=3):
    best = None
    for _ in range(runs):
        out = psql("EXPLAIN (ANALYZE, FORMAT JSON) " + sql)
        t = json.loads(out)[0]["Execution Time"]
        best = t if best is None else min(best, t)
    return best


def h(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024


# ----------------------------------------------------------------------------------------------- данные
U1 = "' '||upper(substr(md5(g::text),1,8))" if UNIQUE else "''"   # уникальный суффикс в названии
U2 = "'/'||substr(md5((g*3)::text),1,6)" if UNIQUE else "''"         # уникальный суффикс в адресе
GEN = f"""
SET client_min_messages = warning;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- словари для правдоподобных распределений (фамилии/имена/города/улицы/ОКВЭД), детерминированно
CREATE TABLE dict_sur AS SELECT i, (ARRAY['Иванов','Петров','Сидоров','Смирнов','Кузнецов','Попов','Васильев','Соколов','Михайлов','Новиков',
 'Фёдоров','Морозов','Волков','Алексеев','Лебедев','Семёнов','Егоров','Павлов','Козлов','Степанов','Николаев','Орлов','Андреев','Макаров','Никитин',
 'Захаров','Зайцев','Соловьёв','Борисов','Яковлев','Григорьев','Романов','Воробьёв','Сергеев','Кузьмин','Фролов','Александров','Дмитриев','Королёв','Гусев'])[i] s
 FROM generate_series(1,40) i;
CREATE TABLE dict_nam AS SELECT i, (ARRAY['Александр','Сергей','Дмитрий','Андрей','Алексей','Михаил','Иван','Владимир','Евгений','Максим','Николай','Юрий',
 'Елена','Ольга','Наталья','Татьяна','Ирина','Светлана','Марина','Анна'])[i] s FROM generate_series(1,20) i;
CREATE TABLE dict_pat AS SELECT i, (ARRAY['Александрович','Сергеевич','Дмитриевич','Андреевич','Алексеевич','Михайлович','Иванович','Владимирович','Евгеньевич','Николаевич',
 'Александровна','Сергеевна','Дмитриевна','Андреевна','Алексеевна','Михайловна','Ивановна','Владимировна','Евгеньевна','Николаевна'])[i] s FROM generate_series(1,20) i;
CREATE TABLE dict_city AS SELECT i, (ARRAY['Москва','Санкт-Петербург','Новосибирск','Екатеринбург','Казань','Нижний Новгород','Челябинск','Самара','Омск','Ростов-на-Дону',
 'Уфа','Красноярск','Воронеж','Пермь','Волгоград','Краснодар','Саратов','Тюмень','Тольятти','Ижевск','Барнаул','Ульяновск','Иркутск','Хабаровск','Ярославль',
 'Владивосток','Махачкала','Томск','Оренбург','Кемерово','Новокузнецк','Рязань','Астрахань','Набережные Челны','Пенза','Липецк','Киров','Чебоксары','Тула','Калининград'])[i] s
 FROM generate_series(1,40) i;
CREATE TABLE dict_str AS SELECT i, (ARRAY['Ленина','Советская','Мира','Центральная','Молодёжная','Школьная','Новая','Садовая','Лесная','Набережная','Октябрьская',
 'Гагарина','Пушкина','Кирова','Комсомольская','Первомайская','Заводская','Железнодорожная','Строителей','Победы'])[i] s FROM generate_series(1,20) i;
CREATE TABLE dict_word AS SELECT i, (ARRAY['Вектор','Альфа','Строй','Торг','Сервис','Пром','Транс','Гарант','Инвест','Групп','Техно','Проект','Ресурс','Стандарт','Профи',
 'Мастер','Логистик','Энерго','Агро','Мед','Консалт','Трейд','Авто','Дом','Регион','Север','Юг','Восток','Запад','Центр'])[i] s FROM generate_series(1,30) i;
CREATE TABLE dict_okved AS SELECT i, lpad((10+ (i*7)%80)::text,2,'0')||'.'||lpad(((i*13)%99)::text,2,'0')||'.'||((i*3)%9)::text s FROM generate_series(1,200) i;

-- A. широкая таблица. Распределения: ~55% действующих, 45% прекративших; ~75% ООО; региональная/городская кучность.
CREATE TABLE wide AS
SELECT
  (1000000000000 + g::bigint*7919 % 9000000000000)::bigint                                   AS ogrn,
  (1000000000 + (g::bigint*104729) % 8999999999)::bigint                                      AS inn,
  (770000000 + (g*31) % 99999)::int                                                   AS kpp,
  'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "'||w1.s||w2.s||CASE WHEN g%3=0 THEN '-'||(g%97)::text ELSE '' END||'"'||{U1} AS full_name,
  'ООО "'||w1.s||w2.s||CASE WHEN g%3=0 THEN '-'||(g%97)::text ELSE '' END||'"'||{U1}  AS short_name,
  (ARRAY[12300,12300,12300,12247,12267,20100,12165])[1 + g%7]::int                   AS opf_code,
  CASE WHEN g%20 < 11 THEN 'ACTIVE' WHEN g%20 < 18 THEN 'LIQUIDATED' ELSE 'REORGANIZED' END AS status,
  (date '2002-07-01' + (g*37 % 8800))::date                                           AS reg_date,
  CASE WHEN g%20 >= 11 THEN (date '2010-01-01' + (g*53 % 6000))::date END            AS liquidation_date,
  (1 + (g*17) % 89)::smallint                                                         AS region_code,
  c.s                                                                                 AS city,
  'ул. '||st.s                                                                        AS street,
  ((g*11)%200+1)::text || CASE WHEN g%4=0 THEN 'к'||(g%5+1)::text ELSE '' END||{U2}   AS house,
  CASE WHEN g%2=0 THEN ((g*7)%400+1)::text END                                        AS flat,
  ok.s                                                                                AS okved_main,
  ok2.s||';'||ok3.s                                                                   AS okved_extra,
  su.s                                                                                AS ceo_last_name,
  na.s                                                                                AS ceo_first_name,
  pa.s                                                                                AS ceo_patronymic,
  (500000000000 + (g::bigint*2654435761) % 499999999999)::bigint                              AS ceo_inn,
  (ARRAY['ГЕНЕРАЛЬНЫЙ ДИРЕКТОР','ДИРЕКТОР','ПРЕЗИДЕНТ','УПРАВЛЯЮЩИЙ'])[1 + CASE WHEN g%10=0 THEN 3 WHEN g%7=0 THEN 1 ELSE 0 END] AS ceo_position,
  (ARRAY[10000,10000,10000,20000,50000,100000,300000,1000000])[1 + g%8]::numeric(18,2) AS capital,
  (1 + (g*3)%4)::smallint                                                             AS founders_count,
  'info'||(g%1000)::text||'@'||lower(w1.s)||'.ru'                                     AS email,
  '+7'||(900+(g%99))::text||lpad(((g::bigint*7717)%10000000)::text,7,'0')                     AS phone,
  (7700 + (g*13)%99)::smallint                                                        AS tax_office,
  (2000000000000 + g::bigint*13)::bigint                                                      AS grn_last,
  (date '2020-01-01' + (g*5 % 2400))::date                                            AS updated_at
FROM generate_series(1,{N}) g
JOIN dict_word w1 ON w1.i = 1 + (g*3)%30 JOIN dict_word w2 ON w2.i = 1 + (g*5)%30
JOIN dict_city c ON c.i = 1 + (g*17)%40 JOIN dict_str st ON st.i = 1 + (g*23)%20
JOIN dict_okved ok ON ok.i = 1 + (g*29)%200 JOIN dict_okved ok2 ON ok2.i = 1 + (g*31)%200 JOIN dict_okved ok3 ON ok3.i = 1 + (g*37)%200
JOIN dict_sur su ON su.i = 1 + (g*41)%40 JOIN dict_nam na ON na.i = 1 + (g*43)%20 JOIN dict_pat pa ON pa.i = 1 + (g*47)%20;
ALTER TABLE wide ADD PRIMARY KEY (ogrn);
CREATE INDEX wide_inn ON wide (inn);
CREATE INDEX wide_name ON wide (full_name text_pattern_ops);
CREATE INDEX wide_region_status ON wide (region_code, status);
VACUUM ANALYZE wide;
"""

# B. типизированный EAV ---------------------------------------------------------------------------
EAV = """
CREATE TABLE eav_ids (s bigint PRIMARY KEY);
INSERT INTO eav_ids SELECT ogrn FROM wide;
CREATE TABLE eav_props (p smallint PRIMARY KEY, name text UNIQUE, dtype text);
INSERT INTO eav_props VALUES
 (1,'inn','int'),(2,'kpp','int'),(3,'full_name','text'),(4,'short_name','text'),(5,'opf_code','int'),(6,'status','text'),(7,'reg_date','date'),
 (8,'liquidation_date','date'),(9,'region_code','int'),(10,'city','text'),(11,'street','text'),(12,'house','text'),(13,'flat','text'),
 (14,'okved_main','text'),(15,'okved_extra','text'),(16,'ceo_last_name','text'),(17,'ceo_first_name','text'),(18,'ceo_patronymic','text'),
 (19,'ceo_inn','int'),(20,'ceo_position','text'),(21,'capital','num'),(22,'founders_count','int'),(23,'email','text'),(24,'phone','text'),
 (25,'tax_office','int'),(26,'grn_last','int'),(27,'updated_at','date');
CREATE TABLE eav_text (s bigint NOT NULL, p smallint NOT NULL, v text NOT NULL);
CREATE TABLE eav_int  (s bigint NOT NULL, p smallint NOT NULL, v bigint NOT NULL);
CREATE TABLE eav_date (s bigint NOT NULL, p smallint NOT NULL, v date NOT NULL);
CREATE TABLE eav_num  (s bigint NOT NULL, p smallint NOT NULL, v numeric NOT NULL);
INSERT INTO eav_int SELECT ogrn,1,inn FROM wide UNION ALL SELECT ogrn,2,kpp FROM wide UNION ALL SELECT ogrn,5,opf_code FROM wide
  UNION ALL SELECT ogrn,9,region_code FROM wide UNION ALL SELECT ogrn,19,ceo_inn FROM wide UNION ALL SELECT ogrn,22,founders_count FROM wide
  UNION ALL SELECT ogrn,25,tax_office FROM wide UNION ALL SELECT ogrn,26,grn_last FROM wide;
INSERT INTO eav_text SELECT ogrn,3,full_name FROM wide UNION ALL SELECT ogrn,4,short_name FROM wide UNION ALL SELECT ogrn,6,status FROM wide
  UNION ALL SELECT ogrn,10,city FROM wide UNION ALL SELECT ogrn,11,street FROM wide UNION ALL SELECT ogrn,12,house FROM wide
  UNION ALL SELECT ogrn,13,flat FROM wide WHERE flat IS NOT NULL UNION ALL SELECT ogrn,14,okved_main FROM wide UNION ALL SELECT ogrn,15,okved_extra FROM wide
  UNION ALL SELECT ogrn,16,ceo_last_name FROM wide UNION ALL SELECT ogrn,17,ceo_first_name FROM wide UNION ALL SELECT ogrn,18,ceo_patronymic FROM wide
  UNION ALL SELECT ogrn,20,ceo_position FROM wide UNION ALL SELECT ogrn,23,email FROM wide UNION ALL SELECT ogrn,24,phone FROM wide;
INSERT INTO eav_date SELECT ogrn,7,reg_date FROM wide UNION ALL SELECT ogrn,8,liquidation_date FROM wide WHERE liquidation_date IS NOT NULL
  UNION ALL SELECT ogrn,27,updated_at FROM wide;
INSERT INTO eav_num SELECT ogrn,21,capital FROM wide;
CREATE INDEX eav_text_sp ON eav_text (s,p); CREATE INDEX eav_text_pv ON eav_text (p, v text_pattern_ops);
CREATE INDEX eav_int_sp  ON eav_int (s,p);  CREATE INDEX eav_int_pv  ON eav_int (p, v);
CREATE INDEX eav_date_sp ON eav_date (s,p); CREATE INDEX eav_date_pv ON eav_date (p, v);
CREATE INDEX eav_num_sp  ON eav_num (s,p);  CREATE INDEX eav_num_pv  ON eav_num (p, v);
VACUUM ANALYZE eav_ids; VACUUM ANALYZE eav_text; VACUUM ANALYZE eav_int; VACUUM ANALYZE eav_date; VACUUM ANALYZE eav_num;
"""

# C. jsonb-документ --------------------------------------------------------------------------------
JSONB = """
CREATE TABLE docs AS SELECT ogrn AS id, jsonb_strip_nulls(to_jsonb(w) - 'ogrn') AS doc FROM wide w;
ALTER TABLE docs ADD PRIMARY KEY (id);
CREATE INDEX docs_gin ON docs USING gin (doc jsonb_path_ops);
CREATE INDEX docs_inn ON docs ((doc->>'inn'));
CREATE INDEX docs_name ON docs ((doc->>'full_name') text_pattern_ops);
VACUUM ANALYZE docs;
"""

# D. раскладка ядра (ac.claims + ac.claim_evidence, те же колонки, PK и UNIQUE) ---------------------
CLAIMS = """
-- источники: один XML-файл выгрузки ФНС на 1000 организаций (как в реальных ZIP ФНС: до 1000 записей в файле)
CREATE TABLE src (n int PRIMARY KEY, source_id text NOT NULL);
INSERT INTO src SELECT g, 'src:sha256:'||encode(sha256(convert_to('egrul-file-'||g, 'UTF8')),'hex') FROM generate_series(0, 999) g;

CREATE TABLE claims (
  claim_id       text PRIMARY KEY,
  project_id     text NOT NULL,
  tenant_id      text NOT NULL,
  subject        text NOT NULL,
  predicate      text NOT NULL,
  object_entity  text,
  produced_kind  text NOT NULL,
  recorded_at    timestamptz NOT NULL,
  ingested_at    timestamptz NOT NULL DEFAULT now(),
  marking        jsonb NOT NULL,
  body           jsonb NOT NULL,
  UNIQUE (project_id, claim_id),
  UNIQUE (claim_id, tenant_id)
);
CREATE TABLE claim_evidence (
  claim_id      text NOT NULL,
  ord           integer NOT NULL,
  tenant_id     text NOT NULL,
  source_id     text NOT NULL,
  span_start    integer NOT NULL,
  span_end      integer NOT NULL,
  quote_sha256  text NOT NULL,
  quote         text,
  graph_node    jsonb,
  PRIMARY KEY (claim_id, ord)
);
-- одно утверждение на атрибут: subject = ent_<ОГРН>, predicate = egrul.<поле>, literal = значение, одно доказательство
-- (цитата = фрагмент XML вида <СвЮЛ ОГРН="…" ИНН="…"/>…), marking PUBLIC, produced_by PIPELINE
CREATE TABLE flat AS
SELECT w.ogrn, kv.key AS predicate, kv.value AS val, (w.ogrn % 1000000)::int AS rowno
FROM wide w, LATERAL jsonb_each(jsonb_strip_nulls(to_jsonb(w) - 'ogrn')) kv;

INSERT INTO claims (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, ingested_at, marking, body)
SELECT c.claim_id, 'prj_egrul', 'tnt_demo', c.subject, c.predicate, NULL, 'PIPELINE', c.recorded_at, c.recorded_at, c.marking,
       jsonb_build_object('claim_id', c.claim_id, 'project_id', 'prj_egrul', 'tenant_id', 'tnt_demo', 'subject', c.subject,
         'predicate', c.predicate, 'object', jsonb_build_object('literal', jsonb_build_object('type', c.ltype, 'value', c.val)),
         'produced_by', jsonb_build_object('kind','PIPELINE','id','egrul-loader/1.0'),
         'recorded_at', to_char(c.recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'marking', c.marking,
         'evidence', jsonb_build_array(jsonb_build_object('source_id', c.source_id,
             'span', jsonb_build_object('start', c.span_start, 'end', c.span_end), 'quote_sha256', c.qsha, 'quote', c.quote)))
FROM (
  SELECT 'clm:sha256:'||encode(sha256(convert_to('egrul|'||f.ogrn||'|'||f.predicate||'|'||f.val::text, 'UTF8')),'hex') AS claim_id,
         'ent_'||f.ogrn AS subject, 'egrul.'||f.predicate AS predicate, f.val,
         CASE jsonb_typeof(f.val) WHEN 'number' THEN 'NUMBER' ELSE CASE WHEN f.predicate LIKE '%date%' OR f.predicate='updated_at' THEN 'DATE' ELSE 'STRING' END END AS ltype,
         timestamptz '2026-10-01 00:00:00+00' + (f.rowno % 86400) * interval '1 second' AS recorded_at,
         jsonb_build_object('level','PUBLIC','categories',jsonb_build_array()) AS marking,
         s.source_id, (f.rowno % 1000) * 900 AS span_start, (f.rowno % 1000) * 900 + 120 AS span_end,
         encode(sha256(convert_to('<СвЮЛ ОГРН="'||f.ogrn||'" '||f.predicate||'="'||(f.val #>> '{}')||'"/>', 'UTF8')),'hex') AS qsha,
         '<СвЮЛ ОГРН="'||f.ogrn||'" '||f.predicate||'="'||(f.val #>> '{}')||'"/>' AS quote
  FROM flat f JOIN src s ON s.n = (f.rowno / 1000) % (SELECT count(*) FROM src)
) c;
INSERT INTO claim_evidence (claim_id, ord, tenant_id, source_id, span_start, span_end, quote_sha256, quote, graph_node)
SELECT claim_id, 0, tenant_id, body->'evidence'->0->>'source_id', (body->'evidence'->0->'span'->>'start')::int,
       (body->'evidence'->0->'span'->>'end')::int, body->'evidence'->0->>'quote_sha256', body->'evidence'->0->>'quote', NULL
FROM claims;
-- индексы, которые реально нужны проекциям ядра: по субъекту и по (предикат, литерал) для поиска
CREATE INDEX claims_subject_pred ON claims (subject, predicate);
CREATE INDEX claims_pred_val ON claims (predicate, (body->'object'->'literal'->>'value') text_pattern_ops);
DROP TABLE flat;
VACUUM ANALYZE claims; VACUUM ANALYZE claim_evidence;
-- D2: одно утверждение на ЗАПИСЬ (вся строка — один литерал-объект), одно доказательство (вся строка как цитата)
-- N-06 (рецензия, раунд 2): НЕ наследовать индексы D (иначе D2 получает btree по тексту всей строки); PK/UNIQUE как у ac.claims
CREATE TABLE claims_rec (LIKE claims INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE claims_rec ADD PRIMARY KEY (claim_id), ADD UNIQUE (project_id, claim_id), ADD UNIQUE (claim_id, tenant_id);
CREATE TABLE claim_evidence_rec (LIKE claim_evidence INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE claim_evidence_rec ADD PRIMARY KEY (claim_id, ord);
INSERT INTO claims_rec (claim_id, project_id, tenant_id, subject, predicate, object_entity, produced_kind, recorded_at, ingested_at, marking, body)
SELECT c.claim_id, 'prj_egrul', 'tnt_demo', c.subject, 'egrul.record', NULL, 'PIPELINE', c.recorded_at, c.recorded_at, c.marking,
       jsonb_build_object('claim_id', c.claim_id, 'project_id', 'prj_egrul', 'tenant_id', 'tnt_demo', 'subject', c.subject,
         'predicate', 'egrul.record', 'object', jsonb_build_object('literal', jsonb_build_object('type', 'OBJECT', 'value', c.rowdoc)),
         'produced_by', jsonb_build_object('kind','PIPELINE','id','egrul-loader/1.0'),
         'recorded_at', to_char(c.recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'marking', c.marking,
         'evidence', jsonb_build_array(jsonb_build_object('source_id', c.source_id,
             'span', jsonb_build_object('start', c.span_start, 'end', c.span_end), 'quote_sha256', c.qsha, 'quote', c.quote)))
FROM (
  SELECT 'clm:sha256:'||encode(sha256(convert_to('egrul|'||w.ogrn||'|record', 'UTF8')),'hex') AS claim_id,
         'ent_'||w.ogrn AS subject, jsonb_strip_nulls(to_jsonb(w) - 'ogrn') AS rowdoc,
         timestamptz '2026-10-01 00:00:00+00' + (w.ogrn % 86400) * interval '1 second' AS recorded_at,
         jsonb_build_object('level','PUBLIC','categories',jsonb_build_array()) AS marking,
         s.source_id, ((w.ogrn % 1000000) % 1000) * 900 AS span_start, ((w.ogrn % 1000000) % 1000) * 900 + 600 AS span_end,
         encode(sha256(convert_to((jsonb_strip_nulls(to_jsonb(w) - 'ogrn'))::text, 'UTF8')),'hex') AS qsha,
         (jsonb_strip_nulls(to_jsonb(w) - 'ogrn'))::text AS quote
  FROM wide w JOIN src s ON s.n = ((w.ogrn % 1000000) / 1000) % (SELECT count(*) FROM src)
) c;
INSERT INTO claim_evidence_rec (claim_id, ord, tenant_id, source_id, span_start, span_end, quote_sha256, quote, graph_node)
SELECT claim_id, 0, tenant_id, body->'evidence'->0->>'source_id', (body->'evidence'->0->'span'->>'start')::int,
       (body->'evidence'->0->'span'->>'end')::int, body->'evidence'->0->>'quote_sha256', body->'evidence'->0->>'quote', NULL
FROM claims_rec;
CREATE INDEX claims_rec_subject_pred ON claims_rec (subject, predicate);
CREATE INDEX claims_rec_inn ON claims_rec ((body->'object'->'literal'->'value'->>'inn'));
CREATE INDEX claims_rec_gin ON claims_rec USING gin ((body->'object'->'literal'->'value') jsonb_path_ops);
CREATE INDEX claims_rec_name ON claims_rec ((body->'object'->'literal'->'value'->>'full_name') text_pattern_ops);
VACUUM ANALYZE claims_rec; VACUUM ANALYZE claim_evidence_rec;
"""

# E. массивный профиль D27: широкая таблица + происхождение на уровне набора данных ----------------
BULK = """
CREATE TABLE bulk AS SELECT w.*, ((ogrn % 1000000) / 1000)::int AS source_n, (ogrn % 1000000)::int AS row_no FROM wide w;
ALTER TABLE bulk ADD PRIMARY KEY (ogrn);
CREATE INDEX bulk_inn ON bulk (inn); CREATE INDEX bulk_name ON bulk (full_name text_pattern_ops); CREATE INDEX bulk_region_status ON bulk (region_code, status);
VACUUM ANALYZE bulk;
"""


def columnar_proxy():
    cols = psql("select string_agg(column_name, ',' order by ordinal_position) from information_schema.columns where table_name='wide'").split(",")
    tot = {"zlib6": 0, "xz6": 0, "raw": 0}
    for c in cols:
        data = psql(f"COPY (SELECT {c} FROM wide ORDER BY ogrn) TO STDOUT").encode()
        tot["raw"] += len(data)
        tot["zlib6"] += len(zlib.compress(data, 6))
        tot["xz6"] += len(lzma.compress(data, preset=6))
    return tot


def main():
    t0 = time.time()
    psql(f"DROP DATABASE IF EXISTS {DB}", db="postgres"); psql(f"CREATE DATABASE {DB}", db="postgres")
    say(f"# Измерение раскладок хранения — {N} организаций × {ATTRS} атрибутов (PostgreSQL 16)\n")
    say(f"Старт {time.strftime('%Y-%m-%d %H:%M:%S')}")
    psql(GEN); say(f"A wide готово ({time.time()-t0:.0f} c)")
    psql(EAV); say(f"B eav готово ({time.time()-t0:.0f} c)")
    psql(JSONB); say(f"C jsonb готово ({time.time()-t0:.0f} c)")
    psql(CLAIMS, timeout=7200); say(f"D claims готово ({time.time()-t0:.0f} c)")
    psql(BULK); say(f"E bulk готово ({time.time()-t0:.0f} c)")

    res, dat = {}, {}
    groups = {"A wide": ["wide"], "B eav": ["eav_ids", "eav_text", "eav_int", "eav_date", "eav_num"], "C jsonb": ["docs"],
              "D claims (утверждение на поле)": ["claims", "claim_evidence"], "D2 claims (утверждение на запись)": ["claims_rec", "claim_evidence_rec"],
              "E bulk": ["bulk"]}
    for k, rels in groups.items():
        res[k] = sizes(rels); dat[k] = sizes(rels, True)
    col = columnar_proxy()
    res["F columnar* zlib6"] = col["zlib6"]; res["F columnar* xz6"] = col["xz6"]; dat["F columnar* zlib6"] = col["zlib6"]; dat["F columnar* xz6"] = col["xz6"]
    nclaims = int(psql("select count(*) from claims"))
    say(f"\nрежим: {'уникальные названия/адреса (высокая энтропия)' if UNIQUE else 'словарные значения (низкая энтропия)'}")
    say(f"утверждений в D: {nclaims} (= атрибутов с непустым значением); в D2: {N}; текст всех колонок A без сжатия: {h(col['raw'])}\n")
    say("| Раскладка | Только данные | × к A (данные) | Данные + индексы | × к A (всего) | На организацию (всего) | Экстраполяция на 8 млн (всего) |")
    say("|---|---|---|---|---|---|---|")
    base, based = res["A wide"], dat["A wide"]
    for k, v in res.items():
        say(f"| {k} | {h(dat[k])} | {dat[k]/based:.2f}× | {h(v)} | {v/base:.2f}× | {v/N:.0f} B | {h(v/N*8_000_000)} |")

    say("\nДетали D (хранилище утверждений):")
    for r in ("claims", "claim_evidence", "claims_rec", "claim_evidence_rec"):
        say(f"  {r}: таблица {h(int(psql(f'select pg_table_size(%s)' % repr(r))))}, индексы {h(int(psql(f'select pg_indexes_size(%s)' % repr(r))))}, всего {h(size(r))}")
    say("Детали B (EAV): " + ", ".join(f"{r} {h(size(r))}" for r in ("eav_ids", "eav_text", "eav_int", "eav_date", "eav_num")))

    # ---------------------------------------------------------------- запросы
    inn = psql("select inn from wide where ogrn = (select ogrn from wide order by ogrn offset 777 limit 1)")
    say("\nЗапросы (лучшее из 3, мс):")
    say("| Запрос | A wide | B eav | C jsonb | D claims (поле) | D2 claims (запись) |")
    say("|---|---|---|---|---|---|")
    q = {}
    q["точечный поиск по ИНН"] = (
        f"select * from wide where inn = {inn}",
        f"select s from eav_int where p=1 and v={inn}",
        f"select * from docs where doc->>'inn' = '{inn}'",
        f"select subject from claims where predicate='egrul.inn' and body->'object'->'literal'->>'value' = '{inn}'",
        f"select subject from claims_rec where body->'object'->'literal'->'value'->>'inn' = '{inn}'")
    q["карточка организации по ОГРН (все атрибуты)"] = (
        "select * from wide where ogrn = (select ogrn from wide order by ogrn offset 777 limit 1)",
        "select p, v::text from eav_text where s=(select s from eav_ids order by s offset 777 limit 1) union all select p, v::text from eav_int where s=(select s from eav_ids order by s offset 777 limit 1) "
        "union all select p, v::text from eav_date where s=(select s from eav_ids order by s offset 777 limit 1) union all select p, v::text from eav_num where s=(select s from eav_ids order by s offset 777 limit 1)",
        "select doc from docs where id = (select id from docs order by id offset 777 limit 1)",
        "select predicate, body->'object'->'literal'->>'value' from claims where subject = 'ent_'||(select ogrn from wide order by ogrn offset 777 limit 1)",
        "select body->'object'->'literal'->'value' from claims_rec where subject = 'ent_'||(select ogrn from wide order by ogrn offset 777 limit 1)")
    q["действующие в регионе 77, count"] = (
        "select count(*) from wide where region_code=77 and status='ACTIVE'",
        "select count(*) from eav_int r join eav_text s on s.s=r.s and s.p=6 and s.v='ACTIVE' where r.p=9 and r.v=77",
        "select count(*) from docs where doc @> '{\"region_code\":77,\"status\":\"ACTIVE\"}'",
        "select count(*) from claims r join claims s on s.subject=r.subject and s.predicate='egrul.status' and s.body->'object'->'literal'->>'value'='ACTIVE' "
        "where r.predicate='egrul.region_code' and r.body->'object'->'literal'->>'value'='77'",
        "select count(*) from claims_rec where body->'object'->'literal'->'value' @> '{\"region_code\":77,\"status\":\"ACTIVE\"}'")
    q["название по префиксу, 100 строк"] = (
        "select ogrn from wide where full_name like 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"ВекторАльфа%' limit 100",
        "select s from eav_text where p=3 and v like 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"ВекторАльфа%' limit 100",
        "select id from docs where doc->>'full_name' like 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"ВекторАльфа%' limit 100",
        "select subject from claims where predicate='egrul.full_name' and body->'object'->'literal'->>'value' like 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"ВекторАльфа%' limit 100",
        "select subject from claims_rec where body->'object'->'literal'->'value'->>'full_name' like 'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"ВекторАльфа%' limit 100")
    for name, sqls in q.items():
        say(f"| {name} | " + " | ".join(f"{ms(s):.2f}" for s in sqls) + " |")

    say(f"\nГотово за {time.time()-t0:.0f} c; база {DB} оставлена для проверки.")
    OUT.write_text("\n".join(LOG) + "\n", encoding="utf-8")
    (HERE / ("storage_layouts_bench_unique.json" if UNIQUE else "storage_layouts_bench.json")).write_text(json.dumps({"N": N, "unique": UNIQUE, "attrs": ATTRS, "claims": nclaims, "sizes": res, "data_only": dat, "columnar_raw": col["raw"]},
                                                                ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

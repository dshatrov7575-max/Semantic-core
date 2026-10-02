-- Архитектура семантики — S9 (цикл 9): «Схема как данные» (D27.1), core-ontology/0.3.
-- Что хранится:
--   * три вида определений схемы tenant: классы (ac.class_defs), связи между классами (ac.link_defs), типы
--     идентификаторов (ac.identifier_defs). Определение — цепочка версий 1..n ключа (tenant, id); версия несёт свою
--     запись журнала (кто, когда, что изменено) — определения без записи журнала не существует; журнал целиком —
--     ac.schema_journal (представление над версиями);
--   * производное, которое пишет только база: замыкание иерархии классов (ac.class_closure) и владельцы предикатов
--     tenant (ac.schema_predicates: предикат «x.…» объявляет ровно одно определение).
-- Правила (каждое — то же, что в validator.py; «база выше заявления»):
--   * версия отличается от предыдущей ровно одним допустимым изменением, и тип изменения ВЫВОДИТСЯ базой из разницы
--     (ac.schema_change_of), а не берётся на слово; вывод из употребления окончателен;
--   * время версии ставит база (после блокировки схемы tenant); исторический импорт — только ac_migrator, после печати;
--   * ссылки схемы не выходят за tenant: чужой класс для пишущего неотличим от несуществующего;
--   * принадлежность сущности классу — утверждение schema.is_a; утверждение с предикатом tenant «x.…» проверяется по
--     схеме на момент записи: предикат объявлен, субъект — экземпляр класса (или его наследника), значение — того
--     типа/единицы/схемы, объект связи — экземпляр класса-диапазона, маркировка не шире маркировки определения;
--   * «задним числом» старую схему не выбрать: живая запись утверждения отвергается, если определение, по которому
--     оно проверяется, менялось после заявленного времени записи утверждения;
--   * десятый корневой тип THING (ac.entities, ключи идентичности — как у понятия).
-- Applied after ddl_s5b.sql.

DO $$ BEGIN CREATE ROLE ac_modeler NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;   -- «Конструктор модели»
GRANT USAGE ON SCHEMA ac TO ac_modeler;

-- ---------------------------------------------------------------- форма значений (то же, что JSON Schema ядра)
-- NonEmpty: 1..2000 знаков, без управляющих, хотя бы один не пробельный (список пробельных — как у Python \s)
CREATE FUNCTION ac.text_ok(t text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT coalesce(char_length(t) BETWEEN 1 AND 2000 AND t !~ '[\u0001-\u001F\u007F]'
     AND t ~ '[^ \u0085   -     　]', false) $$;

CREATE FUNCTION ac.root_type_ok(t text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT t IN ('PERSON','ORGANIZATION','REAL_ESTATE','MOVABLE_PROPERTY','EVENT','CONFLICT','EQUIPMENT','EQUIPMENT_MODEL','CONCEPT','THING') $$;

-- атрибуты класса: массив объектов {predicate_id, name, value_type, cardinality, required[, unit][, scheme]}
CREATE FUNCTION ac.attributes_ok(a jsonb) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT coalesce(jsonb_typeof(a) = 'array' AND jsonb_array_length(a) <= 200 AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(a) x WHERE NOT coalesce(
          jsonb_typeof(x) = 'object'
      AND NOT EXISTS (SELECT 1 FROM jsonb_object_keys(x) k
                      WHERE k NOT IN ('predicate_id', 'name', 'value_type', 'cardinality', 'required', 'unit', 'scheme'))
      AND jsonb_typeof(x->'predicate_id') = 'string' AND x->>'predicate_id' ~ '^x\.[a-z][a-z_]{1,40}$'
      AND jsonb_typeof(x->'name') = 'string' AND ac.text_ok(x->>'name')
      AND jsonb_typeof(x->'value_type') = 'string'
      AND x->>'value_type' IN ('STRING', 'DATE', 'QUANTITY', 'MONEY', 'IDENTIFIER', 'BOOLEAN', 'INTEGER')
      AND jsonb_typeof(x->'cardinality') = 'string' AND x->>'cardinality' IN ('ONE', 'MANY')
      AND jsonb_typeof(x->'required') = 'boolean'
      AND (x ? 'unit') = (x->>'value_type' = 'QUANTITY')
      AND (NOT x ? 'unit' OR (jsonb_typeof(x->'unit') = 'string' AND x->>'unit' ~ '^[A-Za-z%/0-9]{1,16}$'))
      AND (x ? 'scheme') = (x->>'value_type' = 'IDENTIFIER')
      AND (NOT x ? 'scheme' OR (jsonb_typeof(x->'scheme') = 'string' AND x->>'scheme' ~ '^[a-z][a-z0-9.]{1,40}$')), false)), false) $$;

-- формат идентификатора — данные, не регулярное выражение: список сегментов {chars,min,max} | {lit}
CREATE FUNCTION ac.format_ok(f jsonb) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT coalesce(jsonb_typeof(f) = 'array' AND jsonb_array_length(f) BETWEEN 1 AND 16 AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(f) x WHERE NOT coalesce(
      jsonb_typeof(x) = 'object' AND (
        ((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(x) k) = ARRAY['chars', 'max', 'min']
          AND jsonb_typeof(x->'chars') = 'string' AND x->>'chars' IN ('DIGIT', 'UPPER', 'LOWER', 'ALNUM', 'ALNUM_UPPER')
          AND jsonb_typeof(x->'min') = 'number' AND x->>'min' ~ '^[0-9]{1,2}$' AND (x->>'min')::int BETWEEN 1 AND 64
          AND jsonb_typeof(x->'max') = 'number' AND x->>'max' ~ '^[0-9]{1,2}$' AND (x->>'max')::int BETWEEN 1 AND 64
          AND (x->>'min')::int <= (x->>'max')::int)
        OR ((SELECT array_agg(k) FROM jsonb_object_keys(x) k) = ARRAY['lit']
          AND jsonb_typeof(x->'lit') = 'string' AND x->>'lit' ~ '^[A-Za-z0-9_./-]$')), false))
    AND (SELECT sum(coalesce((x->>'max')::int, 1)) FROM jsonb_array_elements(f) x) <= 64, false) $$;

-- формат -> закреплённое с двух сторон выражение (validator.format_regex: тот же перевод, те же строки)
CREATE FUNCTION ac.format_regex(f jsonb) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT '^(?:' || string_agg(CASE WHEN x ? 'chars'
             THEN CASE x->>'chars' WHEN 'DIGIT' THEN '[0-9]' WHEN 'UPPER' THEN '[A-Z]' WHEN 'LOWER' THEN '[a-z]'
                                   WHEN 'ALNUM' THEN '[A-Za-z0-9]' WHEN 'ALNUM_UPPER' THEN '[A-Z0-9]' END
                  || '{' || (x->>'min') || ',' || (x->>'max') || '}'
             ELSE CASE WHEN x->>'lit' ~ '^[A-Za-z0-9_]$' THEN x->>'lit' ELSE '\' || (x->>'lit') END END, '' ORDER BY n) || ')$'
  FROM jsonb_array_elements(f) WITH ORDINALITY AS e(x, n) $$;

-- ---------------------------------------------------------------- определения (append-only; версия = строка)
CREATE TABLE ac.class_defs (
  tenant_id        text NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  class_id         text NOT NULL CHECK (class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  version          integer NOT NULL CHECK (version BETWEEN 1 AND 9999),
  root_type        text NOT NULL CHECK (ac.root_type_ok(root_type)),
  name             text NOT NULL CHECK (ac.text_ok(name)),
  parent_class_id  text CHECK (parent_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  is_abstract      boolean NOT NULL DEFAULT false,
  deprecated       boolean NOT NULL DEFAULT false,
  attributes       jsonb NOT NULL DEFAULT '[]' CHECK (ac.attributes_ok(attributes)),
  marking          jsonb NOT NULL CONSTRAINT class_defs_marking_shape CHECK (ac.marking_ok(marking)),
  change_type      text NOT NULL,
  description      text NOT NULL CHECK (ac.text_ok(description)),
  migration_note   text CHECK (migration_note IS NULL OR ac.text_ok(migration_note)),
  recorded_at      timestamptz NOT NULL,
  recorded_by      text NOT NULL CHECK (recorded_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  PRIMARY KEY (tenant_id, class_id, version)
);

CREATE TABLE ac.link_defs (
  tenant_id        text NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  link_id          text NOT NULL CHECK (link_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  version          integer NOT NULL CHECK (version BETWEEN 1 AND 9999),
  predicate_id     text NOT NULL CHECK (predicate_id ~ '^x\.[a-z][a-z_]{1,40}$'),
  name             text NOT NULL CHECK (ac.text_ok(name)),
  domain_class_id  text NOT NULL CHECK (domain_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  range_class_id   text NOT NULL CHECK (range_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  cardinality      text NOT NULL CHECK (cardinality IN ('ONE', 'MANY')),
  is_symmetric     boolean NOT NULL DEFAULT false,
  deprecated       boolean NOT NULL DEFAULT false,
  marking          jsonb NOT NULL CONSTRAINT link_defs_marking_shape CHECK (ac.marking_ok(marking)),
  change_type      text NOT NULL,
  description      text NOT NULL CHECK (ac.text_ok(description)),
  migration_note   text CHECK (migration_note IS NULL OR ac.text_ok(migration_note)),
  recorded_at      timestamptz NOT NULL,
  recorded_by      text NOT NULL CHECK (recorded_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  PRIMARY KEY (tenant_id, link_id, version),
  CONSTRAINT link_symmetric_one_class CHECK (NOT is_symmetric OR domain_class_id = range_class_id)      -- SCHEMA_DEF_INVALID
);

CREATE TABLE ac.identifier_defs (
  tenant_id             text NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  idef_id               text NOT NULL CHECK (idef_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  version               integer NOT NULL CHECK (version BETWEEN 1 AND 9999),
  scheme                text NOT NULL CHECK (scheme ~ '^(ru\.inn|ru\.ogrn|ru\.ogrnip|imo|x\.[a-z][a-z0-9]{1,38})$'),
  name                  text NOT NULL CHECK (ac.text_ok(name)),
  applies_to_root_type  text NOT NULL CHECK (ac.root_type_ok(applies_to_root_type)),
  strength              text NOT NULL CHECK (strength IN ('STRONG', 'WEAK')),
  priority              integer NOT NULL CHECK (priority BETWEEN 1 AND 999),
  format                jsonb CONSTRAINT identifier_format_shape CHECK (format IS NULL OR ac.format_ok(format)),
  deprecated            boolean NOT NULL DEFAULT false,
  marking               jsonb NOT NULL CONSTRAINT identifier_defs_marking_shape CHECK (ac.marking_ok(marking)),
  change_type           text NOT NULL,
  description           text NOT NULL CHECK (ac.text_ok(description)),
  migration_note        text CHECK (migration_note IS NULL OR ac.text_ok(migration_note)),
  recorded_at           timestamptz NOT NULL,
  recorded_by           text NOT NULL CHECK (recorded_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  PRIMARY KEY (tenant_id, idef_id, version),
  -- схема tenant описывается форматом; встроенную проверяет ядро (контрольные цифры), она всегда сильная
  CONSTRAINT identifier_tenant_scheme_has_format CHECK ((scheme ~ '^x\.') = (format IS NOT NULL)),
  CONSTRAINT identifier_builtin_is_strong CHECK (scheme ~ '^x\.' OR strength = 'STRONG')
);
-- одна схема на корневой тип и один приоритет на корневой тип в tenant (страж даёт код; индекс — страховка)
CREATE UNIQUE INDEX identifier_defs_one_scheme ON ac.identifier_defs (tenant_id, scheme, applies_to_root_type) WHERE version = 1;
CREATE UNIQUE INDEX identifier_defs_one_priority ON ac.identifier_defs (tenant_id, applies_to_root_type, priority) WHERE version = 1;

-- ---------------------------------------------------------------- производное: пишет только база
CREATE TABLE ac.class_closure (
  tenant_id      text NOT NULL,
  ancestor_id    text NOT NULL,
  descendant_id  text NOT NULL,
  depth          integer NOT NULL CHECK (depth >= 0),
  PRIMARY KEY (tenant_id, ancestor_id, descendant_id)
);
CREATE INDEX class_closure_desc ON ac.class_closure (tenant_id, descendant_id);

CREATE TABLE ac.schema_predicates (
  tenant_id     text NOT NULL,
  predicate_id  text NOT NULL,
  definer_kind  text NOT NULL CHECK (definer_kind IN ('ClassDef', 'LinkDef')),
  definer_id    text NOT NULL,
  PRIMARY KEY (tenant_id, predicate_id)                   -- у предиката tenant один определитель: первый
);

-- ---------------------------------------------------------------- схема на момент t
CREATE FUNCTION ac.class_at(tn text, cid text, t timestamptz) RETURNS ac.class_defs LANGUAGE sql STABLE AS $$
  SELECT * FROM ac.class_defs WHERE tenant_id = tn AND class_id = cid AND recorded_at <= t ORDER BY version DESC LIMIT 1 $$;
CREATE FUNCTION ac.link_at(tn text, lid text, t timestamptz) RETURNS ac.link_defs LANGUAGE sql STABLE AS $$
  SELECT * FROM ac.link_defs WHERE tenant_id = tn AND link_id = lid AND recorded_at <= t ORDER BY version DESC LIMIT 1 $$;
-- тип идентификатора схемы для корневого типа, действующий на t (выведенный из употребления — не действует)
CREATE FUNCTION ac.idef_at(tn text, sch text, root text, t timestamptz) RETURNS ac.identifier_defs LANGUAGE sql STABLE AS $$
  SELECT v.* FROM ac.identifier_defs f
  CROSS JOIN LATERAL (SELECT * FROM ac.identifier_defs x WHERE x.tenant_id = f.tenant_id AND x.idef_id = f.idef_id
                      AND x.recorded_at <= t ORDER BY x.version DESC LIMIT 1) v
  WHERE f.tenant_id = tn AND f.scheme = sch AND f.applies_to_root_type = root AND f.version = 1 AND NOT v.deprecated $$;

-- единственное допустимое отличие версии от предыдущей (validator.schema_change_of); NULL — не одно допустимое
CREATE FUNCTION ac.schema_change_of(kind text, prev jsonb, cur jsonb) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE changed text[]; suffix text := CASE kind WHEN 'ClassDef' THEN 'CLASS' WHEN 'LinkDef' THEN 'LINK' ELSE 'IDENTIFIER' END;
        added int; removed int; diff text[]; pa jsonb; ca jsonb;
BEGIN
  IF prev IS NULL THEN
    RETURN CASE kind WHEN 'ClassDef' THEN 'ADD_CLASS' WHEN 'LinkDef' THEN 'ADD_LINK' ELSE 'ADD_IDENTIFIER' END;
  END IF;
  IF (prev->>'deprecated')::boolean THEN
    RETURN NULL;                                                          -- вывод из употребления окончателен
  END IF;
  SELECT coalesce(array_agg(k ORDER BY k), '{}') INTO changed
    FROM (SELECT jsonb_object_keys(prev) UNION SELECT jsonb_object_keys(cur)) x(k)
   WHERE k NOT IN ('version', 'change_type', 'description', 'migration_note', 'recorded_at', 'recorded_by')
     AND prev->k IS DISTINCT FROM cur->k;
  IF changed = ARRAY['name'] THEN
    RETURN 'RENAME_' || suffix;
  ELSIF changed = ARRAY['deprecated'] THEN
    RETURN 'DEPRECATE_' || suffix;
  ELSIF kind = 'IdentifierDef' AND changed = ARRAY['strength'] THEN
    RETURN 'CHANGE_IDENTIFIER_STRENGTH';
  ELSIF kind = 'ClassDef' AND changed = ARRAY['attributes'] THEN
    SELECT coalesce(jsonb_object_agg(x->>'predicate_id', x), '{}') INTO pa FROM jsonb_array_elements(prev->'attributes') x;
    SELECT coalesce(jsonb_object_agg(x->>'predicate_id', x), '{}') INTO ca FROM jsonb_array_elements(cur->'attributes') x;
    SELECT count(*) INTO added FROM jsonb_object_keys(ca) k WHERE NOT pa ? k;
    SELECT count(*) INTO removed FROM jsonb_object_keys(pa) k WHERE NOT ca ? k;
    SELECT coalesce(array_agg(k), '{}') INTO diff FROM jsonb_object_keys(pa) k WHERE ca ? k AND pa->k <> ca->k;
    IF added = 1 AND removed = 0 AND cardinality(diff) = 0 THEN
      RETURN 'ADD_ATTRIBUTE';
    ELSIF removed = 1 AND added = 0 AND cardinality(diff) = 0 THEN
      RETURN 'REMOVE_ATTRIBUTE';
    ELSIF cardinality(diff) = 1 AND added = 0 AND removed = 0
          AND pa->diff[1]->'value_type' IS NOT DISTINCT FROM ca->diff[1]->'value_type'
          AND pa->diff[1]->'unit' IS NOT DISTINCT FROM ca->diff[1]->'unit'
          AND pa->diff[1]->'scheme' IS NOT DISTINCT FROM ca->diff[1]->'scheme' THEN
      RETURN 'CHANGE_ATTRIBUTE';
    END IF;
  END IF;
  RETURN NULL;
END $$;

-- общая часть стражей версий: системное время ПОСЛЕ блокировки схемы tenant, версии подряд, порядок времени,
-- запись журнала = выведенное отличие
-- Время версии — с точностью до секунды (как все времена записей набора): утверждение, записанное в ту же секунду,
-- что и версия, видит её. Историю схемы нельзя дописывать задним числом под уже записанные утверждения схемы tenant
-- (S9R2-02): новая версия определения при историческом импорте — позже последнего такого утверждения.
CREATE FUNCTION ac.schema_version_guard(kind text, tn text, ver int, last_ver int, last_at timestamptz, supplied timestamptz,
                                        prev jsonb, cur jsonb, declared text) RETURNS timestamptz LANGUAGE plpgsql AS $$
DECLARE t timestamptz;
BEGIN
  t := date_trunc('second', ac.guarded_time(supplied));
  IF ver > 1 AND ac.historical() THEN               -- только мигратор (он читает утверждения); вживую время — «сейчас»
    IF t <= (SELECT max(c.recorded_at) FROM ac.claims c JOIN ac.projects p USING (project_id)
              WHERE p.tenant_id = tn AND (c.predicate = 'schema.is_a' OR c.predicate ~ '^x\.'
                    OR c.body->'object'->'literal'->>'scheme' ~ '^x\.')) THEN
      PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'версия определения задним числом под уже записанные утверждения схемы tenant');
    END IF;
  END IF;
  IF ver IS DISTINCT FROM coalesce(last_ver, 0) + 1 THEN
    PERFORM ac.fail('SCHEMA_DEF_INVALID', 'версии определения идут подряд с 1: ожидается ' || (coalesce(last_ver, 0) + 1));
  END IF;
  IF last_at IS NOT NULL AND t <= last_at THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'версия записана не позже предыдущей');
  END IF;
  IF ac.schema_change_of(kind, prev, cur) IS DISTINCT FROM declared THEN
    PERFORM ac.fail('SCHEMA_CHANGE_INVALID', 'запись журнала «' || coalesce(declared, '') || '» не равна единственному допустимому '
                    || 'отличию от предыдущей версии');
  END IF;
  RETURN t;
END $$;

-- класс, на который ссылается определение: в том же tenant, записан к моменту t, не выведен из употребления
CREATE FUNCTION ac.schema_class_ref(tn text, cid text, t timestamptz, what text, m jsonb) RETURNS ac.class_defs LANGUAGE plpgsql STABLE AS $$
DECLARE k ac.class_defs;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ac.class_defs WHERE tenant_id = tn AND class_id = cid) THEN
    PERFORM ac.fail('REF_UNRESOLVED', what || ': класса ' || cid || ' нет в схеме tenant');
  END IF;
  k := ac.class_at(tn, cid, t);
  IF k.class_id IS NULL THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', what || ': класс ' || cid || ' записан позже ссылки на него');
  END IF;
  IF k.deprecated THEN
    PERFORM ac.fail('SCHEMA_DEF_INVALID', what || ': класс ' || cid || ' выведен из употребления');
  END IF;
  IF NOT ac.dominates(m, k.marking) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', what || ': маркировка определения шире маркировки класса ' || cid);
  END IF;
  RETURN k;
END $$;

CREATE FUNCTION ac.class_defs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev ac.class_defs; par ac.class_defs; a jsonb; old jsonb;
BEGIN
  PERFORM ac.lock_keys(ARRAY['schema:' || NEW.tenant_id]);
  SELECT * INTO prev FROM ac.class_defs WHERE tenant_id = NEW.tenant_id AND class_id = NEW.class_id ORDER BY version DESC LIMIT 1;
  NEW.recorded_at := ac.schema_version_guard('ClassDef', NEW.tenant_id, NEW.version, prev.version, prev.recorded_at, NEW.recorded_at,
                                             CASE WHEN prev.class_id IS NOT NULL THEN to_jsonb(prev) END, to_jsonb(NEW), NEW.change_type);
  IF NEW.version = 1 AND NEW.parent_class_id IS NOT NULL THEN
    par := ac.schema_class_ref(NEW.tenant_id, NEW.parent_class_id, NEW.recorded_at, 'родитель', NEW.marking);
    IF par.root_type <> NEW.root_type THEN
      PERFORM ac.fail('SCHEMA_DEF_INVALID', 'корневой тип наследника не равен корневому типу родителя');
    END IF;
  END IF;
  IF (SELECT count(DISTINCT x->>'predicate_id') FROM jsonb_array_elements(NEW.attributes) x) <> jsonb_array_length(NEW.attributes) THEN
    PERFORM ac.fail('SCHEMA_DEF_INVALID', 'атрибут повторяется');
  END IF;
  FOR a IN SELECT x FROM jsonb_array_elements(NEW.attributes) x LOOP
    old := NULL;
    SELECT x INTO old FROM jsonb_array_elements(coalesce(prev.attributes, '[]')) x WHERE x->>'predicate_id' = a->>'predicate_id';
    IF a IS DISTINCT FROM old AND a->>'value_type' = 'IDENTIFIER' AND a->>'scheme' NOT IN ('ru.inn', 'ru.ogrn', 'ru.ogrnip', 'imo')
       AND (ac.idef_at(NEW.tenant_id, a->>'scheme', NEW.root_type, NEW.recorded_at)).idef_id IS NULL THEN
      PERFORM ac.fail('REF_UNRESOLVED', 'атрибут ' || (a->>'predicate_id') || ': тип идентификатора ' || (a->>'scheme')
                      || ' не определён в схеме tenant для этого корневого типа');
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER class_defs_guard BEFORE INSERT ON ac.class_defs FOR EACH ROW EXECUTE FUNCTION ac.class_defs_guard();

-- производные строки: замыкание (только для версии 1 — родитель заморожен) и владельцы предикатов атрибутов
CREATE FUNCTION ac.class_defs_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE a jsonb; owner ac.schema_predicates;
BEGIN
  IF NEW.version = 1 THEN
    INSERT INTO ac.class_closure (tenant_id, ancestor_id, descendant_id, depth)
    SELECT NEW.tenant_id, NEW.class_id, NEW.class_id, 0
    UNION ALL
    SELECT NEW.tenant_id, c.ancestor_id, NEW.class_id, c.depth + 1
      FROM ac.class_closure c WHERE c.tenant_id = NEW.tenant_id AND c.descendant_id = NEW.parent_class_id;
  END IF;
  FOR a IN SELECT x FROM jsonb_array_elements(NEW.attributes) x LOOP
    INSERT INTO ac.schema_predicates VALUES (NEW.tenant_id, a->>'predicate_id', 'ClassDef', NEW.class_id) ON CONFLICT DO NOTHING;
    SELECT * INTO owner FROM ac.schema_predicates WHERE tenant_id = NEW.tenant_id AND predicate_id = a->>'predicate_id';
    IF owner.definer_kind <> 'ClassDef' OR owner.definer_id <> NEW.class_id THEN
      PERFORM ac.fail('SCHEMA_DEF_INVALID', 'предикат ' || (a->>'predicate_id') || ' уже определён в ' || owner.definer_id);
    END IF;
  END LOOP;
  RETURN NULL;
END $$;
CREATE TRIGGER class_defs_after AFTER INSERT ON ac.class_defs FOR EACH ROW EXECUTE FUNCTION ac.class_defs_after();

CREATE FUNCTION ac.link_defs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev ac.link_defs;
BEGIN
  PERFORM ac.lock_keys(ARRAY['schema:' || NEW.tenant_id]);
  SELECT * INTO prev FROM ac.link_defs WHERE tenant_id = NEW.tenant_id AND link_id = NEW.link_id ORDER BY version DESC LIMIT 1;
  NEW.recorded_at := ac.schema_version_guard('LinkDef', NEW.tenant_id, NEW.version, prev.version, prev.recorded_at, NEW.recorded_at,
                                             CASE WHEN prev.link_id IS NOT NULL THEN to_jsonb(prev) END, to_jsonb(NEW), NEW.change_type);
  IF NEW.version = 1 THEN
    PERFORM ac.schema_class_ref(NEW.tenant_id, NEW.domain_class_id, NEW.recorded_at, 'domain_class_id', NEW.marking);
    PERFORM ac.schema_class_ref(NEW.tenant_id, NEW.range_class_id, NEW.recorded_at, 'range_class_id', NEW.marking);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER link_defs_guard BEFORE INSERT ON ac.link_defs FOR EACH ROW EXECUTE FUNCTION ac.link_defs_guard();

CREATE FUNCTION ac.link_defs_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE owner ac.schema_predicates;
BEGIN
  INSERT INTO ac.schema_predicates VALUES (NEW.tenant_id, NEW.predicate_id, 'LinkDef', NEW.link_id) ON CONFLICT DO NOTHING;
  SELECT * INTO owner FROM ac.schema_predicates WHERE tenant_id = NEW.tenant_id AND predicate_id = NEW.predicate_id;
  IF owner.definer_kind <> 'LinkDef' OR owner.definer_id <> NEW.link_id THEN
    PERFORM ac.fail('SCHEMA_DEF_INVALID', 'предикат ' || NEW.predicate_id || ' уже определён в ' || owner.definer_id);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER link_defs_after AFTER INSERT ON ac.link_defs FOR EACH ROW EXECUTE FUNCTION ac.link_defs_after();

CREATE FUNCTION ac.identifier_defs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev ac.identifier_defs;
BEGIN
  PERFORM ac.lock_keys(ARRAY['schema:' || NEW.tenant_id]);
  SELECT * INTO prev FROM ac.identifier_defs WHERE tenant_id = NEW.tenant_id AND idef_id = NEW.idef_id ORDER BY version DESC LIMIT 1;
  NEW.recorded_at := ac.schema_version_guard('IdentifierDef', NEW.tenant_id, NEW.version, prev.version, prev.recorded_at, NEW.recorded_at,
                                             CASE WHEN prev.idef_id IS NOT NULL THEN to_jsonb(prev) END, to_jsonb(NEW), NEW.change_type);
  IF NEW.version = 1 THEN
    IF EXISTS (SELECT 1 FROM ac.identifier_defs WHERE tenant_id = NEW.tenant_id AND scheme = NEW.scheme
               AND applies_to_root_type = NEW.applies_to_root_type) THEN
      PERFORM ac.fail('SCHEMA_DEF_INVALID', 'тип идентификатора ' || NEW.scheme || ' для ' || NEW.applies_to_root_type || ' уже определён');
    END IF;
    IF EXISTS (SELECT 1 FROM ac.identifier_defs WHERE tenant_id = NEW.tenant_id AND applies_to_root_type = NEW.applies_to_root_type
               AND priority = NEW.priority) THEN
      PERFORM ac.fail('SCHEMA_DEF_INVALID', 'приоритет ' || NEW.priority || ' для ' || NEW.applies_to_root_type || ' уже занят');
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER identifier_defs_guard BEFORE INSERT ON ac.identifier_defs FOR EACH ROW EXECUTE FUNCTION ac.identifier_defs_guard();

CREATE TRIGGER class_defs_no_update BEFORE UPDATE OR DELETE ON ac.class_defs FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER link_defs_no_update BEFORE UPDATE OR DELETE ON ac.link_defs FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER identifier_defs_no_update BEFORE UPDATE OR DELETE ON ac.identifier_defs FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER class_closure_no_update BEFORE UPDATE OR DELETE ON ac.class_closure FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER schema_predicates_no_update BEFORE UPDATE OR DELETE ON ac.schema_predicates FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- журнал изменений схемы: каждая версия каждого определения — одна запись (кто, когда, что)
CREATE VIEW ac.schema_journal AS
  SELECT tenant_id, recorded_at, recorded_by, change_type, 'ClassDef' AS target_kind, class_id AS target_id, version, description, migration_note, marking
    FROM ac.class_defs
  UNION ALL SELECT tenant_id, recorded_at, recorded_by, change_type, 'LinkDef', link_id, version, description, migration_note, marking FROM ac.link_defs
  UNION ALL SELECT tenant_id, recorded_at, recorded_by, change_type, 'IdentifierDef', idef_id, version, description, migration_note, marking
    FROM ac.identifier_defs;

-- ---------------------------------------------------------------- утверждения против схемы своего времени
CREATE INDEX claims_is_a ON ac.claims (project_id, subject) WHERE predicate = 'schema.is_a';

-- сущность eid к моменту t названа экземпляром класса cid или его наследника, и это утверждение на момент t не
-- опровергнуто и не отозвано (по системному времени рецензий)
CREATE FUNCTION ac.is_instance(prj text, eid text, tn text, cid text, t timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM ac.claims c
                 JOIN ac.class_closure cc ON cc.tenant_id = tn AND cc.ancestor_id = cid
                                         AND cc.descendant_id = c.body->'object'->'literal'->>'class_id'
                 WHERE c.project_id = prj AND c.subject = eid AND c.predicate = 'schema.is_a' AND c.recorded_at <= t
                   AND ac.status_at(c.claim_id, t) NOT IN ('REFUTED', 'WITHDRAWN')) $$;

-- принадлежность на момент записи утверждения; вживую — ещё и на текущий момент (отзыв принадлежности не обойти
-- утверждением «задним числом» в пределах окна системного времени)
CREATE FUNCTION ac.is_instance_now(prj text, eid text, tn text, cid text, t timestamptz, live boolean) RETURNS boolean LANGUAGE sql VOLATILE AS $$
  SELECT ac.is_instance(prj, eid, tn, cid, t) AND (NOT live OR ac.is_instance(prj, eid, tn, cid, clock_timestamp())) $$;

-- предикат вне реестра ядра теперь проверяет страж: либо реестр, либо схема tenant («x.…»)
ALTER TABLE ac.claims DROP CONSTRAINT claim_predicate_known;

CREATE FUNCTION ac.claims_schema() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tn text; s ac.entities; o ac.entities; lit jsonb := NEW.body->'object'->'literal'; t timestamptz := NEW.recorded_at;
        live boolean := NOT ac.historical(); k ac.class_defs; lk ac.link_defs; idf ac.identifier_defs; own ac.schema_predicates;
        a jsonb; def_marking jsonb; def_at timestamptz; latest timestamptz;
BEGIN
  IF NEW.predicate !~ '^x\.' AND NOT EXISTS (SELECT 1 FROM ac.predicates WHERE predicate_id = NEW.predicate) THEN
    PERFORM ac.fail('PREDICATE_UNKNOWN', NEW.predicate || ' (claim_predicate_known)');
  END IF;
  -- пометка версии записи: прежние утверждения остаются 0.2 (их адреса не меняются); словарь 0.3 — только в записи 0.3
  IF (NEW.predicate ~ '^x\.' OR NEW.predicate = 'schema.is_a' OR lit->>'type' = 'CLASS_REF'
      OR (lit->>'type' = 'IDENTIFIER' AND lit->>'scheme' ~ '^x\.'))
     AND NEW.body->>'schema_version' IS DISTINCT FROM 'core-ontology/0.3' THEN
    PERFORM ac.fail('SCHEMA_INVALID', 'schema_version: словарь core-ontology/0.3 (schema.is_a, предикаты и схемы tenant) — только в записи 0.3');
  END IF;
  IF NOT (NEW.predicate ~ '^x\.' OR NEW.predicate = 'schema.is_a' OR (lit->>'type' = 'IDENTIFIER' AND lit->>'scheme' ~ '^x\.')) THEN
    RETURN NEW;
  END IF;
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = NEW.project_id;
  SELECT * INTO s FROM ac.entities WHERE entity_id = NEW.subject AND project_id = NEW.project_id;
  SELECT * INTO o FROM ac.entities WHERE entity_id = NEW.object_entity AND project_id = NEW.project_id;
  IF tn IS NULL OR s.entity_id IS NULL THEN
    RETURN NEW;                                   -- проект/субъект отвергнут внешними ключами таблицы
  END IF;
  -- запись утверждения и изменение схемы tenant не пересекаются: читатель схемы берёт разделяемую блокировку
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('schema:' || tn, 7));

  IF lit->>'type' = 'IDENTIFIER' AND lit->>'scheme' ~ '^x\.' THEN
    idf := ac.idef_at(tn, lit->>'scheme', s.entity_type, t);
    IF idf.idef_id IS NULL THEN
      PERFORM ac.fail('IDENTIFIER_SCHEME_INVALID', 'тип идентификатора ' || (lit->>'scheme') || ' не определён для ' || s.entity_type);
    END IF;
    IF live AND EXISTS (SELECT 1 FROM ac.identifier_defs x WHERE x.tenant_id = tn AND x.idef_id = idf.idef_id AND x.version > idf.version) THEN
      PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'тип идентификатора изменён после заявленного времени записи утверждения');
    END IF;
    IF jsonb_typeof(lit->'value') <> 'string' OR lit->>'value' !~ ac.format_regex(idf.format) THEN
      PERFORM ac.fail('IDENTIFIER_SCHEME_INVALID', 'значение не в формате ' || (lit->>'scheme'));
    END IF;
  END IF;

  IF NEW.predicate = 'schema.is_a' THEN
    IF lit IS NULL OR lit->>'type' IS DISTINCT FROM 'CLASS_REF' THEN
      RETURN NEW;                                 -- тип объекта отвергает общий страж диапазона (ac.claims_before)
    END IF;
    IF (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(lit) x) <> ARRAY['class_id', 'type']
       OR jsonb_typeof(lit->'class_id') <> 'string' OR lit->>'class_id' !~ '^sdf_[a-z0-9_]{2,64}$' THEN
      PERFORM ac.fail('SCHEMA_INVALID', 'CLASS_REF — ровно {type, class_id}: класс ищется в tenant проекта');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ac.class_defs WHERE tenant_id = tn AND class_id = lit->>'class_id') THEN
      PERFORM ac.fail('REF_UNRESOLVED', 'schema.is_a: класса ' || (lit->>'class_id') || ' нет в схеме tenant');
    END IF;
    k := ac.class_at(tn, lit->>'class_id', t);
    IF k.class_id IS NULL THEN
      PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'schema.is_a: класс записан позже утверждения');
    END IF;
    IF live AND EXISTS (SELECT 1 FROM ac.class_defs x WHERE x.tenant_id = tn AND x.class_id = k.class_id AND x.version > k.version) THEN
      PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'класс изменён после заявленного времени записи утверждения');
    END IF;
    IF k.is_abstract OR k.deprecated THEN
      PERFORM ac.fail('CLASS_NOT_INSTANTIABLE', 'класс ' || k.class_id || ' абстрактный или выведен из употребления');
    END IF;
    IF s.entity_type <> k.root_type THEN
      PERFORM ac.fail('PREDICATE_DOMAIN_VIOLATION', 'тип сущности ' || s.entity_type || ' не равен корневому типу класса ' || k.root_type);
    END IF;
    IF NOT ac.dominates(NEW.marking, k.marking) THEN
      PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка утверждения шире маркировки класса');
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.predicate ~ '^x\.' THEN
    SELECT * INTO own FROM ac.schema_predicates WHERE tenant_id = tn AND predicate_id = NEW.predicate;
    IF own.definer_kind = 'LinkDef' THEN
      lk := ac.link_at(tn, own.definer_id, t);
      IF lk.link_id IS NOT NULL AND NOT lk.deprecated THEN
        def_marking := lk.marking;
        SELECT max(recorded_at) INTO latest FROM ac.link_defs WHERE tenant_id = tn AND link_id = lk.link_id;
        def_at := lk.recorded_at;
      END IF;
    ELSIF own.definer_kind = 'ClassDef' THEN
      k := ac.class_at(tn, own.definer_id, t);
      SELECT x INTO a FROM jsonb_array_elements(k.attributes) x WHERE x->>'predicate_id' = NEW.predicate;
      IF a IS NOT NULL THEN
        def_marking := k.marking;
        SELECT max(recorded_at) INTO latest FROM ac.class_defs WHERE tenant_id = tn AND class_id = k.class_id;
        def_at := k.recorded_at;
      END IF;
    END IF;
    IF def_marking IS NULL THEN
      PERFORM ac.fail('PREDICATE_UNKNOWN', NEW.predicate || ': в схеме tenant на момент записи такого предиката нет');
    END IF;
    IF live AND latest > def_at THEN
      PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'определение предиката изменено после заявленного времени записи утверждения');
    END IF;
    -- отзыв принадлежности (рецензия на schema.is_a берёт блокировку 'claim:') не пересекается с записью утверждения
    PERFORM ac.lock_keys(ARRAY(SELECT 'claim:' || c.claim_id FROM ac.claims c
                               WHERE c.project_id = NEW.project_id AND c.subject IN (s.entity_id, o.entity_id) AND c.predicate = 'schema.is_a'));
    IF NOT ac.is_instance_now(NEW.project_id, s.entity_id, tn, coalesce(lk.domain_class_id, k.class_id), t, live) THEN
      PERFORM ac.fail('PREDICATE_DOMAIN_VIOLATION', 'субъект не является экземпляром класса ' || coalesce(lk.domain_class_id, k.class_id));
    END IF;
    IF a IS NOT NULL THEN
      IF lit IS NULL OR lit->>'type' IS DISTINCT FROM a->>'value_type' OR lit->>'unit' IS DISTINCT FROM a->>'unit'
         OR (lit->>'type' = 'IDENTIFIER' AND lit->>'scheme' IS DISTINCT FROM a->>'scheme') THEN
        PERFORM ac.fail('PREDICATE_RANGE_VIOLATION', 'значение не того типа, единицы или схемы, что объявлены у атрибута');
      END IF;
    ELSIF lit IS NOT NULL OR o.entity_id IS NULL OR NOT ac.is_instance_now(NEW.project_id, o.entity_id, tn, lk.range_class_id, t, live) THEN
      PERFORM ac.fail('PREDICATE_RANGE_VIOLATION', 'объект не является экземпляром класса ' || lk.range_class_id);
    END IF;
    IF NEW.body ? 'qualifiers' AND NEW.body->'qualifiers' <> '{}'::jsonb THEN
      PERFORM ac.fail('QUALIFIER_INVALID', 'у предикатов схемы tenant нет квалификаторов');
    END IF;
    IF NOT ac.dominates(NEW.marking, def_marking) THEN
      PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка утверждения шире маркировки определения в схеме');
    END IF;
  END IF;
  RETURN NEW;
END $$;
-- имя триггера по алфавиту после claims_before: время записи (recorded_at) уже проверено и взято из тела
CREATE TRIGGER claims_schema BEFORE INSERT ON ac.claims FOR EACH ROW EXECUTE FUNCTION ac.claims_schema();

-- ---------------------------------------------------------------- тексты проекций для утверждений схемы
-- у каждого предиката реестра есть шаблон (S3-15); {class} — название класса из схемы на момент t (подставляется как
-- текст, а не как шаблон: фигурные и квадратные скобки в названии класса ничего не значат)
INSERT INTO ac.predicate_texts VALUES ('schema.is_a', '{S}: класс — «{class}».');

-- предложение об утверждении: шаблон реестра, а для schema.is_a и предикатов tenant — название из схемы на момент t
CREATE OR REPLACE FUNCTION ac.fact_text(c ac.claims, t timestamptz) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE tpl text; parts text[]; segs text[]; r text := ''; i int; tn text; own ac.schema_predicates; nm text;
BEGIN
  IF c.predicate = 'schema.is_a' OR c.predicate ~ '^x\.' THEN
    SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = c.project_id;
    IF c.predicate = 'schema.is_a' THEN
      nm := (ac.class_at(tn, c.body->'object'->'literal'->>'class_id', t)).name;
      SELECT template INTO tpl FROM ac.predicate_texts WHERE predicate_id = 'schema.is_a';
      parts := string_to_array(tpl, '{class}');
      r := replace(parts[1], '{S}', ac.ent_name(c.subject, t)) || coalesce(nm, c.body->'object'->'literal'->>'class_id') || parts[2];
    ELSE
      SELECT * INTO own FROM ac.schema_predicates WHERE tenant_id = tn AND predicate_id = c.predicate;
      IF own.definer_kind = 'LinkDef' THEN
        nm := (ac.link_at(tn, own.definer_id, t)).name;
      ELSE
        SELECT x->>'name' INTO nm FROM jsonb_array_elements((ac.class_at(tn, own.definer_id, t)).attributes) x
         WHERE x->>'predicate_id' = c.predicate;
      END IF;
      r := ac.ent_name(c.subject, t) || ': ' || coalesce(nm, c.predicate) || ' — '
           || CASE WHEN c.object_entity IS NULL THEN ac.lit_text(c.body->'object'->'literal') ELSE '«' || ac.ent_name(c.object_entity, t) || '»' END || '.';
    END IF;
    RETURN upper(left(r, 1)) || substr(r, 2);
  END IF;
  SELECT template INTO tpl FROM ac.predicate_texts WHERE predicate_id = c.predicate;
  IF tpl IS NULL THEN
    tpl := '{S}: ' || c.predicate || ' — ' || CASE WHEN c.object_entity IS NULL THEN '{V}' ELSE '{O}' END || '.';
  END IF;
  parts := regexp_split_to_array(tpl, '\[[^]]*\]');
  segs := ARRAY(SELECT m[1] FROM regexp_matches(tpl, '\[([^]]*)\]', 'g') m);
  FOR i IN 1 .. array_length(parts, 1) LOOP
    r := r || ac.render_part(c, parts[i], t, false);
    IF i <= coalesce(array_length(segs, 1), 0) THEN
      r := r || coalesce(ac.render_part(c, segs[i], t, true), '');
    END IF;
  END LOOP;
  r := regexp_replace(r, '\.\.$', '.');          -- «руб.» at the end of a sentence
  RETURN upper(left(r, 1)) || substr(r, 2);
END $$;

-- кардинальность предиката tenant на момент t (заменяет заглушку proj_s3.sql): у атрибута — объявленная, у связи — её
CREATE OR REPLACE FUNCTION ac.tenant_cardinality(c ac.claims, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    (SELECT CASE own.definer_kind
              WHEN 'LinkDef' THEN (ac.link_at(own.tenant_id, own.definer_id, t)).cardinality
              ELSE (SELECT x->>'cardinality' FROM jsonb_array_elements((ac.class_at(own.tenant_id, own.definer_id, t)).attributes) x
                    WHERE x->>'predicate_id' = c.predicate) END
       FROM ac.schema_predicates own
      WHERE own.tenant_id = c.tenant_id AND own.predicate_id = c.predicate), 'MANY') $$;

-- ---------------------------------------------------------------- проекция «модель»: схема tenant проекта на момент as_of
-- Читатель видит определения, маркировка которых не выше его допуска по проекту; у класса — собственные и
-- унаследованные атрибуты (через замыкание); журнал версий. В проекции только схема (без счётчиков по утверждениям:
-- незафиксированная запись утверждения сделала бы ответ на прошлый момент невоспроизводимым, S9R2-03).
-- NOT STABLE (урок S6R-01/02): читатель берёт разделяемую блокировку схемы tenant и только ПОСЛЕ неё читает — изменение
-- схемы, начатое раньше, уже зафиксировано, а начатое позже получит время позже as_of; у VOLATILE-функции каждый оператор
-- видит свежий снимок, поэтому ответ на прошлый момент воспроизводим.
CREATE FUNCTION ac.model(p text, as_of timestamptz DEFAULT now()) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE clr jsonb := ac.my_clearance(p); tn text; res jsonb;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  IF clr IS NULL OR tn IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('schema:' || tn, 7));
  as_of := least(as_of, clock_timestamp());
  res := jsonb_build_object('projection', 'model/0.1', 'project_id', p, 'as_of', as_of,
    'classes', (SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'class_id', k.class_id, 'version', k.version, 'name', k.name, 'root_type', k.root_type, 'parent_class_id', k.parent_class_id,
        'is_abstract', nullif(k.is_abstract, false), 'deprecated', nullif(k.deprecated, false), 'marking', k.marking,
        'attributes', (SELECT jsonb_agg(x.a || jsonb_build_object('declared_in', x.cid) ORDER BY x.depth DESC, x.a->>'predicate_id')
                         FROM (SELECT a.a, up.class_id AS cid, cc.depth FROM ac.class_closure cc
                               CROSS JOIN LATERAL (SELECT (ac.class_at(tn, cc.ancestor_id, as_of)).*) up
                               CROSS JOIN LATERAL jsonb_array_elements(up.attributes) a(a)
                               WHERE cc.tenant_id = tn AND cc.descendant_id = k.class_id AND ac.dominates(clr, up.marking)) x))) ORDER BY k.class_id), '[]')
                FROM (SELECT DISTINCT class_id FROM ac.class_defs WHERE tenant_id = tn) ids
                CROSS JOIN LATERAL (SELECT (ac.class_at(tn, ids.class_id, as_of)).*) k
                WHERE k.class_id IS NOT NULL AND ac.dominates(clr, k.marking)),
    'links', (SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'link_id', l.link_id, 'version', l.version, 'predicate_id', l.predicate_id, 'name', l.name, 'domain_class_id', l.domain_class_id,
        'range_class_id', l.range_class_id, 'cardinality', l.cardinality, 'symmetric', nullif(l.is_symmetric, false),
        'deprecated', nullif(l.deprecated, false), 'marking', l.marking)) ORDER BY l.link_id), '[]')
              FROM (SELECT DISTINCT link_id FROM ac.link_defs WHERE tenant_id = tn) ids
              CROSS JOIN LATERAL (SELECT (ac.link_at(tn, ids.link_id, as_of)).*) l
              WHERE l.link_id IS NOT NULL AND ac.dominates(clr, l.marking)),
    'identifiers', (SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'idef_id', f.idef_id, 'version', f.version, 'scheme', f.scheme, 'name', f.name, 'applies_to_root_type', f.applies_to_root_type,
        'strength', f.strength, 'priority', f.priority, 'format', f.format, 'deprecated', nullif(f.deprecated, false),
        'marking', f.marking)) ORDER BY f.applies_to_root_type, f.priority), '[]')
              FROM (SELECT DISTINCT idef_id FROM ac.identifier_defs WHERE tenant_id = tn) ids
              CROSS JOIN LATERAL (SELECT * FROM ac.identifier_defs x WHERE x.tenant_id = tn AND x.idef_id = ids.idef_id
                                  AND x.recorded_at <= as_of ORDER BY x.version DESC LIMIT 1) f
              WHERE ac.dominates(clr, f.marking)),
    'journal', (SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'recorded_at', j.recorded_at, 'recorded_by', j.recorded_by, 'change', j.change_type, 'target_kind', j.target_kind,
        'target_id', j.target_id, 'version', j.version, 'description', j.description, 'migration_note', j.migration_note))
        ORDER BY j.recorded_at, j.target_kind, j.target_id, j.version), '[]')
                FROM ac.schema_journal j WHERE j.tenant_id = tn AND j.recorded_at <= as_of AND ac.dominates(clr, j.marking)));
  RETURN ac.with_digest(res);
END $$;

-- незаполненные обязательные атрибуты действующей на as_of схемы у экземпляров проекта, видимых читателю
-- (опирается на утверждения, как досье: схема читается под блокировкой, утверждения — по состоянию на момент вызова)
CREATE FUNCTION ac.schema_gaps(p text, as_of timestamptz DEFAULT now()) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' AS $$
DECLARE clr jsonb := ac.my_clearance(p); tn text; res jsonb;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  IF clr IS NULL OR tn IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('schema:' || tn, 7));
  as_of := least(as_of, clock_timestamp());
  SELECT coalesce(jsonb_agg(g ORDER BY g->>'entity_id', g->>'predicate_id'), '[]') INTO res FROM (
    SELECT DISTINCT jsonb_build_object('entity_id', m.subject, 'entity', ac.ent_name(m.subject, as_of),
                 'class_id', up.class_id, 'predicate_id', a.a->>'predicate_id', 'attribute', a.a->>'name') AS g
    FROM ac.claims m
    JOIN ac.class_closure cc ON cc.tenant_id = tn AND cc.descendant_id = m.body->'object'->'literal'->>'class_id'
    CROSS JOIN LATERAL (SELECT (ac.class_at(tn, cc.ancestor_id, as_of)).*) up
    CROSS JOIN LATERAL jsonb_array_elements(up.attributes) a(a)
   WHERE m.project_id = p AND m.predicate = 'schema.is_a' AND m.ingested_at <= as_of
     AND ac.status_at(m.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN')
     AND ac.dominates(clr, m.marking) AND ac.entity_visible(clr, m.subject, as_of) AND ac.dominates(clr, up.marking)
     AND (a.a->>'required')::boolean
     AND NOT EXISTS (SELECT 1 FROM ac.claims c WHERE c.project_id = p AND c.subject = m.subject AND c.predicate = a.a->>'predicate_id'
                       AND c.ingested_at <= as_of AND ac.status_at(c.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN'))) q;
  RETURN ac.with_digest(jsonb_build_object('projection', 'schema_gaps/0.1', 'project_id', p, 'as_of', as_of, 'gaps', res));
END $$;

ALTER FUNCTION ac.model(text, timestamptz) OWNER TO ac_projector;
ALTER FUNCTION ac.schema_gaps(text, timestamptz) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.model(text, timestamptz), ac.schema_gaps(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.model(text, timestamptz), ac.schema_gaps(text, timestamptz) TO ac_reader;

-- ---------------------------------------------------------------- права
-- схему меняет «Конструктор модели» (ac_modeler) и исторический импорт (ac_migrator); загрузчик утверждений её только читает;
-- производные таблицы не пишет никто, кроме триггеров; читатели — только через проекции
REVOKE ALL ON ac.class_defs, ac.link_defs, ac.identifier_defs, ac.class_closure, ac.schema_predicates, ac.schema_journal
  FROM PUBLIC, ac_loader, ac_migrator, ac_trust_admin, ac_storage;
GRANT SELECT ON ac.class_defs, ac.link_defs, ac.identifier_defs, ac.class_closure, ac.schema_predicates, ac.schema_journal
  TO ac_loader, ac_migrator, ac_modeler, ac_projector;
GRANT INSERT ON ac.class_defs, ac.link_defs, ac.identifier_defs TO ac_modeler, ac_migrator;

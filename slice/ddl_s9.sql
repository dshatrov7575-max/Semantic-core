-- Архитектура семантики — S9 (цикл 9): «Схема как данные» (D27.1).
-- Что хранится:
--   * четыре вида записей: ClassDef (классы сущностей), LinkDef (именованные связи между классами),
--     IdentifierDef (схемы идентификаторов для классов), SchemaChange (журнал изменений схемы);
--   * таблица замыкания ac.class_closure (транзитивная цепочка parent_class_id);
--   * предикат schema.is_a: утверждение, что сущность принадлежит классу.
-- Правила:
--   * все schema-записи принадлежат tenant; ссылки между ними не пересекают tenant;
--   * root_type наследника должен совпадать с root_type родителя;
--   * циклическое наследование запрещено;
--   * schema.is_a: entity_type сущности должен совпадать с ClassDef.root_type;
--   * замыкание пересчитывается триггером при каждом INSERT/UPDATE в ac.class_defs;
--   * все записи неизменяемы (только INSERT, без UPDATE/DELETE); SchemaChange — журнал намерений, не миграция.
-- Applied after ddl_s5b.sql.

-- ---------------------------------------------------------------- ClassDef

CREATE TABLE ac.class_defs (
  class_id        text        NOT NULL CHECK (class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  tenant_id       text        NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  root_type       text        NOT NULL CHECK (root_type IN (
                    'PERSON','ORGANIZATION','REAL_ESTATE','MOVABLE_PROPERTY',
                    'EVENT','CONFLICT','EQUIPMENT','EQUIPMENT_MODEL','CONCEPT','THING')),
  name            text        NOT NULL CHECK (length(name) > 0),
  label_ru        text,
  parent_class_id text        CHECK (parent_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  is_abstract     boolean,
  version         integer     NOT NULL CHECK (version >= 1),
  created_at      timestamptz NOT NULL,
  created_by      text        NOT NULL CHECK (created_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  marking         jsonb       NOT NULL,
  PRIMARY KEY (class_id)
);

-- tenant isolation: parent must be in the same tenant
CREATE FUNCTION ac.class_defs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.created_at := CASE WHEN NEW.created_at IS NOT NULL THEN NEW.created_at ELSE clock_timestamp() END;
  IF NEW.parent_class_id IS NOT NULL THEN
    -- parent must exist within the same tenant
    IF NOT EXISTS (SELECT 1 FROM ac.class_defs p
                   WHERE p.class_id = NEW.parent_class_id AND p.tenant_id = NEW.tenant_id) THEN
      PERFORM ac.fail('REF_UNRESOLVED',
        'parent_class_id ' || NEW.parent_class_id || ' не найден в tenant ' || NEW.tenant_id);
    END IF;
    -- root_type of child must match root_type of parent
    PERFORM 1 FROM ac.class_defs p
    WHERE p.class_id = NEW.parent_class_id AND p.root_type <> NEW.root_type;
    IF FOUND THEN
      PERFORM ac.fail('SCHEMA_INVALID',
        'root_type ' || NEW.root_type || ' наследника не совпадает с root_type родителя');
    END IF;
    -- cycle detection: NEW.class_id must not appear in any ancestor chain
    IF EXISTS (
      WITH RECURSIVE chain(cid) AS (
        SELECT NEW.parent_class_id
        UNION ALL
        SELECT p.parent_class_id FROM ac.class_defs p JOIN chain c ON p.class_id = c.cid
        WHERE p.parent_class_id IS NOT NULL
      )
      SELECT 1 FROM chain WHERE cid = NEW.class_id
    ) THEN
      PERFORM ac.fail('SCHEMA_INVALID', 'циклическое наследование: ' || NEW.class_id);
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER class_defs_guard BEFORE INSERT ON ac.class_defs FOR EACH ROW EXECUTE FUNCTION ac.class_defs_guard();
CREATE TRIGGER class_defs_no_update BEFORE UPDATE OR DELETE ON ac.class_defs FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- class_closure (транзитивное замыкание parent_class_id)
-- Строки: (ancestor_id, descendant_id, depth).  Каждый класс — собственный предок (depth=0).
-- Пересчитывается полностью по tenant при каждом INSERT в ac.class_defs, т.к. записи неизменяемы —
-- инкрементальное обновление не нужно; вставки в одном tenant небольшие.

CREATE TABLE ac.class_closure (
  ancestor_id   text    NOT NULL,
  descendant_id text    NOT NULL,
  depth         integer NOT NULL CHECK (depth >= 0),
  tenant_id     text    NOT NULL,
  PRIMARY KEY (ancestor_id, descendant_id)
);
CREATE INDEX class_closure_desc ON ac.class_closure (descendant_id);

CREATE FUNCTION ac.rebuild_class_closure(p_tenant text) RETURNS void LANGUAGE sql AS $$
  DELETE FROM ac.class_closure WHERE tenant_id = p_tenant;
  INSERT INTO ac.class_closure (ancestor_id, descendant_id, depth, tenant_id)
  WITH RECURSIVE closure(ancestor_id, descendant_id, depth) AS (
    SELECT class_id, class_id, 0 FROM ac.class_defs WHERE tenant_id = p_tenant
    UNION ALL
    SELECT c.ancestor_id, d.class_id, c.depth + 1
    FROM closure c
    JOIN ac.class_defs d ON d.parent_class_id = c.descendant_id AND d.tenant_id = p_tenant
  )
  SELECT DISTINCT ancestor_id, descendant_id, depth, p_tenant FROM closure;
$$;

CREATE FUNCTION ac.class_defs_closure_refresh() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.rebuild_class_closure(NEW.tenant_id);
  RETURN NULL;
END $$;
CREATE TRIGGER class_defs_closure_refresh AFTER INSERT ON ac.class_defs
  FOR EACH ROW EXECUTE FUNCTION ac.class_defs_closure_refresh();

-- ---------------------------------------------------------------- LinkDef

CREATE TABLE ac.link_defs (
  link_id           text        NOT NULL CHECK (link_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  tenant_id         text        NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  predicate_id      text        NOT NULL CHECK (predicate_id ~ '^[a-z]+\.[a-z_]+$'),
  label_ru          text,
  domain_class_id   text        NOT NULL CHECK (domain_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  range_class_id    text        NOT NULL CHECK (range_class_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  cardinality       text        NOT NULL CHECK (cardinality IN ('ONE','MANY')),
  symmetric         boolean,
  inverse_predicate_id text     CHECK (inverse_predicate_id ~ '^[a-z]+\.[a-z_]+$'),
  version           integer     NOT NULL CHECK (version >= 1),
  created_at        timestamptz NOT NULL,
  created_by        text        NOT NULL CHECK (created_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  marking           jsonb       NOT NULL,
  PRIMARY KEY (link_id)
);

CREATE FUNCTION ac.link_defs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- domain_class_id must exist in the same tenant
  IF NOT EXISTS (SELECT 1 FROM ac.class_defs c
                 WHERE c.class_id = NEW.domain_class_id AND c.tenant_id = NEW.tenant_id) THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'domain_class_id ' || NEW.domain_class_id || ' не найден в tenant ' || NEW.tenant_id);
  END IF;
  -- range_class_id must exist in the same tenant
  IF NOT EXISTS (SELECT 1 FROM ac.class_defs c
                 WHERE c.class_id = NEW.range_class_id AND c.tenant_id = NEW.tenant_id) THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'range_class_id ' || NEW.range_class_id || ' не найден в tenant ' || NEW.tenant_id);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER link_defs_guard BEFORE INSERT ON ac.link_defs FOR EACH ROW EXECUTE FUNCTION ac.link_defs_guard();
CREATE TRIGGER link_defs_no_update BEFORE UPDATE OR DELETE ON ac.link_defs FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- IdentifierDef

CREATE TABLE ac.identifier_defs (
  idef_id              text        NOT NULL CHECK (idef_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  tenant_id            text        NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  scheme               text        NOT NULL CHECK (scheme ~ '^[a-z][a-z0-9.]{1,40}$'),
  label_ru             text,
  applies_to_root_type text        NOT NULL CHECK (applies_to_root_type IN (
                          'PERSON','ORGANIZATION','REAL_ESTATE','MOVABLE_PROPERTY',
                          'EVENT','CONFLICT','EQUIPMENT','EQUIPMENT_MODEL','CONCEPT','THING')),
  strength             text        NOT NULL CHECK (strength IN ('STRONG','WEAK')),
  priority             integer     NOT NULL CHECK (priority >= 1),
  normalization_regex  text,
  validation_regex     text,
  version              integer     NOT NULL CHECK (version >= 1),
  created_at           timestamptz NOT NULL,
  created_by           text        NOT NULL CHECK (created_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  marking              jsonb       NOT NULL,
  PRIMARY KEY (idef_id)
);

CREATE TRIGGER identifier_defs_no_update BEFORE UPDATE OR DELETE ON ac.identifier_defs
  FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- SchemaChange (audit log — immutable)

CREATE TABLE ac.schema_changes (
  change_id    text        NOT NULL CHECK (change_id ~ '^scx_[a-z0-9_]{2,64}$'),
  tenant_id    text        NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),
  change_type  text        NOT NULL CHECK (change_type IN (
                 'ADD_CLASS','RENAME_CLASS','DEPRECATE_CLASS',
                 'ADD_ATTRIBUTE','CHANGE_ATTRIBUTE_CARDINALITY','REMOVE_ATTRIBUTE',
                 'ADD_LINK','REMOVE_LINK',
                 'ADD_IDENTIFIER_DEF','CHANGE_IDENTIFIER_STRENGTH')),
  target_id    text        NOT NULL CHECK (target_id ~ '^sdf_[a-z0-9_]{2,64}$'),
  target_kind  text        NOT NULL CHECK (target_kind IN ('ClassDef','LinkDef','IdentifierDef')),
  description  text        NOT NULL CHECK (length(description) > 0),
  migration_note text,
  recorded_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  recorded_by  text        NOT NULL CHECK (recorded_by ~ '^(usr|svc)_[a-z0-9_]{2,64}$'),
  marking      jsonb       NOT NULL,
  PRIMARY KEY (change_id)
);

-- target_id must exist in the appropriate catalog table
CREATE FUNCTION ac.schema_changes_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_kind = 'ClassDef' AND NOT EXISTS (
      SELECT 1 FROM ac.class_defs WHERE class_id = NEW.target_id AND tenant_id = NEW.tenant_id) THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'target_id ' || NEW.target_id || ' не найден в ClassDef для tenant ' || NEW.tenant_id);
  ELSIF NEW.target_kind = 'LinkDef' AND NOT EXISTS (
      SELECT 1 FROM ac.link_defs WHERE link_id = NEW.target_id AND tenant_id = NEW.tenant_id) THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'target_id ' || NEW.target_id || ' не найден в LinkDef для tenant ' || NEW.tenant_id);
  ELSIF NEW.target_kind = 'IdentifierDef' AND NOT EXISTS (
      SELECT 1 FROM ac.identifier_defs WHERE idef_id = NEW.target_id AND tenant_id = NEW.tenant_id) THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'target_id ' || NEW.target_id || ' не найден в IdentifierDef для tenant ' || NEW.tenant_id);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER schema_changes_guard BEFORE INSERT ON ac.schema_changes
  FOR EACH ROW EXECUTE FUNCTION ac.schema_changes_guard();
CREATE TRIGGER schema_changes_no_update BEFORE UPDATE OR DELETE ON ac.schema_changes
  FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- schema.is_a guard on ac.claims

-- When a Claim with predicate 'schema.is_a' is inserted, enforce:
--   1. object must be a JSONB literal of type CLASS_REF: {"type":"CLASS_REF","class_id":"sdf_...","tenant_id":"tnt_..."}
--   2. class_id must exist in ac.class_defs within the same tenant
--   3. entity_type of subject entity must match ClassDef.root_type

CREATE FUNCTION ac.claims_isa_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  obj      jsonb;
  cid      text;
  cls      ac.class_defs;
  ent_type text;
  prj_tnt  text;
BEGIN
  IF NEW.predicate <> 'schema.is_a' THEN
    RETURN NEW;
  END IF;
  obj := NEW.object -> 'literal';
  IF obj IS NULL OR obj ->> 'type' <> 'CLASS_REF' THEN
    PERFORM ac.fail('PREDICATE_RANGE_VIOLATION',
      'schema.is_a: объект должен быть литералом CLASS_REF, получено: ' || NEW.object::text);
  END IF;
  cid := obj ->> 'class_id';
  -- resolve tenant from project
  SELECT p.tenant_id INTO prj_tnt FROM ac.projects p WHERE p.project_id = NEW.project_id;
  SELECT * INTO cls FROM ac.class_defs WHERE class_id = cid;
  IF cls.class_id IS NULL THEN
    PERFORM ac.fail('REF_UNRESOLVED',
      'schema.is_a: class_id ' || coalesce(cid, '<null>') || ' не найден');
  END IF;
  IF prj_tnt IS NOT NULL AND cls.tenant_id <> prj_tnt THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE',
      'schema.is_a: ClassDef из tenant ' || cls.tenant_id || ', проект в tenant ' || prj_tnt);
  END IF;
  SELECT e.entity_type INTO ent_type FROM ac.entities e WHERE e.entity_id = NEW.subject;
  IF ent_type IS NOT NULL AND ent_type <> cls.root_type THEN
    PERFORM ac.fail('PREDICATE_DOMAIN_VIOLATION',
      'schema.is_a: entity_type ' || ent_type || ' != ClassDef.root_type ' || cls.root_type);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER claims_isa_guard BEFORE INSERT ON ac.claims
  FOR EACH ROW EXECUTE FUNCTION ac.claims_isa_guard();

-- Архитектура семантики — срез S1: правила онтологии core-ontology/0.2.1 как ограничения PostgreSQL 16.
-- Разделение ответственности (D8):
--   загрузчик = нормативный валидатор (validator.py): JCS-адреса claim_id/receipt_id, подпись Ed25519,
--               нормализация ключей идентичности (скелет, контрольные суммы);
--   база      = всё, что должно держаться без доверия к приложению: уникальность ключей идентичности,
--               границы проекта и tenant, неизменяемость и append-only, системное время, провенанс
--               до байтов источника, маркировки, правила Проверки, один receipt на PIPELINE-утверждение.
-- Каждое правило этого файла атакуется в обход валидатора в slice/attacks_s1.py.

DROP SCHEMA IF EXISTS ac CASCADE;
DROP SCHEMA IF EXISTS ac_trust CASCADE;
DO $$ BEGIN CREATE ROLE ac_loader NOLOGIN;      EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_migrator NOLOGIN;    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_trust_admin NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
-- the application logs in as ac_app (member of ac_loader only) — it can never become ac_migrator (RS-11)
DO $$ BEGIN CREATE ROLE ac_app LOGIN IN ROLE ac_loader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE SCHEMA ac;
CREATE SCHEMA ac_trust;

-- ---------------------------------------------------------------- helpers
CREATE FUNCTION ac.level_rank(t text) RETURNS int IMMUTABLE LANGUAGE sql AS $$
  SELECT CASE t WHEN 'PUBLIC' THEN 0 WHEN 'INTERNAL' THEN 1 WHEN 'CONFIDENTIAL' THEN 2 WHEN 'RESTRICTED' THEN 3 END $$;

-- S22-06: a marking is exactly {level, categories} with known values; anything else is not a marking
CREATE FUNCTION ac.marking_ok(m jsonb) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT coalesce(jsonb_typeof(m) = 'object'
     AND (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(m) k) = ARRAY['categories', 'level']
     AND m->>'level' IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')
     AND jsonb_typeof(m->'categories') = 'array'
     AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(m->'categories') c
                     WHERE jsonb_typeof(c) <> 'string' OR c #>> '{}' NOT IN ('PERSONAL_DATA', 'COMMERCIAL_SECRET', 'OFFICIAL_USE'))
     AND jsonb_array_length(m->'categories') = (SELECT count(DISTINCT c) FROM jsonb_array_elements(m->'categories') c), false) $$;

-- a dominates b: level not lower and categories a superset (D6); fail-closed: an unknown marking dominates nothing
CREATE FUNCTION ac.dominates(a jsonb, b jsonb) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT coalesce(ac.marking_ok(a) AND ac.marking_ok(b)
     AND ac.level_rank(a->>'level') >= ac.level_rank(b->>'level')
     AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(b->'categories') c WHERE NOT (a->'categories') ? c), false) $$;

-- System time (RR-09, OR-13): the database, not the writer, stamps recorded_at / status_changed_at.
-- Only a member of ac_migrator may import historical times, and never times in the future.
CREATE FUNCTION ac.historical() RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('ac.historical_import', true), '') = 'on' AND pg_has_role(session_user, 'ac_migrator', 'MEMBER') $$;

-- S23-10: writers that can change what a closed Check rests on are serialised by advisory locks, taken in key order;
-- the system time of a guarded write is read AFTER the lock (clock_timestamp), not at transaction start
-- Cycle 11 (class S10R-20): every guard of the form «take a lock, then read what others committed» needs a snapshot
-- taken AFTER the lock. REPEATABLE READ and SERIALIZABLE keep the snapshot of the first statement, so two such
-- transactions (or one of them against a READ COMMITTED one) do not see each other and both pass the guard.
-- Guarded writes are therefore accepted in READ COMMITTED only.
CREATE FUNCTION ac.require_read_committed() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'ISOLATION_LEVEL_UNSUPPORTED: записи ядра и проекции, которые берут блокировку (сохранность, модель, пробелы схемы), выполняются только в READ COMMITTED (стражам нужен снимок, взятый после блокировки)'
      USING ERRCODE = 'check_violation';
  END IF;
END $$;

CREATE FUNCTION ac.isolation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.require_read_committed();
  RETURN NULL;
END $$;

CREATE FUNCTION ac.lock_keys_shared(keys text[]) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.require_read_committed();
  PERFORM pg_advisory_xact_lock_shared(hashtextextended(k, 7)) FROM (SELECT DISTINCT k FROM unnest(keys) k WHERE k IS NOT NULL ORDER BY k) x;
END $$;

CREATE FUNCTION ac.lock_keys(keys text[]) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.require_read_committed();
  PERFORM pg_advisory_xact_lock(hashtextextended(k, 7)) FROM (SELECT DISTINCT k FROM unnest(keys) k WHERE k IS NOT NULL ORDER BY k) x;
END $$;

-- Keys 'entity:' (S11R2-05). EXCLUSIVE — only by what changes the entity itself: its merge or retirement, its insert as
-- MERGED, an identity decision about it. SHARED — by everything that only relies on its state: a claim about it, a
-- Check of it (opening, rows, closing), a merge INTO it. Two writers that rely on one entity never wait for each
-- other, so a transaction that writes a claim about an entity and then a Check row or a merge into it does not
-- deadlock with its twin. A transaction that first RELIES on an entity and then CHANGES it (a claim about X and then a
-- decision about the identity of X, or its merge) can still deadlock with its twin, and so can two sessions that merge
-- into two targets in opposite orders (S11R4-03): the loader repeats a transaction refused with 40P01 (S11R3-04). Merges into one target are serialised by the separate key 'merge-into:' (S11R3-01).
-- One call takes the keys in one order: all in the order of the key, exclusive before shared
-- for the same key.
CREATE FUNCTION ac.lock_entities(excl text[], shared text[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  PERFORM ac.require_read_committed();
  FOR r IN SELECT k, bool_or(x) AS x FROM (SELECT unnest(excl) AS k, true AS x UNION ALL SELECT unnest(shared), false) u
           WHERE k IS NOT NULL GROUP BY k ORDER BY k LOOP
    IF r.x THEN
      PERFORM pg_advisory_xact_lock(hashtextextended('entity:' || r.k, 7));
    ELSE
      PERFORM pg_advisory_xact_lock_shared(hashtextextended('entity:' || r.k, 7));
    END IF;
  END LOOP;
END $$;

-- D13: history is sealed after an import; later historical writes may only land after the last seal
CREATE TABLE ac.history_seals (
  sealed_at  timestamptz PRIMARY KEY,
  sealed_by  name NOT NULL DEFAULT current_user
);
CREATE FUNCTION ac.sealed_at() RETURNS timestamptz LANGUAGE sql STABLE AS $$
  SELECT coalesce(max(sealed_at), '-infinity') FROM ac.history_seals $$;
CREATE FUNCTION ac.seal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.sealed_at := clock_timestamp();
  NEW.sealed_by := current_user;
  IF NEW.sealed_at < ac.sealed_at() THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'печать истории не может идти назад');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER seal_guard BEFORE INSERT ON ac.history_seals FOR EACH ROW EXECUTE FUNCTION ac.seal_guard();

CREATE FUNCTION ac.system_time(supplied timestamptz) RETURNS timestamptz LANGUAGE plpgsql AS $$
BEGIN
  IF ac.historical() THEN
    IF supplied IS NULL OR supplied > clock_timestamp() THEN
      RAISE EXCEPTION 'TEMPORAL_ORDER_INVALID: историческое время из будущего' USING ERRCODE = 'check_violation';
    END IF;
    IF supplied <= ac.sealed_at() THEN
      RAISE EXCEPTION 'TEMPORAL_ORDER_INVALID: история до % запечатана', ac.sealed_at() USING ERRCODE = 'check_violation';
    END IF;
    RETURN supplied;
  END IF;
  RETURN now();
END $$;

-- S23-10: for writes serialised by ac.lock_keys the live time is read after the lock (clock), not at transaction start
CREATE FUNCTION ac.guarded_time(supplied timestamptz) RETURNS timestamptz LANGUAGE plpgsql AS $$
BEGIN
  IF ac.historical() THEN
    RETURN ac.system_time(supplied);
  END IF;
  RETURN clock_timestamp();
END $$;

-- For content-addressed records the writer's time is part of the hash and cannot be replaced; the database
-- rejects it unless it is "now" (5-minute clock-skew window). Historical import: only ac_migrator, never future.
CREATE FUNCTION ac.check_supplied_time(t timestamptz) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF t > clock_timestamp() OR (NOT ac.historical() AND t < now() - interval '5 minutes') OR (ac.historical() AND t <= ac.sealed_at()) THEN
    RAISE EXCEPTION 'TEMPORAL_ORDER_INVALID: время записи % вне окна системного времени', t USING ERRCODE = 'check_violation';
  END IF;
END $$;

CREATE FUNCTION ac.forbid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'APPEND_ONLY: % на %.% запрещён', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE FUNCTION ac.fail(code text, msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '%: %', code, msg USING ERRCODE = 'check_violation'; END $$;

-- ---------------------------------------------------------------- trust anchors (separate schema, separate role)
CREATE TABLE ac_trust.keys (
  tenant_id   text NOT NULL,
  key_id      text NOT NULL,
  service_id  text NOT NULL,
  algorithm   text NOT NULL CHECK (algorithm = 'Ed25519'),
  public_key  text NOT NULL,
  not_before  timestamptz NOT NULL,
  not_after   timestamptz NOT NULL,
  revoked_at  timestamptz,
  PRIMARY KEY (tenant_id, key_id),                         -- RR-06: key ids are per tenant
  CHECK (not_before < not_after),
  CHECK (revoked_at IS NULL OR revoked_at >= not_before)
);

-- ---------------------------------------------------------------- registries (loaded from core/predicates.json)
CREATE TABLE ac.predicates (
  predicate_id  text PRIMARY KEY,
  domain        text[] NOT NULL,
  range         jsonb NOT NULL,
  dimensions    text[] NOT NULL,
  cardinality   text NOT NULL DEFAULT 'MANY' CHECK (cardinality IN ('ONE','MANY')),
  qualifiers    jsonb NOT NULL DEFAULT '{}'
);
CREATE FUNCTION ac.is_date(d text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  RETURN d ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' AND to_char(d::date, 'YYYY-MM-DD') = d;
EXCEPTION WHEN others THEN
  RETURN false;
END $$;
-- one qualifier value against its registry spec (validator: enum / integer with bounds / non-blank string / boolean)
CREATE FUNCTION ac.qualifier_ok(s jsonb, v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(CASE s->>'type'
    WHEN 'enum' THEN jsonb_typeof(v) = 'string' AND (s->'enum') ? (v #>> '{}')
    WHEN 'integer' THEN jsonb_typeof(v) = 'number' AND (v #>> '{}') ~ '^-?[0-9]+$'
                        AND (NOT s ? 'min' OR (v #>> '{}')::numeric >= (s->>'min')::numeric)
                        AND (NOT s ? 'max' OR (v #>> '{}')::numeric <= (s->>'max')::numeric)
    WHEN 'string' THEN jsonb_typeof(v) = 'string' AND btrim(v #>> '{}') <> ''
    WHEN 'boolean' THEN jsonb_typeof(v) = 'boolean' END, false) $$;
CREATE TABLE ac.check_profiles (
  profile     text PRIMARY KEY,
  dimensions  text[] NOT NULL
);
CREATE FUNCTION ac.risk_rank(r text) RETURNS int IMMUTABLE LANGUAGE sql AS $$
  SELECT CASE r WHEN 'NONE' THEN 0 WHEN 'LOW' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'HIGH' THEN 3 END $$;

-- ---------------------------------------------------------------- projects, sources
CREATE TABLE ac.projects (
  project_id      text PRIMARY KEY CHECK (project_id ~ '^prj_[a-z0-9_]{2,64}$'),
  tenant_id       text NOT NULL,
  product         text NOT NULL CHECK (product IN ('TECHSENSE','CONFLICTOLOGY','WEB_MONITORING','DOSSIER','COMPLIANCE','SEMANTIC_WIKI')),
  default_marking jsonb NOT NULL,
  body            jsonb NOT NULL,
  UNIQUE (project_id, tenant_id),
  CONSTRAINT projects_marking_shape CHECK (ac.marking_ok(default_marking)),
  CHECK (project_id = body->>'project_id' AND tenant_id = body->>'tenant_id' AND product = body->>'product')
);

CREATE TABLE ac.sources (
  tenant_id    text NOT NULL,
  source_id    text NOT NULL CHECK (source_id ~ '^src:sha256:[0-9a-f]{64}$'),
  byte_length  integer NOT NULL CHECK (byte_length >= 0),
  marking      jsonb NOT NULL,
  body         jsonb NOT NULL,
  PRIMARY KEY (tenant_id, source_id),
  CONSTRAINT sources_marking_shape CHECK (ac.marking_ok(marking)),
  CHECK (source_id = body->>'source_id' AND tenant_id = body->>'tenant_id' AND marking = body->'marking'
         AND byte_length = (body->>'byte_length')::int)
);

-- object store stand-in: bytes addressed by their own hash (D3)
CREATE TABLE ac.source_bytes (
  tenant_id  text NOT NULL,
  source_id  text NOT NULL,
  bytes      bytea NOT NULL,
  PRIMARY KEY (tenant_id, source_id),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.sources,
  CONSTRAINT source_bytes_address CHECK ('src:sha256:' || encode(sha256(bytes), 'hex') = source_id)
);
CREATE FUNCTION ac.source_bytes_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF length(NEW.bytes) <> (SELECT byte_length FROM ac.sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id) THEN
    PERFORM ac.fail('SOURCE_DIGEST_MISMATCH', 'длина байтов не совпадает с byte_length');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER source_bytes_guard BEFORE INSERT ON ac.source_bytes FOR EACH ROW EXECUTE FUNCTION ac.source_bytes_guard();
-- RS-04: sources, their bytes and markings are append-only (a marking change is a new record, O2 erasure a separate procedure)
CREATE TRIGGER sources_no_update BEFORE UPDATE OR DELETE ON ac.sources FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER source_bytes_no_update BEFORE UPDATE OR DELETE ON ac.source_bytes FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER projects_no_update BEFORE UPDATE OR DELETE ON ac.projects FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER predicates_no_update BEFORE UPDATE OR DELETE ON ac.predicates FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER check_profiles_no_update BEFORE UPDATE OR DELETE ON ac.check_profiles FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE TABLE ac.source_observations (
  tenant_id    text NOT NULL,
  source_id    text NOT NULL,
  observed_at  timestamptz NOT NULL,
  origin_uri   text NOT NULL,
  observed_by  text NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, source_id, observed_at, origin_uri),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.sources
);
CREATE FUNCTION ac.observation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- S24 Г-2: an observation is serialised with the closing of Checks citing the source; ingested after the lock
  PERFORM ac.lock_keys(ARRAY['source:' || NEW.source_id]);
  NEW.observed_at := ac.system_time(NEW.observed_at);
  NEW.ingested_at := clock_timestamp();
  RETURN NEW;
END $$;
CREATE TRIGGER observation_guard BEFORE INSERT ON ac.source_observations FOR EACH ROW EXECUTE FUNCTION ac.observation_guard();
CREATE TRIGGER observations_no_update BEFORE UPDATE OR DELETE ON ac.source_observations FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- entities and identity keys
CREATE TABLE ac.entities (
  entity_id          text PRIMARY KEY CHECK (entity_id ~ '^ent_[a-z0-9_]{2,64}$'),
  project_id         text NOT NULL REFERENCES ac.projects,
  entity_type        text NOT NULL CHECK (entity_type IN ('PERSON','ORGANIZATION','REAL_ESTATE','MOVABLE_PROPERTY','EVENT','CONFLICT','EQUIPMENT','EQUIPMENT_MODEL','CONCEPT','THING')),
  identity           jsonb NOT NULL,
  status             text NOT NULL CHECK (status IN ('ACTIVE','MERGED','RETIRED')),
  merged_into        text,
  status_changed_at  timestamptz,
  created_at         timestamptz NOT NULL,
  marking            jsonb NOT NULL,
  display_name       text,                                   -- S3: how projections name the entity
  UNIQUE (project_id, entity_id),
  FOREIGN KEY (project_id, merged_into) REFERENCES ac.entities (project_id, entity_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK ((status = 'MERGED') = (merged_into IS NOT NULL)),
  CHECK ((status = 'ACTIVE') = (status_changed_at IS NULL)),
  CHECK (status_changed_at IS NULL OR status_changed_at >= created_at),
  CONSTRAINT entities_marking_shape CHECK (ac.marking_ok(marking)),
  CONSTRAINT person_has_pd CHECK (entity_type <> 'PERSON' OR marking->'categories' ? 'PERSONAL_DATA')      -- MARKING_PD_MISSING
);

-- merge rules (RR-13): target of the same project and type, ACTIVE at the moment of the merge, no chains
CREATE FUNCTION ac.merge_ok(e ac.entities) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM ac.entities t
                 WHERE t.entity_id = e.merged_into AND t.project_id = e.project_id AND t.entity_type = e.entity_type
                   AND (t.status = 'ACTIVE' OR (t.status = 'RETIRED' AND t.status_changed_at > e.status_changed_at))
                   AND ac.dominates(e.marking, t.marking)) $$;   -- S22-01: the survivor is not broader

CREATE FUNCTION ac.entities_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_at := ac.system_time(NEW.created_at);
    IF NEW.status <> 'ACTIVE' THEN
      NEW.status_changed_at := ac.system_time(NEW.status_changed_at);
    END IF;
    IF NEW.status = 'MERGED' THEN                -- S11R-05: serialised with a merge of the target itself
      PERFORM ac.lock_keys(ARRAY['merge-into:' || NEW.merged_into]);      -- S11R3-01: merges into one target go one by one
      PERFORM ac.lock_entities(ARRAY[NEW.entity_id], ARRAY[NEW.merged_into]);
    END IF;
    IF NEW.status = 'MERGED' AND NOT ac.merge_ok(NEW) THEN
      PERFORM ac.fail('ENTITY_MERGE_INVALID', NEW.entity_id || ': цель того же проекта и типа, ACTIVE на момент слияния, не шире по маркировке');
    END IF;
    RETURN NEW;
  END IF;
  -- UPDATE: identity is immutable; only one status transition out of ACTIVE, stamped by system time
  IF NEW.entity_id <> OLD.entity_id OR NEW.project_id <> OLD.project_id OR NEW.entity_type <> OLD.entity_type
     OR NEW.identity <> OLD.identity OR NEW.created_at <> OLD.created_at OR NEW.marking <> OLD.marking
     OR NEW.display_name IS DISTINCT FROM OLD.display_name THEN
    PERFORM ac.fail('ENTITY_IMMUTABLE', 'идентичность, тип, проект и маркировка сущности не меняются');
  END IF;
  IF OLD.status <> 'ACTIVE' OR NEW.status = 'ACTIVE' THEN
    PERFORM ac.fail('ENTITY_STATUS_TRANSITION', 'допустим только один переход ACTIVE -> MERGED|RETIRED');
  END IF;
  -- S11R3-01: merges into one target go one by one (each must see what the other merged: «различны», moved keys);
  -- the key 'entity:' of the target stays shared, so claims about it and its Checks do not wait
  PERFORM ac.lock_keys(ARRAY['merge-into:' || NEW.merged_into]);
  PERFORM ac.lock_entities(ARRAY[NEW.entity_id], ARRAY[NEW.merged_into]);
  NEW.status_changed_at := clock_timestamp();
  -- S11R2-03: the subject of an open Check is ACTIVE (validator: CHECK_SUBJECT_INVALID) — first close or cancel the Check;
  -- the opening of a Check takes the same key, so it either sees this change or is seen here
  IF EXISTS (SELECT 1 FROM ac.checks k WHERE k.subject_entity_id = NEW.entity_id AND k.status NOT IN ('COMPLETED', 'CANCELLED')) THEN
    PERFORM ac.fail('CHECK_SUBJECT_INVALID', NEW.entity_id || ': у сущности открыта Проверка — сначала закройте или отмените её');
  END IF;
  IF NEW.status = 'MERGED' AND EXISTS (SELECT 1 FROM ac.entities d WHERE d.merged_into = NEW.entity_id) THEN
    PERFORM ac.fail('ENTITY_MERGE_INVALID', NEW.entity_id || ': в неё уже слиты дубли — цепочки слияний запрещены');
  END IF;
  IF NEW.status = 'MERGED' AND NOT ac.merge_ok(NEW) THEN
    PERFORM ac.fail('ENTITY_MERGE_INVALID', NEW.entity_id || ': цель того же проекта и типа, ACTIVE на момент слияния, не шире по маркировке');
  END IF;
  IF NEW.status = 'MERGED' AND ac.distinct_decided(NEW.entity_id, NEW.merged_into) THEN
    PERFORM ac.fail('IDENTITY_DECISION_INVALID', NEW.entity_id || ' и ' || NEW.merged_into || ': аналитик решил «различны»');
  END IF;
  IF NEW.status = 'MERGED' THEN   -- identifiers of the merged entity move to the survivor (D4)
    UPDATE ac.entity_keys k SET owner_entity_id = NEW.merged_into
     WHERE k.owner_entity_id = NEW.entity_id
       AND NOT EXISTS (SELECT 1 FROM ac.entity_keys k2 WHERE k2.project_id = k.project_id AND k2.entity_type = k.entity_type
                         AND k2.scheme = k.scheme AND k2.value = k.value AND k2.owner_entity_id = NEW.merged_into
                         AND coalesce(k2.qual, '') = coalesce(k.qual, ''));
    DELETE FROM ac.entity_keys WHERE owner_entity_id = NEW.entity_id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER entities_guard BEFORE INSERT OR UPDATE ON ac.entities FOR EACH ROW EXECUTE FUNCTION ac.entities_guard();

-- RS-01: identity keys are derived BY THE DATABASE from identity (ac.identity_keys, keys_s1.sql); nobody writes them directly
CREATE FUNCTION ac.entities_keys_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE r record; owner text := CASE WHEN NEW.status = 'MERGED' THEN NEW.merged_into ELSE NEW.entity_id END;
BEGIN
  FOR r IN SELECT * FROM ac.identity_keys(NEW.entity_type, NEW.identity) LOOP
    BEGIN
      INSERT INTO ac.entity_keys VALUES (NEW.project_id, NEW.entity_type, r.scheme, r.value, owner, r.strength, r.qual)
      ON CONFLICT (project_id, entity_type, scheme, value, owner_entity_id, (coalesce(qual, ''))) DO NOTHING;
    EXCEPTION WHEN unique_violation THEN
      PERFORM ac.fail('ENTITY_DUPLICATE_IN_PROJECT', r.scheme || ' уже принадлежит другой сущности проекта');
    END;
  END LOOP;
  RETURN NULL;
END $$;
CREATE TRIGGER entities_no_delete BEFORE DELETE ON ac.entities FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- Identity keys, computed by the normative loader (same code as the validator: skeleton, check digits).
-- STRONG: one owner per key (unique index). WEAK: a collision is a duplicate unless both carry a qualifier
-- (disambiguator / place) and they differ, or both carry different ИНН / ОГРНИП (RR-03c, RR-04).
CREATE TABLE ac.entity_keys (
  project_id       text NOT NULL,
  entity_type      text NOT NULL,
  scheme           text NOT NULL,
  value            text NOT NULL,
  owner_entity_id  text NOT NULL,
  strength         text NOT NULL CHECK (strength IN ('STRONG','WEAK','SOFT')),
  qual             text,
  FOREIGN KEY (project_id, owner_entity_id) REFERENCES ac.entities (project_id, entity_id),
  CHECK (strength = 'WEAK' OR qual IS NULL)
);
-- a merged entity's key with its own qualifier stays a separate row of the survivor (as in the validator)
CREATE UNIQUE INDEX entity_keys_row ON ac.entity_keys (project_id, entity_type, scheme, value, owner_entity_id, (coalesce(qual, '')));
CREATE UNIQUE INDEX entity_keys_one_owner ON ac.entity_keys (project_id, entity_type, scheme, value) WHERE strength = 'STRONG';

CREATE FUNCTION ac.told_apart(p text, a text, b text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM (VALUES ('ru.inn'), ('ru.ogrnip')) s(scheme)
    WHERE EXISTS (SELECT 1 FROM ac.entity_keys WHERE project_id = p AND owner_entity_id = a AND scheme = s.scheme)
      AND EXISTS (SELECT 1 FROM ac.entity_keys WHERE project_id = p AND owner_entity_id = b AND scheme = s.scheme)
      AND NOT EXISTS (SELECT 1 FROM ac.entity_keys ka JOIN ac.entity_keys kb USING (project_id, scheme, value)
                      WHERE ka.project_id = p AND ka.owner_entity_id = a AND kb.owner_entity_id = b AND ka.scheme = s.scheme)) $$;

CREATE FUNCTION ac.entity_keys_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o record;
BEGIN
  IF (SELECT status FROM ac.entities WHERE entity_id = NEW.owner_entity_id) = 'MERGED' THEN
    PERFORM ac.fail('ENTITY_KEY_OWNER', 'владелец ключа — слитая сущность; ключи принадлежат выжившей');
  END IF;
  IF NEW.strength IN ('WEAK', 'SOFT') THEN
    -- RS-10: serialize writers of the same weak/soft key; the checks then see the other's committed row
    PERFORM ac.require_read_committed();
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.project_id || '|' || NEW.entity_type || '|' || NEW.scheme || '|' || NEW.value, 0));
  END IF;
  IF NEW.strength = 'WEAK' THEN
    FOR o IN SELECT * FROM ac.entity_keys k
             WHERE k.project_id = NEW.project_id AND k.entity_type = NEW.entity_type AND k.scheme = NEW.scheme
               AND k.value = NEW.value AND k.strength = 'WEAK' AND k.owner_entity_id <> NEW.owner_entity_id LOOP
      IF NOT (o.qual IS NOT NULL AND NEW.qual IS NOT NULL AND o.qual <> NEW.qual)
         AND NOT ac.told_apart(NEW.project_id, o.owner_entity_id, NEW.owner_entity_id) THEN
        PERFORM ac.fail('ENTITY_DUPLICATE_IN_PROJECT', NEW.scheme || ' совпадает у ' || o.owner_entity_id || ' и ' || NEW.owner_entity_id);
      END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER entity_keys_guard BEFORE INSERT ON ac.entity_keys FOR EACH ROW EXECUTE FUNCTION ac.entity_keys_guard();

-- ---------------------------------------------------------------- identity decisions (v0.2.2: RS-13, RS-15)
-- DISTINCT: an analyst says two entities whose skeletons coincide are different (clears POSSIBLE_DUPLICATE);
-- QUALIFY: append-only refinement — the missing disambiguator / place is added to an existing weak-keyed entity.
CREATE TABLE ac.identity_decisions (
  decision_id  text PRIMARY KEY CHECK (decision_id ~ '^idd_[a-z0-9_]{2,64}$'),
  project_id   text NOT NULL REFERENCES ac.projects,
  decision     text NOT NULL CHECK (decision IN ('DISTINCT','QUALIFY')),
  entity_a     text NOT NULL,
  entity_b     text,
  field        text CHECK (field IN ('disambiguator','place')),
  value        text,
  decided_by   text NOT NULL,
  decided_at   timestamptz NOT NULL,
  body         jsonb NOT NULL,
  FOREIGN KEY (project_id, entity_a) REFERENCES ac.entities (project_id, entity_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (project_id, entity_b) REFERENCES ac.entities (project_id, entity_id) DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT decision_shape CHECK ((decision = 'DISTINCT') = (entity_b IS NOT NULL AND field IS NULL AND value IS NULL)
                                   AND (decision = 'QUALIFY') = (entity_b IS NULL AND field IS NOT NULL AND value IS NOT NULL)
                                   AND entity_a IS DISTINCT FROM entity_b),
  CONSTRAINT decision_columns_match_body CHECK (decision_id = body->>'decision_id' AND project_id = body->>'project_id'
         AND decision = body->>'decision' AND decided_by = body->>'decided_by'
         AND entity_a = coalesce(body->>'entity_id', body->'entity_ids'->>0)
         AND entity_b IS NOT DISTINCT FROM body->'entity_ids'->>1
         AND value IS NOT DISTINCT FROM coalesce(body->>'disambiguator', body->>'place')
         AND field IS NOT DISTINCT FROM CASE WHEN body ? 'disambiguator' THEN 'disambiguator' WHEN body ? 'place' THEN 'place' END)
);
CREATE UNIQUE INDEX identity_decisions_one_qualify ON ac.identity_decisions (entity_a) WHERE decision = 'QUALIFY';
CREATE TRIGGER identity_decisions_no_update BEFORE UPDATE OR DELETE ON ac.identity_decisions FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE FUNCTION ac.resolve(eid text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN status = 'MERGED' THEN merged_into ELSE entity_id END FROM ac.entities WHERE entity_id = eid $$;

CREATE FUNCTION ac.distinct_decided(a text, b text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM ac.identity_decisions d WHERE d.decision = 'DISTINCT'
                   AND ((ac.resolve(d.entity_a) = a AND ac.resolve(d.entity_b) = b) OR (ac.resolve(d.entity_a) = b AND ac.resolve(d.entity_b) = a))) $$;

-- two owners separated by qualifiers of a common weak key (both present, different)
CREATE FUNCTION ac.separated(p text, a text, b text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM ac.entity_keys ka JOIN ac.entity_keys kb USING (project_id, entity_type, scheme, value)
                 WHERE ka.project_id = p AND ka.owner_entity_id = a AND kb.owner_entity_id = b
                   AND ka.strength = 'WEAK' AND kb.strength = 'WEAK' AND ka.qual <> kb.qual) $$;

CREATE FUNCTION ac.identity_decisions_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE e ac.entities; q text;
BEGIN
  NEW.decided_at := ac.system_time(NEW.decided_at);
  IF NEW.decision = 'DISTINCT' THEN
    RETURN NEW;                         -- checked at COMMIT: its entities may be written in the same transaction
  END IF;
  PERFORM ac.lock_keys(ARRAY['entity:' || NEW.entity_a]);      -- S11R2-02: a merge of this entity holds the key until it commits
  SELECT * INTO e FROM ac.entities WHERE entity_id = NEW.entity_a;
  IF e.entity_id IS NULL OR e.project_id <> NEW.project_id THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE', 'уточняемая сущность не найдена в проекте решения');
  END IF;
  IF NOT ((e.entity_type IN ('EVENT','CONFLICT') AND NEW.field = 'place')
          OR (e.entity_type IN ('CONCEPT', 'THING') AND NEW.field = 'disambiguator')
          OR (e.entity_type = 'PERSON' AND e.identity ? 'birth_date' AND NEW.field = 'disambiguator'))
     OR e.identity ? NEW.field OR e.status = 'MERGED'
     OR EXISTS (SELECT 1 FROM ac.identity_decisions d WHERE d.entity_a = NEW.entity_a AND d.decision = 'QUALIFY') THEN
    PERFORM ac.fail('IDENTITY_DECISION_INVALID', NEW.entity_a || ': уточнение допустимо один раз, только недостающего '
                    || NEW.field || ' у слабого ключа (ФИО+дата, событие, конфликт, понятие), не для слитой');
  END IF;
  IF ac.has_unassigned(NEW.value) THEN        -- S11R5-01: the qualifier joins the weak key through NFKC
    PERFORM ac.fail('IDENTITY_DECISION_INVALID', NEW.entity_a || ': уточнение с символом, не назначенным в Юникоде валидатора');
  END IF;
  IF NEW.decided_at < e.created_at THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'решение раньше создания сущности');
  END IF;
  q := CASE WHEN NEW.field = 'place' THEN ac.skel(NEW.value) ELSE NEW.value END;
  -- the qualifier joins the owner's weak keys that have none (also keys of entities merged into it)
  DELETE FROM ac.entity_keys k WHERE k.owner_entity_id = e.entity_id AND k.strength = 'WEAK' AND k.qual IS NULL
     AND EXISTS (SELECT 1 FROM ac.entity_keys k2 WHERE k2.project_id = k.project_id AND k2.entity_type = k.entity_type
                   AND k2.scheme = k.scheme AND k2.value = k.value AND k2.owner_entity_id = k.owner_entity_id AND k2.qual = q);
  UPDATE ac.entity_keys SET qual = q WHERE owner_entity_id = e.entity_id AND strength = 'WEAK' AND qual IS NULL;
  RETURN NEW;
END $$;
CREATE TRIGGER identity_decisions_guard BEFORE INSERT ON ac.identity_decisions FOR EACH ROW EXECUTE FUNCTION ac.identity_decisions_guard();

CREATE FUNCTION ac.identity_decisions_complete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a ac.entities; b ac.entities;
BEGIN
  IF NEW.decision <> 'DISTINCT' THEN
    RETURN NULL;
  END IF;
  -- S11R-06: a merge of this pair holds the same keys until it commits; what it did is read after the lock
  PERFORM ac.lock_keys(ARRAY['entity:' || NEW.entity_a, 'entity:' || NEW.entity_b]);
  SELECT * INTO a FROM ac.entities WHERE entity_id = NEW.entity_a AND project_id = NEW.project_id;
  SELECT * INTO b FROM ac.entities WHERE entity_id = NEW.entity_b AND project_id = NEW.project_id;
  IF a.entity_id IS NULL OR b.entity_id IS NULL THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE', 'сущности решения «различны» не найдены в его проекте');
  END IF;
  IF a.entity_type <> b.entity_type OR ac.resolve(a.entity_id) = ac.resolve(b.entity_id) THEN
    PERFORM ac.fail('IDENTITY_DECISION_INVALID', '«различны» — только для несливших сущностей одного типа');
  END IF;
  IF NEW.decided_at < greatest(a.created_at, b.created_at) THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'решение раньше создания сущности');
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER identity_decisions_complete AFTER INSERT ON ac.identity_decisions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.identity_decisions_complete();

-- RS-13: a skeleton collision is refused at COMMIT unless the analyst decided DISTINCT or qualifiers separate the pair
CREATE FUNCTION ac.soft_keys_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o record; me text := ac.resolve(NEW.owner_entity_id);
BEGIN
  FOR o IN SELECT DISTINCT k.owner_entity_id FROM ac.entity_keys k
           WHERE k.project_id = NEW.project_id AND k.entity_type = NEW.entity_type AND k.scheme = NEW.scheme
             AND k.value = NEW.value AND k.strength = 'SOFT' AND k.owner_entity_id <> me LOOP
    IF NOT ac.distinct_decided(me, o.owner_entity_id) AND NOT ac.separated(NEW.project_id, me, o.owner_entity_id) THEN
      PERFORM ac.fail('POSSIBLE_DUPLICATE', NEW.scheme || ': ' || me || ' и ' || o.owner_entity_id
                      || ' совпадают по скелету — нужно решение аналитика (identity_decisions)');
    END IF;
  END LOOP;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER soft_keys_check AFTER INSERT ON ac.entity_keys DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.strength = 'SOFT') EXECUTE FUNCTION ac.soft_keys_check();

-- ---------------------------------------------------------------- claims and evidence
CREATE TABLE ac.claims (
  claim_id       text PRIMARY KEY CHECK (claim_id ~ '^clm:sha256:[0-9a-f]{64}$'),
  project_id     text NOT NULL,
  tenant_id      text NOT NULL,
  subject        text NOT NULL,
  predicate      text NOT NULL,
  object_entity  text,
  produced_kind  text NOT NULL CHECK (produced_kind IN ('HUMAN','PIPELINE')),
  recorded_at    timestamptz NOT NULL,
  ingested_at    timestamptz NOT NULL DEFAULT now(),
  marking        jsonb NOT NULL,
  body           jsonb NOT NULL,
  UNIQUE (project_id, claim_id),
  UNIQUE (claim_id, tenant_id),
  FOREIGN KEY (project_id, tenant_id) REFERENCES ac.projects (project_id, tenant_id),
  FOREIGN KEY (project_id, subject) REFERENCES ac.entities (project_id, entity_id),
  FOREIGN KEY (project_id, object_entity) REFERENCES ac.entities (project_id, entity_id),
  CONSTRAINT claim_predicate_known FOREIGN KEY (predicate) REFERENCES ac.predicates,       -- PREDICATE_UNKNOWN
  CONSTRAINT claim_dates_valid CHECK ((NOT body ? 'valid_from' OR ac.is_date(body->>'valid_from'))
                                      AND (NOT body ? 'valid_to' OR ac.is_date(body->>'valid_to'))
                                      AND (body->'object'->'literal'->>'type' IS DISTINCT FROM 'DATE' OR ac.is_date(body->'object'->'literal'->>'value'))),
  CONSTRAINT claim_valid_time_order CHECK (NOT (body ? 'valid_from' AND body ? 'valid_to') OR body->>'valid_from' <= body->>'valid_to'),
  -- the columns are the body (no second version of the truth, ONT-03)
  CONSTRAINT claim_columns_match_body CHECK (claim_id = body->>'claim_id' AND project_id = body->>'project_id' AND subject = body->>'subject'
         AND predicate = body->>'predicate' AND object_entity IS NOT DISTINCT FROM body->'object'->>'entity'
         AND produced_kind = body->'produced_by'->>'kind' AND marking = body->'marking'),
  CONSTRAINT claims_marking_shape CHECK (ac.marking_ok(marking)),
  CONSTRAINT claim_has_evidence CHECK (jsonb_typeof(body->'evidence') = 'array' AND jsonb_array_length(body->'evidence') > 0),
  CHECK (recorded_at <= ingested_at)
);

CREATE FUNCTION ac.claims_before() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s ac.entities; o ac.entities; pr ac.predicates;
BEGIN
  NEW.ingested_at := clock_timestamp();
  NEW.recorded_at := (NEW.body->>'recorded_at')::timestamptz;
  PERFORM ac.check_supplied_time(NEW.recorded_at);
  PERFORM ac.lock_keys_shared(ARRAY['entity:' || NEW.subject, 'entity:' || NEW.object_entity]);     -- S11R-04
  SELECT * INTO s FROM ac.entities WHERE entity_id = NEW.subject;
  SELECT * INTO o FROM ac.entities WHERE entity_id = NEW.object_entity;
  IF (s.status = 'MERGED' AND NEW.recorded_at >= s.status_changed_at)
     OR (o.status = 'MERGED' AND NEW.recorded_at >= o.status_changed_at) THEN
    PERFORM ac.fail('CLAIM_ABOUT_MERGED_ENTITY', 'после слияния утверждения пишутся о выжившей сущности');
  END IF;
  SELECT * INTO pr FROM ac.predicates WHERE predicate_id = NEW.predicate;
  IF pr.predicate_id IS NOT NULL AND (
       (NEW.body ? 'qualifiers' AND jsonb_typeof(NEW.body->'qualifiers') <> 'object')
       OR EXISTS (SELECT 1 FROM jsonb_each(coalesce(NEW.body->'qualifiers', '{}')) q
                  WHERE NOT pr.qualifiers ? q.key OR NOT ac.qualifier_ok(pr.qualifiers->q.key, q.value))
       OR EXISTS (SELECT 1 FROM jsonb_each(pr.qualifiers) sq
                  WHERE (sq.value->>'required')::boolean AND NOT coalesce(NEW.body->'qualifiers', '{}') ? sq.key)) THEN
    PERFORM ac.fail('QUALIFIER_INVALID', NEW.predicate || ': квалификатор вне реестра, неверного типа или без обязательного');
  END IF;
  IF pr.predicate_id IS NOT NULL THEN
    IF s.entity_type <> ALL (pr.domain) THEN
      PERFORM ac.fail('PREDICATE_DOMAIN_VIOLATION', s.entity_type || ' не в domain ' || NEW.predicate);
    END IF;
    IF (NEW.body->'object' ? 'entity' AND (NOT pr.range ? 'entity' OR NOT (pr.range->'entity') ? o.entity_type))
       OR (NEW.body->'object' ? 'literal' AND (NOT pr.range ? 'literal' OR NOT (pr.range->'literal') ? (NEW.body->'object'->'literal'->>'type'))) THEN
      PERFORM ac.fail('PREDICATE_RANGE_VIOLATION', NEW.predicate || ': тип объекта вне range');
    END IF;
    IF (NEW.body->'object'->'literal'->>'type' = 'IDENTIFIER' AND pr.range ? 'schemes'
        AND NOT (pr.range->'schemes') ? (NEW.body->'object'->'literal'->>'scheme'))
       OR (NEW.body->'object'->'literal'->>'type' = 'QUANTITY' AND pr.range ? 'units'
        AND NOT (pr.range->'units') ? (NEW.body->'object'->'literal'->>'unit')) THEN
      PERFORM ac.fail('PREDICATE_RANGE_VIOLATION', NEW.predicate || ': схема идентификатора или единица вне range (S24-01)');
    END IF;
  END IF;
  IF NEW.body->'object'->'literal'->>'type' = 'IDENTIFIER' AND NOT (CASE NEW.body->'object'->'literal'->>'scheme'
       WHEN 'ru.inn' THEN coalesce(ac.inn_ok(NEW.body->'object'->'literal'->>'value'), false)
       WHEN 'ru.ogrn' THEN coalesce(ac.ogrn_ok(NEW.body->'object'->'literal'->>'value'), false)
       WHEN 'ru.ogrnip' THEN coalesce(ac.ogrnip_ok(NEW.body->'object'->'literal'->>'value'), false)
       WHEN 'imo' THEN coalesce(ac.imo_ok(NEW.body->'object'->'literal'->>'value'), false)
       ELSE true END) THEN
    PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'контрольные цифры литерала (S24-01)');
  END IF;
  IF NOT ac.dominates(NEW.marking, s.marking) OR (o.entity_id IS NOT NULL AND NOT ac.dominates(NEW.marking, o.marking)) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка утверждения шире маркировки сущности');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER claims_before BEFORE INSERT ON ac.claims FOR EACH ROW EXECUTE FUNCTION ac.claims_before();

-- evidence rows come ONLY from the claim body (no second, editable version of provenance — ONT-03)
CREATE FUNCTION ac.claims_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
BEGIN
  -- a fragment of the bytes of a source, or (cycle 10, D27.4) a ROW of a dataset version: the whole element is kept
  INSERT INTO ac.claim_evidence (claim_id, ord, tenant_id, source_id, span_start, span_end, quote_sha256, quote, graph_node, kind, row_ev)
  SELECT NEW.claim_id, e.ord - 1, NEW.tenant_id, e.v->>'source_id', (e.v->'span'->>'start')::int, (e.v->'span'->>'end')::int,
         e.v->>'quote_sha256', e.v->>'quote', e.v->'graph_node',
         CASE WHEN e.v ? 'kind' THEN e.v->>'kind' ELSE 'SPAN' END, CASE WHEN e.v ? 'kind' THEN e.v END
  FROM jsonb_array_elements(NEW.body->'evidence') WITH ORDINALITY AS e(v, ord);
  RETURN NULL;
END $$;
CREATE TRIGGER claims_after AFTER INSERT ON ac.claims FOR EACH ROW EXECUTE FUNCTION ac.claims_after();
CREATE TRIGGER claims_no_update BEFORE UPDATE OR DELETE ON ac.claims FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE TABLE ac.claim_evidence (
  claim_id      text NOT NULL,
  ord           integer NOT NULL,
  tenant_id     text NOT NULL,
  source_id     text NOT NULL,
  span_start    integer CHECK (span_start >= 0),
  span_end      integer,
  quote_sha256  text CHECK (quote_sha256 ~ '^[0-9a-f]{64}$'),
  quote         text,
  graph_node    jsonb,
  kind          text NOT NULL DEFAULT 'SPAN' CHECK (kind IN ('SPAN', 'ROW')),   -- cycle 10: a fragment of bytes or a row of a dataset
  row_ev        jsonb,                                  -- the ROW element of the claim body, as stated
  CONSTRAINT evidence_form CHECK (CASE kind
      WHEN 'SPAN' THEN span_start IS NOT NULL AND span_end IS NOT NULL AND quote_sha256 IS NOT NULL AND row_ev IS NULL
      ELSE span_start IS NULL AND span_end IS NULL AND quote_sha256 IS NULL AND quote IS NULL AND graph_node IS NULL
           AND row_ev IS NOT NULL END),
  PRIMARY KEY (claim_id, ord),
  FOREIGN KEY (claim_id, tenant_id) REFERENCES ac.claims (claim_id, tenant_id),   -- evidence only from the claim's tenant
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.sources,
  CHECK (span_end > span_start)
);

CREATE FUNCTION ac.evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE b bytea; chunk bytea; q text; c ac.claims; src ac.sources; first_seen timestamptz;
BEGIN
  SELECT * INTO c FROM ac.claims WHERE claim_id = NEW.claim_id;
  -- RS-02: an evidence row is exactly an element of the claim body; nothing else can be attached to a claim
  IF NEW.ord < 0 OR NEW.ord >= jsonb_array_length(c.body->'evidence')
     OR (c.body->'evidence'->NEW.ord) IS DISTINCT FROM (CASE WHEN NEW.kind = 'SPAN' THEN jsonb_strip_nulls(jsonb_build_object(
          'source_id', NEW.source_id, 'span', jsonb_build_object('start', NEW.span_start, 'end', NEW.span_end),
          'quote_sha256', NEW.quote_sha256, 'quote', NEW.quote, 'graph_node', NEW.graph_node)) ELSE NEW.row_ev END)
     OR (NEW.kind <> 'SPAN' AND NEW.source_id IS DISTINCT FROM NEW.row_ev->>'source_id') THEN
    PERFORM ac.fail('APPEND_ONLY', 'доказательство не совпадает с телом утверждения');
  END IF;
  SELECT * INTO src FROM ac.sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF src.source_id IS NULL THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE', 'источник не найден в tenant утверждения');
  END IF;
  SELECT bytes INTO b FROM ac.source_bytes WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF b IS NULL THEN
    PERFORM ac.fail('SOURCE_CONTENT_UNAVAILABLE', NEW.source_id);
  END IF;
  IF NEW.kind = 'ROW' THEN
    -- cycle 10 (ddl_s10.sql): the row is proved against the manifest of the dataset version; without that file loaded
    -- the call fails and the claim is refused (fail-closed)
    PERFORM ac.row_evidence_guard(c, src, NEW.row_ev);
  ELSE
  IF NEW.span_end > length(b) THEN
    PERFORM ac.fail('EVIDENCE_SPAN_INVALID', 'фрагмент за пределами байтов источника');
  END IF;
  chunk := substring(b FROM NEW.span_start + 1 FOR NEW.span_end - NEW.span_start);
  IF encode(sha256(chunk), 'hex') <> NEW.quote_sha256 THEN
    PERFORM ac.fail('EVIDENCE_SPAN_INVALID', 'sha256 фрагмента не совпадает');
  END IF;
  BEGIN
    q := convert_from(chunk, 'UTF8');
  EXCEPTION WHEN others THEN
    PERFORM ac.fail('EVIDENCE_SPAN_INVALID', 'фрагмент режет символ UTF-8');
  END;
  IF NEW.quote IS NOT NULL AND NEW.quote <> q THEN
    PERFORM ac.fail('EVIDENCE_SPAN_INVALID', 'quote не совпадает с байтами');
  END IF;
  END IF;
  IF NEW.graph_node IS NOT NULL AND c.produced_kind = 'HUMAN' THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', 'узел графа допустим только у PIPELINE-утверждения');
  END IF;
  IF NOT ac.dominates(c.marking, src.marking) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка утверждения шире маркировки источника');
  END IF;
  SELECT min(observed_at) INTO first_seen FROM ac.source_observations WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF first_seen IS NULL OR first_seen > c.recorded_at THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'утверждение записано раньше, чем получен источник');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER evidence_guard BEFORE INSERT ON ac.claim_evidence FOR EACH ROW EXECUTE FUNCTION ac.evidence_guard();
CREATE TRIGGER evidence_no_update BEFORE UPDATE OR DELETE ON ac.claim_evidence FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- reviews (append-only, system time)
CREATE TABLE ac.claim_reviews (
  review_id    text PRIMARY KEY,
  claim_id     text NOT NULL REFERENCES ac.claims,
  status       text NOT NULL CHECK (status IN ('ASSERTED','ACCEPTED','DISPUTED','REFUTED','WITHDRAWN')),
  reviewer     text NOT NULL,
  reviewed_at  timestamptz NOT NULL,
  recorded_at  timestamptz NOT NULL,
  CHECK (reviewed_at <= recorded_at)
);
CREATE FUNCTION ac.reviews_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.lock_keys(ARRAY['claim:' || NEW.claim_id]);
  NEW.recorded_at := ac.guarded_time(NEW.recorded_at);
  -- S22-05: history may not be written under a closed Check that relies on this claim
  IF NEW.recorded_at <= (SELECT max(coalesce(k.completed_at, k.cancelled_at)) FROM ac.check_finding_claims x
                         JOIN ac.checks k USING (check_id) WHERE x.claim_id = NEW.claim_id AND k.status IN ('COMPLETED','CANCELLED')) THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'рецензия задним числом под закрытую Проверку, которая опирается на это утверждение');
  END IF;
  IF NEW.reviewed_at < (SELECT recorded_at FROM ac.claims WHERE claim_id = NEW.claim_id) THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'рецензия раньше записи утверждения');
  END IF;
  IF EXISTS (SELECT 1 FROM ac.claim_reviews WHERE claim_id = NEW.claim_id AND recorded_at = NEW.recorded_at AND status <> NEW.status) THEN
    PERFORM ac.fail('CLAIM_REVIEW_AMBIGUOUS', 'разные статусы с одинаковым временем записи');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER reviews_guard BEFORE INSERT ON ac.claim_reviews FOR EACH ROW EXECUTE FUNCTION ac.reviews_guard();
CREATE TRIGGER reviews_no_update BEFORE UPDATE OR DELETE ON ac.claim_reviews FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE FUNCTION ac.status_at(cid text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT status FROM ac.claim_reviews WHERE claim_id = cid AND recorded_at <= t
                   ORDER BY recorded_at DESC LIMIT 1), 'ASSERTED') $$;

-- ---------------------------------------------------------------- Проверки (checks)
CREATE TABLE ac.checks (
  check_id          text PRIMARY KEY,
  project_id        text NOT NULL,
  subject_entity_id text NOT NULL,
  profile           text NOT NULL,
  status            text NOT NULL CHECK (status IN ('REQUESTED','IN_PROGRESS','COMPLETED','CANCELLED')),
  requested_at      timestamptz NOT NULL,
  completed_at      timestamptz,
  cancelled_at      timestamptz,
  as_of             date NOT NULL,
  overall_risk      text,
  previous_check_id text REFERENCES ac.checks,                                   -- REF_UNRESOLVED
  marking           jsonb NOT NULL,
  body              jsonb NOT NULL,
  UNIQUE (project_id, check_id),
  FOREIGN KEY (project_id, subject_entity_id) REFERENCES ac.entities (project_id, entity_id),
  FOREIGN KEY (profile) REFERENCES ac.check_profiles,
  CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
  CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL)),
  CONSTRAINT check_time_order CHECK (coalesce(completed_at, cancelled_at, requested_at) >= requested_at
                                     AND as_of <= (coalesce(completed_at, cancelled_at, 'infinity') AT TIME ZONE 'UTC')::date),
  CHECK ((status = 'COMPLETED') = (overall_risk IS NOT NULL)),
  CONSTRAINT checks_marking_shape CHECK (ac.marking_ok(marking)),
  closed_xact       xid8,                                         -- S22-04/05: the transaction that closed the Check
  CONSTRAINT check_columns_match_body CHECK (check_id = body->>'check_id' AND project_id = body->>'project_id'
         AND subject_entity_id = body->>'subject_entity_id' AND status = body->>'status' AND marking = body->'marking')
);
CREATE FUNCTION ac.checks_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE s ac.entities;
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.status IN ('COMPLETED','CANCELLED') THEN
    PERFORM ac.fail('CHECK_CLOSED', 'закрытая Проверка не меняется');
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.check_id <> OLD.check_id OR NEW.project_id <> OLD.project_id OR NEW.subject_entity_id <> OLD.subject_entity_id
       OR NEW.profile <> OLD.profile OR NEW.requested_at <> OLD.requested_at OR NEW.as_of <> OLD.as_of
       OR NEW.marking <> OLD.marking OR NEW.previous_check_id IS DISTINCT FROM OLD.previous_check_id
       OR (NEW.body - 'status' - 'completed_at' - 'cancelled_at' - 'overall_risk' - 'findings')
          <> (OLD.body - 'status' - 'completed_at' - 'cancelled_at' - 'overall_risk' - 'findings')) THEN
    PERFORM ac.fail('CHECK_IMMUTABLE', 'у Проверки меняются только статус и итог');
  END IF;
  IF TG_OP = 'INSERT' THEN
    NEW.requested_at := ac.system_time(NEW.requested_at);
  END IF;
  IF NEW.status IN ('COMPLETED','CANCELLED') AND (TG_OP = 'INSERT' OR OLD.status NOT IN ('COMPLETED','CANCELLED')) THEN
    -- S24 Г-1: first the Check itself (every writer of its rows holds it), THEN the set it rests on is read — after
    -- the lock, so rows committed by a concurrent writer are seen; order check < claim < entity < source is global
    PERFORM ac.lock_keys(ARRAY['check:' || NEW.check_id]);
    PERFORM ac.lock_keys(ARRAY(SELECT 'claim:' || x.claim_id FROM ac.check_finding_claims x WHERE x.check_id = NEW.check_id));
    PERFORM ac.lock_entities(NULL, ARRAY[NEW.subject_entity_id]             -- shared: a merge of any of them holds it exclusively
      || ARRAY(SELECT e FROM ac.check_finding_claims x JOIN ac.claims c USING (claim_id), unnest(ARRAY[c.subject, c.object_entity]) e
               WHERE x.check_id = NEW.check_id));
    PERFORM ac.lock_keys(ARRAY(SELECT 'source:' || ev.source_id FROM ac.check_finding_claims x JOIN ac.claim_evidence ev USING (claim_id)
               WHERE x.check_id = NEW.check_id));
  END IF;
  IF NEW.status = 'CANCELLED' AND (TG_OP = 'INSERT' OR OLD.status <> 'CANCELLED') THEN
    NEW.cancelled_at := ac.guarded_time(NEW.cancelled_at);
  END IF;
  IF (SELECT product FROM ac.projects WHERE project_id = NEW.project_id) <> 'COMPLIANCE' THEN
    PERFORM ac.fail('CHECK_PROJECT_NOT_COMPLIANCE', NEW.check_id);
  END IF;
  IF NEW.status NOT IN ('COMPLETED','CANCELLED') THEN       -- S11R2-03: with a merge or retirement of the subject
    PERFORM ac.lock_keys_shared(ARRAY['entity:' || NEW.subject_entity_id]);
  END IF;
  SELECT * INTO s FROM ac.entities WHERE entity_id = NEW.subject_entity_id;
  IF NEW.previous_check_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM ac.checks pv JOIN ac.entities pe ON pe.entity_id = pv.subject_entity_id
       WHERE pv.check_id = NEW.previous_check_id AND pv.as_of < NEW.as_of
         AND (pv.subject_entity_id = NEW.subject_entity_id OR pe.merged_into = NEW.subject_entity_id
              OR s.merged_into = pv.subject_entity_id)) THEN
    PERFORM ac.fail('CHECK_PREVIOUS_INVALID', 'предыдущая Проверка: тот же субъект и более ранняя дата');
  END IF;
  IF NEW.previous_check_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ac.checks pv WHERE pv.check_id = NEW.previous_check_id
                                                          AND pv.status = 'COMPLETED' AND pv.completed_at <= NEW.requested_at) THEN
    PERFORM ac.fail('CHECK_PREVIOUS_INVALID', 'предыдущая Проверка завершена до запроса новой (S23-01)');
  END IF;
  IF NEW.previous_check_id IS NOT NULL AND NOT ac.dominates(NEW.marking, (SELECT marking FROM ac.checks WHERE check_id = NEW.previous_check_id)) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'Проверка уже маркировки предыдущей Проверки (S22-03)');
  END IF;
  IF s.entity_type NOT IN ('PERSON','ORGANIZATION') OR (NEW.status NOT IN ('COMPLETED','CANCELLED') AND s.status <> 'ACTIVE') THEN
    PERFORM ac.fail('CHECK_SUBJECT_INVALID', 'субъект — ACTIVE физлицо или юрлицо');
  END IF;
  IF NOT ac.dominates(NEW.marking, s.marking) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'Проверка шире маркировки субъекта');
  END IF;
  IF NEW.status = 'COMPLETED' AND (TG_OP = 'INSERT' OR OLD.status <> 'COMPLETED') THEN
    NEW.completed_at := ac.guarded_time(NEW.completed_at);
    -- a closed Check keeps a subject merged/retired strictly AFTER closing (RR-01)
    IF s.status <> 'ACTIVE' AND s.status_changed_at <= NEW.completed_at THEN
      PERFORM ac.fail('CHECK_SUBJECT_INVALID', 'субъект слит или выведен из оборота до закрытия Проверки');
    END IF;
  END IF;
  -- the transaction that closes a Check is the only one that may still add its rows (S22-04, S22-05)
  NEW.closed_xact := CASE WHEN NEW.status IN ('COMPLETED','CANCELLED') THEN
                       CASE WHEN TG_OP = 'UPDATE' AND OLD.status IN ('COMPLETED','CANCELLED') THEN OLD.closed_xact ELSE pg_current_xact_id() END END;
  RETURN NEW;
END $$;

-- rows of a closed Check: only inside the transaction that closed it
CREATE FUNCTION ac.check_open_for_rows(kid text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT status NOT IN ('COMPLETED','CANCELLED') OR (status = 'COMPLETED' AND closed_xact = pg_current_xact_id())
  FROM ac.checks WHERE check_id = kid $$;
CREATE TRIGGER checks_guard BEFORE INSERT OR UPDATE ON ac.checks FOR EACH ROW EXECUTE FUNCTION ac.checks_guard();
CREATE TRIGGER checks_no_delete BEFORE DELETE ON ac.checks FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE TABLE ac.check_findings (
  check_id   text NOT NULL REFERENCES ac.checks,
  dimension  text NOT NULL,
  result     text NOT NULL CHECK (result IN ('FOUND','NOT_FOUND')),
  risk       text NOT NULL CHECK (risk IN ('NONE','LOW','MEDIUM','HIGH')),
  PRIMARY KEY (check_id, dimension),                                                     -- no repeated dimension
  CONSTRAINT not_found_no_risk CHECK (result <> 'NOT_FOUND' OR risk = 'NONE')
);
CREATE TRIGGER check_findings_no_update BEFORE UPDATE OR DELETE ON ac.check_findings FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE FUNCTION ac.check_findings_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.lock_keys(ARRAY['check:' || NEW.check_id]);
  IF NOT ac.check_open_for_rows(NEW.check_id) THEN
    PERFORM ac.fail('CHECK_CLOSED', 'в закрытую Проверку нельзя дописывать итоги (S22-04)');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER check_findings_guard BEFORE INSERT ON ac.check_findings FOR EACH ROW EXECUTE FUNCTION ac.check_findings_guard();

CREATE TABLE ac.check_finding_claims (
  project_id  text NOT NULL,
  check_id    text NOT NULL,
  dimension   text NOT NULL,
  claim_id    text NOT NULL,
  PRIMARY KEY (check_id, dimension, claim_id),
  FOREIGN KEY (project_id, check_id) REFERENCES ac.checks (project_id, check_id),
  FOREIGN KEY (check_id, dimension) REFERENCES ac.check_findings,
  FOREIGN KEY (project_id, claim_id) REFERENCES ac.claims (project_id, claim_id)          -- claims of the Check's project only
);
CREATE FUNCTION ac.check_claims_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k ac.checks; c ac.claims;
BEGIN
  SELECT * INTO c FROM ac.claims WHERE claim_id = NEW.claim_id;
  PERFORM ac.lock_keys(ARRAY['check:' || NEW.check_id]);
  PERFORM ac.lock_keys(ARRAY['claim:' || NEW.claim_id]);
  PERFORM ac.lock_entities(NULL, ARRAY[c.subject, c.object_entity]);
  PERFORM ac.lock_keys(ARRAY(SELECT 'source:' || ev.source_id FROM ac.claim_evidence ev WHERE ev.claim_id = NEW.claim_id));
  SELECT * INTO k FROM ac.checks WHERE check_id = NEW.check_id;
  IF c.project_id <> k.project_id OR NEW.project_id <> k.project_id THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE', 'утверждение другого проекта в Проверке');
  END IF;
  IF NOT ac.check_open_for_rows(k.check_id) THEN
    PERFORM ac.fail('CHECK_CLOSED', 'в закрытую Проверку нельзя добавлять утверждения');
  END IF;
  IF NOT ac.dominates(k.marking, c.marking) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'Проверка шире маркировки утверждения');         -- ONT-01
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ac.predicates pr WHERE pr.predicate_id = c.predicate AND NEW.dimension = ANY (pr.dimensions)) THEN
    PERFORM ac.fail('CHECK_CLAIM_DIMENSION_MISMATCH', c.predicate || ' не относится к ' || NEW.dimension);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ac.entities e WHERE e.entity_id IN (c.subject, c.object_entity)
                   AND (e.entity_id = k.subject_entity_id OR e.merged_into = k.subject_entity_id)) THEN
    PERFORM ac.fail('CHECK_CLAIM_NOT_ABOUT_SUBJECT', NEW.claim_id);
  END IF;
  IF k.status = 'COMPLETED' AND ac.status_at(NEW.claim_id, k.completed_at) <> 'ACCEPTED' THEN
    PERFORM ac.fail('CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION', NEW.claim_id);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER check_claims_guard BEFORE INSERT ON ac.check_finding_claims FOR EACH ROW EXECUTE FUNCTION ac.check_claims_guard();
CREATE TRIGGER check_claims_no_update BEFORE UPDATE OR DELETE ON ac.check_finding_claims FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE TABLE ac.check_searches (
  check_id          text NOT NULL REFERENCES ac.checks,
  dimension         text NOT NULL,
  n                 integer NOT NULL,
  performed_at      timestamptz NOT NULL,
  tenant_id         text NOT NULL,
  result_source_id  text,
  body              jsonb NOT NULL,
  PRIMARY KEY (check_id, dimension, n),
  CONSTRAINT search_time_matches_body CHECK (NOT body ? 'performed_at' OR (body->>'performed_at')::timestamptz = performed_at),
  FOREIGN KEY (check_id, dimension) REFERENCES ac.check_findings,
  FOREIGN KEY (tenant_id, result_source_id) REFERENCES ac.sources (tenant_id, source_id)
);
CREATE FUNCTION ac.check_searches_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k ac.checks;
BEGIN
  PERFORM ac.lock_keys(ARRAY['check:' || NEW.check_id]);
  SELECT * INTO k FROM ac.checks WHERE check_id = NEW.check_id;
  IF NEW.performed_at > clock_timestamp() THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'поиск из будущего (S23-05)');
  END IF;
  IF NOT ac.check_open_for_rows(k.check_id) THEN
    PERFORM ac.fail('CHECK_CLOSED', 'в закрытую Проверку нельзя дописывать след поиска');
  END IF;
  IF NEW.tenant_id <> (SELECT tenant_id FROM ac.projects WHERE project_id = k.project_id) THEN
    PERFORM ac.fail('CROSS_SCOPE_REFERENCE', 'след поиска в чужом tenant');
  END IF;
  IF NEW.result_source_id IS NOT NULL THEN
    IF NOT EXISTS (SELECT 1 FROM ac.source_bytes WHERE tenant_id = NEW.tenant_id AND source_id = NEW.result_source_id) THEN
      PERFORM ac.fail('SOURCE_CONTENT_UNAVAILABLE', 'у источника результата поиска нет байтов');          -- RR-08b
    END IF;
    IF NOT ac.dominates(k.marking, (SELECT marking FROM ac.sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.result_source_id)) THEN
      PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'Проверка шире маркировки источника результата поиска');  -- RR-08c
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER check_searches_guard BEFORE INSERT ON ac.check_searches FOR EACH ROW EXECUTE FUNCTION ac.check_searches_guard();
CREATE TRIGGER check_searches_no_update BEFORE UPDATE OR DELETE ON ac.check_searches FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- completeness and consistency of a Check, checked at COMMIT (all its rows are in place by then)
CREATE FUNCTION ac.check_complete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k ac.checks; dims text[]; f record;
BEGIN
  SELECT * INTO k FROM ac.checks WHERE check_id = NEW.check_id;
  SELECT dimensions INTO dims FROM ac.check_profiles WHERE profile = k.profile;
  IF EXISTS (SELECT 1 FROM ac.check_findings WHERE check_id = k.check_id AND dimension <> ALL (dims)) THEN
    PERFORM ac.fail('CHECK_DIMENSION_OUTSIDE_PROFILE', k.check_id);
  END IF;
  FOR f IN SELECT cf.*, (SELECT count(*) FROM ac.check_finding_claims x WHERE x.check_id = cf.check_id AND x.dimension = cf.dimension) AS n
           FROM ac.check_findings cf WHERE cf.check_id = k.check_id LOOP
    IF (f.result = 'FOUND') <> (f.n > 0) THEN
      PERFORM ac.fail('CHECK_FINDING_INCONSISTENT', k.check_id || '/' || f.dimension || ': FOUND ⇔ есть утверждения');
    END IF;
    IF k.status = 'COMPLETED' AND NOT EXISTS (SELECT 1 FROM ac.check_searches s WHERE s.check_id = k.check_id AND s.dimension = f.dimension
                                                AND s.performed_at BETWEEN k.requested_at AND k.completed_at) THEN
      PERFORM ac.fail('CHECK_SEARCH_MISSING', k.check_id || '/' || f.dimension);
    END IF;
  END LOOP;
  IF k.status = 'COMPLETED' THEN
    IF EXISTS (SELECT 1 FROM ac.check_finding_claims x JOIN ac.claims c USING (claim_id) WHERE x.check_id = k.check_id
                 AND ac.status_at(x.claim_id, k.completed_at) <> 'ACCEPTED') THEN
      PERFORM ac.fail('CHECK_CLAIM_NOT_ACCEPTED_AT_COMPLETION', k.check_id);
    END IF;
    IF EXISTS (SELECT 1 FROM ac.check_finding_claims x JOIN ac.claims c USING (claim_id) WHERE x.check_id = k.check_id
                 AND NOT ac.dominates(k.marking, c.marking))
       OR EXISTS (SELECT 1 FROM ac.check_searches s JOIN ac.sources src ON src.tenant_id = s.tenant_id AND src.source_id = s.result_source_id
                  WHERE s.check_id = k.check_id AND NOT ac.dominates(k.marking, src.marking)) THEN
      PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', k.check_id || ': Проверка шире своих утверждений или источников поиска');
    END IF;
    IF EXISTS (SELECT 1 FROM ac.check_finding_claims x JOIN ac.claims c USING (claim_id) WHERE x.check_id = k.check_id
                 AND NOT EXISTS (SELECT 1 FROM ac.entities e WHERE e.entity_id IN (c.subject, c.object_entity)
                                   AND (e.entity_id = k.subject_entity_id OR e.merged_into = k.subject_entity_id))) THEN
      PERFORM ac.fail('CHECK_CLAIM_NOT_ABOUT_SUBJECT', k.check_id);
    END IF;
    IF EXISTS (SELECT unnest(dims) EXCEPT SELECT dimension FROM ac.check_findings WHERE check_id = k.check_id) THEN
      PERFORM ac.fail('CHECK_DIMENSION_MISSING', k.check_id);
    END IF;
    IF ac.risk_rank(k.overall_risk) <> coalesce((SELECT max(ac.risk_rank(risk)) FROM ac.check_findings WHERE check_id = k.check_id), 0) THEN
      PERFORM ac.fail('CHECK_FINDING_INCONSISTENT', k.check_id || ': overall_risk <> max(риск)');
    END IF;
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_complete AFTER INSERT OR UPDATE ON ac.checks DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.check_complete();
CREATE CONSTRAINT TRIGGER check_complete_f AFTER INSERT ON ac.check_findings DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.check_complete();

-- ---------------------------------------------------------------- artifact receipts
CREATE TABLE ac.artifact_receipts (
  receipt_id  text PRIMARY KEY CHECK (receipt_id ~ '^rcp:sha256:[0-9a-f]{64}$'),
  project_id  text NOT NULL,
  tenant_id   text NOT NULL,
  key_id      text NOT NULL,
  service_id  text NOT NULL,
  issued_at   timestamptz NOT NULL,
  body        jsonb NOT NULL,
  UNIQUE (receipt_id, tenant_id),
  FOREIGN KEY (project_id, tenant_id) REFERENCES ac.projects (project_id, tenant_id),
  FOREIGN KEY (tenant_id, key_id) REFERENCES ac_trust.keys (tenant_id, key_id),             -- key only from the tenant's trust anchors
  CHECK (receipt_id = body->>'receipt_id' AND project_id = body->>'project_id' AND key_id = body->>'key_id'
         AND service_id = body->'producer'->>'service_id')
);
CREATE FUNCTION ac.receipts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k ac_trust.keys;
BEGIN
  SELECT * INTO k FROM ac_trust.keys WHERE tenant_id = NEW.tenant_id AND key_id = NEW.key_id;
  IF k.service_id <> NEW.service_id OR NOT (k.not_before <= NEW.issued_at AND NEW.issued_at < k.not_after)
     OR (k.revoked_at IS NOT NULL AND k.revoked_at <= NEW.issued_at) THEN
    PERFORM ac.fail('RECEIPT_KEY_INVALID', 'ключ чужой службы или не действует на issued_at');
  END IF;
  PERFORM ac.check_supplied_time(NEW.issued_at);
  RETURN NEW;
END $$;
CREATE TRIGGER receipts_guard BEFORE INSERT ON ac.artifact_receipts FOR EACH ROW EXECUTE FUNCTION ac.receipts_guard();
CREATE TRIGGER receipts_no_update BEFORE UPDATE OR DELETE ON ac.artifact_receipts FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE TABLE ac.receipt_inputs (
  receipt_id  text NOT NULL,
  tenant_id   text NOT NULL,
  source_id   text NOT NULL,
  PRIMARY KEY (receipt_id, source_id),
  FOREIGN KEY (receipt_id, tenant_id) REFERENCES ac.artifact_receipts (receipt_id, tenant_id),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.sources                         -- inputs from the receipt's tenant only
);
CREATE TRIGGER receipt_inputs_no_update BEFORE UPDATE OR DELETE ON ac.receipt_inputs FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE FUNCTION ac.receipt_inputs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT ((SELECT body->'input_source_ids' FROM ac.artifact_receipts WHERE receipt_id = NEW.receipt_id) ? NEW.source_id) THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', NEW.source_id || ': нет в input_source_ids подписанного тела receipt');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER receipt_inputs_guard BEFORE INSERT ON ac.receipt_inputs FOR EACH ROW EXECUTE FUNCTION ac.receipt_inputs_guard();

CREATE TABLE ac.receipt_claims (
  receipt_id  text NOT NULL REFERENCES ac.artifact_receipts,
  claim_id    text NOT NULL UNIQUE REFERENCES ac.claims,          -- at most one receipt per claim
  PRIMARY KEY (receipt_id, claim_id)
);
CREATE FUNCTION ac.receipt_claims_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r ac.artifact_receipts; c ac.claims;
BEGIN
  SELECT * INTO r FROM ac.artifact_receipts WHERE receipt_id = NEW.receipt_id;
  SELECT * INTO c FROM ac.claims WHERE claim_id = NEW.claim_id;
  IF NOT (r.body->'emitted_claim_ids') ? NEW.claim_id THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', NEW.claim_id || ': нет в emitted_claim_ids подписанного тела receipt');
  END IF;
  IF c.produced_kind <> 'PIPELINE' OR c.project_id <> r.project_id OR c.body->'produced_by'->>'service_id' <> r.service_id
     OR c.body->'produced_by'->>'run_id' <> r.body->>'run_id' OR c.recorded_at > r.issued_at THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', NEW.claim_id);
  END IF;
  IF EXISTS (SELECT 1 FROM ac.claim_evidence e WHERE e.claim_id = NEW.claim_id
               AND (NOT EXISTS (SELECT 1 FROM ac.receipt_inputs i WHERE i.receipt_id = NEW.receipt_id AND i.source_id = e.source_id)
                    OR (e.graph_node IS NOT NULL AND e.graph_node->>'artifact_digest' <> r.body->>'artifact_digest'))) THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', NEW.claim_id || ': источник не во входах receipt или узел графа другого артефакта');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER receipt_claims_guard BEFORE INSERT ON ac.receipt_claims FOR EACH ROW EXECUTE FUNCTION ac.receipt_claims_guard();
CREATE TRIGGER receipt_claims_no_update BEFORE UPDATE OR DELETE ON ac.receipt_claims FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- at least one receipt per PIPELINE claim, checked at COMMIT (deferred)
CREATE FUNCTION ac.pipeline_needs_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.produced_kind = 'PIPELINE' AND NOT EXISTS (SELECT 1 FROM ac.receipt_claims WHERE claim_id = NEW.claim_id) THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', NEW.claim_id || ': PIPELINE-утверждение без receipt');
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER pipeline_needs_receipt AFTER INSERT ON ac.claims DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.pipeline_needs_receipt();

-- ---------------------------------------------------------------- provenance view (projection S3 builds on it)
CREATE VIEW ac.claim_provenance AS
SELECT c.project_id, c.claim_id, c.subject, c.predicate, c.body->'object' AS object, ac.status_at(c.claim_id, now()) AS status,
       e.ord, s.body->>'title' AS source_title, s.body->>'source_kind' AS source_kind, e.span_start, e.span_end,
       convert_from(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start), 'UTF8') AS quote,
       encode(sha256(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start)), 'hex') = e.quote_sha256 AS verified
FROM ac.claims c
JOIN ac.claim_evidence e USING (claim_id)
JOIN ac.sources s ON s.tenant_id = e.tenant_id AND s.source_id = e.source_id
JOIN ac.source_bytes b ON b.tenant_id = e.tenant_id AND b.source_id = e.source_id;   -- rows of datasets: ddl_s10.sql

-- ---------------------------------------------------------------- privileges (least privilege)
REVOKE ALL ON ALL TABLES IN SCHEMA ac, ac_trust FROM PUBLIC, ac_loader, ac_migrator, ac_trust_admin;
GRANT USAGE ON SCHEMA ac, ac_trust TO ac_loader, ac_migrator, ac_trust_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA ac TO ac_loader, ac_migrator;
GRANT SELECT ON ALL TABLES IN SCHEMA ac_trust TO ac_loader, ac_migrator;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ac_trust TO ac_trust_admin;
-- data written by the application (append-only tables: INSERT only)
GRANT INSERT ON ac.sources, ac.source_bytes, ac.source_observations, ac.entities, ac.claims, ac.claim_reviews,
               ac.checks, ac.check_findings, ac.check_finding_claims, ac.check_searches,
               ac.artifact_receipts, ac.receipt_inputs, ac.receipt_claims TO ac_loader, ac_migrator;
-- the only UPDATE paths: entity status transition, Check status transition
GRANT UPDATE (status, merged_into, status_changed_at) ON ac.entities TO ac_loader, ac_migrator;
GRANT UPDATE (status, completed_at, cancelled_at, overall_risk, body) ON ac.checks TO ac_loader, ac_migrator;
-- configuration (projects, registries) only by the migrator; entity_keys and claim_evidence only by DB triggers
GRANT INSERT ON ac.projects, ac.predicates, ac.check_profiles TO ac_migrator;
GRANT INSERT ON ac.identity_decisions TO ac_loader, ac_migrator;
GRANT INSERT ON ac.history_seals TO ac_migrator;
CREATE TRIGGER history_seals_no_update BEFORE UPDATE OR DELETE ON ac.history_seals FOR EACH ROW EXECUTE FUNCTION ac.forbid();
DO $$ BEGIN EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database()); END $$;
DO $$ BEGIN EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO ac_migrator', current_database()); END $$;

CREATE CONSTRAINT TRIGGER check_complete_c AFTER INSERT ON ac.check_finding_claims DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.check_complete();
CREATE CONSTRAINT TRIGGER check_complete_s AFTER INSERT ON ac.check_searches DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.check_complete();

CREATE TRIGGER entities_keys_after AFTER INSERT ON ac.entities FOR EACH ROW EXECUTE FUNCTION ac.entities_keys_after();

CREATE FUNCTION ac.receipt_complete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r ac.artifact_receipts;
BEGIN
  SELECT * INTO r FROM ac.artifact_receipts WHERE receipt_id = NEW.receipt_id;
  IF (SELECT count(*) FROM ac.receipt_claims WHERE receipt_id = r.receipt_id) <> jsonb_array_length(r.body->'emitted_claim_ids')
     OR (SELECT count(*) FROM ac.receipt_inputs WHERE receipt_id = r.receipt_id) <> jsonb_array_length(r.body->'input_source_ids') THEN
    PERFORM ac.fail('RECEIPT_CLAIM_BINDING_INVALID', r.receipt_id || ': строки receipt не совпадают с подписанным телом');
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER receipt_complete AFTER INSERT ON ac.artifact_receipts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.receipt_complete();

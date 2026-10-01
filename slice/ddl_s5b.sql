-- Архитектура семантики — S5 (часть 2): оригиналы в объектном хранилище (D26).
-- Что где лежит:
--   * ТЕКСТ источника (байты, по которым проверяются цитаты) остаётся в базе: иначе база не смогла бы сама
--     сверять доказательства (D8) — это не переносится;
--   * ОРИГИНАЛ забора (страница, PDF, скан), из которого текст извлечён, лежит в объектном хранилище по адресу
--     sha256; база хранит только реестр: адрес, длину, кто и когда сохранил, и журнал проверок целостности.
-- Правила:
--   * реестр объектов и журнал проверок пишет только роль шлюза хранилища ac_storage; приложение (ac_loader)
--     не может объявить объект сохранённым;
--   * объект регистрируется только вместе с успешной проверкой чтением (в той же транзакции);
--   * наблюдение может назвать оригинал только зарегистрированный в его tenant, с той же длиной и с последней
--     проверкой «цел»;
--   * время записи и проверки ставит база; записи неизменяемы.
-- Applied after proj_s5.sql.

DO $$ BEGIN CREATE ROLE ac_storage NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA ac TO ac_storage;
-- S6R-06: the gateway process connects AS this role — a real login, member of ac_storage and nothing else — never
-- as a superuser session with SET SESSION AUTHORIZATION (undoable with a bare RESET from the same channel).
DO $$ BEGIN CREATE ROLE ac_gateway LOGIN IN ROLE ac_storage; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE ac.objects (
  tenant_id       text NOT NULL CHECK (tenant_id ~ '^tnt_[a-z0-9_]{2,64}$'),  -- S6R-09: same pattern as object_store.valid_tenant
  object_address  text NOT NULL CHECK (object_address ~ '^sha256:[0-9a-f]{64}$'),
  byte_length     bigint NOT NULL CHECK (byte_length > 0),
  stored_at       timestamptz,                    -- set by the database
  stored_by       name,                           -- set by the database
  PRIMARY KEY (tenant_id, object_address)
);
CREATE TABLE ac.object_checks (
  tenant_id       text NOT NULL,
  object_address  text NOT NULL,
  checked_at      timestamptz NOT NULL,           -- set by the database
  result          text NOT NULL CHECK (result IN ('OK', 'MISSING', 'CORRUPT')),
  checked_by      name,                           -- set by the database
  PRIMARY KEY (tenant_id, object_address, checked_at),
  FOREIGN KEY (tenant_id, object_address) REFERENCES ac.objects
);

-- S6R-01/04: an object's stored_at/checked_at are "guarded" time (S23-10 style) — the advisory lock on this exact
-- object is taken BEFORE the clock is read, and the SAME key is taken by ac.custody before it reads this object's
-- state (below) and by the observation guard before it trusts that state (observation_original_guard). Whichever
-- of a writer and a reader asks for the lock first forces the other to wait for it to finish, so a repeat read at
-- a fixed past as_of can never see a different, later-arriving answer than before, and an observation can never be
-- accepted against a check that has not yet committed.
CREATE FUNCTION ac.objects_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.lock_keys(ARRAY['object:' || NEW.tenant_id || '/' || NEW.object_address]);
  NEW.stored_at := clock_timestamp();
  NEW.stored_by := session_user;
  RETURN NEW;
END $$;
CREATE TRIGGER objects_guard BEFORE INSERT ON ac.objects FOR EACH ROW EXECUTE FUNCTION ac.objects_guard();
CREATE TRIGGER objects_no_update BEFORE UPDATE OR DELETE ON ac.objects FOR EACH ROW EXECUTE FUNCTION ac.forbid();

CREATE FUNCTION ac.object_checks_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM ac.lock_keys(ARRAY['object:' || NEW.tenant_id || '/' || NEW.object_address]);
  NEW.checked_at := clock_timestamp();
  NEW.checked_by := session_user;
  RETURN NEW;
END $$;
CREATE TRIGGER object_checks_guard BEFORE INSERT ON ac.object_checks FOR EACH ROW EXECUTE FUNCTION ac.object_checks_guard();
CREATE TRIGGER object_checks_no_update BEFORE UPDATE OR DELETE ON ac.object_checks FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- an object is registered only together with a successful read-back check (same transaction)
CREATE FUNCTION ac.object_verified() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ac.object_checks c WHERE c.tenant_id = NEW.tenant_id AND c.object_address = NEW.object_address AND c.result = 'OK') THEN
    PERFORM ac.fail('ORIGINAL_INVALID', NEW.object_address || ': объект регистрируется только с успешной проверкой чтением');
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER object_verified AFTER INSERT ON ac.objects DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.object_verified();

-- state of an object as of time t: the result of its latest check by then (NULL = not checked yet)
CREATE FUNCTION ac.object_status_at(tenant text, addr text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT c.result FROM ac.object_checks c WHERE c.tenant_id = tenant AND c.object_address = addr AND c.checked_at <= t
  ORDER BY c.checked_at DESC LIMIT 1 $$;

-- ---------------------------------------------------------------- оригинал у наблюдения
ALTER TABLE ac.source_observations
  ADD COLUMN original_object      text,
  ADD COLUMN original_media_type  text CHECK (original_media_type ~ '^[a-z]+/[a-z0-9.+-]+(; ?charset=[a-z0-9-]+)?$'),
  ADD COLUMN original_length      bigint,
  ADD CONSTRAINT observation_original_whole CHECK ((original_object IS NULL) = (original_media_type IS NULL)
                                                   AND (original_object IS NULL) = (original_length IS NULL)),
  ADD CONSTRAINT observation_original_fk FOREIGN KEY (tenant_id, original_object) REFERENCES ac.objects;

CREATE FUNCTION ac.observation_original_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o ac.objects;
BEGIN
  IF NEW.original_object IS NULL THEN
    RETURN NEW;
  END IF;
  -- S6R-04: wait for any in-flight registration/check write on this exact object (same key as objects_guard /
  -- object_checks_guard) to commit first, so an uncommitted MISSING/CORRUPT can never be invisible to us.
  PERFORM ac.lock_keys(ARRAY['object:' || NEW.tenant_id || '/' || NEW.original_object]);
  SELECT * INTO o FROM ac.objects WHERE tenant_id = NEW.tenant_id AND object_address = NEW.original_object;
  IF o.object_address IS NULL THEN
    PERFORM ac.fail('ORIGINAL_INVALID', 'оригинал не зарегистрирован в хранилище объектов этого tenant');
  END IF;
  IF o.byte_length <> NEW.original_length THEN
    PERFORM ac.fail('ORIGINAL_INVALID', 'длина оригинала не совпадает с зарегистрированной');
  END IF;
  IF ac.object_status_at(NEW.tenant_id, NEW.original_object, clock_timestamp()) IS DISTINCT FROM 'OK' THEN
    PERFORM ac.fail('ORIGINAL_INVALID', 'оригинал повреждён или утрачен по последней проверке');
  END IF;
  RETURN NEW;
END $$;
-- named to fire after observation_guard (alphabetical order of BEFORE triggers)
CREATE TRIGGER observation_original_guard BEFORE INSERT ON ac.source_observations FOR EACH ROW EXECUTE FUNCTION ac.observation_original_guard();

-- ---------------------------------------------------------------- права
REVOKE ALL ON ac.objects, ac.object_checks FROM PUBLIC, ac_loader, ac_migrator, ac_trust_admin, ac_storage;
GRANT SELECT ON ac.objects, ac.object_checks TO ac_storage, ac_loader, ac_migrator, ac_projector;
GRANT INSERT (tenant_id, object_address, byte_length) ON ac.objects TO ac_storage;
GRANT INSERT (tenant_id, object_address, result) ON ac.object_checks TO ac_storage;

-- ---------------------------------------------------------------- проекция «сохранность оригиналов» одного утверждения
-- Для каждого источника, на который опирается утверждение: его ПЕРВОЕ наблюдение (как провенанс — только
-- first_observed_at, D15 — а не полный список заборов: источник общий для tenant, и не-первые заборы могут
-- принадлежать работе другого проекта, S6R-03) и его оригинал — тип, размер, когда сохранён, состояние по
-- последней проверке на момент as_of и сколько раз проверялся. Допуск — как у провенанса (D15).
-- NOT STABLE (S6R-01/02, root cause found in review): PostgreSQL gives a STABLE function's internal statements
-- the snapshot of the CALLING query, not a fresh one each — a VOLATILE function's statements each get the latest
-- snapshot, which is what makes "lock, then read" above actually see what the lock waited for. Confirmed by a
-- minimal isolated probe: the identical lock-then-read body returns fresh data as VOLATILE and stale data the
-- instant STABLE is added, independent of how the read itself is written (plain SELECT, jsonb_build_object,
-- a nested STABLE SQL helper, one lock or two). custody is only ever called as a lone top-level statement
-- (never nested inside another function), so losing the planner's STABLE-caching assumption costs nothing here.
CREATE FUNCTION ac.custody(cid text, as_of timestamptz DEFAULT now()) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE c ac.claims; clr jsonb; res jsonb; src_ids text[]; obj_keys text[];
BEGIN
  as_of := least(as_of, clock_timestamp());
  SELECT * INTO c FROM ac.claims WHERE claim_id = cid;
  IF c.claim_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(c.project_id, c.marking);
  IF c.recorded_at > as_of OR NOT (ac.entity_visible(clr, c.subject, as_of) AND ac.entity_visible(clr, c.object_entity, as_of)) THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- S6R-01/02: serialise with every writer that could still change a PAST answer, through the SAME keys those
  -- writers take before computing their own guarded time (observation_guard: 'source:'; objects_guard/
  -- object_checks_guard: 'object:'). Whichever of us and a concurrent writer asks first, the other waits for it
  -- to finish before proceeding — so by the time we read, no write that could land at or before as_of is still
  -- in flight, and a later call at the same as_of can only ever see the same, by-then-settled answer.
  SELECT array_agg(DISTINCT e.source_id) INTO src_ids FROM ac.claim_evidence e WHERE e.claim_id = cid;
  PERFORM ac.lock_keys(ARRAY(SELECT 'source:' || s FROM unnest(coalesce(src_ids, ARRAY[]::text[])) s));
  SELECT array_agg(DISTINCT 'object:' || o.tenant_id || '/' || o.original_object) INTO obj_keys
    FROM ac.source_observations o WHERE o.source_id = ANY(coalesce(src_ids, ARRAY[]::text[])) AND o.original_object IS NOT NULL;
  PERFORM ac.lock_keys(coalesce(obj_keys, ARRAY[]::text[]));
  res := jsonb_build_object(
    'projection', 'custody/0.1', 'claim_id', cid, 'project_id', c.project_id, 'text', ac.fact_text(c, as_of), 'as_of', as_of,
    'marking', c.marking,
    'sources', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                  'source_id', s.source_id, 'title', s.body->>'title', 'kind', s.body->>'source_kind',
                  'text_bytes', s.byte_length,
                  'observations', (SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                                     'observed_at', o.observed_at, 'origin_uri', o.origin_uri,
                                     'original', CASE WHEN o.original_object IS NOT NULL THEN jsonb_build_object(
                                         'object', o.original_object, 'media_type', o.original_media_type, 'byte_length', o.original_length,
                                         'stored_at', ob.stored_at,
                                         'status', coalesce(ac.object_status_at(o.tenant_id, o.original_object, as_of), 'UNCHECKED'),
                                         'last_checked_at', (SELECT max(k.checked_at) FROM ac.object_checks k WHERE k.tenant_id = o.tenant_id
                                                             AND k.object_address = o.original_object AND k.checked_at <= as_of),
                                         'checks', (SELECT count(*) FROM ac.object_checks k WHERE k.tenant_id = o.tenant_id
                                                    AND k.object_address = o.original_object AND k.checked_at <= as_of)) END))),
                                   '[]')
                                   FROM (SELECT * FROM ac.source_observations o
                                         WHERE o.tenant_id = s.tenant_id AND o.source_id = s.source_id AND o.ingested_at <= as_of
                                         ORDER BY o.observed_at, o.origin_uri LIMIT 1) o
                                   LEFT JOIN ac.objects ob ON ob.tenant_id = o.tenant_id AND ob.object_address = o.original_object))
                  ORDER BY s.source_id), '[]')
                FROM ac.sources s
                WHERE (s.tenant_id, s.source_id) IN (SELECT e.tenant_id, e.source_id FROM ac.claim_evidence e WHERE e.claim_id = cid)
                  AND ac.dominates(clr, s.marking)));
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;
ALTER FUNCTION ac.custody(text, timestamptz) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.custody(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.custody(text, timestamptz) TO ac_reader;

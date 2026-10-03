-- Архитектура семантики — S10 (цикл 10, часть 1): «Массивный профиль» (D27.2, D27.4), core-ontology/0.4.
--
-- Версия набора данных — это Source вида DATASET_VERSION, байты которого — манифест (ac-dataset-manifest/0.1).
-- Утверждение может опираться на СТРОКУ версии: доказательство ROW несёт ячейки строки (процитированные — со
-- значением и солью, остальные — листом), хэш строки и путь включения строки в файл версии. База проверяет его
-- по манифесту сама, без файла строк и без таблицы строк («база выше заявления»):
--   * ac.datasets              — каталог версий, строка появляется только из триггера при записи байтов манифеста;
--   * ac.row_evidence_guard    — зеркало validator.row_evidence_error (вызывается из ac.evidence_guard, ddl_s1.sql);
--   * ac.dataset_open / _seal  — широкая типизированная таблица строк версии (схема acd, секция на версию),
--                                запечатывается после сверки КАЖДОЙ строки и корня КАЖДОГО файла с манифестом;
--                                после печати DML отвергается для любой роли (DDL владельца базы — вне модели угроз);
--   * ac.dataset_evidence      — доказательство ROW, собранное базой из таблицы строк;
--   * ac.dataset_row / ac.dataset_find — чтение строки и поиск по идентификатору с допуском читателя.
-- Правила валидатора ↔ базы сверяются на векторах цикла 10 (s10_tests.py, S10-PARITY).

DROP SCHEMA IF EXISTS acd CASCADE;
CREATE SCHEMA acd;                                   -- wide tables of dataset versions; nobody reads them directly
REVOKE ALL ON SCHEMA acd FROM PUBLIC;

-- ---------------------------------------------------------------- canonical JSON (RFC 8785) of a jsonb value
-- strings: to_json(text) escapes exactly what JCS escapes (", \, \b \f \n \r \t, other C0 as \u00xx lowercase);
-- numbers: integers only (the integer profile of the ontology) — anything else is refused by the callers;
-- object keys: the manifests and cells use ASCII keys, for which byte order = UTF-16 order
CREATE FUNCTION ac.jcs(j jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE jsonb_typeof(j)
    WHEN 'object' THEN '{' || coalesce((SELECT string_agg(to_json(k)::text || ':' || ac.jcs(v), ',' ORDER BY k COLLATE "C")
                                        FROM jsonb_each(j) e(k, v)), '') || '}'
    WHEN 'array' THEN '[' || coalesce((SELECT string_agg(ac.jcs(v), ',' ORDER BY o)
                                       FROM jsonb_array_elements(j) WITH ORDINALITY a(v, o)), '') || ']'
    WHEN 'string' THEN to_json(j #>> '{}')::text
    WHEN 'null' THEN 'null'
    ELSE j #>> '{}' END $$;

CREATE FUNCTION ac.is_int(j jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(jsonb_typeof(j) = 'number' AND (j #>> '{}') ~ '^-?(0|[1-9][0-9]{0,15})$'
                  AND abs((j #>> '{}')::numeric) <= 9007199254740991, false) $$;

-- ---------------------------------------------------------------- hashes of a cell, a row, a file (validator.py: cell_leaf, row_leaf, merkle_root)
CREATE FUNCTION ac.cell_leaf(salt bytea, name text, v jsonb) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT sha256('\x00'::bytea || salt || convert_to('[' || to_json(name)::text || ',' || ac.jcs(v) || ']', 'UTF8')) $$;

CREATE FUNCTION ac.row_leaf(h bytea) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT sha256('\x02'::bytea || h) $$;

-- the salt of a cell: derived from the secret of its row and the name of its column (producer convention, dataset.py)
CREATE FUNCTION ac.cell_salt(secret bytea, name text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
  SELECT sha256('\x03'::bytea || secret || convert_to(name, 'UTF8')) $$;

-- RFC 6962 tree: pairing level by level with the odd last node carried up gives the same root as «the left subtree is
-- the largest power of two»
CREATE FUNCTION ac.merkle_root(leaves bytea[]) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE cur bytea[] := leaves; nxt bytea[]; n int; i int;
BEGIN
  n := coalesce(cardinality(cur), 0);
  IF n = 0 THEN RETURN NULL; END IF;
  WHILE n > 1 LOOP
    nxt := ARRAY[]::bytea[];
    i := 1;
    WHILE i < n LOOP
      nxt := nxt || sha256('\x01'::bytea || cur[i] || cur[i + 1]);
      i := i + 2;
    END LOOP;
    IF i = n THEN nxt := nxt || cur[n]; END IF;
    cur := nxt;
    n := cardinality(cur);
  END LOOP;
  RETURN cur[1];
END $$;

-- the root implied by an audit path (RFC 9162 2.1.3.2); NULL if the path does not fit (index, size)
CREATE FUNCTION ac.inclusion_root(leaf bytea, idx bigint, size bigint, path bytea[]) RETURNS bytea LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE fn bigint := idx; sn bigint := size - 1; r bytea := leaf; p bytea;
BEGIN
  IF idx IS NULL OR size IS NULL OR idx < 0 OR idx >= size THEN RETURN NULL; END IF;
  FOREACH p IN ARRAY coalesce(path, ARRAY[]::bytea[]) LOOP
    IF sn = 0 THEN RETURN NULL; END IF;
    IF fn & 1 = 1 OR fn = sn THEN
      r := sha256('\x01'::bytea || p || r);
      IF fn & 1 = 0 THEN
        WHILE fn <> 0 AND fn & 1 = 0 LOOP fn := fn >> 1; sn := sn >> 1; END LOOP;
      END IF;
    ELSE
      r := sha256('\x01'::bytea || r || p);
    END IF;
    fn := fn >> 1; sn := sn >> 1;
  END LOOP;
  RETURN CASE WHEN sn = 0 THEN r END;
END $$;

-- sibling hashes from the leaf up to the root (dataset.py: audit_path), for the tree built as in ac.merkle_root
CREATE FUNCTION ac.audit_path(leaves bytea[], idx int) RETURNS bytea[] LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE cur bytea[] := leaves; nxt bytea[]; n int := cardinality(leaves); i int; pos int := idx + 1; res bytea[] := ARRAY[]::bytea[];
BEGIN
  WHILE n > 1 LOOP
    IF pos % 2 = 1 THEN
      IF pos < n THEN res := res || cur[pos + 1]; END IF;      -- the odd last node has no sibling on this level
    ELSE
      res := res || cur[pos - 1];
    END IF;
    nxt := ARRAY[]::bytea[];
    i := 1;
    WHILE i < n LOOP
      nxt := nxt || sha256('\x01'::bytea || cur[i] || cur[i + 1]);
      i := i + 2;
    END LOOP;
    IF i = n THEN nxt := nxt || cur[n]; END IF;
    cur := nxt;
    pos := (pos + 1) / 2;
    n := cardinality(cur);
  END LOOP;
  RETURN res;
END $$;

-- the value of a cell fits the type of its column (validator.py: cell_value_ok); null = an empty cell
CREATE FUNCTION ac.cell_value_ok(ctype text, v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(CASE
    WHEN jsonb_typeof(v) = 'null' THEN true
    WHEN ctype = 'BOOLEAN' THEN jsonb_typeof(v) = 'boolean'
    WHEN ctype = 'INTEGER' THEN ac.is_int(v)
    WHEN ctype = 'STRING' THEN jsonb_typeof(v) = 'string'
    WHEN ctype = 'DATE' THEN jsonb_typeof(v) = 'string' AND (v #>> '{}') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' AND ac.is_date(v #>> '{}')
                             AND left(v #>> '{}', 4) <> '0000'
    ELSE false END, false) $$;

-- ---------------------------------------------------------------- the manifest (validator.py: parse_manifest + DatasetManifest of core.schema.json)
CREATE FUNCTION ac.manifest_error(m jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE c jsonb; f jsonb; names text[]; idents text[];
BEGIN
  IF jsonb_typeof(m) IS DISTINCT FROM 'object' THEN RETURN 'манифест — не объект'; END IF;
  IF NOT (m ?& ARRAY['manifest_format', 'dataset_id', 'tenant_id', 'version_label', 'columns', 'key', 'row_count', 'files'])
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(m) k WHERE k NOT IN ('manifest_format', 'dataset_id', 'tenant_id', 'version_label',
                                                                    'previous', 'columns', 'key', 'subject', 'row_count', 'files')) THEN
    RETURN 'состав полей манифеста';
  END IF;
  IF m->'manifest_format' IS DISTINCT FROM '"ac-dataset-manifest/0.1"' THEN RETURN 'manifest_format'; END IF;
  IF jsonb_typeof(m->'dataset_id') <> 'string' OR m->>'dataset_id' !~ '^dst_[a-z0-9_]{2,64}$' THEN RETURN 'dataset_id'; END IF;
  IF jsonb_typeof(m->'tenant_id') <> 'string' OR m->>'tenant_id' !~ '^tnt_[a-z0-9_]{2,64}$' THEN RETURN 'tenant_id'; END IF;
  IF jsonb_typeof(m->'version_label') <> 'string' OR length(m->>'version_label') NOT BETWEEN 1 AND 2000
     OR m->>'version_label' ~ '[\x01-\x1f\x7f]'                                   -- a structural field: no control characters
     OR m->>'version_label' !~ '[^ \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]' THEN   -- not blank (Unicode White_Space)
    RETURN 'version_label'; END IF;
  IF m ? 'previous' AND (jsonb_typeof(m->'previous') <> 'string' OR m->>'previous' !~ '^src:sha256:[0-9a-f]{64}$') THEN RETURN 'previous'; END IF;
  IF jsonb_typeof(m->'columns') <> 'array' OR jsonb_array_length(m->'columns') NOT BETWEEN 1 AND 512 THEN RETURN 'columns'; END IF;
  FOR c IN SELECT x FROM jsonb_array_elements(m->'columns') x LOOP
    IF jsonb_typeof(c) <> 'object' OR NOT (c ?& ARRAY['name', 'type', 'marking'])
       OR EXISTS (SELECT 1 FROM jsonb_object_keys(c) k WHERE k NOT IN ('name', 'type', 'marking', 'identifier_scheme', 'predicate'))
       OR jsonb_typeof(c->'name') <> 'string' OR c->>'name' !~ '^[a-z][a-z0-9_]{0,62}$'
       OR jsonb_typeof(c->'type') <> 'string' OR c->>'type' NOT IN ('STRING', 'INTEGER', 'BOOLEAN', 'DATE')
       OR NOT ac.marking_ok(c->'marking')
       OR (c ? 'identifier_scheme' AND (jsonb_typeof(c->'identifier_scheme') <> 'string' OR c->>'identifier_scheme' !~ '^[a-z][a-z0-9.]{1,40}$'))
       OR (c ? 'predicate' AND (jsonb_typeof(c->'predicate') <> 'string' OR c->>'predicate' !~ '^[a-z]+\.[a-z_]+$')) THEN
      RETURN 'колонка не по схеме манифеста';
    END IF;
  END LOOP;
  IF jsonb_typeof(m->'key') <> 'array' OR jsonb_array_length(m->'key') > 8
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(m->'key') x WHERE jsonb_typeof(x) <> 'string' OR x #>> '{}' !~ '^[a-z][a-z0-9_]{0,62}$')
     OR (SELECT count(DISTINCT x) FROM jsonb_array_elements(m->'key') x) <> jsonb_array_length(m->'key') THEN RETURN 'key'; END IF;
  IF m ? 'subject' AND (jsonb_typeof(m->'subject') <> 'array' OR jsonb_array_length(m->'subject') NOT BETWEEN 1 AND 8
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(m->'subject') x WHERE jsonb_typeof(x) <> 'string' OR x #>> '{}' !~ '^[a-z][a-z0-9_]{0,62}$')
     OR (SELECT count(DISTINCT x) FROM jsonb_array_elements(m->'subject') x) <> jsonb_array_length(m->'subject')) THEN RETURN 'subject'; END IF;
  IF NOT ac.is_int(m->'row_count') OR (m->>'row_count')::numeric < 0 THEN RETURN 'row_count'; END IF;
  IF jsonb_typeof(m->'files') <> 'array' OR jsonb_array_length(m->'files') > 100000 THEN RETURN 'files'; END IF;
  FOR f IN SELECT x FROM jsonb_array_elements(m->'files') x LOOP
    IF jsonb_typeof(f) <> 'object' OR NOT (f ?& ARRAY['object', 'byte_length', 'rows', 'rows_root'])
       OR EXISTS (SELECT 1 FROM jsonb_object_keys(f) k WHERE k NOT IN ('object', 'byte_length', 'rows', 'rows_root'))
       OR jsonb_typeof(f->'object') <> 'string' OR f->>'object' !~ '^sha256:[0-9a-f]{64}$'
       OR NOT ac.is_int(f->'byte_length') OR (f->>'byte_length')::numeric < 1
       OR NOT ac.is_int(f->'rows') OR (f->>'rows')::numeric < 1
       OR jsonb_typeof(f->'rows_root') <> 'string' OR f->>'rows_root' !~ '^[0-9a-f]{64}$' THEN
      RETURN 'файл не по схеме манифеста';
    END IF;
  END LOOP;
  names := ARRAY(SELECT x->>'name' FROM jsonb_array_elements(m->'columns') x);
  idents := ARRAY(SELECT x->>'name' FROM jsonb_array_elements(m->'columns') x WHERE x ? 'identifier_scheme');
  IF (SELECT count(DISTINCT n) FROM unnest(names) n) <> cardinality(names) THEN RETURN 'имя колонки повторяется'; END IF;
  IF NOT ARRAY(SELECT jsonb_array_elements_text(m->'key')) <@ names THEN RETURN 'ключ набора называет колонку, которой нет'; END IF;
  IF (m->>'row_count')::numeric <> (SELECT coalesce(sum((x->>'rows')::numeric), 0) FROM jsonb_array_elements(m->'files') x) THEN
    RETURN 'row_count не равен сумме строк файлов';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(m->'columns') x WHERE x ? 'identifier_scheme' AND x->>'type' <> 'STRING') THEN
    RETURN 'схема идентификатора — только у строковой колонки';
  END IF;
  IF m ? 'subject' AND NOT ARRAY(SELECT jsonb_array_elements_text(m->'subject')) <@ idents THEN
    RETURN 'subject называет колонку, которой нет или которая не идентификатор';
  END IF;
  RETURN NULL;
END $$;

-- ---------------------------------------------------------------- the catalog of dataset versions
CREATE TABLE ac.datasets (
  tenant_id      text NOT NULL,
  source_id      text NOT NULL,
  dataset_id     text NOT NULL,
  version_label  text NOT NULL,
  previous       text,
  row_count      bigint NOT NULL,
  manifest       jsonb NOT NULL,
  PRIMARY KEY (tenant_id, source_id),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.sources
);
CREATE INDEX datasets_by_dataset ON ac.datasets (tenant_id, dataset_id);
CREATE INDEX datasets_by_previous ON ac.datasets (tenant_id, previous) WHERE previous IS NOT NULL;
CREATE TRIGGER datasets_no_update BEFORE UPDATE OR DELETE ON ac.datasets FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- a source of kind DATASET_VERSION is a record of core-ontology/0.4 with the media type of the manifest
CREATE FUNCTION ac.sources_dataset_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.body->>'source_kind' = 'DATASET_VERSION'
     AND (NEW.body->>'schema_version' IS DISTINCT FROM 'core-ontology/0.4'
          OR NEW.body->>'media_type' IS DISTINCT FROM 'application/vnd.ac.dataset-manifest+json') THEN
    PERFORM ac.fail('SCHEMA_INVALID', 'версия набора данных — запись core-ontology/0.4 с типом содержимого манифеста');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER sources_dataset_guard BEFORE INSERT ON ac.sources FOR EACH ROW EXECUTE FUNCTION ac.sources_dataset_guard();

-- the bytes of a DATASET_VERSION source are its manifest: parsed, checked and registered when the bytes arrive
CREATE FUNCTION ac.dataset_register() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE src ac.sources; m jsonb; why text;
BEGIN
  SELECT * INTO src FROM ac.sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF src.body->>'source_kind' IS DISTINCT FROM 'DATASET_VERSION' THEN
    RETURN NULL;
  END IF;
  BEGIN
    m := convert_from(NEW.bytes, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'манифест не JSON в UTF-8');
  END;
  why := ac.manifest_error(m);
  IF why IS NOT NULL THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'манифест не по схеме ac-dataset-manifest/0.1: ' || why);
  END IF;
  -- jsonb drops duplicate keys, spaces and the order of keys; the canonical bytes are the ones stored — or it is refused
  IF convert_to(ac.jcs(m), 'UTF8') <> NEW.bytes THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'манифест не в канонической форме RFC 8785 (или с повторяющимися ключами)');
  END IF;
  IF m->>'tenant_id' <> NEW.tenant_id THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'tenant манифеста не равен tenant источника');
  END IF;
  -- a file of the version that the object store already holds has the length the manifest states
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(m->'files') f JOIN ac.objects o ON o.tenant_id = NEW.tenant_id AND o.object_address = f->>'object'
             WHERE o.byte_length <> (f->>'byte_length')::bigint) THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'файл версии набора: длина в манифесте не равна длине объекта в хранилище');
  END IF;
  INSERT INTO ac.datasets VALUES (NEW.tenant_id, NEW.source_id, m->>'dataset_id', m->>'version_label', m->>'previous',
                                  (m->>'row_count')::bigint, m);
  RETURN NULL;
END $$;
CREATE TRIGGER dataset_register AFTER INSERT ON ac.source_bytes FOR EACH ROW EXECUTE FUNCTION ac.dataset_register();

-- What a version says about OTHER records is checked at COMMIT, whichever of them arrived first (S10R-01):
--   * «previous»: if the named source is known IN THE TENANT, it is a registered version of the same dataset (a source
--     of another tenant is unknown to this one; a source without a registered manifest is not a version);
--   * a column is declared for a predicate that existed when the version was received: of the registry, or of the
--     schema of the tenant, defined not later than the first observation of the version (S10R-17).
CREATE FUNCTION ac.dataset_refs_check(tn text, sid text) RETURNS void LANGUAGE plpgsql STABLE AS $$
DECLARE d ac.datasets; seen timestamptz; bad text;
BEGIN
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.previous IS NOT NULL AND EXISTS (SELECT 1 FROM ac.sources s WHERE s.tenant_id = tn AND s.source_id = d.previous)
     AND NOT EXISTS (SELECT 1 FROM ac.datasets p WHERE p.tenant_id = tn AND p.source_id = d.previous AND p.dataset_id = d.dataset_id) THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'previous — не версия того же набора данных того же tenant');
  END IF;
  SELECT min(observed_at) INTO seen FROM ac.source_observations WHERE tenant_id = tn AND source_id = sid;
  SELECT c->>'predicate' INTO bad FROM jsonb_array_elements(d.manifest->'columns') c
  WHERE c ? 'predicate' AND NOT EXISTS (SELECT 1 FROM ac.predicates pr WHERE pr.predicate_id = c->>'predicate')
    AND NOT ac.tenant_predicate_by(tn, c->>'predicate', seen) LIMIT 1;
  IF bad IS NOT NULL THEN
    PERFORM ac.fail('DATASET_MANIFEST_INVALID', 'колонка объявлена для предиката ' || bad || ', которого нет ни в реестре, ни в схеме tenant '
                    'к моменту получения версии');
  END IF;
END $$;

-- the predicate pid was declared in the schema of the tenant not later than t (by a class attribute or by a link)
CREATE FUNCTION ac.tenant_predicate_by(tn text, pid text, t timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM ac.class_defs k, jsonb_array_elements(k.attributes) a
                 WHERE k.tenant_id = tn AND k.recorded_at <= t AND a->>'predicate_id' = pid)
      OR EXISTS (SELECT 1 FROM ac.link_defs l WHERE l.tenant_id = tn AND l.recorded_at <= t AND l.predicate_id = pid) $$;

CREATE FUNCTION ac.dataset_refs_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d record;
BEGIN
  PERFORM ac.require_read_committed();     -- the check reads what others committed while this one waited (S10R-20)
  IF TG_TABLE_NAME = 'datasets' THEN
    PERFORM ac.lock_keys(ARRAY['dsprev:' || NEW.tenant_id || '/' || coalesce(NEW.previous, '-')]);
    PERFORM ac.dataset_refs_check(NEW.tenant_id, NEW.source_id);
  ELSE   -- a source arrived: every version that names it as «previous» is checked again
    PERFORM ac.lock_keys(ARRAY['dsprev:' || NEW.tenant_id || '/' || NEW.source_id]);
    FOR d IN SELECT source_id FROM ac.datasets WHERE tenant_id = NEW.tenant_id AND previous = NEW.source_id LOOP
      PERFORM ac.dataset_refs_check(NEW.tenant_id, d.source_id);
    END LOOP;
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER dataset_refs AFTER INSERT ON ac.datasets DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.dataset_refs_trigger();
CREATE CONSTRAINT TRIGGER dataset_refs_source AFTER INSERT ON ac.sources DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.dataset_refs_trigger();

-- ---------------------------------------------------------------- evidence ROW (validator.py: row_evidence_error)
-- strong identifiers 'scheme|value' of the entity eid at time «at»: of the entity it was resolved to by then and of
-- every entity merged into that one by then (the same group as ac.node_names, S4R-02 / S4R-11)
CREATE FUNCTION ac.group_strong_keys(eid text, at timestamptz) RETURNS text[] LANGUAGE sql STABLE AS $$
  WITH o AS (SELECT CASE WHEN status = 'MERGED' AND status_changed_at <= at THEN merged_into ELSE entity_id END AS oid
             FROM ac.entities WHERE entity_id = eid),
       g AS (SELECT x.entity_type, x.identity FROM ac.entities x, o
             WHERE x.entity_id = o.oid OR (x.status = 'MERGED' AND x.merged_into = o.oid AND x.status_changed_at <= at))
  SELECT ARRAY(SELECT DISTINCT unnest(ac.strong_keys(g.entity_type, g.identity)) FROM g) $$;

-- who carries a strong key: looked up by the conflict rule of a row (cycle 11)
-- (the index expression runs as the writer of the entity: it reads the fixed Unicode case-folding table)
GRANT SELECT ON ac.casefold_map TO ac_loader, ac_migrator;
CREATE INDEX entities_strong_keys ON ac.entities USING gin (ac.strong_keys(entity_type, identity));

-- an identifier taken from a cell of a row, as the strong key of an entity 'scheme|value' (validator.py: row_id): the
-- value in the normal form in which ac.identity_keys keeps keys of that scheme
CREATE FUNCTION ac.row_id(scheme text, v text) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF scheme = 'ru.cadastral' THEN          -- digits and colons only; anything else is compared as written
    RETURN scheme || '|' || CASE WHEN v ~ '^[0-9]{1,18}(:[0-9]{1,18})*$' THEN ac.cadastral_norm(v) ELSE v END;
  END IF;
  -- a value with a code point unassigned in the validator's Unicode version is compared as written (S11R2-01)
  RETURN scheme || '|' || CASE WHEN scheme IN ('ru.inn', 'ru.ogrn', 'ru.ogrnip', 'vin', 'imo') OR ac.has_unassigned(v) THEN v ELSE ac.id_norm(v) END;
END $$;

-- the identifiers of the row's subject that the evidence quotes, as entity keys (validator.py: row_subject_ids)
CREATE FUNCTION ac.row_subject_ids(ev jsonb, m jsonb) RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
  SELECT ARRAY(SELECT DISTINCT ac.row_id(col->>'identifier_scheme', q->>'value')
               FROM jsonb_array_elements(m->'columns') col
               JOIN jsonb_array_elements(ev->'cells') q ON q->>'name' = col->>'name'
               WHERE coalesce(m->'subject', '[]') ? (col->>'name') AND q ? 'salt' AND jsonb_typeof(q->'value') = 'string'
                 -- «-» and the empty string are not identifiers: registries use them as blanks (S11R2-09)
                 AND ac.row_id(col->>'identifier_scheme', q->>'value') <> (col->>'identifier_scheme') || '|') $$;

-- The conflict of strong keys of a row (D27.3, validator.py: ROW_SUBJECT_CONFLICT): the identifiers of the row name
-- ONE entity; if one of them belongs — at the moment t — to another entity of the project than the subject of the
-- claim, the project holds two entities where the row has one. It is a state of the project (it can arise after the
-- claim was written and ends with a merge), so it is shown where the claim is read, not refused where it is written.
-- An entity the READER may not see is not counted (S11R2-04: by the clearance of the reader, not by the marking of the
-- claim — a reader cleared for both entities sees the conflict, as in ac.dataset_subject). A session without a
-- clearance in the project is either the owner of the database (sees everything, like the validator) or gets what the
-- marking of the claim allows.
CREATE FUNCTION ac.conflict_clearance(c ac.claims) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(ac.my_clearance(c.project_id),
                  CASE WHEN NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user) THEN c.marking END) $$;

CREATE FUNCTION ac.row_subject_conflict(c ac.claims, ev jsonb, m jsonb, t timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM ac.entities s0
    JOIN ac.entities e2 ON e2.project_id = s0.project_id AND e2.entity_type = s0.entity_type
     AND ac.strong_keys(e2.entity_type, e2.identity) && ac.row_subject_ids(ev, m)
    WHERE s0.entity_id = c.subject AND e2.created_at <= t
      AND ac.resolve_at(e2.entity_id, t) <> ac.resolve_at(s0.entity_id, t)
      AND (ac.conflict_clearance(c) IS NULL OR (ac.dominates(ac.conflict_clearance(c), e2.marking)
           AND ac.dominates(ac.conflict_clearance(c), (SELECT x.marking FROM ac.entities x WHERE x.entity_id = ac.resolve_at(e2.entity_id, t)))))) $$;

-- the shape of a ROW element (core.schema.json: Claim.evidence, the ROW form)
CREATE FUNCTION ac.row_shape_ok(ev jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(
    jsonb_typeof(ev) = 'object' AND ev ?& ARRAY['kind', 'source_id', 'row_sha256', 'cells', 'proof']
    AND NOT EXISTS (SELECT 1 FROM jsonb_object_keys(ev) k WHERE k NOT IN ('kind', 'source_id', 'row_key', 'row_sha256', 'cells', 'proof'))
    AND ev->'kind' = '"ROW"' AND jsonb_typeof(ev->'source_id') = 'string'
    AND jsonb_typeof(ev->'row_sha256') = 'string' AND ev->>'row_sha256' ~ '^[0-9a-f]{64}$'
    AND (NOT ev ? 'row_key' OR (jsonb_typeof(ev->'row_key') = 'array' AND jsonb_array_length(ev->'row_key') BETWEEN 1 AND 8
         AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(ev->'row_key') x
                         WHERE NOT (jsonb_typeof(x) IN ('string', 'boolean') OR ac.is_int(x)))))
    AND jsonb_typeof(ev->'cells') = 'array' AND jsonb_array_length(ev->'cells') BETWEEN 1 AND 512
    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(ev->'cells') x WHERE NOT coalesce(
          jsonb_typeof(x) = 'object' AND jsonb_typeof(x->'name') = 'string' AND x->>'name' ~ '^[a-z][a-z0-9_]{0,62}$'
          AND CASE WHEN x ? 'leaf'
                   THEN (SELECT count(*) FROM jsonb_object_keys(x)) = 2 AND jsonb_typeof(x->'leaf') = 'string' AND x->>'leaf' ~ '^[0-9a-f]{64}$'
                   ELSE (SELECT count(*) FROM jsonb_object_keys(x)) = 3 AND x ? 'value' AND x ? 'salt'
                        AND jsonb_typeof(x->'salt') = 'string' AND x->>'salt' ~ '^[0-9a-f]{64}$'
                        AND (jsonb_typeof(x->'value') IN ('string', 'boolean', 'null') OR ac.is_int(x->'value')) END, false))
    AND jsonb_typeof(ev->'proof') = 'object' AND ev->'proof' ?& ARRAY['file', 'index', 'hashes']
    AND (SELECT count(*) FROM jsonb_object_keys(ev->'proof')) = 3
    AND ac.is_int(ev->'proof'->'file') AND (ev->'proof'->>'file')::numeric >= 0
    AND ac.is_int(ev->'proof'->'index') AND (ev->'proof'->>'index')::numeric >= 0
    AND jsonb_typeof(ev->'proof'->'hashes') = 'array' AND jsonb_array_length(ev->'proof'->'hashes') <= 64
    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(ev->'proof'->'hashes') x
                    WHERE jsonb_typeof(x) <> 'string' OR x #>> '{}' !~ '^[0-9a-f]{64}$'), false) $$;

-- NULL if the ROW evidence proves a row of the version with manifest m and the claim says what the row says
CREATE FUNCTION ac.row_evidence_error(ev jsonb, m jsonb, c ac.claims) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE cols jsonb := m->'columns'; cells jsonb := ev->'cells'; n int; i int; cell jsonb; col jsonb; leaves bytea[] := ARRAY[]::bytea[];
        f jsonb; root bytea; quoted jsonb := '{}'; k text; ids text[]; subj_keys text[]; obj_keys text[]; lit jsonb := c.body->'object'->'literal';
        v jsonb;
BEGIN
  n := jsonb_array_length(cols);
  IF jsonb_array_length(cells) <> n
     OR EXISTS (SELECT 1 FROM generate_series(0, n - 1) g WHERE cells->g->>'name' <> cols->g->>'name') THEN
    RETURN 'ячейки не совпадают с колонками манифеста (состав или порядок)';
  END IF;
  FOR i IN 0 .. n - 1 LOOP
    cell := cells->i; col := cols->i;
    IF cell ? 'salt' THEN
      IF NOT ac.cell_value_ok(col->>'type', cell->'value') THEN
        RETURN 'значение колонки ' || (col->>'name') || ' не типа ' || (col->>'type');
      END IF;
      leaves := leaves || ac.cell_leaf(decode(cell->>'salt', 'hex'), cell->>'name', cell->'value');
      quoted := quoted || jsonb_build_object(cell->>'name', cell->'value');
    ELSE
      leaves := leaves || decode(cell->>'leaf', 'hex');
    END IF;
  END LOOP;
  IF encode(ac.merkle_root(leaves), 'hex') <> ev->>'row_sha256' THEN
    RETURN 'хэш строки не равен корню дерева её ячеек';
  END IF;
  IF (ev->'proof'->>'file')::numeric >= jsonb_array_length(m->'files') THEN
    RETURN 'в манифесте нет файла с таким номером';
  END IF;
  f := m->'files'->((ev->'proof'->>'file')::int);
  root := ac.inclusion_root(ac.row_leaf(decode(ev->>'row_sha256', 'hex')), (ev->'proof'->>'index')::bigint, (f->>'rows')::bigint,
                            ARRAY(SELECT decode(h, 'hex') FROM jsonb_array_elements_text(ev->'proof'->'hashes') WITH ORDINALITY x(h, o) ORDER BY o));
  IF root IS NULL OR encode(root, 'hex') <> f->>'rows_root' THEN
    RETURN 'строка не входит в файл версии набора (доказательство включения не сходится)';
  END IF;
  IF jsonb_array_length(m->'key') > 0 THEN
    IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(m->'key') x WHERE NOT quoted ? x)
       OR ev->'row_key' IS DISTINCT FROM (SELECT jsonb_agg(quoted->x ORDER BY o) FROM jsonb_array_elements_text(m->'key') WITH ORDINALITY a(x, o)) THEN
      RETURN 'ключ строки: колонки ключа должны быть процитированы, а row_key — равен их значениям';
    END IF;
  ELSIF ev ? 'row_key' THEN
    RETURN 'у набора без ключа строка называется своим хэшем, row_key не указывается';
  END IF;
  -- the row is about the subject of the claim; a dataset that does not say whom its rows are about supports no claim
  IF NOT m ? 'subject' THEN
    RETURN 'набор не объявляет субъект строки (subject) — его строка не может подтверждать утверждение о сущности';
  END IF;
  subj_keys := ac.group_strong_keys(c.subject, c.recorded_at);
  ids := ac.row_subject_ids(ev, m);
  IF NOT ids && subj_keys THEN
    RETURN 'строка не о субъекте утверждения: ни один процитированный идентификатор субъекта строки не принадлежит ему';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ids) x WHERE x <> ALL (subj_keys)
             AND EXISTS (SELECT 1 FROM unnest(subj_keys) y WHERE split_part(y, '|', 1) = split_part(x, '|', 1))) THEN
    RETURN 'строка не о субъекте утверждения: идентификатор субъекта строки расходится с идентификатором субъекта';
  END IF;
  -- the claim says what the row says
  IF c.object_entity IS NOT NULL THEN
    obj_keys := ac.group_strong_keys(c.object_entity, c.recorded_at);
  END IF;
  FOR col IN SELECT x FROM jsonb_array_elements(cols) x LOOP
    CONTINUE WHEN col->>'predicate' IS DISTINCT FROM c.predicate OR NOT quoted ? (col->>'name');
    v := quoted->(col->>'name');
    IF c.object_entity IS NOT NULL THEN
      IF jsonb_typeof(v) = 'string' AND col ? 'identifier_scheme' AND ac.row_id(col->>'identifier_scheme', v #>> '{}') = ANY (obj_keys) THEN
        RETURN NULL;
      END IF;
    ELSIF col ? 'identifier_scheme' THEN
      IF lit->>'type' = 'IDENTIFIER' AND lit->>'scheme' = col->>'identifier_scheme' AND lit->'value' = v THEN
        RETURN NULL;
      END IF;
    ELSIF lit->>'type' = col->>'type' AND lit->'value' = v THEN
      RETURN NULL;
    END IF;
  END LOOP;
  RETURN 'ни одна процитированная колонка не объявлена для предиката утверждения с этим значением';
END $$;

-- called by ac.evidence_guard (ddl_s1.sql) for an evidence row of kind ROW; the source is known and its bytes are stored
CREATE FUNCTION ac.row_evidence_guard(c ac.claims, src ac.sources, ev jsonb) RETURNS void LANGUAGE plpgsql STABLE AS $$
DECLARE m jsonb; why text; x record;
BEGIN
  IF NOT ac.row_shape_ok(ev) THEN
    PERFORM ac.fail('SCHEMA_INVALID', 'доказательство-строка не по схеме');
  END IF;
  IF c.body->>'schema_version' IS DISTINCT FROM 'core-ontology/0.4' THEN
    PERFORM ac.fail('SCHEMA_INVALID', 'schema_version: доказательство-строка — только в записи core-ontology/0.4');
  END IF;
  SELECT manifest INTO m FROM ac.datasets WHERE tenant_id = src.tenant_id AND source_id = src.source_id;
  IF m IS NULL THEN
    PERFORM ac.fail('EVIDENCE_ROW_INVALID', 'доказательство-строка ссылается на источник, который не версия набора данных');
  END IF;
  why := ac.row_evidence_error(ev, m, c);
  IF why IS NOT NULL THEN
    PERFORM ac.fail('EVIDENCE_ROW_INVALID', why);
  END IF;
  FOR x IN SELECT col FROM jsonb_array_elements(m->'columns') WITH ORDINALITY a(col, o)
           WHERE (ev->'cells'->(o::int - 1)) ? 'salt' AND NOT ac.dominates(c.marking, col->'marking') LOOP
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка утверждения шире маркировки колонки ' || (x.col->>'name'));
  END LOOP;
END $$;

-- the vocabulary of 0.3 may be carried by a record marked 0.3 or 0.4 (ddl_s9.sql knew only 0.3)
DO $$
DECLARE src text;
BEGIN
  SELECT pg_get_functiondef(p.oid) INTO src FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'ac' AND p.prosrc LIKE '%IS DISTINCT FROM ''core-ontology/0.3''%';
  IF src IS NULL THEN RAISE EXCEPTION 'ddl_s10: не найдена проверка пометки 0.3'; END IF;
  EXECUTE replace(src, 'NEW.body->>''schema_version'' IS DISTINCT FROM ''core-ontology/0.3''',
                       'coalesce(NEW.body->>''schema_version'', '''') NOT IN (''core-ontology/0.3'', ''core-ontology/0.4'')');
END $$;

-- ---------------------------------------------------------------- wide tables of rows (D27.2)
-- One table per (tenant, dataset, column signature), list-partitioned by version; a partition is filled by the loader
-- (COPY), then SEALED: every row hash is recomputed from the typed cells and the row secret, every file root from the
-- row hashes, and both are compared with the manifest. Only a sealed version is readable. A sealed partition is immutable.
CREATE TABLE ac.dataset_tables (
  tenant_id   text NOT NULL,
  source_id   text NOT NULL,
  version_no  integer NOT NULL UNIQUE,  -- the partition key of the rows of this version (4 bytes per row, not the 75 of source_id)
  table_name  text NOT NULL,          -- acd.<name>: the partition of this version
  parent_name text NOT NULL,
  opened_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  sealed_at   timestamptz,
  PRIMARY KEY (tenant_id, source_id),
  UNIQUE (table_name),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.datasets
);

CREATE SEQUENCE ac.dataset_version_no;

CREATE FUNCTION ac.column_sql_type(t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE t WHEN 'STRING' THEN 'text' WHEN 'INTEGER' THEN 'bigint' WHEN 'BOOLEAN' THEN 'boolean' WHEN 'DATE' THEN 'date' END $$;

-- JCS text of a typed cell, as an SQL expression over the column «c_<name>»
CREATE FUNCTION ac.column_jcs_expr(name text, t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT format('coalesce(%s, ''null'')', CASE t
    WHEN 'STRING' THEN format('to_json(%I)::text', 'c_' || name)
    WHEN 'DATE' THEN format('''"'' || to_char(%I, ''YYYY-MM-DD'') || ''"''', 'c_' || name)
    ELSE format('%I::text', 'c_' || name) END) $$;

-- the hash of a row as one SQL expression: the RFC 6962 tree over the cell leaves, unrolled for this column list
CREATE FUNCTION ac.row_hash_expr(cols jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE cur text[]; nxt text[]; n int; i int;
BEGIN
  cur := ARRAY(SELECT format('sha256(''\x00''::bytea || sha256(''\x03''::bytea || row_secret || %L::bytea) || convert_to(%L || %s || '']'', ''UTF8''))',
                             convert_to(c->>'name', 'UTF8'), '[' || to_json(c->>'name')::text || ',', ac.column_jcs_expr(c->>'name', c->>'type'))
               FROM jsonb_array_elements(cols) WITH ORDINALITY a(c, o) ORDER BY o);
  n := cardinality(cur);
  WHILE n > 1 LOOP
    nxt := ARRAY[]::text[];
    i := 1;
    WHILE i < n LOOP
      nxt := nxt || format('sha256(''\x01''::bytea || %s || %s)', cur[i], cur[i + 1]);
      i := i + 2;
    END LOOP;
    IF i = n THEN nxt := nxt || cur[n]; END IF;
    cur := nxt;
    n := cardinality(cur);
  END LOOP;
  RETURN cur[1];
END $$;

-- open the partition of a registered version for loading (the loader then COPYs rows into the returned table)
-- a loaded value outside the profile of the ontology, as an SQL condition over the columns: a date outside
-- 0001-01-01 … 9999-12-31 (BC, ±infinity — their text is not the text that was hashed), an integer outside ±(2^53−1)
CREATE FUNCTION ac.row_profile_expr(cols jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(string_agg(CASE c->>'type'
           WHEN 'DATE' THEN format('(%1$I IS NOT NULL AND NOT (%1$I BETWEEN DATE ''0001-01-01'' AND DATE ''9999-12-31''))', 'c_' || (c->>'name'))
           WHEN 'INTEGER' THEN format('(%1$I IS NOT NULL AND abs(%1$I::numeric) > 9007199254740991)', 'c_' || (c->>'name')) END, ' OR '), 'false')
  FROM jsonb_array_elements(cols) c WHERE c->>'type' IN ('DATE', 'INTEGER') $$;

-- an unsealed load that went wrong is thrown away and can be repeated (a sealed version is never reset)
CREATE FUNCTION ac.dataset_reset(tn text, sid text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE t ac.dataset_tables;
BEGIN
  PERFORM ac.require_read_committed();
  SELECT * INTO t FROM ac.dataset_tables WHERE tenant_id = tn AND source_id = sid FOR UPDATE;
  IF t.source_id IS NULL OR t.sealed_at IS NOT NULL THEN
    PERFORM ac.fail('APPEND_ONLY', 'таблица строк версии не открыта или уже запечатана');
  END IF;
  EXECUTE format('TRUNCATE acd.%I', t.table_name);
END $$;

CREATE FUNCTION ac.dataset_open(tn text, sid text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE d ac.datasets; sig text; parent text; part text; coldefs text; vno int;
BEGIN
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.source_id IS NULL THEN
    PERFORM ac.fail('REF_UNRESOLVED', 'версия набора данных не зарегистрирована');
  END IF;
  IF EXISTS (SELECT 1 FROM ac.dataset_tables WHERE tenant_id = tn AND source_id = sid) THEN
    PERFORM ac.fail('APPEND_ONLY', 'таблица строк этой версии уже открыта');
  END IF;
  -- names: the parent by 240 bits of the hash of (tenant, dataset, columns) — no birthday collisions within reach;
  -- the partition by its number
  sig := substr(encode(sha256(convert_to(tn || '|' || d.dataset_id || '|' || ac.jcs(d.manifest->'columns'), 'UTF8')), 'hex'), 1, 60);
  parent := 'd_' || sig;
  vno := nextval('ac.dataset_version_no');
  part := 'v_' || vno;
  IF to_regclass('acd.' || quote_ident(parent)) IS NULL THEN
    coldefs := (SELECT string_agg(format('%I %s', 'c_' || (c->>'name'), ac.column_sql_type(c->>'type')), ', ' ORDER BY o)
                FROM jsonb_array_elements(d.manifest->'columns') WITH ORDINALITY a(c, o));
    EXECUTE format('CREATE TABLE acd.%I (version_no integer NOT NULL, file_no integer NOT NULL, row_no integer NOT NULL, '
                   'row_hash bytea NOT NULL, row_secret bytea NOT NULL, %s) PARTITION BY LIST (version_no)', parent, coldefs);
  END IF;
  EXECUTE format('CREATE TABLE acd.%I PARTITION OF acd.%I FOR VALUES IN (%s)', part, parent, vno);
  EXECUTE format('ALTER TABLE acd.%I ALTER COLUMN version_no SET DEFAULT %s', part, vno);
  EXECUTE format('GRANT INSERT ON acd.%I TO ac_loader', part);
  EXECUTE format('CREATE TRIGGER a_isolation_guard BEFORE INSERT OR UPDATE OR DELETE ON acd.%I FOR EACH STATEMENT '
                 'EXECUTE FUNCTION ac.isolation_guard()', part);
  INSERT INTO ac.dataset_tables (tenant_id, source_id, version_no, table_name, parent_name) VALUES (tn, sid, vno, part, parent);
  RETURN 'acd.' || quote_ident(part);
END $$;

-- seal: compare everything loaded with the manifest, index, forbid further changes
CREATE FUNCTION ac.dataset_seal(tn text, sid text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE d ac.datasets; t ac.dataset_tables; bad bigint; total bigint; c jsonb; keycols text; f record; nfiles int;
BEGIN
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  SELECT * INTO t FROM ac.dataset_tables WHERE tenant_id = tn AND source_id = sid FOR UPDATE;
  IF t.source_id IS NULL OR t.sealed_at IS NOT NULL THEN
    PERFORM ac.fail('APPEND_ONLY', 'таблица строк версии не открыта или уже запечатана');
  END IF;
  EXECUTE format('LOCK TABLE acd.%I IN SHARE ROW EXCLUSIVE MODE', t.table_name);
  -- every row: its stored hash is the hash of its typed cells
  EXECUTE format('SELECT count(*), count(*) FILTER (WHERE row_hash IS DISTINCT FROM %s OR length(row_secret) <> 16 OR %s) FROM acd.%I',
                 ac.row_hash_expr(d.manifest->'columns'), ac.row_profile_expr(d.manifest->'columns'), t.table_name) INTO total, bad;
  IF bad > 0 THEN
    PERFORM ac.fail('DATASET_LOAD_INVALID', bad || ' строк: хэш строки не равен хэшу её ячеек или значение вне профиля (дата, целое)');
  END IF;
  IF total <> d.row_count THEN
    PERFORM ac.fail('DATASET_LOAD_INVALID', 'строк загружено ' || total || ', в манифесте ' || d.row_count);
  END IF;
  -- every file: rows numbered 0..n-1 without gaps, the root of their hashes is the root in the manifest
  nfiles := jsonb_array_length(d.manifest->'files');
  FOR f IN EXECUTE format('SELECT file_no, count(*) AS n, min(row_no) AS lo, max(row_no) AS hi, '
                          'ac.merkle_root(array_agg(ac.row_leaf(row_hash) ORDER BY row_no)) AS root FROM acd.%I GROUP BY file_no', t.table_name) LOOP
    IF f.file_no < 0 OR f.file_no >= nfiles OR f.lo <> 0 OR f.hi <> f.n - 1
       OR f.n <> (d.manifest->'files'->f.file_no->>'rows')::bigint
       OR encode(f.root, 'hex') <> d.manifest->'files'->f.file_no->>'rows_root' THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'файл ' || f.file_no || ': строки не те, что в манифесте (число, номера или корень)');
    END IF;
  END LOOP;
  -- (file_no, row_no) unique — with «no gaps» above this makes the loaded rows exactly the rows of the manifest
  BEGIN
    EXECUTE format('CREATE UNIQUE INDEX ON acd.%I (file_no, row_no)', t.table_name);
  EXCEPTION WHEN unique_violation THEN
    PERFORM ac.fail('DATASET_LOAD_INVALID', 'номер строки в файле повторяется');
  END;
  -- the key of the dataset is unique within the version
  IF jsonb_array_length(d.manifest->'key') > 0 THEN
    keycols := (SELECT string_agg(format('%I', 'c_' || k), ', ' ORDER BY o) FROM jsonb_array_elements_text(d.manifest->'key') WITH ORDINALITY a(k, o));
    BEGIN
      EXECUTE format('CREATE UNIQUE INDEX ON acd.%I (%s)', t.table_name, keycols);
    EXCEPTION WHEN unique_violation THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'ключ строки повторяется');
    WHEN program_limit_exceeded THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'значение ключа слишком длинно для индекса');
    END;
    EXECUTE format('SELECT count(*) FROM acd.%I WHERE %s', t.table_name,
                   (SELECT string_agg(format('%I IS NULL', 'c_' || k), ' OR ') FROM jsonb_array_elements_text(d.manifest->'key') k)) INTO bad;
    IF bad > 0 THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'пустое значение в колонке ключа');
    END IF;
  ELSE
    BEGIN
      EXECUTE format('CREATE UNIQUE INDEX ON acd.%I (row_hash)', t.table_name);
    EXCEPTION WHEN unique_violation THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'строка повторяется (у набора без ключа строка называется своим хэшем)');
    END;
  END IF;
  -- the identifier index: one b-tree per identifier column (D27.3 reads it by scheme)
  FOR c IN SELECT x FROM jsonb_array_elements(d.manifest->'columns') x WHERE x ? 'identifier_scheme'
                                                                         AND NOT (jsonb_array_length(d.manifest->'key') = 1 AND d.manifest->'key'->>0 = x->>'name') LOOP
    BEGIN
      EXECUTE format('CREATE INDEX ON acd.%I (%I) WHERE %I IS NOT NULL', t.table_name, 'c_' || (c->>'name'), 'c_' || (c->>'name'));
    EXCEPTION WHEN program_limit_exceeded THEN
      PERFORM ac.fail('DATASET_LOAD_INVALID', 'значение идентификатора в колонке ' || (c->>'name') || ' слишком длинно для индекса');
    END;
  END LOOP;
  EXECUTE format('REVOKE INSERT ON acd.%I FROM ac_loader', t.table_name);
  -- from now on no row of the version changes, whoever asks and through whichever table (the partition or its parent)
  EXECUTE format('CREATE TRIGGER sealed_rows BEFORE INSERT OR UPDATE OR DELETE ON acd.%I FOR EACH ROW EXECUTE FUNCTION ac.forbid()', t.table_name);
  EXECUTE format('CREATE TRIGGER sealed_truncate BEFORE TRUNCATE ON acd.%I FOR EACH STATEMENT EXECUTE FUNCTION ac.forbid()', t.table_name);
  EXECUTE format('ANALYZE acd.%I', t.table_name);
  UPDATE ac.dataset_tables SET sealed_at = clock_timestamp() WHERE tenant_id = tn AND source_id = sid;
  RETURN jsonb_build_object('rows', total, 'files', nfiles, 'table', 'acd.' || t.table_name);
END $$;
CREATE FUNCTION ac.dataset_tables_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR OLD.sealed_at IS NOT NULL OR NEW.sealed_at IS NULL
     OR (NEW.tenant_id, NEW.source_id, NEW.version_no, NEW.table_name, NEW.parent_name, NEW.opened_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.source_id, OLD.version_no, OLD.table_name, OLD.parent_name, OLD.opened_at) THEN
    RAISE EXCEPTION 'APPEND_ONLY: % на ac.dataset_tables запрещён', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER dataset_tables_guard BEFORE UPDATE OR DELETE ON ac.dataset_tables FOR EACH ROW EXECUTE FUNCTION ac.dataset_tables_guard();

-- the sealed table of a version (or an error)
CREATE FUNCTION ac.dataset_table(tn text, sid text) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE t ac.dataset_tables;
BEGIN
  SELECT * INTO t FROM ac.dataset_tables WHERE tenant_id = tn AND source_id = sid;
  IF t.source_id IS NULL OR t.sealed_at IS NULL THEN
    PERFORM ac.fail('SOURCE_CONTENT_UNAVAILABLE', 'строки версии набора не загружены или не запечатаны');
  END IF;
  RETURN t.table_name;
END $$;

-- one row as a list of cells [{name, value, salt}] in column order (internal: no clearance applied here)
CREATE FUNCTION ac.dataset_cells(tn text, sid text, key jsonb, OUT file_no int, OUT row_no int, OUT row_hash bytea, OUT cells jsonb)
  LANGUAGE plpgsql STABLE AS $$
DECLARE d ac.datasets; tbl text; cond text; sel text;
BEGIN
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  tbl := ac.dataset_table(tn, sid);
  IF jsonb_array_length(d.manifest->'key') > 0 THEN
    IF jsonb_typeof(key) <> 'array' OR jsonb_array_length(key) <> jsonb_array_length(d.manifest->'key') THEN
      PERFORM ac.fail('REF_UNRESOLVED', 'ключ строки не той длины, что ключ набора');
    END IF;
    cond := (SELECT string_agg(format('%I = (%L::jsonb->>%s)::%s', 'c_' || k, key, o - 1,
                                      ac.column_sql_type((SELECT c->>'type' FROM jsonb_array_elements(d.manifest->'columns') c WHERE c->>'name' = k))),
                               ' AND ') FROM jsonb_array_elements_text(d.manifest->'key') WITH ORDINALITY a(k, o));
  ELSE
    cond := format('row_hash = decode(%L, ''hex'')', key #>> '{}');     -- without a key a row is named by its hash
  END IF;
  sel := (SELECT string_agg(format('jsonb_build_object(''name'', %L, ''value'', %s, ''salt'', encode(ac.cell_salt(row_secret, %L), ''hex''))',
                                   c->>'name', CASE c->>'type' WHEN 'DATE' THEN format('to_char(%I, ''YYYY-MM-DD'')', 'c_' || (c->>'name'))
                                                               ELSE format('%I', 'c_' || (c->>'name')) END, c->>'name'), ', ' ORDER BY o)
          FROM jsonb_array_elements(d.manifest->'columns') WITH ORDINALITY a(c, o));
  -- to_jsonb(ARRAY[…]) and not jsonb_build_array(…): a function takes at most 100 arguments, a version has up to 512 columns
  EXECUTE format('SELECT file_no, row_no, row_hash, to_jsonb(ARRAY[%s]) FROM acd.%I WHERE %s', sel, tbl, cond) INTO file_no, row_no, row_hash, cells;
END $$;

-- the ROW evidence of a row, built by the database from the sealed table: the columns of «quote» and of the key are
-- quoted, the others are leaves. The caller must be cleared for every quoted column (project p gives the clearance).
CREATE FUNCTION ac.dataset_evidence(p text, sid text, key jsonb, quote text[]) RETURNS jsonb LANGUAGE plpgsql STABLE
  SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE tn text; d ac.datasets; clr jsonb; r record; shown text[]; leaves bytea[]; out_cells jsonb; ev jsonb; c jsonb;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.source_id IS NULL THEN        -- the same answer as «no clearance»: whether a version exists is not disclosed
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, (SELECT marking FROM ac.sources WHERE tenant_id = tn AND source_id = sid));
  shown := quote || ARRAY(SELECT jsonb_array_elements_text(d.manifest->'key'));
  IF NOT shown <@ ARRAY(SELECT x->>'name' FROM jsonb_array_elements(d.manifest->'columns') x) THEN
    PERFORM ac.fail('REF_UNRESOLVED', 'в наборе нет такой колонки');
  END IF;
  FOR c IN SELECT x FROM jsonb_array_elements(d.manifest->'columns') x WHERE x->>'name' = ANY (shown) LOOP
    IF NOT ac.dominates(clr, c->'marking') THEN
      PERFORM ac.fail('CLEARANCE_INSUFFICIENT', 'допуск читателя ниже маркировки колонки ' || (c->>'name'));
    END IF;
  END LOOP;
  SELECT * INTO r FROM ac.dataset_cells(tn, sid, key);
  IF r.cells IS NULL THEN
    PERFORM ac.fail('REF_UNRESOLVED', 'строки с таким ключом в версии набора нет');
  END IF;
  out_cells := (SELECT jsonb_agg(CASE WHEN x->>'name' = ANY (shown) THEN x
                                      ELSE jsonb_build_object('name', x->>'name', 'leaf',
                                             encode(ac.cell_leaf(decode(x->>'salt', 'hex'), x->>'name', x->'value'), 'hex')) END ORDER BY o)
                FROM jsonb_array_elements(r.cells) WITH ORDINALITY a(x, o));
  EXECUTE format('SELECT array_agg(ac.row_leaf(row_hash) ORDER BY row_no) FROM acd.%I WHERE file_no = %s', ac.dataset_table(tn, sid), r.file_no)
    INTO leaves;
  ev := jsonb_build_object('kind', 'ROW', 'source_id', sid, 'row_sha256', encode(r.row_hash, 'hex'), 'cells', out_cells,
                           'proof', jsonb_build_object('file', r.file_no, 'index', r.row_no,
                                                       'hashes', (SELECT coalesce(jsonb_agg(encode(h, 'hex') ORDER BY o), '[]')
                                                                  FROM unnest(ac.audit_path(leaves, r.row_no)) WITH ORDINALITY a(h, o))));
  IF jsonb_array_length(d.manifest->'key') > 0 THEN
    -- the key as the cells hold it (not as the caller spelled it)
    ev := ev || jsonb_build_object('row_key', (SELECT jsonb_agg((SELECT x->'value' FROM jsonb_array_elements(r.cells) x WHERE x->>'name' = k) ORDER BY o)
                                               FROM jsonb_array_elements_text(d.manifest->'key') WITH ORDINALITY a(k, o)));
  END IF;
  RETURN ev;
END $$;

-- a row for a reader: only the columns his clearance (in project p) dominates; the others are named in «withheld»
CREATE FUNCTION ac.dataset_row(p text, sid text, key jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE
  SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE tn text; d ac.datasets; clr jsonb; r record;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.source_id IS NULL THEN        -- the same answer as «no clearance»: whether a version exists is not disclosed
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, (SELECT marking FROM ac.sources WHERE tenant_id = tn AND source_id = sid));
  -- asking by a key is asking «is there such a row»: the reader must be cleared for the key columns
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(d.manifest->'columns') c
             WHERE (d.manifest->'key') ? (c->>'name') AND NOT ac.dominates(clr, c->'marking')) THEN
    PERFORM ac.fail('CLEARANCE_INSUFFICIENT', 'допуск читателя ниже маркировки ключа набора');
  END IF;
  SELECT * INTO r FROM ac.dataset_cells(tn, sid, key);
  IF r.cells IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'projection', 'dataset_row/0.1', 'dataset_id', d.dataset_id, 'version_label', d.version_label, 'source_id', sid,
    'row_sha256', encode(r.row_hash, 'hex'),
    'cells', (SELECT coalesce(jsonb_object_agg(x->>'name', x->'value'), '{}')
              FROM jsonb_array_elements(r.cells) WITH ORDINALITY a(x, o) JOIN jsonb_array_elements(d.manifest->'columns') WITH ORDINALITY b(c, o2) ON o = o2
              WHERE ac.dominates(clr, c->'marking')),
    'withheld', (SELECT coalesce(jsonb_agg(c->>'name' ORDER BY o2), '[]')
                 FROM jsonb_array_elements(d.manifest->'columns') WITH ORDINALITY b(c, o2) WHERE NOT ac.dominates(clr, c->'marking')));
END $$;

-- search by identifier across the sealed versions of the tenant of project p: which rows carry (scheme, value)
CREATE FUNCTION ac.dataset_find(p text, scheme text, val text) RETURNS jsonb LANGUAGE plpgsql STABLE
  SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE tn text; clr jsonb; d record; c jsonb; hits jsonb := '[]'; part jsonb; keyexpr text; key_visible boolean;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  clr := ac.my_clearance(p);
  IF clr IS NULL THEN
    PERFORM ac.fail('CLEARANCE_INSUFFICIENT', 'у читателя нет допуска в проекте');
  END IF;
  FOR d IN SELECT x.*, t.table_name FROM ac.datasets x JOIN ac.dataset_tables t USING (tenant_id, source_id)
           JOIN ac.sources s USING (tenant_id, source_id)
           WHERE x.tenant_id = tn AND t.sealed_at IS NOT NULL AND ac.dominates(clr, s.marking) ORDER BY x.dataset_id, x.source_id LOOP
    FOR c IN SELECT x FROM jsonb_array_elements(d.manifest->'columns') x
             WHERE x->>'identifier_scheme' = scheme AND ac.dominates(clr, x->'marking') LOOP
      -- the key of the row is shown only if the reader is cleared for every key column; the hash of the row names it anyway
      key_visible := NOT EXISTS (SELECT 1 FROM jsonb_array_elements(d.manifest->'columns') k2
                                 WHERE (d.manifest->'key') ? (k2->>'name') AND NOT ac.dominates(clr, k2->'marking'));
      keyexpr := CASE WHEN NOT key_visible THEN 'NULL::jsonb' WHEN jsonb_array_length(d.manifest->'key') > 0
                      THEN 'jsonb_build_array(' || (SELECT string_agg(format('%s', CASE (SELECT k2->>'type' FROM jsonb_array_elements(d.manifest->'columns') k2 WHERE k2->>'name' = k)
                                                                                    WHEN 'DATE' THEN format('to_char(%I, ''YYYY-MM-DD'')', 'c_' || k)
                                                                                    ELSE format('%I', 'c_' || k) END), ', ' ORDER BY o)
                                                    FROM jsonb_array_elements_text(d.manifest->'key') WITH ORDINALITY a(k, o)) || ')'
                      ELSE 'to_jsonb(encode(row_hash, ''hex''))' END;
      EXECUTE format('SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(''dataset_id'', %L, ''version_label'', %L, ''source_id'', %L, '
                     '''column'', %L, ''row_sha256'', encode(row_hash, ''hex''), ''row'', %s)) ORDER BY file_no, row_no), ''[]'') FROM acd.%I WHERE %I = %L',
                     d.dataset_id, d.version_label, d.source_id, c->>'name', keyexpr, d.table_name, 'c_' || (c->>'name'), val) INTO part;
      hits := hits || part;
    END LOOP;
  END LOOP;
  RETURN jsonb_build_object('projection', 'dataset_find/0.1', 'scheme', scheme, 'value', val, 'hits', hits);
END $$;

-- ---------------------------------------------------------------- «актуальность строки» (cycle 11, D27.3)
-- A claim rests on a row of ITS version and stays true of that version forever. What became of the row since: the
-- versions that FOLLOW the claim's one are those that name it (or its follower) as «previous»; the row is looked up in
-- the last of them whose rows are loaded and sealed by the moment t.
--   CURRENT            no later version is known: the claim rests on the latest one
--   NOT_LOADED         later versions are known, the rows of none of them are loaded
--   UNCHANGED          the same row (the same hash) is in the latest loaded version
--   CHANGED            a quoted cell holds another value now: changed_columns names them
--   CHANGED_ELSEWHERE  the quoted cells are the same, the row differs (in the cells the claim does not quote)
--   ABSENT             no row with this key in the latest loaded version (a dataset without a key names a row by its
--                      hash, so a changed row of such a dataset is ABSENT too)
--   INCOMPARABLE       the latest loaded version has another key (other columns or types)
--   BRANCHED           two versions name the same one as «previous»: «the latest» is not defined
-- Nothing is said beyond what the reader of the claim may know: a version whose source is marked above the claim does
-- not exist for this projection (the chain of followers ends before it); a quoted column is compared by value only if
-- the claim dominates its marking in the latest version; no values are returned. That the row as a whole is or is not the same is said by its hash — the hash the claim itself carries.
-- A version registered or sealed within the last minutes is «provisional» like everything else in a projection (S23).
CREATE FUNCTION ac.row_currency(tn text, sid text, ev jsonb, claim_marking jsonb, t timestamptz) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE d ac.datasets; l ac.datasets; r record; changed jsonb; who jsonb; cur text := sid; nxt text[]; hid text[]; last text;
        later boolean := false; hops int := 0;
BEGIN
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  LOOP
    -- the followers the reader of the claim may know of: registered by t, their source not marked above the claim
    SELECT array_agg(x.source_id) FILTER (WHERE ac.dominates(claim_marking, s.marking)),
           array_agg(x.source_id) FILTER (WHERE NOT ac.dominates(claim_marking, s.marking)) INTO nxt, hid
    FROM ac.datasets x JOIN ac.sources s USING (tenant_id, source_id)
    WHERE x.tenant_id = tn AND x.previous = cur AND x.dataset_id = d.dataset_id
      AND EXISTS (SELECT 1 FROM ac.source_observations o WHERE o.tenant_id = tn AND o.source_id = x.source_id AND o.ingested_at <= t);
    IF cardinality(nxt) > 1 THEN
      RETURN jsonb_build_object('status', 'BRANCHED');
    END IF;
    IF nxt IS NULL THEN
      -- S11R2-06: a version marked above the claim is passed through without being named or counted — a later version
      -- the reader may know is still «the latest»; several hidden followers: the chain is not followed further
      EXIT WHEN hid IS NULL OR cardinality(hid) > 1;
      cur := hid[1];
      hops := hops + 1;
      EXIT WHEN hops > 100000;
      CONTINUE;
    END IF;
    cur := nxt[1];
    later := true;
    IF EXISTS (SELECT 1 FROM ac.dataset_tables tt WHERE tt.tenant_id = tn AND tt.source_id = cur AND tt.sealed_at <= t) THEN
      last := cur;
    END IF;
    hops := hops + 1;
    EXIT WHEN hops > 100000;
  END LOOP;
  IF last IS NULL THEN
    RETURN jsonb_build_object('status', CASE WHEN later THEN 'NOT_LOADED' ELSE 'CURRENT' END);
  END IF;
  SELECT * INTO l FROM ac.datasets WHERE tenant_id = tn AND source_id = last;
  who := jsonb_build_object('source_id', l.source_id, 'version_label', l.version_label);
  -- the same key: the same columns of the same types
  IF (SELECT jsonb_agg(jsonb_build_array(c->>'name', c->>'type') ORDER BY c->>'name') FROM jsonb_array_elements(l.manifest->'columns') c
      WHERE (l.manifest->'key') ? (c->>'name'))
     IS DISTINCT FROM
     (SELECT jsonb_agg(jsonb_build_array(c->>'name', c->>'type') ORDER BY c->>'name') FROM jsonb_array_elements(d.manifest->'columns') c
      WHERE (d.manifest->'key') ? (c->>'name'))
     OR l.manifest->'key' IS DISTINCT FROM d.manifest->'key' THEN
    RETURN jsonb_build_object('status', 'INCOMPARABLE', 'latest', who);
  END IF;
  BEGIN
    SELECT * INTO r FROM ac.dataset_cells(tn, l.source_id, CASE WHEN jsonb_array_length(d.manifest->'key') > 0 THEN ev->'row_key'
                                                                ELSE to_jsonb(ev->>'row_sha256') END);
  EXCEPTION WHEN others THEN
    RETURN jsonb_build_object('status', 'INCOMPARABLE', 'latest', who);
  END;
  IF r.cells IS NULL THEN
    RETURN jsonb_build_object('status', 'ABSENT', 'latest', who);
  END IF;
  IF encode(r.row_hash, 'hex') = ev->>'row_sha256' THEN
    RETURN jsonb_build_object('status', 'UNCHANGED', 'latest', who);
  END IF;
  SELECT jsonb_agg(q->>'name' ORDER BY o) INTO changed
  FROM jsonb_array_elements(ev->'cells') WITH ORDINALITY a(q, o)
  WHERE q ? 'salt'
    AND coalesce((SELECT ac.dominates(claim_marking, c->'marking') FROM jsonb_array_elements(l.manifest->'columns') c WHERE c->>'name' = q->>'name'), true)
    AND (q->'value') IS DISTINCT FROM (SELECT x->'value' FROM jsonb_array_elements(r.cells) x WHERE x->>'name' = q->>'name');
  IF changed IS NULL THEN
    RETURN jsonb_build_object('status', 'CHANGED_ELSEWHERE', 'latest', who);
  END IF;
  RETURN jsonb_build_object('status', 'CHANGED', 'latest', who, 'changed_columns', changed);
END $$;

-- whom a row is about IN A PROJECT: the entities that own the identifiers of the row's subject (D27.3) —
--   NONE           nobody owns them: an entity for this row does not exist yet
--   ONE            one entity owns them
--   CONFLICT       two entities of one type own them: the row is one entity, the project has two — a merge decides
--   SEVERAL_TYPES  entities of different types own them (a company and a trailer with the same number): not a conflict
-- The reader must be cleared for the key and the subject columns; owners he may not see are neither listed nor counted.
CREATE FUNCTION ac.dataset_subject(p text, sid text, key jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE
  SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE tn text; d ac.datasets; clr jsonb; r record; owners jsonb; st text;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.source_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, (SELECT marking FROM ac.sources WHERE tenant_id = tn AND source_id = sid));
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(d.manifest->'columns') c
             WHERE ((d.manifest->'key') ? (c->>'name') OR coalesce(d.manifest->'subject', '[]') ? (c->>'name'))
               AND NOT ac.dominates(clr, c->'marking')) THEN
    PERFORM ac.fail('CLEARANCE_INSUFFICIENT', 'допуск читателя ниже маркировки ключа или идентификаторов субъекта строки');
  END IF;
  SELECT * INTO r FROM ac.dataset_cells(tn, sid, key);
  IF r.cells IS NULL THEN
    RETURN NULL;
  END IF;
  -- only the owners the reader may see are listed AND counted: an owner above his clearance does not turn ONE into CONFLICT
  SELECT coalesce(jsonb_agg(jsonb_build_object('entity_id', o.owner, 'entity_type', o.entity_type, 'by', o.by) ORDER BY o.owner), '[]'),
         CASE WHEN count(*) = 0 THEN 'NONE' WHEN count(*) = 1 THEN 'ONE'
              WHEN count(*) > count(DISTINCT o.entity_type) THEN 'CONFLICT'       -- two owners of one type
              ELSE 'SEVERAL_TYPES' END                                            -- one owner per type: not a conflict
  INTO owners, st
  FROM (SELECT k.owner_entity_id AS owner, k.entity_type, jsonb_agg(DISTINCT k.scheme) AS by
        FROM ac.entity_keys k
        JOIN jsonb_array_elements(d.manifest->'columns') c ON k.scheme = c->>'identifier_scheme'
        JOIN jsonb_array_elements(r.cells) x ON x->>'name' = c->>'name' AND jsonb_typeof(x->'value') = 'string'
                                            AND k.scheme || '|' || k.value = ac.row_id(c->>'identifier_scheme', x->>'value')
        WHERE k.project_id = p AND k.strength = 'STRONG' AND (d.manifest->'subject') ? (c->>'name')
          AND ac.entity_visible(clr, k.owner_entity_id, now())
        GROUP BY k.owner_entity_id, k.entity_type) o;
  RETURN jsonb_build_object('projection', 'dataset_subject/0.1', 'dataset_id', d.dataset_id, 'source_id', sid,
                            'row_sha256', encode(r.row_hash, 'hex'), 'status', st, 'owners', owners);
END $$;
ALTER FUNCTION ac.dataset_subject(text, text, jsonb) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.dataset_subject(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.dataset_subject(text, text, jsonb) TO ac_reader;

-- ---------------------------------------------------------------- evidence of a claim for the projections: a fragment or a row
CREATE OR REPLACE FUNCTION ac.evidence_json(cid text, t timestamptz) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(CASE WHEN e.kind = 'ROW' THEN jsonb_strip_nulls(jsonb_build_object(
           'source_id', e.source_id, 'source_title', s.body->>'title', 'source_kind', s.body->>'source_kind',
           'row_key', e.row_ev->'row_key', 'row_sha256', e.row_ev->>'row_sha256',
           'cells', (SELECT jsonb_object_agg(x->>'name', x->'value') FROM jsonb_array_elements(e.row_ev->'cells') x WHERE x ? 'salt')))
           || jsonb_build_object(
           'proves', '["subject", "object"]'::jsonb,     -- qualifiers and validity are the author's statement, as with a quote
           'currency', ac.row_currency(e.tenant_id, e.source_id, e.row_ev,           -- the row in the latest version (cycle 11)
                                       (SELECT c.marking FROM ac.claims c WHERE c.claim_id = e.claim_id), t),
           'subject_conflict', CASE WHEN ac.row_subject_conflict((SELECT c FROM ac.claims c WHERE c.claim_id = e.claim_id), e.row_ev,
                                       (SELECT d.manifest FROM ac.datasets d WHERE d.tenant_id = e.tenant_id AND d.source_id = e.source_id), t)
                                    THEN true END,
           'verified', ac.row_evidence_error(e.row_ev, (SELECT d.manifest FROM ac.datasets d WHERE d.tenant_id = e.tenant_id AND d.source_id = e.source_id),
                                             (SELECT c FROM ac.claims c WHERE c.claim_id = e.claim_id)) IS NULL,
           'first_observed_at', (SELECT min(o.observed_at) FROM ac.source_observations o
                                 WHERE o.tenant_id = e.tenant_id AND o.source_id = e.source_id AND o.ingested_at <= t))
         ELSE jsonb_build_object(
           'source_id', e.source_id, 'source_title', s.body->>'title', 'source_kind', s.body->>'source_kind',
           'span', jsonb_build_array(e.span_start, e.span_end),
           'quote', convert_from(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start), 'UTF8'),
           'verified', encode(sha256(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start)), 'hex') = e.quote_sha256,
           'first_observed_at', (SELECT min(o.observed_at) FROM ac.source_observations o
                                 WHERE o.tenant_id = e.tenant_id AND o.source_id = e.source_id AND o.ingested_at <= t)) END
         ORDER BY e.ord), '[]')
  FROM ac.claim_evidence e
  JOIN ac.sources s ON s.tenant_id = e.tenant_id AND s.source_id = e.source_id
  JOIN ac.source_bytes b ON b.tenant_id = e.tenant_id AND b.source_id = e.source_id
  WHERE e.claim_id = cid $$;

-- the support of a fact is counted by families (D27.4): N versions of one dataset are one support, like three fetches
-- of one article (S5)
CREATE OR REPLACE FUNCTION ac.support_key(tenant text, sid text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT 'dataset:' || d.dataset_id FROM ac.datasets d WHERE d.tenant_id = tenant AND d.source_id = sid),
                  (SELECT min(x) FROM ac.source_pubs(tenant, sid, t) x), sid) $$;

CREATE OR REPLACE VIEW ac.claim_provenance AS
SELECT c.project_id, c.claim_id, c.subject, c.predicate, c.body->'object' AS object, ac.status_at(c.claim_id, now()) AS status,
       e.ord, s.body->>'title' AS source_title, s.body->>'source_kind' AS source_kind, e.span_start, e.span_end,
       CASE WHEN e.kind = 'ROW' THEN (SELECT jsonb_object_agg(x->>'name', x->'value') FROM jsonb_array_elements(e.row_ev->'cells') x WHERE x ? 'salt')::text
            ELSE convert_from(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start), 'UTF8') END AS quote,
       CASE WHEN e.kind = 'ROW' THEN ac.row_evidence_error(e.row_ev, (SELECT d.manifest FROM ac.datasets d WHERE d.tenant_id = e.tenant_id
                                                                      AND d.source_id = e.source_id), c) IS NULL
            ELSE encode(sha256(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start)), 'hex') = e.quote_sha256 END AS verified,
       CASE WHEN e.kind = 'ROW' THEN '["subject", "object"]'::jsonb END AS proves     -- what a row proves (S10R-30)
FROM ac.claims c
JOIN ac.claim_evidence e USING (claim_id)
JOIN ac.sources s ON s.tenant_id = e.tenant_id AND s.source_id = e.source_id
JOIN ac.source_bytes b ON b.tenant_id = e.tenant_id AND b.source_id = e.source_id;

-- a version for a reader: its columns, its files (and whether the object store holds each), whether its rows are loaded
CREATE FUNCTION ac.dataset_info(p text, sid text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE tn text; d ac.datasets; clr jsonb;
BEGIN
  SELECT tenant_id INTO tn FROM ac.projects WHERE project_id = p;
  SELECT * INTO d FROM ac.datasets WHERE tenant_id = tn AND source_id = sid;
  IF d.source_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, (SELECT marking FROM ac.sources WHERE tenant_id = tn AND source_id = sid));
  -- the previous version is named only to a reader cleared for it (S10R-25)
  IF EXISTS (SELECT 1 FROM ac.sources s WHERE s.tenant_id = tn AND s.source_id = d.previous AND NOT ac.dominates(clr, s.marking)) THEN
    d.previous := NULL;
  END IF;
  RETURN jsonb_build_object(
    'projection', 'dataset_info/0.1', 'dataset_id', d.dataset_id, 'version_label', d.version_label, 'source_id', sid,
    'previous', d.previous, 'row_count', d.row_count, 'key', d.manifest->'key', 'subject', d.manifest->'subject',
    'columns', d.manifest->'columns',
    'rows_loaded', EXISTS (SELECT 1 FROM ac.dataset_tables t WHERE t.tenant_id = tn AND t.source_id = sid AND t.sealed_at IS NOT NULL),
    'files', (SELECT coalesce(jsonb_agg(jsonb_build_object('object', f->>'object', 'byte_length', (f->>'byte_length')::bigint, 'rows', (f->>'rows')::bigint,
                'stored', o.object_address IS NOT NULL,
                'status', CASE WHEN o.object_address IS NULL THEN 'NOT_STORED'
                               WHEN o.byte_length <> (f->>'byte_length')::bigint THEN 'LENGTH_MISMATCH'   -- the object is not this file
                               ELSE coalesce(ac.object_status_at(tn, f->>'object', now()), 'UNCHECKED') END)
                ORDER BY n), '[]')
              FROM jsonb_array_elements(d.manifest->'files') WITH ORDINALITY a(f, n)
              LEFT JOIN ac.objects o ON o.tenant_id = tn AND o.object_address = f->>'object'));
END $$;
ALTER FUNCTION ac.dataset_info(text, text) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.dataset_info(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.dataset_info(text, text) TO ac_reader;

-- ---------------------------------------------------------------- privileges
REVOKE ALL ON ac.datasets, ac.dataset_tables FROM PUBLIC, ac_loader, ac_migrator;
GRANT SELECT ON ac.datasets, ac.dataset_tables TO ac_loader, ac_migrator;
REVOKE EXECUTE ON FUNCTION ac.dataset_open(text, text), ac.dataset_seal(text, text), ac.dataset_evidence(text, text, jsonb, text[]),
                           ac.dataset_row(text, text, jsonb), ac.dataset_find(text, text, text),
                           ac.dataset_cells(text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION ac.dataset_reset(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.dataset_open(text, text), ac.dataset_seal(text, text), ac.dataset_reset(text, text) TO ac_loader, ac_migrator;
ALTER FUNCTION ac.dataset_evidence(text, text, jsonb, text[]) OWNER TO ac_projector;
ALTER FUNCTION ac.dataset_row(text, text, jsonb) OWNER TO ac_projector;
ALTER FUNCTION ac.dataset_find(text, text, text) OWNER TO ac_projector;
GRANT USAGE ON SCHEMA acd TO ac_projector, ac_loader;
GRANT SELECT ON ac.datasets, ac.dataset_tables TO ac_projector;
GRANT EXECUTE ON FUNCTION ac.dataset_cells(text, text, jsonb) TO ac_projector;
GRANT EXECUTE ON FUNCTION ac.dataset_evidence(text, text, jsonb, text[]), ac.dataset_row(text, text, jsonb),
                          ac.dataset_find(text, text, text) TO ac_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA acd GRANT SELECT ON TABLES TO ac_projector;

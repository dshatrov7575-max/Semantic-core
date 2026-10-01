-- Архитектура семантики — S4: артефакты производителей смысла (TechSense, RR-07, D17).
-- Правила (зеркало валидатора, кроме канонической формы байтов — она только в валидаторе, D8):
--   * артефакт хранится байтами по адресу sha256; тело разбирает сама база (из байтов, не из параметра);
--   * формат и профиль — из реестра ролей ac.artifact_roles (данные, загружает мигратор из predicates.json);
--   * узлы артефакта база раскладывает в ac.artifact_nodes сама; якоря проверяются по байтам входов;
--   * receipt принимается только при сохранённом артефакте, совпадающем с ним по формату, профилю, службе,
--     запуску и входам;
--   * доказательство с узлом графа: узел есть, это отношение, фрагмент внутри якоря, и отношение говорит то же,
--     что утверждение (предикат по роли, субъект и объект по строгим ключам, литерал, уточнения);
--   * один узел — одно доказательство (уникальный индекс); PIPELINE-утверждение receipt без узла не принимается.
-- Applied after ddl_s1.sql, unicode_s1.sql, keys_s1.sql, proj_s3.sql.

-- ---------------------------------------------------------------- реестр ролей (конфигурация, append-only)
CREATE TABLE ac.artifact_roles (
  artifact_format   text NOT NULL,
  semantic_profile  text NOT NULL,
  role              text NOT NULL,
  predicate_id      text NOT NULL REFERENCES ac.predicates,
  object_kind       text NOT NULL CHECK (object_kind IN ('ENTITY','QUANTITY','ACTION')),
  qualifier         text CHECK (qualifier IN ('parameter','condition')),
  PRIMARY KEY (artifact_format, semantic_profile, role)
);
CREATE TRIGGER artifact_roles_no_update BEFORE UPDATE OR DELETE ON ac.artifact_roles FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- артефакты
CREATE TABLE ac.artifacts (
  tenant_id        text NOT NULL,
  artifact_digest  text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  bytes            bytea NOT NULL,
  body             jsonb,                                      -- set by the database from bytes
  ingested_at      timestamptz,                                -- set by the database
  PRIMARY KEY (tenant_id, artifact_digest),
  CONSTRAINT artifact_address CHECK ('sha256:' || encode(sha256(bytes), 'hex') = artifact_digest)
);

CREATE TABLE ac.artifact_nodes (
  tenant_id        text NOT NULL,
  artifact_digest  text NOT NULL,
  node_id          text NOT NULL CHECK (node_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  node_type        text NOT NULL CHECK (node_type IN ('ENTITY','QUANTITY','ACTION','CONDITION','RELATION')),
  anchor_source    text,
  anchor_start     integer,
  anchor_end       integer,
  body             jsonb NOT NULL,
  PRIMARY KEY (tenant_id, artifact_digest, node_id),
  FOREIGN KEY (tenant_id, artifact_digest) REFERENCES ac.artifacts,
  CHECK ((anchor_source IS NULL) = (anchor_start IS NULL) AND (anchor_start IS NULL) = (anchor_end IS NULL)),
  CHECK (anchor_start IS NULL OR (anchor_start >= 0 AND anchor_end > anchor_start))
);

CREATE FUNCTION ac.artifact_bad(msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN PERFORM ac.fail('ARTIFACT_INVALID', msg); END $$;

-- strong identity keys of an identity (the same function that derives entity keys) as one comparable value
CREATE FUNCTION ac.strong_keys(t text, i jsonb) RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(array_agg(k.scheme || '|' || k.value ORDER BY k.scheme, k.value), '{}')
  FROM ac.identity_keys(t, i) k WHERE k.strength = 'STRONG' $$;

-- S4R-02 / S4R-11: a node names entity eid at time «at» (the claim's recorded_at) when every strong key of the node
-- is a strong key of eid's group at that time: the entity eid resolved to at «at» and every entity merged into it by «at»
CREATE FUNCTION ac.node_names(eid text, t text, i jsonb, at timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
  WITH o AS (SELECT CASE WHEN status = 'MERGED' AND status_changed_at <= at THEN merged_into ELSE entity_id END AS oid, entity_type
             FROM ac.entities WHERE entity_id = eid),
       g AS (SELECT x.entity_type, x.identity FROM ac.entities x, o
             WHERE x.entity_id = o.oid OR (x.status = 'MERGED' AND x.merged_into = o.oid AND x.status_changed_at <= at))
  SELECT (SELECT entity_type FROM o) = t AND cardinality(ac.strong_keys(t, i)) > 0
         AND ac.strong_keys(t, i) <@ ARRAY(SELECT DISTINCT unnest(ac.strong_keys(g.entity_type, g.identity)) FROM g) $$;

-- S4R-03: strings of an artifact as the validator sees them: no control characters in structural fields
-- (the text of an ACTION is free text), at most 2000 characters, not blank
CREATE FUNCTION ac.artifact_strings_ok(j jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT NOT EXISTS (SELECT 1 FROM jsonb_path_query(j, 'strict $.**') v
                     WHERE jsonb_typeof(v) = 'string' AND ((v #>> '{}') ~ '[\x01-\x1f\x7f]' OR length(v #>> '{}') > 2000)) $$;

CREATE FUNCTION ac.artifacts_before() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a jsonb;
BEGIN
  BEGIN
    a := convert_from(NEW.bytes, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    PERFORM ac.artifact_bad('артефакт не JSON в UTF-8');
  END;
  IF jsonb_typeof(a) <> 'object'
     OR EXISTS (SELECT 1 FROM jsonb_object_keys(a) k WHERE k NOT IN ('artifact_format','semantic_profile','producer','run_id','inputs','nodes'))
     OR a->>'artifact_format' IS DISTINCT FROM 'umr-artifact/0.3'
     OR jsonb_typeof(a->'producer') IS DISTINCT FROM 'object'
     OR NOT (a->'producer' ?& array['service_id','version']) OR (SELECT count(*) FROM jsonb_object_keys(a->'producer')) <> 2
     OR coalesce(a->'producer'->>'service_id', '') !~ '^svc_[a-z0-9_]{2,64}$'
     OR coalesce(a->'producer'->>'version', '') !~ '^[0-9]+\.[0-9]+\.[0-9]+$'
     OR coalesce(a->>'run_id', '') !~ '^run_[a-z0-9_]{2,64}$' OR jsonb_typeof(a->'run_id') <> 'string'
     OR jsonb_typeof(a->'inputs') IS DISTINCT FROM 'array' OR jsonb_array_length(a->'inputs') = 0
     OR jsonb_typeof(a->'nodes') IS DISTINCT FROM 'array' OR jsonb_array_length(a->'nodes') = 0 THEN
    PERFORM ac.artifact_bad('артефакт не по форме umr-artifact/0.3');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ac.artifact_roles WHERE artifact_format = a->>'artifact_format' AND semantic_profile = a->>'semantic_profile') THEN
    PERFORM ac.artifact_bad('неизвестный семантический профиль артефакта');
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(a->'inputs') x WHERE jsonb_typeof(x) <> 'string' OR x #>> '{}' !~ '^src:sha256:[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT x) FROM jsonb_array_elements(a->'inputs') x) <> jsonb_array_length(a->'inputs') THEN
    PERFORM ac.artifact_bad('входы артефакта: адреса источников без повторов');
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(a->'inputs') x
             WHERE NOT EXISTS (SELECT 1 FROM ac.source_bytes b WHERE b.tenant_id = NEW.tenant_id AND b.source_id = x)) THEN
    PERFORM ac.artifact_bad('вход артефакта не найден среди байтов источников tenant');
  END IF;
  IF NOT ac.artifact_strings_ok(a - 'nodes')
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(a->'nodes') x
                WHERE NOT ac.artifact_strings_ok(CASE WHEN x->>'type' = 'ACTION' THEN x - 'text' ELSE x END)
                   OR (x->>'type' = 'ACTION' AND length(x->>'text') > 2000)) THEN
    PERFORM ac.artifact_bad('управляющий символ в структурном поле или строка длиннее 2000 (S4R-03)');
  END IF;
  NEW.body := a;
  NEW.ingested_at := clock_timestamp();
  RETURN NEW;
END $$;
CREATE TRIGGER artifacts_before BEFORE INSERT ON ac.artifacts FOR EACH ROW EXECUTE FUNCTION ac.artifacts_before();
CREATE TRIGGER artifacts_no_update BEFORE UPDATE OR DELETE ON ac.artifacts FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER artifact_nodes_no_update BEFORE UPDATE OR DELETE ON ac.artifact_nodes FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- nodes come ONLY from the artifact body; every node is checked here, relations after all nodes are known
CREATE FUNCTION ac.artifacts_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE n jsonb; b bytea; rl ac.artifact_roles; a0 jsonb; a1 jsonb; nid text;
BEGIN
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.body->'nodes') x WHERE jsonb_typeof(x) <> 'object' OR jsonb_typeof(x->'id') IS DISTINCT FROM 'string')
     OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(NEW.body->'nodes') x) <> jsonb_array_length(NEW.body->'nodes') THEN
    PERFORM ac.artifact_bad('узлы: объекты с уникальными id');
  END IF;
  FOR n IN SELECT x FROM jsonb_array_elements(NEW.body->'nodes') x LOOP
    nid := n->>'id';
    IF nid !~ '^[A-Za-z0-9_.:-]{1,128}$' OR n->>'type' IS NULL
       OR n->>'type' NOT IN ('ENTITY','QUANTITY','ACTION','CONDITION','RELATION') OR jsonb_typeof(n->'type') <> 'string' THEN
      PERFORM ac.artifact_bad('узел ' || nid || ': id или тип');
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_object_keys(n) k WHERE k NOT IN (
         SELECT unnest((CASE n->>'type' WHEN 'ENTITY' THEN array['id','type','anchor','entity_type','identity']
                                        WHEN 'QUANTITY' THEN array['id','type','anchor','value','unit']
                                        WHEN 'RELATION' THEN array['id','type','anchor','role','args','parameter','condition']
                                        ELSE array['id','type','anchor','text'] END)))) THEN
      PERFORM ac.artifact_bad('узел ' || nid || ': лишние поля');
    END IF;
    IF n ? 'anchor' THEN
      IF jsonb_typeof(n->'anchor') <> 'object' OR (SELECT count(*) FROM jsonb_object_keys(n->'anchor')) <> 3
         OR jsonb_typeof(n->'anchor'->'start') <> 'number' OR jsonb_typeof(n->'anchor'->'end') <> 'number'
         OR (n->'anchor'->>'start') !~ '^[0-9]{1,9}$' OR (n->'anchor'->>'end') !~ '^[0-9]{1,9}$'
         OR jsonb_typeof(n->'anchor'->'source_id') <> 'string' THEN
        PERFORM ac.artifact_bad('узел ' || nid || ': якорь {source_id, start, end}');
      END IF;
      IF NOT (NEW.body->'inputs') ? (n->'anchor'->>'source_id') THEN
        PERFORM ac.artifact_bad('якорь узла ' || nid || ': источник не во входах артефакта');
      END IF;
      SELECT bytes INTO b FROM ac.source_bytes WHERE tenant_id = NEW.tenant_id AND source_id = n->'anchor'->>'source_id';
      IF NOT ((n->'anchor'->>'start')::int < (n->'anchor'->>'end')::int AND (n->'anchor'->>'end')::int <= length(b)) THEN
        PERFORM ac.artifact_bad('якорь узла ' || nid || ' не попадает в байты источника');
      END IF;
      BEGIN
        PERFORM convert_from(substring(b FROM (n->'anchor'->>'start')::int + 1
                                       FOR (n->'anchor'->>'end')::int - (n->'anchor'->>'start')::int), 'UTF8');
      EXCEPTION WHEN others THEN
        PERFORM ac.artifact_bad('якорь узла ' || nid || ' режет символ UTF-8');
      END;
    ELSIF n->>'type' <> 'ENTITY' THEN
      PERFORM ac.artifact_bad('узел ' || nid || ' без якоря');
    END IF;
    IF n->>'type' = 'ENTITY' THEN
      IF n->>'entity_type' IS NULL OR n->>'entity_type' NOT IN ('EQUIPMENT','EQUIPMENT_MODEL') OR jsonb_typeof(n->'identity') IS DISTINCT FROM 'object'
         OR EXISTS (SELECT 1 FROM jsonb_each(n->'identity') kv WHERE jsonb_typeof(kv.value) <> 'string' OR kv.value #>> '{}' !~ '\S'
                      OR kv.key NOT IN (SELECT unnest(CASE n->>'entity_type' WHEN 'EQUIPMENT' THEN array['site_id','tag','description']
                                                                             ELSE array['manufacturer','model','description'] END)))
         OR (n->>'entity_type' = 'EQUIPMENT' AND (NOT n->'identity' ?& array['site_id','tag'] OR (n->'identity'->>'site_id') !~ '^site_[a-z0-9_]{2,64}$'))
         OR (n->>'entity_type' = 'EQUIPMENT_MODEL' AND NOT n->'identity' ?& array['manufacturer','model']) THEN
        PERFORM ac.artifact_bad('узел ' || nid || ': тип или идентичность сущности');
      END IF;
    ELSIF n->>'type' = 'QUANTITY' THEN
      IF jsonb_typeof(n->'value') IS DISTINCT FROM 'string' OR (n->>'value') !~ '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$'
         OR jsonb_typeof(n->'unit') IS DISTINCT FROM 'string' OR (n->>'unit') !~ '^[A-Za-z%/0-9]{1,16}$' THEN
        PERFORM ac.artifact_bad('узел ' || nid || ': величина');
      END IF;
    ELSIF n->>'type' IN ('ACTION', 'CONDITION') THEN
      IF jsonb_typeof(n->'text') IS DISTINCT FROM 'string' OR (n->>'text') !~ '\S' THEN
        PERFORM ac.artifact_bad('узел ' || nid || ': текст');
      END IF;
    ELSE
      IF jsonb_typeof(n->'role') IS DISTINCT FROM 'string' OR (n->>'role') !~ '^[a-z][a-z0-9-]{1,40}$'
         OR jsonb_typeof(n->'args') IS DISTINCT FROM 'array' OR jsonb_array_length(n->'args') <> 2
         OR EXISTS (SELECT 1 FROM jsonb_array_elements(n->'args') x WHERE jsonb_typeof(x) <> 'string')
         OR (n ? 'parameter' AND (jsonb_typeof(n->'parameter') <> 'string' OR (n->>'parameter') !~ '^[a-z][a-z0-9_]{1,64}$'))
         OR (n ? 'condition' AND jsonb_typeof(n->'condition') <> 'string') THEN
        PERFORM ac.artifact_bad('узел ' || nid || ': отношение');
      END IF;
    END IF;
    INSERT INTO ac.artifact_nodes VALUES (NEW.tenant_id, NEW.artifact_digest, nid, n->>'type', n->'anchor'->>'source_id',
                                          (n->'anchor'->>'start')::int, (n->'anchor'->>'end')::int, n);
  END LOOP;
  FOR n IN SELECT body FROM ac.artifact_nodes WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.artifact_digest AND node_type = 'RELATION' LOOP
    SELECT body INTO a0 FROM ac.artifact_nodes WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.artifact_digest AND node_id = n->'args'->>0;
    SELECT body INTO a1 FROM ac.artifact_nodes WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.artifact_digest AND node_id = n->'args'->>1;
    IF a0 IS NULL OR a1 IS NULL OR (n ? 'condition' AND NOT EXISTS (
         SELECT 1 FROM ac.artifact_nodes WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.artifact_digest
                                         AND node_id = n->>'condition' AND node_type = 'CONDITION')) THEN
      PERFORM ac.artifact_bad('отношение ' || (n->>'id') || ': ссылка на несуществующий узел (или условие не CONDITION)');
    END IF;
    SELECT * INTO rl FROM ac.artifact_roles WHERE artifact_format = NEW.body->>'artifact_format'
                                             AND semantic_profile = NEW.body->>'semantic_profile' AND role = n->>'role';
    IF rl.role IS NOT NULL AND NOT (a0->>'type' = 'ENTITY' AND a1->>'type' = rl.object_kind
                                    AND (n ? 'parameter') = (rl.qualifier IS NOT DISTINCT FROM 'parameter')
                                    AND (n ? 'condition') = (rl.qualifier IS NOT DISTINCT FROM 'condition')) THEN
      PERFORM ac.artifact_bad('отношение ' || (n->>'id') || ' (' || (n->>'role') || '): аргументы или уточнение не по профилю');
    END IF;
  END LOOP;
  RETURN NULL;
END $$;
CREATE TRIGGER artifacts_after AFTER INSERT ON ac.artifacts FOR EACH ROW EXECUTE FUNCTION ac.artifacts_after();

-- ---------------------------------------------------------------- receipt ↔ артефакт
CREATE FUNCTION ac.receipts_artifact_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a ac.artifacts;
BEGIN
  SELECT * INTO a FROM ac.artifacts WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.body->>'artifact_digest';
  IF a.artifact_digest IS NULL THEN
    PERFORM ac.artifact_bad('нет артефакта receipt в хранилище tenant (RR-07)');
  END IF;
  IF a.body->>'artifact_format' IS DISTINCT FROM NEW.body->>'artifact_schema_version'
     OR a.body->>'semantic_profile' IS DISTINCT FROM NEW.body->>'semantic_profile_version'
     OR a.body->'producer' IS DISTINCT FROM NEW.body->'producer' OR a.body->>'run_id' IS DISTINCT FROM NEW.body->>'run_id'
     OR (SELECT array_agg(x ORDER BY x) FROM jsonb_array_elements_text(a.body->'inputs') x)
        IS DISTINCT FROM (SELECT array_agg(x ORDER BY x) FROM jsonb_array_elements_text(NEW.body->'input_source_ids') x) THEN
    PERFORM ac.artifact_bad('артефакт не совпадает с receipt: формат, профиль, служба, запуск или входы');
  END IF;
  RETURN NEW;
END $$;
-- named after receipts_guard so that the key check (D7) fires first
CREATE TRIGGER receipts_guard_artifact BEFORE INSERT ON ac.artifact_receipts FOR EACH ROW EXECUTE FUNCTION ac.receipts_artifact_guard();

-- ---------------------------------------------------------------- доказательство ↔ узел графа
CREATE UNIQUE INDEX claim_evidence_one_node ON ac.claim_evidence (tenant_id, (graph_node->>'artifact_digest'), (graph_node->>'node_id'))
  WHERE graph_node IS NOT NULL;

CREATE FUNCTION ac.graph_says(c ac.claims, n jsonb, tenant text, dg text) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE a ac.artifacts; rl ac.artifact_roles; a0 jsonb; a1 jsonb; want jsonb := '{}';
BEGIN
  SELECT * INTO a FROM ac.artifacts WHERE tenant_id = tenant AND artifact_digest = dg;
  SELECT * INTO rl FROM ac.artifact_roles WHERE artifact_format = a.body->>'artifact_format'
                                           AND semantic_profile = a.body->>'semantic_profile' AND role = n->>'role';
  IF rl.role IS NULL THEN
    RETURN 'роль ' || (n->>'role') || ' не отображается в предикат профиля';
  END IF;
  IF c.predicate <> rl.predicate_id THEN
    RETURN 'предикат не совпадает с ролью узла';
  END IF;
  SELECT body INTO a0 FROM ac.artifact_nodes WHERE tenant_id = tenant AND artifact_digest = dg AND node_id = n->'args'->>0;
  SELECT body INTO a1 FROM ac.artifact_nodes WHERE tenant_id = tenant AND artifact_digest = dg AND node_id = n->'args'->>1;
  IF a0->>'type' <> 'ENTITY' OR NOT coalesce(ac.node_names(c.subject, a0->>'entity_type', a0->'identity', c.recorded_at), false) THEN
    RETURN 'субъект не совпадает с узлом-аргументом';
  END IF;
  IF rl.object_kind = 'ENTITY' THEN
    IF c.object_entity IS NULL OR a1->>'type' <> 'ENTITY'
       OR NOT coalesce(ac.node_names(c.object_entity, a1->>'entity_type', a1->'identity', c.recorded_at), false) THEN
      RETURN 'объект не совпадает с узлом-аргументом';
    END IF;
  ELSIF c.body->'object'->'literal' IS DISTINCT FROM (CASE rl.object_kind
          WHEN 'QUANTITY' THEN jsonb_build_object('type', 'QUANTITY', 'value', a1->'value', 'unit', a1->'unit')
          ELSE jsonb_build_object('type', 'STRING', 'value', a1->'text') END) THEN
    RETURN 'объект не совпадает с узлом-аргументом';
  END IF;
  IF rl.qualifier = 'parameter' THEN
    want := jsonb_build_object('parameter', n->'parameter');
  ELSIF rl.qualifier = 'condition' THEN
    want := jsonb_build_object('condition', (SELECT body->'text' FROM ac.artifact_nodes
                                             WHERE tenant_id = tenant AND artifact_digest = dg AND node_id = n->>'condition'));
  END IF;
  IF coalesce(c.body->'qualifiers', '{}') IS DISTINCT FROM want THEN
    RETURN 'уточнения не совпадают с узлом';
  END IF;
  IF c.body ?| array['valid_from', 'valid_to'] THEN          -- S4R-01
    RETURN 'у отношения нет срока действия, а у утверждения есть';
  END IF;
  RETURN NULL;
END $$;

CREATE FUNCTION ac.evidence_graph_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c ac.claims; nd ac.artifact_nodes; why text;
BEGIN
  IF NEW.graph_node IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO c FROM ac.claims WHERE claim_id = NEW.claim_id;
  SELECT * INTO nd FROM ac.artifact_nodes WHERE tenant_id = NEW.tenant_id AND artifact_digest = NEW.graph_node->>'artifact_digest'
                                            AND node_id = NEW.graph_node->>'node_id';
  IF nd.node_id IS NULL OR nd.node_type <> 'RELATION' THEN
    PERFORM ac.fail('GRAPH_NODE_INVALID', 'узла ' || coalesce(NEW.graph_node->>'node_id', '?') || ' нет в сохранённом артефакте tenant или это не отношение');
  END IF;
  IF nd.anchor_source <> NEW.source_id OR NOT (nd.anchor_start <= NEW.span_start AND NEW.span_end <= nd.anchor_end) THEN
    PERFORM ac.fail('GRAPH_NODE_INVALID', 'фрагмент доказательства вне якоря узла ' || nd.node_id);
  END IF;
  why := ac.graph_says(c, nd.body, NEW.tenant_id, nd.artifact_digest);
  IF why IS NOT NULL THEN
    PERFORM ac.fail('GRAPH_NODE_INVALID', 'узел ' || nd.node_id || ': ' || why);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER evidence_guard_graph BEFORE INSERT ON ac.claim_evidence FOR EACH ROW EXECUTE FUNCTION ac.evidence_graph_guard();

-- a claim bound to a receipt rests on at least one graph node of the receipt's artifact
CREATE FUNCTION ac.receipt_claims_graph_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ac.claim_evidence e WHERE e.claim_id = NEW.claim_id)
     OR EXISTS (SELECT 1 FROM ac.claim_evidence e JOIN ac.artifact_receipts r ON r.receipt_id = NEW.receipt_id
                WHERE e.claim_id = NEW.claim_id AND (e.graph_node->>'artifact_digest') IS DISTINCT FROM r.body->>'artifact_digest') THEN
    PERFORM ac.fail('GRAPH_NODE_INVALID', NEW.claim_id || ': доказательство утверждения из артефакта без узла графа этого артефакта');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER receipt_claims_graph_guard BEFORE INSERT ON ac.receipt_claims FOR EACH ROW EXECUTE FUNCTION ac.receipt_claims_graph_guard();

-- S4R-13: an artifact is stored only in the transaction that also stores its receipt (no squatting on a run id)
CREATE FUNCTION ac.artifact_has_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ac.artifact_receipts r WHERE r.tenant_id = NEW.tenant_id AND r.body->>'artifact_digest' = NEW.artifact_digest) THEN
    PERFORM ac.artifact_bad('артефакт без receipt в той же транзакции (S4R-13)');
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER artifact_has_receipt AFTER INSERT ON ac.artifacts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ac.artifact_has_receipt();

-- S4R-08: one run of a service gives one artifact and one receipt (a replay with other bytes is refused)
CREATE UNIQUE INDEX artifacts_one_per_run ON ac.artifacts (tenant_id, (body->'producer'->>'service_id'), (body->>'run_id'));
CREATE UNIQUE INDEX receipts_one_per_run ON ac.artifact_receipts (tenant_id, service_id, (body->>'run_id'));

-- ---------------------------------------------------------------- права
REVOKE ALL ON ac.artifact_roles, ac.artifacts, ac.artifact_nodes FROM PUBLIC, ac_loader, ac_migrator, ac_trust_admin;
GRANT SELECT ON ac.artifact_roles, ac.artifacts, ac.artifact_nodes TO ac_loader, ac_migrator, ac_projector;
GRANT INSERT (tenant_id, artifact_digest, bytes) ON ac.artifacts TO ac_loader, ac_migrator;
GRANT INSERT ON ac.artifact_roles TO ac_migrator;

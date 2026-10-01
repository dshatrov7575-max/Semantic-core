-- Архитектура семантики — S4: проекция «карточка оборудования» (TechSense).
-- Те же правила, что у проекций S3 (proj_s3.sql): допуск по session_user, SECURITY DEFINER у ac_projector,
-- единый отказ, имена и статусы на момент as_of, digest. Дополнительно:
--   * у экземпляра — модель, место в составе (родитель и состав), собственные параметры и действия;
--     параметры и действия МОДЕЛИ показываются отдельными разделами, с пометкой, что это данные модели;
--   * у каждого утверждения от производителя — путь до узла графа: receipt (служба, версия, запуск, время),
--     артефакт (адрес), узел, его роль и то, что фрагмент лежит внутри якоря узла (проверяется при чтении);
--   * у модели — параметры, действия и известные экземпляры.
-- Applied after proj_s3.sql and ddl_s4.sql.

CREATE TABLE ac.card_sections (section text PRIMARY KEY, title text NOT NULL, ord int NOT NULL);
INSERT INTO ac.card_sections VALUES
 ('MODEL', 'Модель', 1), ('PART_OF', 'Входит в состав', 2), ('COMPONENTS', 'Состав', 3),
 ('PARAMETERS', 'Параметры', 4), ('MODEL_PARAMETERS', 'Параметры модели (по документации модели)', 5),
 ('ACTIONS', 'Требуемые действия', 6), ('MODEL_ACTIONS', 'Требуемые действия для модели', 7),
 ('INSTANCES', 'Экземпляры модели', 8), ('OTHER', 'Прочие сведения', 9);
CREATE TRIGGER card_sections_frozen BEFORE UPDATE OR DELETE ON ac.card_sections FOR EACH ROW EXECUTE FUNCTION ac.forbid();
INSERT INTO ac.value_texts VALUES ('nominal_pressure', 'номинальное давление');
GRANT SELECT ON ac.card_sections TO ac_projector;

-- how a claim was produced: for PIPELINE claims the path down to the graph node, re-checked on read
CREATE FUNCTION ac.production_json(cid text) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT CASE c.produced_kind
    WHEN 'HUMAN' THEN jsonb_build_object('kind', 'HUMAN')
    ELSE (SELECT jsonb_build_object(
            'kind', 'PIPELINE', 'receipt_id', r.receipt_id, 'service_id', r.service_id,
            'version', r.body->'producer'->>'version', 'run_id', r.body->>'run_id', 'issued_at', r.issued_at,
            'artifact_digest', r.body->>'artifact_digest', 'artifact_stored', a.artifact_digest IS NOT NULL,
            'nodes', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                         'node_id', e.graph_node->>'node_id', 'role', n.body->>'role',
                         'span_in_anchor', n.anchor_source = e.source_id AND n.anchor_start <= e.span_start AND e.span_end <= n.anchor_end)
                       ORDER BY e.ord), '[]')
                      FROM ac.claim_evidence e
                      LEFT JOIN ac.artifact_nodes n ON n.tenant_id = e.tenant_id AND n.artifact_digest = e.graph_node->>'artifact_digest'
                                                   AND n.node_id = e.graph_node->>'node_id'
                      WHERE e.claim_id = c.claim_id AND e.graph_node IS NOT NULL))
          FROM ac.receipt_claims rc JOIN ac.artifact_receipts r USING (receipt_id)
          LEFT JOIN ac.artifacts a ON a.tenant_id = r.tenant_id AND a.artifact_digest = r.body->>'artifact_digest'
          WHERE rc.claim_id = c.claim_id)
  END
  FROM ac.claims c WHERE c.claim_id = cid $$;

CREATE FUNCTION ac.equipment_card(p text, eid text, as_of timestamptz DEFAULT now()) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE e ac.entities; clr jsonb; focus text; vis text[]; mvis text[] := '{}'; secs jsonb := '[]'; s record; ids text[];
        f jsonb; used text[] := '{}'; res jsonb; marks jsonb; mfocus text; ambiguous boolean;
BEGIN
  as_of := least(as_of, clock_timestamp());
  SELECT * INTO e FROM ac.entities WHERE entity_id = eid AND project_id = p AND entity_type IN ('EQUIPMENT', 'EQUIPMENT_MODEL');
  IF e.entity_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, e.marking);
  focus := ac.resolve_at(e.entity_id, as_of);
  SELECT * INTO e FROM ac.entities WHERE entity_id = focus;
  clr := ac.require_clearance(p, e.marking);
  -- visible claims of the project at as_of (the same filter as the dossier)
  SELECT coalesce(array_agg(c.claim_id), '{}') INTO vis
  FROM ac.claims c
  WHERE c.project_id = p AND c.recorded_at <= as_of
    AND (ac.resolve_at(c.subject, as_of) = focus OR ac.resolve_at(c.object_entity, as_of) = focus)
    AND ac.status_at(c.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN')
    AND ac.dominates(clr, c.marking)
    AND ac.entity_visible(clr, c.subject, as_of) AND ac.entity_visible(clr, c.object_entity, as_of);
  -- the model of an instance is the one the section «Модель» names (the main fact of facts_json: best status, then
  -- most sources); model data is shown for that model only; a discrepancy is flagged (S4R-09, S4R-12)
  FOR s IN SELECT * FROM ac.card_sections ORDER BY ord LOOP
    ids := ARRAY(SELECT c.claim_id FROM ac.claims c WHERE c.claim_id = ANY (CASE WHEN s.section LIKE 'MODEL\_%' THEN mvis ELSE vis END)
      AND CASE s.section
        WHEN 'MODEL' THEN c.predicate = 'ts.instance_of' AND ac.resolve_at(c.subject, as_of) = focus
        WHEN 'PART_OF' THEN c.predicate = 'ts.part_of' AND ac.resolve_at(c.subject, as_of) = focus
        WHEN 'COMPONENTS' THEN c.predicate = 'ts.part_of' AND ac.resolve_at(c.object_entity, as_of) = focus
        WHEN 'PARAMETERS' THEN c.predicate = 'ts.has_parameter' AND ac.resolve_at(c.subject, as_of) = focus
        WHEN 'ACTIONS' THEN c.predicate = 'ts.requires_action' AND ac.resolve_at(c.subject, as_of) = focus
        WHEN 'MODEL_PARAMETERS' THEN c.predicate = 'ts.has_parameter'
        WHEN 'MODEL_ACTIONS' THEN c.predicate = 'ts.requires_action'
        WHEN 'INSTANCES' THEN c.predicate = 'ts.instance_of' AND ac.resolve_at(c.object_entity, as_of) = focus
        ELSE NOT (c.claim_id = ANY (used)) END);
    CONTINUE WHEN (e.entity_type = 'EQUIPMENT' AND s.section = 'INSTANCES')
               OR (e.entity_type = 'EQUIPMENT_MODEL' AND s.section IN ('MODEL', 'PART_OF', 'COMPONENTS', 'MODEL_PARAMETERS', 'MODEL_ACTIONS'))
               OR (s.section IN ('OTHER', 'MODEL_PARAMETERS', 'MODEL_ACTIONS') AND cardinality(ids) = 0);
    used := used || ids;                               -- only what is shown counts (marking, production)
    f := ac.facts_json(ids, as_of, CASE WHEN s.section LIKE 'MODEL\_%' THEN mfocus ELSE focus END);
    IF s.section = 'MODEL' AND jsonb_array_length(f) > 0 THEN
      SELECT ac.resolve_at(c.object_entity, as_of) INTO mfocus FROM ac.claims c WHERE c.claim_id = f->0->'claims'->0->>'claim_id';
      ambiguous := CASE WHEN f->0 ? 'note' THEN true END;
      SELECT coalesce(array_agg(c.claim_id), '{}') INTO mvis
      FROM ac.claims c
      WHERE c.project_id = p AND c.recorded_at <= as_of AND ac.resolve_at(c.subject, as_of) = mfocus
        AND c.predicate IN ('ts.has_parameter', 'ts.requires_action')
        AND ac.status_at(c.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN')
        AND ac.dominates(clr, c.marking) AND ac.entity_visible(clr, c.subject, as_of);
    END IF;
    secs := secs || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object('section', s.section, 'title', s.title,
               'facts', CASE WHEN jsonb_array_length(f) > 0 THEN f END,
               'empty', CASE WHEN jsonb_array_length(f) = 0 THEN 'Сведений нет.' END)));
  END LOOP;
  SELECT jsonb_agg(x) INTO marks FROM (SELECT e.marking AS x UNION ALL SELECT c.marking FROM ac.claims c WHERE c.claim_id = ANY (used)) y;
  res := jsonb_build_object(
    'projection', 'equipment_card/0.1', 'project_id', p, 'entity_id', focus, 'display_name', coalesce(e.display_name, e.entity_id),
    'entity_type', e.entity_type, 'identity', e.identity, 'as_of', as_of, 'marking', ac.marking_lub(marks),
    'provisional', CASE WHEN as_of > clock_timestamp() - interval '5 minutes' THEN true END,
    'also_known_as', (SELECT jsonb_agg(jsonb_build_object('entity_id', x.entity_id, 'display_name', x.display_name) ORDER BY x.entity_id)
                      FROM ac.entities x WHERE x.merged_into = focus AND x.status_changed_at <= as_of AND ac.dominates(clr, x.marking)),
    'sections', secs,
    'model_disputed', ambiguous,
    'production', (SELECT jsonb_object_agg(cid, ac.production_json(cid)) FROM unnest(used) cid));
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;

ALTER FUNCTION ac.equipment_card(text, text, timestamptz) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.equipment_card(text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.equipment_card(text, text, timestamptz) TO ac_reader;

-- Архитектура семантики — S5: проекция «лента упоминаний» (Web Monitoring).
-- Одна статья, полученная несколько раз (разные байты, адреса, мобильная версия, метки), — ОДНА позиция ленты:
-- позиция строится по публикации, а не по источнику; внутри позиции — только те рендеринги, на которые опираются
-- видимые утверждения этого проекта (источники общие для tenant: чужие заборы не раскрываются, S5R-05). Упоминание без публикации
-- (источник вне изданий) — отдельной позицией по источнику. Правила доступа — как у досье (D15, D16):
-- допуск по session_user, единый отказ, всё на момент as_of (наблюдения и публикации — по времени поступления),
-- публикация показывается только читателю, которому она видна, рендеринги — только видимые.
-- Applied after ddl_s5.sql.

CREATE FUNCTION ac.wm_feed(p text, eid text, as_of timestamptz DEFAULT now(), date_from date DEFAULT NULL, date_to date DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE e ac.entities; clr jsonb; focus text; cids text[]; items jsonb := '[]'; it record; res jsonb; marks jsonb := '[]';
BEGIN
  as_of := least(as_of, clock_timestamp());
  SELECT * INTO e FROM ac.entities WHERE entity_id = eid AND project_id = p;
  IF e.entity_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(p, e.marking);
  focus := ac.resolve_at(e.entity_id, as_of);
  SELECT * INTO e FROM ac.entities WHERE entity_id = focus;
  clr := ac.require_clearance(p, e.marking);
  SELECT coalesce(array_agg(c.claim_id), '{}') INTO cids
  FROM ac.claims c
  WHERE c.project_id = p AND c.recorded_at <= as_of AND c.predicate IN ('wm.mentioned', 'media.negative_mention')
    AND ac.resolve_at(c.subject, as_of) = focus
    AND ac.status_at(c.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN')
    AND ac.dominates(clr, c.marking) AND ac.entity_visible(clr, c.subject, as_of);
  FOR it IN
    WITH ev AS (   -- every (claim, cited source) -> the visible publications of that source at as_of, or the source itself
      SELECT DISTINCT ce.claim_id, ce.tenant_id, ce.source_id,
             coalesce(pp.publication_id, 'src:' || ce.source_id) AS ikey, pp.publication_id
      FROM ac.claim_evidence ce
      LEFT JOIN LATERAL (SELECT x AS publication_id FROM ac.source_pubs(ce.tenant_id, ce.source_id, as_of) x
                         JOIN ac.publications pb ON pb.publication_id = x WHERE ac.dominates(clr, pb.marking)) pp ON true
      WHERE ce.claim_id = ANY (cids)),
    items AS (
      SELECT ikey, min(publication_id) AS publication_id, min(tenant_id) AS tenant_id, min(source_id) AS source_id,
             array_agg(DISTINCT claim_id) AS claim_ids, array_agg(DISTINCT source_id) AS cited
      FROM ev GROUP BY ikey)
    SELECT i.*, pb.outlet, pb.canonical_url, pb.body->>'title' AS ptitle, pb.published_at, pb.marking AS pmarking,
           s.body->>'title' AS stitle, (s.body->>'published_at')::timestamptz AS spublished,
           CASE WHEN i.publication_id IS NOT NULL
                THEN (SELECT min(r.first_seen) FROM ac.renditions_at(i.publication_id, as_of) r
                      JOIN ac.sources rs ON rs.tenant_id = i.tenant_id AND rs.source_id = r.source_id
                      WHERE ac.dominates(clr, rs.marking) AND r.source_id = ANY (i.cited))
                ELSE (SELECT min(o.observed_at) FROM ac.source_observations o
                      WHERE o.tenant_id = i.tenant_id AND o.source_id = i.source_id AND o.ingested_at <= as_of) END AS first_seen
    FROM items i
    LEFT JOIN ac.publications pb ON pb.publication_id = i.publication_id
    LEFT JOIN ac.sources s ON s.tenant_id = i.tenant_id AND s.source_id = i.source_id
  LOOP
    CONTINUE WHEN date_from IS NOT NULL AND coalesce(it.published_at, it.spublished, it.first_seen)::date < date_from;
    CONTINUE WHEN date_to IS NOT NULL AND coalesce(it.published_at, it.spublished, it.first_seen)::date > date_to;
    IF it.publication_id IS NOT NULL THEN
      marks := marks || jsonb_build_array(it.pmarking);
    END IF;
    marks := marks || (SELECT coalesce(jsonb_agg(s2.marking), '[]') FROM ac.sources s2       -- S5R-06: what is shown counts
                       WHERE s2.tenant_id = it.tenant_id AND s2.source_id = ANY (it.cited));
    items := items || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'publication_id', it.publication_id,
      'outlet', it.outlet,
      'title', coalesce(it.ptitle, it.stitle),
      'canonical_url', it.canonical_url,
      'published_at', coalesce(it.published_at, it.spublished),
      'first_seen', it.first_seen,
      'renditions', CASE WHEN it.publication_id IS NOT NULL THEN
          (SELECT jsonb_agg(jsonb_build_object('source_id', r.source_id, 'first_seen', r.first_seen, 'urls', to_jsonb(r.urls))
                            ORDER BY r.first_seen, r.source_id)
           FROM ac.renditions_at(it.publication_id, as_of) r
           JOIN ac.sources rs ON rs.tenant_id = it.tenant_id AND rs.source_id = r.source_id
           WHERE ac.dominates(clr, rs.marking) AND r.source_id = ANY (it.cited)) END,
      'mentions', ac.facts_json(it.claim_ids, as_of, focus))));
  END LOOP;
  SELECT coalesce(jsonb_agg(x ORDER BY coalesce(x->>'published_at', x->>'first_seen') DESC, x->>'title'), '[]') INTO items
  FROM jsonb_array_elements(items) x;
  SELECT marks || coalesce(jsonb_agg(c.marking), '[]') || jsonb_build_array(e.marking) INTO marks FROM ac.claims c WHERE c.claim_id = ANY (cids);
  res := jsonb_build_object(
    'projection', 'wm_feed/0.1', 'project_id', p, 'entity_id', focus, 'display_name', coalesce(e.display_name, e.entity_id),
    'as_of', as_of, 'date_from', date_from, 'date_to', date_to, 'marking', ac.marking_lub(marks),
    'provisional', CASE WHEN as_of > clock_timestamp() - interval '5 minutes' THEN true END,
    'items', items);
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;

ALTER FUNCTION ac.wm_feed(text, text, timestamptz, date, date) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.wm_feed(text, text, timestamptz, date, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.wm_feed(text, text, timestamptz, date, date) TO ac_reader;

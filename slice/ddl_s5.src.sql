-- Архитектура семантики — S5 (часть 1): публикации Web Monitoring (O4, D21).
-- Правила (зеркало валидатора core-ontology/0.2.5):
--   * текст рендеринга: невидимые символы сняты, NFC, каждый пробельный отрезок — один пробел, без краевых пробелов;
--     sha256 этого текста база считает сама при записи байтов источника (ac.source_texts);
--   * публикация адресуется по (tenant, издание, нормализованный текст): adres = sha256(JCS) — его база проверяет;
--   * канонический адрес — в нормальной форме (http/https, нижний регистр хоста, без порта по умолчанию, без фрагмента,
--     без меток utm_* и подобных, параметры упорядочены); издание = хост без одного «www.», «m.» или «amp.»;
--   * рендеринги не перечисляются, а ВЫВОДЯТСЯ: любой источник tenant с тем же текстом, полученный с этого издания;
--     новый повторный забор той же статьи присоединяется сам, без правки записи публикации;
--   * публикация опирается хотя бы на один рендеринг, полученный к recorded_at; её маркировка не шире маркировки
--     этих рендерингов; дата выхода — не позже первого получения;
--   * всё, что зависит от публикаций, в проекциях считается на момент t (поступление в систему ≤ t).
-- Applied after ddl_s1.sql, unicode_s1.sql, keys_s1.sql, proj_s3.sql, ddl_s4.sql, proj_s4.sql.
-- GENERATED from ddl_s5.src.sql by gen_ddl_s5.py (the whitespace class and the class of code points unassigned in the
-- validator's Unicode version are written with \u escapes).

-- ---------------------------------------------------------------- нормализация (= validator.pub_norm / url_norm / url_outlet)
CREATE FUNCTION ac.pub_norm(t text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT btrim(regexp_replace(normalize(ac.drop_ignorable(t), NFC), '@@WS@@', ' ', 'g'), ' ') $$;

CREATE FUNCTION ac.text_digest(b bytea) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE t text;
BEGIN
  BEGIN
    t := convert_from(b, 'UTF8');
  EXCEPTION WHEN others THEN
    RETURN NULL;
  END;
  IF t ~ '@@CN@@' THEN                 -- a code point unassigned in the validator's Unicode version: not comparable (S5R-02)
    RETURN NULL;
  END IF;
  RETURN 'sha256:' || encode(sha256(convert_to(ac.pub_norm(t), 'UTF8')), 'hex');
END $$;

CREATE FUNCTION ac.url_norm(u text) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE m text[]; scheme text; host text; keep text[];
BEGIN
  m := regexp_match(u, '^([A-Za-z][A-Za-z0-9+.-]*)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(/[^?#]*)?(?:\?([^#]*))?(?:#.*)?$');
  IF m IS NULL OR lower(m[1]) NOT IN ('http', 'https') THEN
    RETURN NULL;
  END IF;
  scheme := lower(m[1]);
  host := rtrim(lower(m[2]), '.');
  IF host = '' THEN
    RETURN NULL;
  END IF;
  IF m[3] IS NOT NULL AND NOT ((scheme = 'http' AND m[3] = '80') OR (scheme = 'https' AND m[3] = '443')) THEN
    host := host || ':' || m[3];
  END IF;
  keep := ARRAY(SELECT x FROM unnest(string_to_array(coalesce(m[5], ''), '&')) x
                WHERE x <> '' AND NOT (starts_with(lower(split_part(x, '=', 1)), 'utm_')
                                       OR lower(split_part(x, '=', 1)) IN ('fbclid', 'gclid', 'yclid', '_openstat', 'mc_cid', 'mc_eid'))
                ORDER BY x COLLATE "C");
  RETURN scheme || '://' || host || coalesce(nullif(m[4], ''), '/')
         || CASE WHEN cardinality(keep) > 0 THEN '?' || array_to_string(keep, '&') ELSE '' END;
END $$;

CREATE FUNCTION ac.url_outlet(u text) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE n text := ac.url_norm(u); host text; pre text;
BEGIN
  IF n IS NULL THEN
    RETURN NULL;
  END IF;
  host := split_part(split_part(split_part(n, '://', 2), '/', 1), ':', 1);
  FOREACH pre IN ARRAY ARRAY['www.', 'm.', 'amp.'] LOOP
    IF starts_with(host, pre) AND position('.' IN substr(host, length(pre) + 1)) > 0 THEN
      RETURN substr(host, length(pre) + 1);
    END IF;
  END LOOP;
  RETURN host;
END $$;

-- sha256(JCS({outlet, tenant_id, text_digest})): keys in code-point order; the three values are restricted to
-- characters that to_json escapes exactly as RFC 8785 does
CREATE FUNCTION ac.publication_address(tenant text, outlet text, td text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT 'pub:sha256:' || encode(sha256(convert_to('{"outlet":' || to_json(outlet)::text || ',"tenant_id":' || to_json(tenant)::text
                                                   || ',"text_digest":' || to_json(td)::text || '}', 'UTF8')), 'hex') $$;

-- ---------------------------------------------------------------- текст каждого источника (выводится базой)
CREATE TABLE ac.source_texts (
  tenant_id    text NOT NULL,
  source_id    text NOT NULL,
  text_digest  text NOT NULL,
  known_at     timestamptz NOT NULL,          -- when the text became known (bytes may arrive after the observation, S5R-04)
  PRIMARY KEY (tenant_id, source_id),
  FOREIGN KEY (tenant_id, source_id) REFERENCES ac.source_bytes
);
CREATE INDEX source_texts_digest ON ac.source_texts (tenant_id, text_digest);
CREATE TRIGGER source_texts_no_update BEFORE UPDATE OR DELETE ON ac.source_texts FOR EACH ROW EXECUTE FUNCTION ac.forbid();
-- S11R-07: a rendition that arrives AFTER a publication was written (in another session or later in the same
-- transaction) but is observed by the publication's recorded_at is its basis too — the publication may not be marked
-- broader than it. The publication is already there, so the arriving rendition is refused.
-- a code point unassigned in the validator's Unicode version (the same generated class as in ac.text_digest): the
-- normal form of such a string differs between Unicode versions (S5R-02, S11R2-01)
CREATE FUNCTION ac.has_unassigned(t text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT t ~ '@@CN@@' $$;

CREATE FUNCTION ac.rendition_check(tn text, sid text) RETURNS void LANGUAGE plpgsql STABLE AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM ac.source_texts st
             JOIN ac.sources s ON s.tenant_id = st.tenant_id AND s.source_id = st.source_id
             JOIN ac.source_observations o ON o.tenant_id = st.tenant_id AND o.source_id = st.source_id
             JOIN ac.publications p ON p.tenant_id = st.tenant_id AND p.text_digest = st.text_digest
                                   AND p.outlet = ac.url_outlet(o.origin_uri) AND o.observed_at <= p.recorded_at
             WHERE st.tenant_id = tn AND st.source_id = sid AND NOT ac.dominates(p.marking, s.marking)) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'источник — рендеринг уже записанной публикации, полученный к её recorded_at, '
                    'и маркирован строже неё');
  END IF;
END $$;

CREATE FUNCTION ac.observation_rendition_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE d text;
BEGIN
  SELECT text_digest INTO d FROM ac.source_texts WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
  IF d IS NOT NULL THEN                 -- the text is known: otherwise the check runs when its bytes arrive
    PERFORM ac.lock_keys(ARRAY['text:' || NEW.tenant_id || '/' || d]);
    PERFORM ac.rendition_check(NEW.tenant_id, NEW.source_id);
  END IF;
  RETURN NULL;
END $$;

CREATE FUNCTION ac.source_texts_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE d text := ac.text_digest(NEW.bytes);
BEGIN
  IF d IS NOT NULL THEN
    PERFORM ac.lock_keys(ARRAY['source:' || NEW.source_id]);      -- serialised with Check closing (D14), time after the lock
    PERFORM ac.lock_keys(ARRAY['text:' || NEW.tenant_id || '/' || d]);   -- and with publications of this text (S11R-07)
    INSERT INTO ac.source_texts VALUES (NEW.tenant_id, NEW.source_id, d, clock_timestamp());
    PERFORM ac.rendition_check(NEW.tenant_id, NEW.source_id);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER source_texts_after AFTER INSERT ON ac.source_bytes FOR EACH ROW EXECUTE FUNCTION ac.source_texts_after();
CREATE TRIGGER observation_rendition_after AFTER INSERT ON ac.source_observations FOR EACH ROW EXECUTE FUNCTION ac.observation_rendition_after();

-- ---------------------------------------------------------------- публикации
CREATE TABLE ac.publications (
  publication_id  text PRIMARY KEY CHECK (publication_id ~ '^pub:sha256:[0-9a-f]{64}$'),
  tenant_id       text NOT NULL,
  outlet          text NOT NULL CHECK (outlet ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' AND length(outlet) <= 253),
  canonical_url   text NOT NULL CHECK (length(canonical_url) <= 2000),
  text_digest     text NOT NULL CHECK (text_digest ~ '^sha256:[0-9a-f]{64}$'),
  published_at    timestamptz,
  recorded_at     timestamptz,                                -- from the body (trigger)
  marking         jsonb NOT NULL,
  body            jsonb NOT NULL,
  ingested_at     timestamptz,                                -- set by the database
  CONSTRAINT publications_marking_shape CHECK (ac.marking_ok(marking)),
  CONSTRAINT publication_columns_match_body CHECK (publication_id = body->>'publication_id' AND tenant_id = body->>'tenant_id'
         AND outlet = body->>'outlet' AND canonical_url = body->>'canonical_url' AND text_digest = body->>'text_digest'
         AND marking = body->'marking' AND body->>'kind' = 'Publication'),
  CONSTRAINT publication_address CHECK (publication_id = ac.publication_address(tenant_id, outlet, text_digest)),
  CONSTRAINT publication_url CHECK (canonical_url = ac.url_norm(canonical_url) AND outlet = ac.url_outlet(canonical_url))
);
CREATE TRIGGER publications_no_update BEFORE UPDATE OR DELETE ON ac.publications FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- renditions of a publication known at time t: sources of the tenant with the same text, observed at the outlet
CREATE FUNCTION ac.renditions_at(pid text, t timestamptz) RETURNS TABLE (source_id text, first_seen timestamptz, urls text[])
LANGUAGE sql STABLE AS $$
  SELECT st.source_id, min(o.observed_at), array_agg(DISTINCT o.origin_uri ORDER BY o.origin_uri)
  FROM ac.publications p
  JOIN ac.source_texts st ON st.tenant_id = p.tenant_id AND st.text_digest = p.text_digest AND st.known_at <= t
  JOIN ac.source_observations o ON o.tenant_id = st.tenant_id AND o.source_id = st.source_id
                               AND ac.url_outlet(o.origin_uri) = p.outlet AND o.ingested_at <= t
  WHERE p.publication_id = pid
  GROUP BY st.source_id $$;

-- the publications a source belongs to at time t (support counts publications, not fetches: D19, D21)
CREATE FUNCTION ac.source_pubs(tenant text, sid text, t timestamptz) RETURNS SETOF text LANGUAGE sql STABLE AS $$
  SELECT DISTINCT p.publication_id
  FROM ac.source_texts st
  JOIN ac.publications p ON p.tenant_id = st.tenant_id AND p.text_digest = st.text_digest AND p.ingested_at <= t
  JOIN ac.source_observations o ON o.tenant_id = st.tenant_id AND o.source_id = st.source_id
                               AND ac.url_outlet(o.origin_uri) = p.outlet AND o.ingested_at <= t
  WHERE st.tenant_id = tenant AND st.source_id = sid AND st.known_at <= t $$;

CREATE FUNCTION ac.support_key(tenant text, sid text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT min(x) FROM ac.source_pubs(tenant, sid, t) x), sid) $$;

CREATE FUNCTION ac.publications_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE first_seen timestamptz;
BEGIN
  -- strict timestamps (no 'epoch', '-infinity', time zones other than Z: S5R-08)
  IF coalesce(NEW.body->>'recorded_at', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
     OR (NEW.body ? 'published_at' AND coalesce(NEW.body->>'published_at', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') THEN
    PERFORM ac.fail('PUBLICATION_INVALID', 'время записи или выхода не в формате ГГГГ-ММ-ДДTчч:мм:ссZ');
  END IF;
  NEW.recorded_at := (NEW.body->>'recorded_at')::timestamptz;
  NEW.published_at := (NEW.body->>'published_at')::timestamptz;
  PERFORM ac.check_supplied_time(NEW.recorded_at);
  -- S5R-01: serialised with the closing of Checks that cite any source with this text; time read after the lock
  PERFORM ac.lock_keys(ARRAY['text:' || NEW.tenant_id || '/' || NEW.text_digest]);   -- S11R-07: with arriving renditions
  PERFORM ac.lock_keys(ARRAY(SELECT 'source:' || st.source_id FROM ac.source_texts st
                             WHERE st.tenant_id = NEW.tenant_id AND st.text_digest = NEW.text_digest));
  NEW.ingested_at := clock_timestamp();
  -- the basis: renditions observed by recorded_at
  SELECT min(o.observed_at) INTO first_seen
  FROM ac.source_texts st
  JOIN ac.source_observations o ON o.tenant_id = st.tenant_id AND o.source_id = st.source_id AND ac.url_outlet(o.origin_uri) = NEW.outlet
  WHERE st.tenant_id = NEW.tenant_id AND st.text_digest = NEW.text_digest AND o.observed_at <= NEW.recorded_at;
  IF first_seen IS NULL THEN
    PERFORM ac.fail('PUBLICATION_INVALID', 'нет ни одного источника этого издания с этим текстом, полученного к recorded_at');
  END IF;
  IF EXISTS (SELECT 1 FROM ac.source_texts st JOIN ac.sources s ON s.tenant_id = st.tenant_id AND s.source_id = st.source_id
             WHERE st.tenant_id = NEW.tenant_id AND st.text_digest = NEW.text_digest AND NOT ac.dominates(NEW.marking, s.marking)
               AND EXISTS (SELECT 1 FROM ac.source_observations o WHERE o.tenant_id = st.tenant_id AND o.source_id = st.source_id
                             AND ac.url_outlet(o.origin_uri) = NEW.outlet AND o.observed_at <= NEW.recorded_at)) THEN
    PERFORM ac.fail('MARKING_BROADER_THAN_INPUT', 'маркировка публикации шире маркировки её источника');
  END IF;
  IF NEW.published_at > first_seen THEN
    PERFORM ac.fail('TEMPORAL_ORDER_INVALID', 'публикация вышла позже, чем её получили');
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER publications_guard BEFORE INSERT ON ac.publications FOR EACH ROW EXECUTE FUNCTION ac.publications_guard();

-- ---------------------------------------------------------------- права
REVOKE ALL ON ac.source_texts, ac.publications FROM PUBLIC, ac_loader, ac_migrator, ac_trust_admin;
GRANT SELECT ON ac.source_texts, ac.publications TO ac_loader, ac_migrator, ac_projector;
GRANT INSERT (publication_id, tenant_id, outlet, canonical_url, text_digest, marking, body) ON ac.publications TO ac_loader, ac_migrator;

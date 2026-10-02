-- Архитектура семантики — S3: проекции «досье», «отчёт Проверки», «провенанс» прямо из таблиц среза.
-- Правила:
--   * читатель видит только то, что доминирует его допуск (ac_trust.clearances: уровень + категории на проект);
--     допуск берётся по session_user — передать «чужой» допуск параметром нельзя;
--   * читатель (роль ac_reader) не имеет SELECT ни на одну таблицу: только EXECUTE трёх функций;
--     функции SECURITY DEFINER принадлежат ac_projector (только SELECT), не суперпользователю;
--   * каждое предложение ведёт к утверждениям и фрагментам источников (байты сверяются: verified);
--     «Не выявлено» в отчёте Проверки ведёт к следу поиска;
--   * отчёт завершённой Проверки строится на момент её завершения (статусы, утверждения) — поздние рецензии
--     его не меняют; досье — на момент as_of;
--   * у каждой проекции — digest (sha256 канонического jsonb) для сверки воспроизводимости.
-- Applied after ddl_s1.sql, unicode_s1.sql, keys_s1.sql.

DO $$ BEGIN CREATE ROLE ac_projector NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_reader NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA ac, ac_trust TO ac_projector;
GRANT SELECT ON ALL TABLES IN SCHEMA ac TO ac_projector;
GRANT USAGE ON SCHEMA ac TO ac_reader;

-- ---------------------------------------------------------------- допуски читателей (реестр доверия, append-only)
CREATE TABLE ac_trust.clearances (
  role_name   name NOT NULL,
  project_id  text NOT NULL,
  level       text CHECK (level IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),   -- NULL = допуск отозван
  categories  text[] NOT NULL DEFAULT '{}' CHECK (categories <@ ARRAY['PERSONAL_DATA','COMMERCIAL_SECRET','OFFICIAL_USE']),
  granted_at  timestamptz NOT NULL DEFAULT now(),
  granted_by  name NOT NULL DEFAULT current_user,
  PRIMARY KEY (role_name, project_id, granted_at)
);
CREATE FUNCTION ac_trust.clearance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.granted_at := clock_timestamp();
  NEW.granted_by := current_user;
  RETURN NEW;
END $$;
CREATE TRIGGER clearance_guard BEFORE INSERT ON ac_trust.clearances FOR EACH ROW EXECUTE FUNCTION ac_trust.clearance_guard();
CREATE TRIGGER clearances_no_update BEFORE UPDATE OR DELETE ON ac_trust.clearances FOR EACH ROW EXECUTE FUNCTION ac.forbid();
REVOKE ALL ON ac_trust.clearances FROM PUBLIC, ac_loader, ac_migrator;
GRANT SELECT, INSERT ON ac_trust.clearances TO ac_trust_admin;
GRANT SELECT ON ac_trust.clearances TO ac_projector;

-- ---------------------------------------------------------------- тексты (данные, не код)
CREATE TABLE ac.predicate_texts (predicate_id text PRIMARY KEY, template text NOT NULL);
INSERT INTO ac.predicate_texts VALUES
 ('person.birth_date',          '{S}: дата рождения — {V}.'),
 ('entity.registered_address',  '{S}: адрес регистрации — {V}.'),
 ('corp.director_of',           '{S} — {q:title|руководитель} {O}[ с {valid_from}].'),
 ('corp.founder_of',            '{S} — учредитель {O}[, доля {q:share_bp}].'),
 ('prop.owns',                  '{S} владеет объектом «{O}»[, доля {q:share_bp}][ с {valid_from}].'),
 ('media.negative_mention',     '{S}: негативное упоминание в СМИ — «{V}»[, значимость {q:severity}].'),
 ('court.party_to_case',        '{S}: участник дела № {V}[, {q:role}].'),
 ('tender.participated',        '{S}: участие в закупке «{O}»[, итог — {q:outcome}][, сумма контракта {q:contract_amount_minor}].'),
 ('social.account',             '{S}: аккаунт {scheme} — {V}.'),
 ('wm.mentioned',               '{S}: упоминание — «{V}»[, тональность {q:sentiment}].'),
 ('conflict.party_to',          '{S}: {q:role} конфликта «{O}».'),
 ('conflict.influences',        '{S}: влияние на конфликт «{O}»[, {q:mode}][, канал — {q:channel}].'),
 ('event.part_of_conflict',     '{S}: эпизод конфликта «{O}».'),
 ('rel.affiliated_with',        '{S}: {q:kind} связь с {O}.'),
 ('competitor.competes_with',   '{S}: конкурент — {O}.'),
 ('ts.part_of',                 '{S}: входит в состав «{O}».'),
 ('ts.has_parameter',           '{S}: {q:parameter} — {V}.'),
 ('ts.requires_action',         '{S}: при условии «{q:condition}» требуется {V}.'),
 ('ts.instance_of',             '{S}: экземпляр модели «{O}».'),
 ('wiki.is_a',                  '{S}: относится к понятию «{O}».'),
 ('wiki.part_of',               '{S}: часть понятия «{O}».'),
 ('wiki.property',              '{S}: {q:property} — {V}.'),
 ('corp.branch_of',             '{S} — филиал {O}.'),
 ('person.sole_proprietor',     '{S} зарегистрирован(а) как индивидуальный предприниматель, ОГРНИП {V}.');

CREATE TABLE ac.value_texts (value text PRIMARY KEY, text text NOT NULL);
INSERT INTO ac.value_texts VALUES
 ('LOW', 'низкая'), ('MEDIUM', 'средняя'), ('HIGH', 'высокая'),
 ('PLAINTIFF', 'истец'), ('DEFENDANT', 'ответчик'), ('THIRD_PARTY', 'третье лицо'),
 ('WON', 'победа, контракт заключён'), ('LOST', 'проигрыш'), ('REJECTED', 'заявка отклонена'), ('PENDING', 'итоги не подведены'),
 ('NEGATIVE', 'негативная'), ('NEUTRAL', 'нейтральная'), ('POSITIVE', 'позитивная'),
 ('PARTY', 'сторона'), ('MEDIATOR', 'посредник'), ('AUTHORITY', 'орган власти'), ('SUPPORTER', 'сторонник'),
 ('EXPLICIT', 'явное'), ('IMPLICIT', 'неявное'),
 ('FINANCIAL', 'финансовый'), ('POLITICAL', 'политический'), ('ADMINISTRATIVE', 'административный'), ('MEDIA', 'медийный'), ('LEGAL', 'правовой'),
 ('FAMILY', 'родственная'), ('BUSINESS', 'деловая'),
 ('RUB', 'руб.'), ('USD', 'долл. США'), ('EUR', 'евро'), ('CNY', 'юаней'), ('KZT', 'тенге'), ('UZS', 'сумов'),
 ('telegram', 'Telegram'), ('vk', 'ВКонтакте'), ('ok', 'Одноклассники'), ('youtube', 'YouTube'), ('x', 'X'),
 ('instagram', 'Instagram'), ('facebook', 'Facebook'), ('max', 'MAX'),
 ('max_working_pressure', 'максимальное рабочее давление'), ('max_length', 'максимальная длина'), ('max_mass', 'максимальная масса'),
 ('bar', 'бар'), ('MPa', 'МПа'), ('kPa', 'кПа'), ('m', 'м'), ('t', 'т'), ('kg', 'кг'), ('degC', '°C'), ('rpm', 'об/мин'),
 ('kW', 'кВт'), ('m3/h', 'м³/ч');

CREATE TABLE ac.section_texts (section text PRIMARY KEY, title text NOT NULL, ord int NOT NULL);
INSERT INTO ac.section_texts VALUES
 ('IDENTITY', 'Сведения о личности', 1), ('CORPORATE', 'Корпоративные связи и регистрация', 2), ('PROPERTY', 'Имущество', 3),
 ('COURT', 'Судебные дела', 4), ('TENDERS', 'Государственные закупки', 5), ('NEGATIVE', 'Негативные упоминания', 6),
 ('SOCIAL_MEDIA', 'Социальные сети', 7), ('OTHER', 'Прочие сведения', 8);
GRANT SELECT ON ac.predicate_texts, ac.value_texts, ac.section_texts TO ac_projector;
-- texts are part of the projection version: never edited in place (a new version is a new DDL release) (S23-15)
CREATE TRIGGER predicate_texts_frozen BEFORE UPDATE OR DELETE ON ac.predicate_texts FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER value_texts_frozen BEFORE UPDATE OR DELETE ON ac.value_texts FOR EACH ROW EXECUTE FUNCTION ac.forbid();
CREATE TRIGGER section_texts_frozen BEFORE UPDATE OR DELETE ON ac.section_texts FOR EACH ROW EXECUTE FUNCTION ac.forbid();

-- ---------------------------------------------------------------- помощники рендеринга (INVOKER, вызываются из проекций)
CREATE FUNCTION ac.vt(v text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce((SELECT text FROM ac.value_texts WHERE value = v), v) $$;

-- S22-02: merges are followed only if they happened by time t (a closed Check keeps the names of its closing time)
CREATE FUNCTION ac.resolve_at(eid text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN status = 'MERGED' AND status_changed_at <= t THEN merged_into ELSE entity_id END FROM ac.entities WHERE entity_id = eid $$;

CREATE FUNCTION ac.ent_name(eid text, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce(display_name, entity_id) FROM ac.entities WHERE entity_id = ac.resolve_at(eid, t) $$;

-- S22-01: the reader must dominate both the entity itself and the entity it resolves to at time t
CREATE FUNCTION ac.entity_visible(clr jsonb, eid text, t timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT eid IS NULL OR (ac.dominates(clr, (SELECT marking FROM ac.entities WHERE entity_id = eid))
                         AND ac.dominates(clr, (SELECT marking FROM ac.entities WHERE entity_id = ac.resolve_at(eid, t)))) $$;

CREATE FUNCTION ac.fmt_date(d text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN ac.is_date(d) THEN to_char(d::date, 'DD.MM.YYYY') ELSE d END $$;

CREATE FUNCTION ac.fmt_money(minor bigint, cur text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT replace(to_char(minor / 100, 'FM999,999,999,999,999'), ',', ' ') || ',' || lpad((minor % 100)::text, 2, '0')
         || coalesce(' ' || ac.vt(cur), '') $$;

CREATE FUNCTION ac.lit_text(l jsonb) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE l->>'type' WHEN 'DATE' THEN ac.fmt_date(l->>'value')
                         WHEN 'QUANTITY' THEN replace(l->>'value', '.', ',') || ' ' || ac.vt(l->>'unit')   -- 1,6 МПа
                         ELSE l->>'value' END $$;

-- one placeholder of a template: S, O, V, scheme, valid_from, q:<name>[|default]
CREATE FUNCTION ac.ph(c ac.claims, ph text, t timestamptz) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE name text := split_part(ph, '|', 1); dflt text := nullif(split_part(ph, '|', 2), ''); q jsonb := c.body->'qualifiers'; v text;
BEGIN
  v := CASE
    WHEN name = 'S' THEN ac.ent_name(c.subject, t)
    WHEN name = 'O' THEN ac.ent_name(c.object_entity, t)
    WHEN name = 'V' THEN ac.lit_text(c.body->'object'->'literal')
    WHEN name = 'scheme' THEN ac.vt(c.body->'object'->'literal'->>'scheme')
    WHEN name = 'valid_from' THEN ac.fmt_date(c.body->>'valid_from')
    WHEN name = 'q:share_bp' THEN CASE WHEN (q->>'share_bp') ~ '^[0-9]+$'
                                       THEN trim(to_char((q->>'share_bp')::numeric / 100, 'FM990.99'), '.') || '%' END
    WHEN name = 'q:contract_amount_minor' THEN CASE WHEN (q->>'contract_amount_minor') ~ '^[0-9]{1,15}$'
                                                    THEN ac.fmt_money((q->>'contract_amount_minor')::bigint, q->>'currency') END
    WHEN name LIKE 'q:%' THEN CASE WHEN q ? substr(name, 3) THEN
                                     CASE jsonb_typeof(q->substr(name, 3)) WHEN 'boolean' THEN NULL ELSE ac.vt(q->>substr(name, 3)) END END
  END;
  RETURN coalesce(v, dflt);
END $$;

-- render a template fragment in ONE pass: pieces between placeholders are copied, placeholders are replaced once;
-- strict = true: NULL if any placeholder is empty (optional [segment]); false: empty placeholders become ''
CREATE FUNCTION ac.render_part(c ac.claims, s text, t timestamptz, strict boolean) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE parts text[] := regexp_split_to_array(s, '\{[^}]+\}'); phs text[]; r text := ''; v text; i int;
BEGIN
  phs := ARRAY(SELECT m[1] FROM regexp_matches(s, '\{([^}]+)\}', 'g') m);
  FOR i IN 1 .. array_length(parts, 1) LOOP
    r := r || parts[i];
    IF i <= coalesce(array_length(phs, 1), 0) THEN
      v := ac.ph(c, phs[i], t);
      IF v IS NULL AND strict THEN
        RETURN NULL;
      END IF;
      r := r || coalesce(v, '');
    END IF;
  END LOOP;
  RETURN r;
END $$;

-- render a claim as one sentence: [optional parts] vanish when a placeholder inside is empty
CREATE FUNCTION ac.fact_text(c ac.claims, t timestamptz) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE tpl text; parts text[]; segs text[]; r text := ''; i int;
BEGIN
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

-- evidence of a claim: source, span, the quote re-read from the bytes and verified against quote_sha256
CREATE FUNCTION ac.evidence_json(cid text, t timestamptz) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'source_id', e.source_id, 'source_title', s.body->>'title', 'source_kind', s.body->>'source_kind',
           'span', jsonb_build_array(e.span_start, e.span_end),
           'quote', convert_from(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start), 'UTF8'),
           'verified', encode(sha256(substring(b.bytes FROM e.span_start + 1 FOR e.span_end - e.span_start)), 'hex') = e.quote_sha256,
           'first_observed_at', (SELECT min(o.observed_at) FROM ac.source_observations o
                                 WHERE o.tenant_id = e.tenant_id AND o.source_id = e.source_id AND o.ingested_at <= t))
         ORDER BY e.ord), '[]')
  FROM ac.claim_evidence e
  JOIN ac.sources s ON s.tenant_id = e.tenant_id AND s.source_id = e.source_id
  JOIN ac.source_bytes b ON b.tenant_id = e.tenant_id AND b.source_id = e.source_id
  WHERE e.claim_id = cid $$;

CREATE FUNCTION ac.status_rank(s text) RETURNS int LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE s WHEN 'ACCEPTED' THEN 3 WHEN 'ASSERTED' THEN 2 WHEN 'DISPUTED' THEN 1 ELSE 0 END $$;

-- least upper bound of markings (for the marking of a projection)
CREATE FUNCTION ac.marking_lub(ms jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object(
    'level', (SELECT m->>'level' FROM jsonb_array_elements(ms) m ORDER BY ac.level_rank(m->>'level') DESC LIMIT 1),
    'categories', coalesce((SELECT jsonb_agg(DISTINCT c ORDER BY c) FROM jsonb_array_elements(ms) m, jsonb_array_elements_text(m->'categories') c), '[]')) $$;

CREATE FUNCTION ac.with_digest(j jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT j || jsonb_build_object('digest', 'sha256:' || encode(sha256(convert_to(j::text, 'UTF8')), 'hex')) $$;

-- ---------------------------------------------------------------- допуск вызывающего
CREATE FUNCTION ac.my_clearance(p text) RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN level IS NOT NULL THEN jsonb_build_object('level', level, 'categories', to_jsonb(categories)) END
  FROM ac_trust.clearances WHERE role_name = session_user AND project_id = p ORDER BY granted_at DESC LIMIT 1 $$;

CREATE FUNCTION ac.require_clearance(p text, need jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE clr jsonb := ac.my_clearance(p);
BEGIN
  IF clr IS NULL OR NOT ac.dominates(clr, need) THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN clr;
END $$;

-- ---------------------------------------------------------------- фрагменты фактов
-- facts of a set of visible claims (already filtered), evaluated at time t: one fact per sentence; a predicate of
-- cardinality ONE seen from its subject gives ONE fact: the best-supported value and an explanation of the others
-- cardinality of a predicate OUTSIDE the registry of the core (a tenant predicate «x.…», D27.1): the hook is replaced
-- by ddl_s9.sql with the reading of the tenant's schema at time t; without that slice no such claim can exist
CREATE FUNCTION ac.tenant_cardinality(c ac.claims, t timestamptz) RETURNS text LANGUAGE sql STABLE AS $$ SELECT 'MANY'::text $$;

CREATE FUNCTION ac.facts_json(cids text[], t timestamptz, focus text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE r jsonb := '[]'; g record; alt text;
BEGIN
  FOR g IN
    WITH cl AS (
      SELECT c.*, ac.status_at(c.claim_id, t) AS st, ac.fact_text(c, t) AS txt, coalesce(pr.cardinality, ac.tenant_cardinality(c, t)) AS cardinality,
             -- support key: the publication of the cited source (S5: three fetches of one article are one), else the source
             (SELECT min(ac.support_key(e.tenant_id, e.source_id, t)) FROM ac.claim_evidence e WHERE e.claim_id = c.claim_id) AS src,
             (ac.resolve_at(c.subject, t) = focus) AS outgoing
      FROM ac.claims c LEFT JOIN ac.predicates pr ON pr.predicate_id = c.predicate WHERE c.claim_id = ANY (cids)),
    grp AS (
      SELECT CASE WHEN cardinality = 'ONE' AND outgoing THEN 'ONE:' || predicate ELSE 'TXT:' || txt END AS gkey, *
      FROM cl),
    val AS (   -- values inside a group, best first
      SELECT gkey, txt, max(ac.status_rank(st)) AS srank, count(DISTINCT src) AS n, min(recorded_at) AS first_rec,
             min(body->>'valid_from') AS vf, jsonb_agg(jsonb_build_object('claim_id', claim_id, 'status', st, 'recorded_at', recorded_at,
                                                     'evidence', ac.evidence_json(claim_id, t)) ORDER BY claim_id) AS claims,
             -- support = distinct publications / sources, not claims: re-runs and re-fetches add nothing (S4R-08, D21)
             row_number() OVER (PARTITION BY gkey ORDER BY max(ac.status_rank(st)) DESC, count(DISTINCT src) DESC, min(recorded_at), txt) AS pos
      FROM grp GROUP BY gkey, txt)
    SELECT gkey, (array_agg(txt ORDER BY pos))[1] AS main_txt, (array_agg(claims ORDER BY pos))[1] AS main_claims,
           min(vf) AS vf, jsonb_agg(jsonb_build_object('txt', txt, 'claims', claims)) FILTER (WHERE pos > 1) AS others
    FROM val GROUP BY gkey HAVING max(srank) >= 2 ORDER BY min(vf) NULLS FIRST, 2
  LOOP
    alt := NULL;
    IF g.others IS NOT NULL THEN
      SELECT 'Расхождение источников: ' || string_agg(format('в источнике «%s» указано: %s%s', ev->>'source_title',
                                                             rtrim(regexp_replace(o->>'txt', '^[^:]*: ', ''), '.'),
                                                             CASE oc->>'status' WHEN 'DISPUTED' THEN ' (сведения оспорены)' ELSE '' END), '; ')
             || '. Приведено значение по '
             || (SELECT string_agg(DISTINCT format('источнику «%s»', e2->>'source_title'), ', ')
                 FROM jsonb_array_elements(g.main_claims) mc, jsonb_array_elements(mc->'evidence') e2)
             || CASE WHEN g.main_claims->0->>'status' = 'ACCEPTED' THEN ', подтверждённому при проверке.' ELSE '.' END
        INTO alt
      FROM jsonb_array_elements(g.others) o, jsonb_array_elements(o->'claims') oc, jsonb_array_elements(oc->'evidence') ev;
    END IF;
    r := r || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
           'text', g.main_txt, 'claims', g.main_claims, 'note', alt,
           'other_claims', (SELECT jsonb_agg(c) FROM jsonb_array_elements(g.others) o, jsonb_array_elements(o->'claims') c))));
  END LOOP;
  RETURN r;
END $$;

-- ---------------------------------------------------------------- ДОСЬЕ
CREATE FUNCTION ac.dossier(p text, eid text, as_of timestamptz DEFAULT now()) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE e ac.entities; clr jsonb; focus text; cids text[]; secs jsonb := '[]'; s record; f jsonb; res jsonb; marks jsonb;
BEGIN
  as_of := least(as_of, clock_timestamp());         -- the future is not known yet (S23-07)
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
  WHERE c.project_id = p AND c.recorded_at <= as_of
    AND (ac.resolve_at(c.subject, as_of) = focus OR ac.resolve_at(c.object_entity, as_of) = focus)
    AND ac.status_at(c.claim_id, as_of) NOT IN ('REFUTED', 'WITHDRAWN')
    AND ac.dominates(clr, c.marking)
    AND ac.entity_visible(clr, c.subject, as_of) AND ac.entity_visible(clr, c.object_entity, as_of);
  FOR s IN
    SELECT st.section, st.title, st.ord FROM ac.section_texts st
    WHERE (e.entity_type IN ('PERSON', 'ORGANIZATION') AND st.section <> 'OTHER' AND (st.section <> 'IDENTITY' OR e.entity_type = 'PERSON'))
       OR EXISTS (SELECT 1 FROM ac.claims c LEFT JOIN ac.predicates pr ON pr.predicate_id = c.predicate
                  WHERE c.claim_id = ANY (cids)
                    AND coalesce(pr.dimensions[1], CASE WHEN c.predicate = 'person.birth_date' THEN 'IDENTITY' ELSE 'OTHER' END) = st.section)
    ORDER BY st.ord
  LOOP
    f := ac.facts_json(ARRAY(SELECT c.claim_id FROM ac.claims c LEFT JOIN ac.predicates pr ON pr.predicate_id = c.predicate
                             WHERE c.claim_id = ANY (cids)
                               AND coalesce(pr.dimensions[1], CASE WHEN c.predicate = 'person.birth_date' THEN 'IDENTITY' ELSE 'OTHER' END) = s.section),
                       as_of, focus);
    secs := secs || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object('section', s.section, 'title', s.title,
               'facts', CASE WHEN jsonb_array_length(f) > 0 THEN f END,
               'empty', CASE WHEN jsonb_array_length(f) = 0 THEN 'Сведений нет.' END)));
  END LOOP;
  SELECT jsonb_agg(m) INTO marks FROM (SELECT e.marking AS m UNION ALL SELECT c.marking FROM ac.claims c WHERE c.claim_id = ANY (cids)) x;
  res := jsonb_build_object(
    'projection', 'dossier/0.1', 'project_id', p, 'entity_id', focus, 'display_name', coalesce(e.display_name, e.entity_id),
    'entity_type', e.entity_type, 'as_of', as_of, 'marking', ac.marking_lub(marks),
    'provisional', CASE WHEN as_of > clock_timestamp() - interval '5 minutes' THEN true END,
    'also_known_as', (SELECT jsonb_agg(jsonb_build_object('entity_id', m.entity_id, 'display_name', m.display_name) ORDER BY m.entity_id)
                      FROM ac.entities m WHERE m.merged_into = focus AND m.status_changed_at <= as_of AND ac.dominates(clr, m.marking)),
    'sections', secs,
    'sources', (SELECT coalesce(jsonb_agg(DISTINCT jsonb_build_object('source_id', s2.source_id, 'title', s2.body->>'title',
                                                                   'kind', s2.body->>'source_kind')), '[]')
                FROM ac.claim_evidence ce JOIN ac.sources s2 ON s2.tenant_id = ce.tenant_id AND s2.source_id = ce.source_id
                WHERE ce.claim_id = ANY (cids)));
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;

-- ---------------------------------------------------------------- ОТЧЁТ ПРОВЕРКИ
CREATE FUNCTION ac.check_report(kid text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE k ac.checks; t timestamptz; dims jsonb := '[]'; d record; f jsonb; srch jsonb; res jsonb; pv ac.checks; clr jsonb;
BEGIN
  SELECT * INTO k FROM ac.checks WHERE check_id = kid;
  IF k.check_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(k.project_id, k.marking);
  t := coalesce(k.completed_at, k.cancelled_at, now());          -- a closed Check is read as of its closing
  FOR d IN SELECT dim, n FROM unnest((SELECT dimensions FROM ac.check_profiles WHERE profile = k.profile)) WITH ORDINALITY u(dim, n) ORDER BY n LOOP
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
             'n', s.n, 'performed_at', s.performed_at, 'scope', s.body->>'search_scope', 'query', s.body->>'query',
             'result_source', CASE WHEN s.result_source_id IS NOT NULL THEN jsonb_build_object('source_id', s.result_source_id,
                                   'title', (SELECT body->>'title' FROM ac.sources WHERE tenant_id = s.tenant_id AND source_id = s.result_source_id)) END))
             ORDER BY s.n), '[]')
      INTO srch FROM ac.check_searches s WHERE s.check_id = kid AND s.dimension = d.dim;
    f := ac.facts_json(ARRAY(SELECT claim_id FROM ac.check_finding_claims WHERE check_id = kid AND dimension = d.dim
                             AND (k.status = 'COMPLETED' OR ac.status_at(claim_id, t) NOT IN ('REFUTED', 'WITHDRAWN'))), t, k.subject_entity_id);
    dims := dims || jsonb_build_array(jsonb_strip_nulls(
      (SELECT jsonb_build_object('dimension', d.dim, 'title', coalesce(st.title, d.dim), 'result', cf.result,
                                 'risk', CASE WHEN k.status = 'COMPLETED' THEN cf.risk END,
                                 'facts', CASE WHEN jsonb_array_length(f) > 0 THEN f END,
                                 'text', CASE WHEN k.status = 'COMPLETED' AND cf.result = 'NOT_FOUND' THEN 'Не выявлено.'
                                              WHEN k.status = 'CANCELLED' THEN 'Проверка отменена, вывод по направлению не сделан.'
                                              WHEN cf.result = 'NOT_FOUND' AND jsonb_array_length(srch) > 0 THEN 'По выполненному поиску не выявлено; Проверка не завершена.'
                                              WHEN cf.result = 'NOT_FOUND' THEN 'Поиск по этому направлению не выполнен.'
                                              WHEN cf.result IS NULL THEN 'Проверка по этому направлению не завершена.' END,
                                 'searches', srch)
       FROM (SELECT 1) one LEFT JOIN ac.check_findings cf ON cf.check_id = kid AND cf.dimension = d.dim
       LEFT JOIN ac.section_texts st ON st.section = d.dim)));
  END LOOP;
  SELECT * INTO pv FROM ac.checks WHERE check_id = k.previous_check_id;
  res := jsonb_build_object(
    'projection', 'check_report/0.1', 'check_id', kid, 'project_id', k.project_id,
    'subject', jsonb_build_object('entity_id', k.subject_entity_id, 'display_name', ac.ent_name(k.subject_entity_id, t)),
    'draft', CASE WHEN k.status <> 'COMPLETED' THEN true END,
    'profile', k.profile, 'status', k.status, 'requested_at', k.requested_at, 'completed_at', k.completed_at,
    'cancelled_at', k.cancelled_at, 'as_of', k.as_of, 'evaluated_at', t, 'overall_risk', k.overall_risk, 'marking', k.marking,
    'previous', CASE WHEN pv.check_id IS NOT NULL AND ac.dominates(clr, pv.marking) THEN jsonb_build_object('check_id', pv.check_id, 'as_of', pv.as_of,
                     'overall_risk', pv.overall_risk, 'profile', pv.profile) END,
    'dimensions', dims);
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;

-- ---------------------------------------------------------------- ПРОВЕНАНС одного утверждения
CREATE FUNCTION ac.provenance(cid text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ac, ac_trust, pg_temp SET TimeZone = 'UTC' SET lc_numeric = 'C' AS $$
DECLARE c ac.claims; res jsonb; clr jsonb;
BEGIN
  SELECT * INTO c FROM ac.claims WHERE claim_id = cid;
  IF c.claim_id IS NULL THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  clr := ac.require_clearance(c.project_id, c.marking);
  IF NOT (ac.entity_visible(clr, c.subject, now()) AND ac.entity_visible(clr, c.object_entity, now())) THEN
    RAISE EXCEPTION 'ACCESS_DENIED: нет допуска' USING ERRCODE = 'insufficient_privilege';
  END IF;
  res := jsonb_build_object(
    'projection', 'provenance/0.1', 'claim_id', cid, 'project_id', c.project_id, 'text', ac.fact_text(c, now()),
    'recorded_at', c.recorded_at, 'ingested_at', c.ingested_at, 'produced_by', c.body->'produced_by', 'marking', c.marking,
    'reviews', (SELECT coalesce(jsonb_agg(jsonb_build_object('status', status, 'reviewer', reviewer, 'reviewed_at', reviewed_at,
                                                            'recorded_at', recorded_at) ORDER BY recorded_at), '[]')
                FROM ac.claim_reviews WHERE claim_id = cid),
    'status_now', ac.status_at(cid, now()),
    'evidence', ac.evidence_json(cid, now()),
    'receipt', (SELECT jsonb_build_object('receipt_id', r.receipt_id, 'service_id', r.service_id, 'key_id', r.key_id,
                                          'issued_at', r.issued_at, 'artifact_digest', r.body->>'artifact_digest')
                FROM ac.receipt_claims rc JOIN ac.artifact_receipts r USING (receipt_id) WHERE rc.claim_id = cid));
  RETURN ac.with_digest(jsonb_strip_nulls(res));
END $$;

-- ---------------------------------------------------------------- права
ALTER FUNCTION ac.dossier(text, text, timestamptz) OWNER TO ac_projector;
ALTER FUNCTION ac.check_report(text) OWNER TO ac_projector;
ALTER FUNCTION ac.provenance(text) OWNER TO ac_projector;
REVOKE EXECUTE ON FUNCTION ac.dossier(text, text, timestamptz), ac.check_report(text), ac.provenance(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ac.dossier(text, text, timestamptz), ac.check_report(text), ac.provenance(text) TO ac_reader;

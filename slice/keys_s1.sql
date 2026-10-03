-- Identity keys computed BY THE DATABASE from Entity.identity (RS-01): a port of validator.py
-- base_key / norm / id_norm / tag_norm / tag_compact / cadastral_norm / entity_identifiers and the check digits.
-- Character tables (width, invisible, casefold, dashes, quotes, whitespace, look-alikes, accents) are GENERATED from
-- the validator in unicode_s1.sql (gen_unicode_s1.py). Parity is tested by keys_parity_s1.py.
-- Applied after ddl_s1.sql and unicode_s1.sql.

CREATE FUNCTION ac.base_key(s text, fold boolean DEFAULT true) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT ac.punct_space(CASE WHEN fold THEN ac.casefold(x) ELSE x END)
  FROM (SELECT ac.drop_ignorable(ac.width_fold(normalize(s, NFC))) AS x) t $$;

-- skeleton: width + look-alikes first (before NFKC: lunate sigma would become Σ), [NFKC], accents dropped,
-- look-alikes again, base_key, look-alikes after casefold, ё -> е  (validator.norm)
CREATE FUNCTION ac.skel(s text, nfkc boolean DEFAULT true) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT replace(ac.confusables_low(ac.base_key(ac.confusables(ac.drop_marks(CASE WHEN nfkc THEN normalize(x, NFKC) ELSE x END)))),
                 chr(1105), chr(1077))
  FROM (SELECT ac.confusables(ac.width_fold(normalize(s, NFC))) AS x) t $$;

CREATE FUNCTION ac.id_norm(v text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT regexp_replace(ac.base_key(normalize(v, NFKC)), '[ ./_-]', '', 'g') $$;

-- equipment tag (RS-14): separators between a letter and a digit are ignored, between two digits or two
-- letters they are a group boundary '-'  (validator.tag_norm)
CREATE FUNCTION ac.tag_norm(v text) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE s text := ac.base_key(v); r text := ''; i int := 1; j int; n int := length(s);
BEGIN
  WHILE i <= n LOOP
    IF strpos(' -_./', substr(s, i, 1)) > 0 THEN
      j := i;
      WHILE j <= n AND strpos(' -_./', substr(s, j, 1)) > 0 LOOP
        j := j + 1;
      END LOOP;
      IF r <> '' AND j <= n AND (right(r, 1) ~ '^[0-9]$') = (substr(s, j, 1) ~ '^[0-9]$') THEN
        r := r || '-';
      END IF;
      i := j;
    ELSE
      r := r || substr(s, i, 1);
      i := i + 1;
    END IF;
  END LOOP;
  RETURN r;
END $$;

-- soft key of a tag: every separator dropped  (validator.tag_compact)
CREATE FUNCTION ac.tag_compact(v text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT regexp_replace(v, '[ ./_-]', '', 'g') $$;

CREATE FUNCTION ac.cadastral_norm(v text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT string_agg(p::numeric::text, ':' ORDER BY n) FROM unnest(string_to_array(v, ':')) WITH ORDINALITY u(p, n) $$;

-- check digits (the validator's inn_ok / ogrn_ok / ogrnip_ok / imo_ok)
CREATE FUNCTION ac.ctl(v text, coef int[]) RETURNS int IMMUTABLE LANGUAGE sql AS $$
  SELECT (sum(coef[i] * substr(v, i, 1)::int) % 11) % 10 FROM generate_series(1, array_length(coef, 1)) i $$;
CREATE FUNCTION ac.inn_ok(v text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT CASE WHEN v !~ '^[0-9]+$' THEN false
              WHEN length(v) = 10 THEN ac.ctl(v, '{2,4,10,3,5,9,4,6,8}') = substr(v, 10, 1)::int
              WHEN length(v) = 12 THEN ac.ctl(v, '{7,2,4,10,3,5,9,4,6,8}') = substr(v, 11, 1)::int
                                       AND ac.ctl(v, '{3,7,2,4,10,3,5,9,4,6,8}') = substr(v, 12, 1)::int
              ELSE false END $$;
CREATE FUNCTION ac.ogrn_ok(v text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT v ~ '^[0-9]{13}$' AND (substr(v, 1, 12)::numeric % 11) % 10 = substr(v, 13, 1)::int $$;
CREATE FUNCTION ac.ogrnip_ok(v text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT v ~ '^[0-9]{15}$' AND (substr(v, 1, 14)::numeric % 13) % 10 = substr(v, 15, 1)::int $$;
CREATE FUNCTION ac.imo_ok(v text) RETURNS boolean IMMUTABLE LANGUAGE sql AS $$
  SELECT v ~ '^[0-9]{7}$' AND (SELECT sum(substr(v, i, 1)::int * (8 - i)) FROM generate_series(1, 6) i) % 10 = substr(v, 7, 1)::int $$;

-- (scheme, value, strength, qual) rows for one entity, STRONG and WEAK first, SOFT (skeleton, 'skel:' scheme) last;
-- raises IDENTIFIER_CHECKSUM_INVALID / ENTITY_IDENTITY_INSUFFICIENT  (validator.entity_identifiers)
CREATE FUNCTION ac.identity_keys(t text, i jsonb) RETURNS TABLE (scheme text, value text, strength text, qual text)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE fio text; f jsonb; n int := 0; need text; ns text;
BEGIN
  -- S11R4-01: keys are built with NFKC and casefold; for a code point unassigned in the validator's Unicode version they
  -- differ between Unicode versions — such an identity is refused as a whole (any string field)
  IF EXISTS (SELECT 1 FROM jsonb_path_query(i, 'strict $.** ? (@.type() == "string")') v WHERE ac.has_unassigned(v #>> '{}')) THEN
    PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'identity с символом, не назначенным в Юникоде валидатора');
  END IF;
  IF t = 'PERSON' THEN
    fio := ac.skel(concat_ws(' ', i->>'surname', i->>'given_name', nullif(i->>'patronymic', '')));
    IF i ? 'inn' THEN
      IF NOT ac.inn_ok(i->>'inn') OR length(i->>'inn') <> 12 THEN PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'ru.inn физлица'); END IF;
      scheme := 'ru.inn'; value := i->>'inn'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
    END IF;
    IF i ? 'ogrnip' THEN
      IF NOT ac.ogrnip_ok(i->>'ogrnip') THEN PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'ru.ogrnip'); END IF;
      scheme := 'ru.ogrnip'; value := i->>'ogrnip'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
    END IF;
    IF i ? 'birth_date' THEN
      scheme := 'person.fio_dob'; value := fio || '|' || (i->>'birth_date'); strength := 'WEAK'; qual := i->>'disambiguator'; RETURN NEXT; n := n + 1;
    END IF;
    IF n = 0 THEN
      IF NOT i ? 'disambiguator' THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'PERSON без ИНН, ОГРНИП, даты рождения и disambiguator'); END IF;
      scheme := 'person.fio_disamb'; value := fio || '|' || (i->>'disambiguator'); strength := 'STRONG'; qual := NULL; RETURN NEXT;
    END IF;
  ELSIF t = 'ORGANIZATION' THEN
    IF coalesce((i->>'informal')::boolean, false) THEN
      IF NOT i ? 'disambiguator' OR i ?| array['ogrn', 'inn', 'kpp', 'legal_form'] THEN
        PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'неформальная организация: только название и disambiguator');
      END IF;
      scheme := 'org.informal'; value := ac.skel(i->>'name') || '|' || (i->>'disambiguator'); strength := 'STRONG'; qual := NULL; RETURN NEXT;
      RETURN;
    END IF;
    IF i ? 'inn' AND NOT ac.inn_ok(i->>'inn') THEN PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'ИНН юрлица'); END IF;
    IF i ? 'ogrn' AND NOT ac.ogrn_ok(i->>'ogrn') THEN PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'ОГРН'); END IF;
    IF coalesce(i->>'legal_form', 'LEGAL_ENTITY') = 'BRANCH' THEN
      IF NOT (i ? 'inn' AND i ? 'kpp') OR i ? 'ogrn' THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'филиал: ИНН и КПП, без ОГРН'); END IF;
      scheme := 'ru.inn_kpp'; value := (i->>'inn') || '|' || (i->>'kpp'); strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
    ELSE
      IF i ? 'ogrn' THEN scheme := 'ru.ogrn'; value := i->>'ogrn'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1; END IF;
      IF i ? 'inn' THEN scheme := 'ru.inn'; value := i->>'inn'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1; END IF;
      IF i->>'jurisdiction' = 'RU' AND NOT i ?| array['ogrn', 'inn'] THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'организация РФ без ОГРН и ИНН'); END IF;
    END IF;
    FOR f IN SELECT * FROM jsonb_array_elements(coalesce(i->'foreign_ids', '[]')) LOOP
      scheme := f->>'scheme'; value := ac.id_norm(f->>'value'); strength := 'STRONG'; qual := NULL;
      IF value = '' THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'иностранный идентификатор без единого значащего знака'); END IF;   -- S11R2-09
      RETURN NEXT; n := n + 1;
    END LOOP;
    IF n = 0 AND i->>'jurisdiction' <> 'RU' THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'иностранная организация без идентификатора'); END IF;
  ELSIF t = 'REAL_ESTATE' THEN
    scheme := 'ru.cadastral'; value := ac.cadastral_norm(i->>'cadastral_number'); strength := 'STRONG'; qual := NULL; RETURN NEXT;
  ELSIF t = 'MOVABLE_PROPERTY' THEN
    need := CASE i->>'subtype' WHEN 'VEHICLE' THEN 'vin' WHEN 'VESSEL' THEN 'imo' END;
    IF i ? 'vin' THEN scheme := 'vin'; value := i->>'vin'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1; END IF;
    IF i ? 'imo' THEN
      IF NOT ac.imo_ok(i->>'imo') THEN PERFORM ac.fail('IDENTIFIER_CHECKSUM_INVALID', 'IMO'); END IF;
      scheme := 'imo'; value := i->>'imo'; strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
    END IF;
    IF i ? 'registration' THEN
      scheme := i->'registration'->>'scheme'; value := ac.id_norm(i->'registration'->>'value'); strength := 'STRONG'; qual := NULL;
      IF value = '' THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'регистрационный номер без единого значащего знака'); END IF;   -- S11R2-09
      RETURN NEXT; n := n + 1;
    END IF;
    IF (need IS NOT NULL AND NOT i ? need) OR n = 0 THEN PERFORM ac.fail('ENTITY_IDENTITY_INSUFFICIENT', 'нет обязательного идентификатора имущества'); END IF;
  ELSIF t = 'EVENT' THEN
    scheme := 'event'; value := ac.skel(i->>'title') || '|' || (i->>'date'); strength := 'WEAK';
    qual := CASE WHEN i ? 'place' THEN ac.skel(i->>'place') END; RETURN NEXT;
  ELSIF t = 'CONFLICT' THEN
    scheme := 'conflict'; value := ac.skel(i->>'title') || '|' || (i->>'started_on'); strength := 'WEAK';
    qual := CASE WHEN i ? 'place' THEN ac.skel(i->>'place') END; RETURN NEXT;
  ELSIF t = 'EQUIPMENT' THEN
    scheme := 'equipment'; value := (i->>'site_id') || '|' || ac.tag_norm(i->>'tag'); strength := 'STRONG'; qual := NULL; RETURN NEXT;
    scheme := 'skel:equipment'; value := (i->>'site_id') || '|' || ac.tag_compact(ac.skel(i->>'tag')); strength := 'SOFT'; RETURN NEXT;
  ELSIF t = 'EQUIPMENT_MODEL' THEN
    scheme := 'equipment_model'; value := ac.skel(i->>'manufacturer', false) || '|' || ac.skel(i->>'model', false);
    strength := 'STRONG'; qual := NULL; RETURN NEXT;
  ELSIF t = 'CONCEPT' THEN
    ns := coalesce(i->>'namespace', '') || '|' || (i->>'lang') || '|';
    scheme := 'concept'; value := ns || ac.base_key(i->>'label'); strength := 'WEAK'; qual := i->>'disambiguator'; RETURN NEXT;
    scheme := 'skel:concept'; value := ns || ac.skel(i->>'label'); strength := 'SOFT'; qual := NULL; RETURN NEXT;
  ELSIF t = 'THING' THEN            -- the tenth root (cycle 9): the same identity rules as a concept
    ns := coalesce(i->>'namespace', '') || '|' || (i->>'lang') || '|';
    scheme := 'thing'; value := ns || ac.base_key(i->>'label'); strength := 'WEAK'; qual := i->>'disambiguator'; RETURN NEXT;
    scheme := 'skel:thing'; value := ns || ac.skel(i->>'label'); strength := 'SOFT'; qual := NULL; RETURN NEXT;
  END IF;
END $$;

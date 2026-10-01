-- Identity keys computed BY THE DATABASE from Entity.identity (RS-01): a port of validator.py
-- base_key / norm / id_norm / tag_norm / cadastral_norm / entity_identifiers and the check-digit functions.
-- Parity with the normative Python code is tested by slice/keys_parity_s1.py on every entity of every vector
-- and on a corpus of hostile strings. Applied after ddl_s1.sql.

CREATE FUNCTION ac.u(cp int) RETURNS text IMMUTABLE LANGUAGE sql AS $$ SELECT chr(cp) $$;

-- fullwidth ASCII FF01-FF5E -> 0021-007E, ideographic space -> space  (width folding, <wide>/<narrow>)
CREATE FUNCTION ac.width_fold(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT translate(s,
    (SELECT string_agg(chr(c), '' ORDER BY c) FROM generate_series(65281, 65374) c) || chr(12288),
    (SELECT string_agg(chr(c - 65248), '' ORDER BY c) FROM generate_series(65281, 65374) c) || ' ') $$;

-- Default_Ignorable_Code_Point + general category Cf (the validator drops both)
CREATE FUNCTION ac.drop_ignorable(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT regexp_replace(s,
    '[\u00AD\u034F\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u115F\u1160\u17B4\u17B5\u180B-\u180F'
    '\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFB'
    '\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0000-\U000E0FFF]', '', 'g') $$;

-- str.casefold() for the scripts that matter here: lower() + the few non-trivial folds
CREATE FUNCTION ac.casefold(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT replace(replace(replace(lower(s), 'ß', 'ss'), 'ẞ', 'ss'), 'ς', 'σ') $$;

-- dashes (category Pd) and U+2212 -> '-'; quotes and Pi/Pf punctuation removed; whitespace collapsed
CREATE FUNCTION ac.punct_space(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT btrim(regexp_replace(
           regexp_replace(
             regexp_replace(s, '[֊־᐀᠆‐-―⸗⸚⸺⸻⹀⹝〜〰゠︱︲﹘﹣\uFF0D−\U00010EAD]', '-', 'g'),
             '["''«»„“”‟‚‘’‛‹›`⸂-⸅⸉⸊⸌⸍⸜⸝⸠⸡]', '', 'g'),
           '[\u0009-\u000D\u001C- \u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+', ' ', 'g'), ' ') $$;

CREATE FUNCTION ac.base_key(s text, fold boolean DEFAULT true) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT ac.punct_space(CASE WHEN fold THEN ac.casefold(x) ELSE x END)
  FROM (SELECT ac.drop_ignorable(ac.width_fold(normalize(s, NFC))) AS x) t $$;

-- look-alikes (Latin, Greek) -> Cyrillic: the same table as validator._CONFUSABLE
CREATE FUNCTION ac.confusables(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT translate(s, 'AaBCcEeHKkMOoPpTXxYyΑΒΕΖΗΙΚΜΝΟΡΤΥΧαειοκρτυχ',
                      'АаВСсЕеНКкМОоРрТХхУуАВЕЗНІКМНОРТУХаеіокртух') $$;

CREATE FUNCTION ac.skel(s text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT replace(ac.base_key(ac.confusables(normalize(s, NFKC))), 'ё', 'е') $$;

CREATE FUNCTION ac.id_norm(v text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT regexp_replace(ac.base_key(normalize(v, NFKC)), '[ \-_./]', '', 'g') $$;

CREATE FUNCTION ac.tag_norm(v text) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT regexp_replace(ac.base_key(v), '[ \-_./]', '', 'g') $$;

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

-- (scheme, value, strength, qual) rows for one entity; raises IDENTIFIER_CHECKSUM_INVALID / ENTITY_IDENTITY_INSUFFICIENT
CREATE FUNCTION ac.identity_keys(t text, i jsonb) RETURNS TABLE (scheme text, value text, strength text, qual text)
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE fio text; f jsonb; n int := 0; need text;
BEGIN
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
      scheme := f->>'scheme'; value := ac.id_norm(f->>'value'); strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
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
      scheme := i->'registration'->>'scheme'; value := ac.id_norm(i->'registration'->>'value'); strength := 'STRONG'; qual := NULL; RETURN NEXT; n := n + 1;
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
  ELSIF t = 'EQUIPMENT_MODEL' THEN
    scheme := 'equipment_model'; value := ac.skel(i->>'manufacturer') || '|' || ac.skel(i->>'model'); strength := 'STRONG'; qual := NULL; RETURN NEXT;
  ELSIF t = 'CONCEPT' THEN
    scheme := 'concept'; value := coalesce(i->>'namespace', '') || '|' || (i->>'lang') || '|' || ac.base_key(i->>'label');
    strength := 'WEAK'; qual := i->>'disambiguator'; RETURN NEXT;
  END IF;
END $$;

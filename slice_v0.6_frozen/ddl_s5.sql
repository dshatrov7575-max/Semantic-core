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
  SELECT btrim(regexp_replace(normalize(ac.drop_ignorable(t), NFC), '[\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000]+', ' ', 'g'), ' ') $$;

CREATE FUNCTION ac.text_digest(b bytea) RETURNS text IMMUTABLE LANGUAGE plpgsql AS $$
DECLARE t text;
BEGIN
  BEGIN
    t := convert_from(b, 'UTF8');
  EXCEPTION WHEN others THEN
    RETURN NULL;
  END;
  IF t ~ '[\u0378-\u0379\u0380-\u0383\u038B\u038D\u03A2\u0530\u0557-\u0558\u058B-\u058C\u0590\u05C8-\u05CF\u05EB-\u05EE\u05F5-\u05FF\u070E\u074B-\u074C\u07B2-\u07BF\u07FB-\u07FC\u082E-\u082F\u083F\u085C-\u085D\u085F\u086B-\u086F\u088F\u0892-\u0897\u0984\u098D-\u098E\u0991-\u0992\u09A9\u09B1\u09B3-\u09B5\u09BA-\u09BB\u09C5-\u09C6\u09C9-\u09CA\u09CF-\u09D6\u09D8-\u09DB\u09DE\u09E4-\u09E5\u09FF-\u0A00\u0A04\u0A0B-\u0A0E\u0A11-\u0A12\u0A29\u0A31\u0A34\u0A37\u0A3A-\u0A3B\u0A3D\u0A43-\u0A46\u0A49-\u0A4A\u0A4E-\u0A50\u0A52-\u0A58\u0A5D\u0A5F-\u0A65\u0A77-\u0A80\u0A84\u0A8E\u0A92\u0AA9\u0AB1\u0AB4\u0ABA-\u0ABB\u0AC6\u0ACA\u0ACE-\u0ACF\u0AD1-\u0ADF\u0AE4-\u0AE5\u0AF2-\u0AF8\u0B00\u0B04\u0B0D-\u0B0E\u0B11-\u0B12\u0B29\u0B31\u0B34\u0B3A-\u0B3B\u0B45-\u0B46\u0B49-\u0B4A\u0B4E-\u0B54\u0B58-\u0B5B\u0B5E\u0B64-\u0B65\u0B78-\u0B81\u0B84\u0B8B-\u0B8D\u0B91\u0B96-\u0B98\u0B9B\u0B9D\u0BA0-\u0BA2\u0BA5-\u0BA7\u0BAB-\u0BAD\u0BBA-\u0BBD\u0BC3-\u0BC5\u0BC9\u0BCE-\u0BCF\u0BD1-\u0BD6\u0BD8-\u0BE5\u0BFB-\u0BFF\u0C0D\u0C11\u0C29\u0C3A-\u0C3B\u0C45\u0C49\u0C4E-\u0C54\u0C57\u0C5B-\u0C5C\u0C5E-\u0C5F\u0C64-\u0C65\u0C70-\u0C76\u0C8D\u0C91\u0CA9\u0CB4\u0CBA-\u0CBB\u0CC5\u0CC9\u0CCE-\u0CD4\u0CD7-\u0CDC\u0CDF\u0CE4-\u0CE5\u0CF0\u0CF3-\u0CFF\u0D0D\u0D11\u0D45\u0D49\u0D50-\u0D53\u0D64-\u0D65\u0D80\u0D84\u0D97-\u0D99\u0DB2\u0DBC\u0DBE-\u0DBF\u0DC7-\u0DC9\u0DCB-\u0DCE\u0DD5\u0DD7\u0DE0-\u0DE5\u0DF0-\u0DF1\u0DF5-\u0E00\u0E3B-\u0E3E\u0E5C-\u0E80\u0E83\u0E85\u0E8B\u0EA4\u0EA6\u0EBE-\u0EBF\u0EC5\u0EC7\u0ECE-\u0ECF\u0EDA-\u0EDB\u0EE0-\u0EFF\u0F48\u0F6D-\u0F70\u0F98\u0FBD\u0FCD\u0FDB-\u0FFF\u10C6\u10C8-\u10CC\u10CE-\u10CF\u1249\u124E-\u124F\u1257\u1259\u125E-\u125F\u1289\u128E-\u128F\u12B1\u12B6-\u12B7\u12BF\u12C1\u12C6-\u12C7\u12D7\u1311\u1316-\u1317\u135B-\u135C\u137D-\u137F\u139A-\u139F\u13F6-\u13F7\u13FE-\u13FF\u169D-\u169F\u16F9-\u16FF\u1716-\u171E\u1737-\u173F\u1754-\u175F\u176D\u1771\u1774-\u177F\u17DE-\u17DF\u17EA-\u17EF\u17FA-\u17FF\u181A-\u181F\u1879-\u187F\u18AB-\u18AF\u18F6-\u18FF\u191F\u192C-\u192F\u193C-\u193F\u1941-\u1943\u196E-\u196F\u1975-\u197F\u19AC-\u19AF\u19CA-\u19CF\u19DB-\u19DD\u1A1C-\u1A1D\u1A5F\u1A7D-\u1A7E\u1A8A-\u1A8F\u1A9A-\u1A9F\u1AAE-\u1AAF\u1ACF-\u1AFF\u1B4D-\u1B4F\u1B7F\u1BF4-\u1BFB\u1C38-\u1C3A\u1C4A-\u1C4C\u1C89-\u1C8F\u1CBB-\u1CBC\u1CC8-\u1CCF\u1CFB-\u1CFF\u1F16-\u1F17\u1F1E-\u1F1F\u1F46-\u1F47\u1F4E-\u1F4F\u1F58\u1F5A\u1F5C\u1F5E\u1F7E-\u1F7F\u1FB5\u1FC5\u1FD4-\u1FD5\u1FDC\u1FF0-\u1FF1\u1FF5\u1FFF\u2065\u2072-\u2073\u208F\u209D-\u209F\u20C1-\u20CF\u20F1-\u20FF\u218C-\u218F\u2427-\u243F\u244B-\u245F\u2B74-\u2B75\u2B96\u2CF4-\u2CF8\u2D26\u2D28-\u2D2C\u2D2E-\u2D2F\u2D68-\u2D6E\u2D71-\u2D7E\u2D97-\u2D9F\u2DA7\u2DAF\u2DB7\u2DBF\u2DC7\u2DCF\u2DD7\u2DDF\u2E5E-\u2E7F\u2E9A\u2EF4-\u2EFF\u2FD6-\u2FEF\u2FFC-\u2FFF\u3040\u3097-\u3098\u3100-\u3104\u3130\u318F\u31E4-\u31EF\u321F\uA48D-\uA48F\uA4C7-\uA4CF\uA62C-\uA63F\uA6F8-\uA6FF\uA7CB-\uA7CF\uA7D2\uA7D4\uA7DA-\uA7F1\uA82D-\uA82F\uA83A-\uA83F\uA878-\uA87F\uA8C6-\uA8CD\uA8DA-\uA8DF\uA954-\uA95E\uA97D-\uA97F\uA9CE\uA9DA-\uA9DD\uA9FF\uAA37-\uAA3F\uAA4E-\uAA4F\uAA5A-\uAA5B\uAAC3-\uAADA\uAAF7-\uAB00\uAB07-\uAB08\uAB0F-\uAB10\uAB17-\uAB1F\uAB27\uAB2F\uAB6C-\uAB6F\uABEE-\uABEF\uABFA-\uABFF\uD7A4-\uD7AF\uD7C7-\uD7CA\uD7FC-\uD7FF\uFA6E-\uFA6F\uFADA-\uFAFF\uFB07-\uFB12\uFB18-\uFB1C\uFB37\uFB3D\uFB3F\uFB42\uFB45\uFBC3-\uFBD2\uFD90-\uFD91\uFDC8-\uFDCE\uFDD0-\uFDEF\uFE1A-\uFE1F\uFE53\uFE67\uFE6C-\uFE6F\uFE75\uFEFD-\uFEFE\uFF00\uFFBF-\uFFC1\uFFC8-\uFFC9\uFFD0-\uFFD1\uFFD8-\uFFD9\uFFDD-\uFFDF\uFFE7\uFFEF-\uFFF8\uFFFE-\uFFFF\U0001000C\U00010027\U0001003B\U0001003E\U0001004E-\U0001004F\U0001005E-\U0001007F\U000100FB-\U000100FF\U00010103-\U00010106\U00010134-\U00010136\U0001018F\U0001019D-\U0001019F\U000101A1-\U000101CF\U000101FE-\U0001027F\U0001029D-\U0001029F\U000102D1-\U000102DF\U000102FC-\U000102FF\U00010324-\U0001032C\U0001034B-\U0001034F\U0001037B-\U0001037F\U0001039E\U000103C4-\U000103C7\U000103D6-\U000103FF\U0001049E-\U0001049F\U000104AA-\U000104AF\U000104D4-\U000104D7\U000104FC-\U000104FF\U00010528-\U0001052F\U00010564-\U0001056E\U0001057B\U0001058B\U00010593\U00010596\U000105A2\U000105B2\U000105BA\U000105BD-\U000105FF\U00010737-\U0001073F\U00010756-\U0001075F\U00010768-\U0001077F\U00010786\U000107B1\U000107BB-\U000107FF\U00010806-\U00010807\U00010809\U00010836\U00010839-\U0001083B\U0001083D-\U0001083E\U00010856\U0001089F-\U000108A6\U000108B0-\U000108DF\U000108F3\U000108F6-\U000108FA\U0001091C-\U0001091E\U0001093A-\U0001093E\U00010940-\U0001097F\U000109B8-\U000109BB\U000109D0-\U000109D1\U00010A04\U00010A07-\U00010A0B\U00010A14\U00010A18\U00010A36-\U00010A37\U00010A3B-\U00010A3E\U00010A49-\U00010A4F\U00010A59-\U00010A5F\U00010AA0-\U00010ABF\U00010AE7-\U00010AEA\U00010AF7-\U00010AFF\U00010B36-\U00010B38\U00010B56-\U00010B57\U00010B73-\U00010B77\U00010B92-\U00010B98\U00010B9D-\U00010BA8\U00010BB0-\U00010BFF\U00010C49-\U00010C7F\U00010CB3-\U00010CBF\U00010CF3-\U00010CF9\U00010D28-\U00010D2F\U00010D3A-\U00010E5F\U00010E7F\U00010EAA\U00010EAE-\U00010EAF\U00010EB2-\U00010EFF\U00010F28-\U00010F2F\U00010F5A-\U00010F6F\U00010F8A-\U00010FAF\U00010FCC-\U00010FDF\U00010FF7-\U00010FFF\U0001104E-\U00011051\U00011076-\U0001107E\U000110C3-\U000110CC\U000110CE-\U000110CF\U000110E9-\U000110EF\U000110FA-\U000110FF\U00011135\U00011148-\U0001114F\U00011177-\U0001117F\U000111E0\U000111F5-\U000111FF\U00011212\U0001123F-\U0001127F\U00011287\U00011289\U0001128E\U0001129E\U000112AA-\U000112AF\U000112EB-\U000112EF\U000112FA-\U000112FF\U00011304\U0001130D-\U0001130E\U00011311-\U00011312\U00011329\U00011331\U00011334\U0001133A\U00011345-\U00011346\U00011349-\U0001134A\U0001134E-\U0001134F\U00011351-\U00011356\U00011358-\U0001135C\U00011364-\U00011365\U0001136D-\U0001136F\U00011375-\U000113FF\U0001145C\U00011462-\U0001147F\U000114C8-\U000114CF\U000114DA-\U0001157F\U000115B6-\U000115B7\U000115DE-\U000115FF\U00011645-\U0001164F\U0001165A-\U0001165F\U0001166D-\U0001167F\U000116BA-\U000116BF\U000116CA-\U000116FF\U0001171B-\U0001171C\U0001172C-\U0001172F\U00011747-\U000117FF\U0001183C-\U0001189F\U000118F3-\U000118FE\U00011907-\U00011908\U0001190A-\U0001190B\U00011914\U00011917\U00011936\U00011939-\U0001193A\U00011947-\U0001194F\U0001195A-\U0001199F\U000119A8-\U000119A9\U000119D8-\U000119D9\U000119E5-\U000119FF\U00011A48-\U00011A4F\U00011AA3-\U00011AAF\U00011AF9-\U00011BFF\U00011C09\U00011C37\U00011C46-\U00011C4F\U00011C6D-\U00011C6F\U00011C90-\U00011C91\U00011CA8\U00011CB7-\U00011CFF\U00011D07\U00011D0A\U00011D37-\U00011D39\U00011D3B\U00011D3E\U00011D48-\U00011D4F\U00011D5A-\U00011D5F\U00011D66\U00011D69\U00011D8F\U00011D92\U00011D99-\U00011D9F\U00011DAA-\U00011EDF\U00011EF9-\U00011FAF\U00011FB1-\U00011FBF\U00011FF2-\U00011FFE\U0001239A-\U000123FF\U0001246F\U00012475-\U0001247F\U00012544-\U00012F8F\U00012FF3-\U00012FFF\U0001342F\U00013439-\U000143FF\U00014647-\U000167FF\U00016A39-\U00016A3F\U00016A5F\U00016A6A-\U00016A6D\U00016ABF\U00016ACA-\U00016ACF\U00016AEE-\U00016AEF\U00016AF6-\U00016AFF\U00016B46-\U00016B4F\U00016B5A\U00016B62\U00016B78-\U00016B7C\U00016B90-\U00016E3F\U00016E9B-\U00016EFF\U00016F4B-\U00016F4E\U00016F88-\U00016F8E\U00016FA0-\U00016FDF\U00016FE5-\U00016FEF\U00016FF2-\U00016FFF\U000187F8-\U000187FF\U00018CD6-\U00018CFF\U00018D09-\U0001AFEF\U0001AFF4\U0001AFFC\U0001AFFF\U0001B123-\U0001B14F\U0001B153-\U0001B163\U0001B168-\U0001B16F\U0001B2FC-\U0001BBFF\U0001BC6B-\U0001BC6F\U0001BC7D-\U0001BC7F\U0001BC89-\U0001BC8F\U0001BC9A-\U0001BC9B\U0001BCA4-\U0001CEFF\U0001CF2E-\U0001CF2F\U0001CF47-\U0001CF4F\U0001CFC4-\U0001CFFF\U0001D0F6-\U0001D0FF\U0001D127-\U0001D128\U0001D1EB-\U0001D1FF\U0001D246-\U0001D2DF\U0001D2F4-\U0001D2FF\U0001D357-\U0001D35F\U0001D379-\U0001D3FF\U0001D455\U0001D49D\U0001D4A0-\U0001D4A1\U0001D4A3-\U0001D4A4\U0001D4A7-\U0001D4A8\U0001D4AD\U0001D4BA\U0001D4BC\U0001D4C4\U0001D506\U0001D50B-\U0001D50C\U0001D515\U0001D51D\U0001D53A\U0001D53F\U0001D545\U0001D547-\U0001D549\U0001D551\U0001D6A6-\U0001D6A7\U0001D7CC-\U0001D7CD\U0001DA8C-\U0001DA9A\U0001DAA0\U0001DAB0-\U0001DEFF\U0001DF1F-\U0001DFFF\U0001E007\U0001E019-\U0001E01A\U0001E022\U0001E025\U0001E02B-\U0001E0FF\U0001E12D-\U0001E12F\U0001E13E-\U0001E13F\U0001E14A-\U0001E14D\U0001E150-\U0001E28F\U0001E2AF-\U0001E2BF\U0001E2FA-\U0001E2FE\U0001E300-\U0001E7DF\U0001E7E7\U0001E7EC\U0001E7EF\U0001E7FF\U0001E8C5-\U0001E8C6\U0001E8D7-\U0001E8FF\U0001E94C-\U0001E94F\U0001E95A-\U0001E95D\U0001E960-\U0001EC70\U0001ECB5-\U0001ED00\U0001ED3E-\U0001EDFF\U0001EE04\U0001EE20\U0001EE23\U0001EE25-\U0001EE26\U0001EE28\U0001EE33\U0001EE38\U0001EE3A\U0001EE3C-\U0001EE41\U0001EE43-\U0001EE46\U0001EE48\U0001EE4A\U0001EE4C\U0001EE50\U0001EE53\U0001EE55-\U0001EE56\U0001EE58\U0001EE5A\U0001EE5C\U0001EE5E\U0001EE60\U0001EE63\U0001EE65-\U0001EE66\U0001EE6B\U0001EE73\U0001EE78\U0001EE7D\U0001EE7F\U0001EE8A\U0001EE9C-\U0001EEA0\U0001EEA4\U0001EEAA\U0001EEBC-\U0001EEEF\U0001EEF2-\U0001EFFF\U0001F02C-\U0001F02F\U0001F094-\U0001F09F\U0001F0AF-\U0001F0B0\U0001F0C0\U0001F0D0\U0001F0F6-\U0001F0FF\U0001F1AE-\U0001F1E5\U0001F203-\U0001F20F\U0001F23C-\U0001F23F\U0001F249-\U0001F24F\U0001F252-\U0001F25F\U0001F266-\U0001F2FF\U0001F6D8-\U0001F6DC\U0001F6ED-\U0001F6EF\U0001F6FD-\U0001F6FF\U0001F774-\U0001F77F\U0001F7D9-\U0001F7DF\U0001F7EC-\U0001F7EF\U0001F7F1-\U0001F7FF\U0001F80C-\U0001F80F\U0001F848-\U0001F84F\U0001F85A-\U0001F85F\U0001F888-\U0001F88F\U0001F8AE-\U0001F8AF\U0001F8B2-\U0001F8FF\U0001FA54-\U0001FA5F\U0001FA6E-\U0001FA6F\U0001FA75-\U0001FA77\U0001FA7D-\U0001FA7F\U0001FA87-\U0001FA8F\U0001FAAD-\U0001FAAF\U0001FABB-\U0001FABF\U0001FAC6-\U0001FACF\U0001FADA-\U0001FADF\U0001FAE8-\U0001FAEF\U0001FAF7-\U0001FAFF\U0001FB93\U0001FBCB-\U0001FBEF\U0001FBFA-\U0001FFFF\U0002A6E0-\U0002A6FF\U0002B739-\U0002B73F\U0002B81E-\U0002B81F\U0002CEA2-\U0002CEAF\U0002EBE1-\U0002F7FF\U0002FA1E-\U0002FFFF\U0003134B-\U000E0000\U000E0002-\U000E001F\U000E0080-\U000E00FF\U000E01F0-\U000EFFFF\U000FFFFE-\U000FFFFF\U0010FFFE-\U0010FFFF]' THEN                 -- a code point unassigned in the validator's Unicode version: not comparable (S5R-02)
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
CREATE FUNCTION ac.source_texts_after() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ac, pg_temp AS $$
DECLARE d text := ac.text_digest(NEW.bytes);
BEGIN
  IF d IS NOT NULL THEN
    PERFORM ac.lock_keys(ARRAY['source:' || NEW.source_id]);      -- serialised with Check closing (D14), time after the lock
    INSERT INTO ac.source_texts VALUES (NEW.tenant_id, NEW.source_id, d, clock_timestamp());
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER source_texts_after AFTER INSERT ON ac.source_bytes FOR EACH ROW EXECUTE FUNCTION ac.source_texts_after();

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

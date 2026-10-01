"""Mutation run for validator.py (replaces the v0.1 'T3' which was a tautology).

Each mutant weakens (or over-tightens) exactly one condition of the validator. A mutant is KILLED when the
valid world or at least one vector gives a result different from its expectation. Every surviving mutant
must be listed in EQUIVALENT with a reason, otherwise the run fails.

python3 mutants.py      (about a minute)
"""
import sys
import types
from pathlib import Path

from vectors import VECTORS, build

HERE = Path(__file__).resolve().parent
SRC = (HERE / "validator.py").read_text(encoding="utf-8")

M = [  # (id, description, old, new)
    # phase 0/1 and trust
    ("M001", "дробные числа разрешены", "if isinstance(node, float):", "if False:"),
    ("M002", "целые вне 2^53 разрешены", "if abs(node) > MAX_SAFE:", "if False:"),
    ("M003", "суррогаты в значениях разрешены", "if _bad_str(node):", "if False:"),
    ("M004", "управляющие символы разрешены", "elif not free and any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in node):", "elif False:"),
    ("M005", "ключи не проверяются", 'if not isinstance(k, str) or _bad_str(k) or any(ord(ch) < 0x20 for ch in k):', "if not isinstance(k, str):"),
    ("M006", "шаблоны по re.search ($ перед \\n)", "SCHEMA = _fullmatch_patterns(json.loads(", "SCHEMA = (json.loads("),
    ("M007", "календарь не проверяется", "DATASET_V = Draft202012Validator(SCHEMA, format_checker=FORMATS)", "DATASET_V = Draft202012Validator(SCHEMA)"),
    ("M008", "повтор ключа доверия", "if kk in keys:", "if False:"),
    ("M009", "интервал ключа доверия", 'not k["not_before"] < k["not_after"] or ', ""),
    ("M010", "отзыв раньше начала", ' or ("revoked_at" in k and k["revoked_at"] < k["not_before"])', ""),
    ("M012", "семантика на битой схеме", "return R  # fail-closed", "pass  # fail-closed"),
    ("M013", "повтор id", "if rid in by[k]:", "if False:"),
    # sources
    ("M020", "inline vs хранилище", "if inline is not None and stored is not None and inline != stored:", "if False:"),
    ("M021", "byte_length", ' or len(b) != s["byte_length"]', ""),
    ("M022", "адрес = хэш", '"src:sha256:" + hashlib.sha256(b).hexdigest() != sid or ', ""),
    ("M023", "нет байтов — молча", "if sid not in unavailable_reported and sid not in bad_sources:", "if False:"),
    ("M024", "хранилище игнорируется", "b = inline if inline is not None else stored", "b = inline"),
    # entities, merges
    ("M030", "проект сущности", 'if e["project_id"] not in P:', "if False:"),
    ("M031", "status_changed_at < created_at", 'if "status_changed_at" in e and e["status_changed_at"] < e["created_at"]:', "if False:"),
    ("M032", "PD у физлица", 'if e["entity_type"] == "PERSON" and "PERSONAL_DATA" not in e["marking"]["categories"]:', "if False:"),
    ("M033", "слияние в неизвестную", "if (t is None or ", "if ("),
    ("M034", "слияние в не-ACTIVE", 'not (t["status"] == "ACTIVE" or (t["status"] == "RETIRED"', 'not (True or (t["status"] == "RETIRED"'),
    ("M035", "слияние в другой проект", ' or t["project_id"] != e["project_id"]', ""),
    ("M036", "слияние в другой тип", '\n                    or t["entity_type"] != e["entity_type"]', ""),
    ("M037", "resolve без слияний", 'return e["merged_into"] if e and e["status"] == "MERGED" else eid', "return eid"),
    # identifiers
    ("M040", "контрольные цифры физлица", "if not ok(i[f]):", "if False:"),
    ("M041", "ИНН-12: 12-я цифра", "\n                and ctl([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 11) == d[11])", ")"),
    ("M042", "ИНН-12: 11-я цифра", "(ctl([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], 10) == d[10]", "(True"),
    ("M043", "ИНН-10", "return ctl([2, 4, 10, 3, 5, 9, 4, 6, 8], 9) == d[9]", "return True"),
    ("M044", "ОГРН", "return len(v) == 13 and int(v[:12]) % 11 % 10 == int(v[12])", "return True"),
    ("M045", "ОГРНИП", "return len(v) == 15 and int(v[:14]) % 13 % 10 == int(v[14])", "return True"),
    ("M046", "IMO", "return len(d) == 7 and sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]", "return True"),
    ("M047", "ИНН/ОГРНИП физлица не индексируются", "strong.append((scheme, i[f]))", "pass"),
    ("M048", "пометка у одного тёзки отключает дубль (RR-03c)", "if qa is not None and qb is not None and qa != qb:", "if (qa is not None or qb is not None) and qa != qb:"),
    ("M049", "слабого ключа нет", 'if "birth_date" in i:\n            weak.append', 'if False:\n            weak.append'),
    ("M050", "физлицо без идентичности", 'if "disambiguator" not in i:\n                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "PERSON', 'if False:\n                R.err("ENTITY_IDENTITY_INSUFFICIENT", ref, "PERSON'),
    ("M051", "неформальная без disambiguator", 'if "disambiguator" not in i or {"ogrn", "inn", "kpp"}', 'if {"ogrn", "inn", "kpp"}'),
    ("M052", "неформальная с ИНН", ' or {"ogrn", "inn", "kpp"} & i.keys()', ""),
    ("M053", "неформальная с legal_form", ' or "legal_form" in i:', ":"),
    ("M054", "ИНН юрлица", 'if "inn" in i and not inn_ok(i["inn"]):', "if False:"),
    ("M055", "ОГРН юрлица", 'if "ogrn" in i and not ogrn_ok(i["ogrn"]):', "if False:"),
    ("M056", "филиал без КПП", 'if not ({"inn", "kpp"} <= i.keys()) or "ogrn" in i:', 'if "ogrn" in i:'),
    ("M057", "филиал с ОГРН", 'if not ({"inn", "kpp"} <= i.keys()) or "ogrn" in i:', 'if not ({"inn", "kpp"} <= i.keys()):'),
    ("M058", "ключ филиала", 'strong.append(("ru.inn_kpp", i["inn"] + "|" + i["kpp"]))', "pass"),
    ("M059", "филиал как юрлицо", 'if form == "BRANCH":', "if False:"),
    ("M060", "ОГРН не индексируется", 'strong.append(("ru.ogrn", i["ogrn"]))', "pass"),
    ("M061", "ИНН не индексируется", 'strong.append(("ru.inn", i["inn"]))', "pass"),
    ("M062", "организация РФ без ОГРН/ИНН", 'if i["jurisdiction"] == "RU" and not ({"ogrn", "inn"} & i.keys()):', "if False:"),
    ("M063", "foreign_ids не индексируются", 'strong.append((f["scheme"], id_norm(f["value"])))', "pass"),
    ("M064", "иностранная без id", 'if not strong and i["jurisdiction"] != "RU":', "if False:"),
    ("M065", "кадастр без нормализации", 'strong.append(("ru.cadastral", cadastral_norm(i["cadastral_number"])))', 'strong.append(("ru.cadastral", i["cadastral_number"]))'),
    ("M066", "VIN не обязателен", "if (need and need not in i) or not strong:", "if not strong:"),
    ("M067", "имущество без id", "if (need and need not in i) or not strong:", "if (need and need not in i):"),
    ("M068", "VIN не индексируется", 'strong.append(("vin", i["vin"]))', "pass"),
    ("M069", "IMO не проверяется", 'if not imo_ok(i["imo"]):', "if False:"),
    ("M070", "регистрация не индексируется", 'strong.append((i["registration"]["scheme"], id_norm(i["registration"]["value"])))', "pass"),
    ("M071", "событие не индексируется", 'weak.append(("event", norm(i["title"]) + "|" + i["date"], norm(i["place"]) if "place" in i else None))', "pass"),
    ("M072", "конфликт не индексируется", 'weak.append(("conflict", norm(i["title"]) + "|" + i["started_on"], norm(i["place"]) if "place" in i else None))', "pass"),
    ("M073", "оборудование не индексируется", 'strong.append(("equipment", i["site_id"] + "|" + tag_norm(i["tag"])))', "pass"),
    ("M074", "модель не индексируется", 'strong.append(("equipment_model", norm(i["manufacturer"]) + "|" + norm(i["model"])))', "pass"),
    ("M075", "понятие не индексируется", 'weak.append(("concept", ns + base_key(i["label"]), i.get("disambiguator")))', "pass"),
    # normalisation
    ("M080", "скелет без NFKC", 'return base_key(unicodedata.normalize("NFKC", s).translate(_CONFUSABLE))', "return base_key(s.translate(_CONFUSABLE))"),
    ("M081", "без удаления невидимых символов", "s = \"\".join(ch for ch in s if not _ignorable(ch))", "s = s"),
    ("M082", "без конфузаблов", ".translate(_CONFUSABLE)", ""),
    ("M083", "без casefold", "    if fold:\n        s = s.casefold()", "    if False:\n        s = s.casefold()"),
    ("M084", "без ё→е", '.replace("ё", "е")', ""),
    ("M085", "без тире", 's = "".join("-" if unicodedata.category(ch) == "Pd" or ch == "\u2212" else ch for ch in s)', "s = s"),
    ("M086", "без кавычек", 's = "".join(ch for ch in s if ch not in _QUOTES and unicodedata.category(ch) not in ("Pi", "Pf"))', "s = s"),
    ("M087", "без пробелов", 'return " ".join(s.split())', "return s"),
    # uniqueness
    ("M090", "дубли по сильным ключам", "if len(owners) > 1:", "if False:"),
    ("M091", "владелец = сама сущность (без слияний)", "owner = resolve(eid)", "owner = eid"),
    ("M092", "дубли по слабым ключам", "reported.add(frozenset((oa, ob)))\n                R.err(\"ENTITY_DUPLICATE_IN_PROJECT\"", "reported.add(frozenset((oa, ob)))\n                0 and R.err(\"ENTITY_DUPLICATE_IN_PROJECT\""),
    ("M093", "ИНН/ОГРНИП не различают тёзок", "if told_apart(oa, ob):", "if False:"),
    ("M094", "различие по ИНН у одного", "distinct[a][sch] and distinct[b][sch] and not", "(distinct[a][sch] or distinct[b][sch]) and not"),
    # claims
    ("M100", "claim_id", "if claim_digest_id(c) != cid:", "if False:"),
    ("M101", "проект утверждения", 'if c["project_id"] not in P:\n            R.err("REF_UNRESOLVED", cid', 'if False:\n            R.err("REF_UNRESOLVED", cid'),
    ("M102", "субъект неизвестен", 'if subj is None:\n            R.err("REF_UNRESOLVED", cid, "неизвестный subject")', 'if False:\n            R.err("REF_UNRESOLVED", cid, "неизвестный subject")'),
    ("M103", "субъект из чужого проекта", 'elif subj["project_id"] != c["project_id"]:', "elif False:"),
    ("M104", "объект неизвестен", 'if obj_ent is None:\n                R.err("REF_UNRESOLVED", cid', 'if False:\n                R.err("REF_UNRESOLVED", cid'),
    ("M105", "объект из чужого проекта", 'elif obj_ent["project_id"] != c["project_id"]:', "elif False:"),
    ("M106", "предикат неизвестен", 'if p is None:\n            R.err("PREDICATE_UNKNOWN"', 'if False:\n            R.err("PREDICATE_UNKNOWN"'),
    ("M107", "domain", 'if subj is not None and subj["entity_type"] not in p["domain"]:', "if False:"),
    ("M108", "range: сущность вместо литерала", 'if "entity" not in rng or (obj_ent', "if (obj_ent"),
    ("M109", "range: тип сущности", ' or (obj_ent is not None and obj_ent["entity_type"] not in rng["entity"])', ""),
    ("M110", "range: литерал вместо сущности", '("literal" not in rng or lit["type"]', '(lit["type"]'),
    ("M111", "range: тип литерала", '("literal" not in rng or lit["type"] not in rng["literal"]', '("literal" not in rng'),
    ("M112", "range: схема идентификатора", '\n                        or (lit["type"] == "IDENTIFIER" and "schemes" in rng and lit["scheme"] not in rng["schemes"])', ""),
    ("M113", "range: единица", '\n                        or (lit["type"] == "QUANTITY" and "units" in rng and lit["unit"] not in rng["units"])', ""),
    ("M114", "enum", '(s["type"] == "enum" and isinstance(v, str) and v in s["enum"])', '(s["type"] == "enum")'),
    ("M115", "bool как int", " and not isinstance(v, bool)", ""),
    ("M116", "диапазон int", '\n                     and s.get("min", v) <= v <= s.get("max", v))', ")"),
    ("M117", "строка из пробелов", '(s["type"] == "string" and isinstance(v, str) and v.strip() != "")', '(s["type"] == "string" and isinstance(v, str))'),
    ("M118", "boolean", '(s["type"] == "boolean" and isinstance(v, bool))', '(s["type"] == "boolean")'),
    ("M119", "необъявленный квалификатор", "ok = s is not None and (", "ok = s is None or ("),
    ("M120", "обязательный квалификатор", 'if s.get("required") and name not in q:', "if False:"),
    ("M121", "valid_from > valid_to", 'if "valid_from" in c and "valid_to" in c and c["valid_from"] > c["valid_to"]:', "if False:"),
    ("M122", "утверждение ≥ сущностей", 'if x is not None and not dominates(c["marking"], x["marking"]):', "if False:"),
    ("M123", "утверждение ≥ только субъекта", "for x in (subj, obj_ent):", "for x in (subj,):"),
    ("M124", "dominates: категории", ' and set(a["categories"]) >= set(b["categories"])', ""),
    ("M125", "dominates: уровень", 'LEVEL[a["level"]] >= LEVEL[b["level"]] and ', ""),
    ("M126", "источник доказательства неизвестен", 'if s is None:\n                R.err("REF_UNRESOLVED", cid, "неизвестный источник")', 'if False:\n                R.err("REF_UNRESOLVED", cid, "неизвестный источник")'),
    ("M127", "tenant источника", 'if s["tenant_id"] != tenant_of(c["project_id"]):\n                R.err("CROSS_SCOPE_REFERENCE", cid', 'if False:\n                R.err("CROSS_SCOPE_REFERENCE", cid'),
    ("M128", "источник получен позже", 'if min(o["observed_at"] for o in s["observations"]) > c["recorded_at"]:', "if False:"),
    ("M129", "max вместо min observed_at", 'if min(o["observed_at"] for o in s["observations"])', 'if max(o["observed_at"] for o in s["observations"])'),
    ("M130", "утверждение ≥ источника", 'if not dominates(c["marking"], s["marking"]):', "if False:"),
    ("M131", "span: start < end", "span_ok = st < en <= len(b)", "span_ok = en <= len(b)"),
    ("M132", "span: end <= len", "span_ok = st < en <= len(b)", "span_ok = st < en"),
    ("M133", "граница UTF-8", 'txt = chunk.decode("utf-8")', 'txt = chunk.decode("utf-8", "replace")'),
    ("M134", "sha фрагмента", 'span_ok = hashlib.sha256(chunk).hexdigest() == ev["quote_sha256"] and ev.get("quote", txt) == txt', 'span_ok = ev.get("quote", txt) == txt'),
    ("M135", "текст цитаты", 'span_ok = hashlib.sha256(chunk).hexdigest() == ev["quote_sha256"] and ev.get("quote", txt) == txt', 'span_ok = hashlib.sha256(chunk).hexdigest() == ev["quote_sha256"]'),
    # reviews, contradictions
    ("M140", "рецензия на неизвестное", 'if c is None:\n            R.err("REF_UNRESOLVED", rid', 'if False:\n            R.err("REF_UNRESOLVED", rid'),
    ("M141", "рецензия раньше утверждения", 'rv["reviewed_at"] < c["recorded_at"] or ', ""),
    ("M142", "записана раньше решения", ' or rv["recorded_at"] < rv["reviewed_at"]', ""),
    ("M143", "неоднозначность", "if any(len(v) > 1 for v in seen.values()):", "if False:"),
    ("M144", "неоднозначность по заявленному времени", 'seen[rv["recorded_at"]].add(rv["status"])', 'seen[rv["reviewed_at"]].add(rv["status"])'),
    ("M145", "status_at по заявленному времени (окно)", 'rv["recorded_at"] <= t]', 'rv["reviewed_at"] <= t]'),
    ("M146", "status_at по заявленному времени (порядок)", 'key=lambda r: r["recorded_at"])', 'key=lambda r: r["reviewed_at"])'),
    ("M147", "status_at строго <", 'rv["recorded_at"] <= t]', 'rv["recorded_at"] < t]'),
    ("M148", "противоречие: любая кардинальность", 'if p and p["cardinality"] == "ONE" and ', "if p and "),
    ("M149", "противоречие: отклонённые учитываются", ' and status_at(cid, None) not in ("REFUTED", "WITHDRAWN")', ""),
    ("M150", "противоречие: без слияний", 'groups[(c["project_id"], resolve(c["subject"]), c["predicate"])]', 'groups[(c["project_id"], c["subject"], c["predicate"])]'),
    ("M151", "противоречие: без пересечения сроков", "if overlap and canon(", "if canon("),
    ("M152", "противоречие: равные значения", 'if overlap and canon(x["object"]) != canon(y["object"]):', "if overlap:"),
    # Checks
    ("M160", "проект Проверки неизвестен", 'if prj is None:\n            R.err("REF_UNRESOLVED", kid', 'if False:\n            R.err("REF_UNRESOLVED", kid'),
    ("M161", "Проверка вне COMPLIANCE", 'if prj["product"] != "COMPLIANCE":', "if False:"),
    ("M162", "субъект Проверки неизвестен", 'if subj is None:\n            R.err("REF_UNRESOLVED", kid', 'if False:\n            R.err("REF_UNRESOLVED", kid'),
    ("M163", "субъект Проверки из чужого проекта", 'elif subj["project_id"] != k["project_id"]:', "elif False:"),
    ("M164", "субъект не обязан быть ACTIVE", 'live = subj["status"] == "ACTIVE" or (', "live = True or ("),
    ("M165", "слияние до закрытия допустимо", 'subj["status_changed_at"] > closed_at', "True"),
    ("M166", "слияние в момент закрытия допустимо", 'subj["status_changed_at"] > closed_at', 'subj["status_changed_at"] >= closed_at'),
    ("M167", "тип субъекта", ' or subj["entity_type"] not in ("PERSON", "ORGANIZATION")', ""),
    ("M168", "Проверка ≥ субъекта", 'if not dominates(k["marking"], subj["marking"]):', "if False:"),
    ("M169", "закрытие раньше запроса", 'closed_at < k["requested_at"] or ', ""),
    ("M170", "as_of позже закрытия", ' or k["as_of"] > closed_at[:10]', ""),
    ("M171", "отмена не закрывает", 'closed_at = k.get("completed_at") or k.get("cancelled_at")', 'closed_at = k.get("completed_at")'),
    ("M172", "повтор измерения", "if len(set(fdims)) != len(fdims):", "if False:"),
    ("M173", "измерение вне профиля", "for d in sorted(set(fdims) - set(dims)):", "for d in []:"),
    ("M174", "не все измерения", "if done and set(dims) - set(fdims):", "if False:"),
    ("M175", "все измерения и у незавершённых", "if done and set(dims) - set(fdims):", "if set(dims) - set(fdims):"),
    ("M176", "CANCELLED как завершённая", 'done = k["status"] == "COMPLETED"', 'done = k["status"] != "IN_PROGRESS"'),
    ("M177", "FOUND ⇔ утверждения", '(f["result"] == "FOUND") != bool(f["claim_ids"]) or ', ""),
    ("M178", "NOT_FOUND с риском", ' or (f["result"] == "NOT_FOUND" and f["risk"] != "NONE")', ""),
    ("M179", "поиск не обязателен", 'if done and not any(k["requested_at"] <= s["performed_at"] <= k["completed_at"] for s in f["searches"]):', "if False:"),
    ("M180", "поиск до запроса", 'k["requested_at"] <= s["performed_at"] <= k["completed_at"]', 's["performed_at"] <= k["completed_at"]'),
    ("M181", "поиск после завершения", 'k["requested_at"] <= s["performed_at"] <= k["completed_at"]', 'k["requested_at"] <= s["performed_at"]'),
    ("M182", "окно поиска строго", 'k["requested_at"] <= s["performed_at"] <= k["completed_at"]', 'k["requested_at"] < s["performed_at"] < k["completed_at"]'),
    ("M183", "источник поиска неизвестен", "if rs is None:", "if False:"),
    ("M184", "tenant источника поиска", 'elif rs["tenant_id"] != prj["tenant_id"]:', "elif False:"),
    ("M185", "утверждение Проверки неизвестно", 'if c is None:\n                    R.err("REF_UNRESOLVED", kid', 'if False:\n                    R.err("REF_UNRESOLVED", kid'),
    ("M186", "утверждение Проверки из чужого проекта", 'if c["project_id"] != k["project_id"]:\n                    R.err("CROSS_SCOPE_REFERENCE", kid', 'if False:\n                    R.err("CROSS_SCOPE_REFERENCE", kid'),
    ("M187", "не о субъекте", "if subj_id not in touches:", "if False:"),
    ("M188", "объект не учитывается", ' | ({resolve(c["object"]["entity"])} if "entity" in c["object"] else set())', ""),
    ("M189", "дубли субъекта не учитываются", 'touches = {resolve(c["subject"])}', 'touches = {c["subject"]}'),
    ("M190", "субъект Проверки без слияний", 'subj_id = resolve(k["subject_entity_id"])', 'subj_id = k["subject_entity_id"]'),
    ("M191", "измерение предиката", 'if p is not None and f["dimension"] not in p["dimensions"]:', "if False:"),
    ("M192", "ACCEPTED на момент завершения", 'if done and status_at(cid, k["completed_at"]) != "ACCEPTED":', "if False:"),
    ("M193", "Проверка ≥ утверждения", 'if not dominates(k["marking"], c["marking"]):', "if False:"),
    ("M194", "итоговый риск", 'if RISK[k["overall_risk"]] != exp:', "if False:"),
    ("M195", "предыдущая неизвестна", "if pv is None:", "if False:"),
    ("M196", "предыдущая: другой субъект", 'resolve(pv["subject_entity_id"]) != subj_id or ', ""),
    ("M197", "предыдущая: дата", ' or pv["as_of"] >= k["as_of"]', ""),
    ("M198", "предыдущая: та же дата", 'pv["as_of"] >= k["as_of"]', 'pv["as_of"] > k["as_of"]'),
    ("M199", "предыдущая без слияний", 'resolve(pv["subject_entity_id"]) != subj_id', 'pv["subject_entity_id"] != subj_id'),
    # receipts
    ("M200", "receipt_id", "if receipt_digest_id(r) != rid:", "if False:"),
    ("M201", "проект receipt", 'if r["project_id"] not in P:\n            R.err("REF_UNRESOLVED", rid', 'if False:\n            R.err("REF_UNRESOLVED", rid'),
    ("M202", "ключ неизвестен", "(key is None or ", "("),
    ("M204", "служба ключа", ' or key["service_id"] != r["producer"]["service_id"]', ""),
    ("M205", "not_before строго", 'not (key["not_before"] <= t < key["not_after"])', 'not (key["not_before"] < t < key["not_after"])'),
    ("M206", "not_before не проверяется", 'not (key["not_before"] <= t < key["not_after"])', 'not (t < key["not_after"])'),
    ("M207", "not_after включительно", 'not (key["not_before"] <= t < key["not_after"])', 'not (key["not_before"] <= t <= key["not_after"])'),
    ("M208", "not_after не проверяется", 'not (key["not_before"] <= t < key["not_after"])', 'not (key["not_before"] <= t)'),
    ("M209", "отзыв строго", 'key["revoked_at"] <= t', 'key["revoked_at"] < t'),
    ("M210", "отзыв не проверяется", ' or ("revoked_at" in key and key["revoked_at"] <= t)', ""),
    ("M211", "подпись не проверяется", 'Ed25519PublicKey.from_public_bytes(b64u_dec(key["public_key"])).verify(b64u_dec(r["signature"]), rid.encode("utf-8"))', "pass"),
    ("M212", "входной источник неизвестен", 'if s is None:\n                R.err("REF_UNRESOLVED", rid', 'if False:\n                R.err("REF_UNRESOLVED", rid'),
    ("M213", "tenant входа", 'elif s["tenant_id"] != tenant_of(r["project_id"]):', "elif False:"),
    ("M214", "выпущенное утверждение неизвестно", 'if c is None:\n                R.err("REF_UNRESOLVED", rid', 'if False:\n                R.err("REF_UNRESOLVED", rid'),
    ("M215", "HUMAN в receipt", 'if pb["kind"] != "PIPELINE":', "if False:"),
    ("M216", "служба утверждения", 'if pb["service_id"] != r["producer"]["service_id"]:', "if False:"),
    ("M217", "run_id", 'if pb["run_id"] != r["run_id"]:', "if False:"),
    ("M218", "проект утверждения receipt", 'if c["project_id"] != r["project_id"]:\n                R.err("RECEIPT_CLAIM_BINDING_INVALID"', 'if False:\n                R.err("RECEIPT_CLAIM_BINDING_INVALID"'),
    ("M219", "записано после issued_at", 'if c["recorded_at"] > t:', "if False:"),
    ("M220", "записано в момент issued_at", 'if c["recorded_at"] > t:', 'if c["recorded_at"] >= t:'),
    ("M221", "источники ⊆ входов", 'if not {ev["source_id"] for ev in c["evidence"]} <= set(r["input_source_ids"]):', "if False:"),
    ("M222", "узел графа другого артефакта", 'if any("graph_node" in ev and ev["graph_node"]["artifact_digest"] != r["artifact_digest"] for ev in c["evidence"]):', "if False:"),
    ("M223", "ровно один receipt → хотя бы один", 'if c["produced_by"]["kind"] == "PIPELINE" and n != 1:', 'if c["produced_by"]["kind"] == "PIPELINE" and n < 1:'),
    ("M224", "receipt не обязателен", 'if c["produced_by"]["kind"] == "PIPELINE" and n != 1:', "if False:"),
    ("M225", "узел графа у HUMAN", 'if c["produced_by"]["kind"] == "HUMAN" and any("graph_node" in ev for ev in c["evidence"]):', "if False:"),

    # ---- v0.2.1 (RR-01…RR-15)
    ("M300", "RETIRED после закрытия не допускается (RR-01)", 'live = subj["status"] == "ACTIVE" or (closed_at is not None and subj["status_changed_at"] > closed_at)', 'live = subj["status"] == "ACTIVE" or (closed_at is not None and subj["status"] == "MERGED" and subj["status_changed_at"] > closed_at)'),
    ("M301", "закрытие включительно (RR-01)", 'subj["status_changed_at"] > closed_at)', 'subj["status_changed_at"] >= closed_at)'),
    ("M302", "цель слияния RETIRED в любой момент (RR-13)", 'and t["status_changed_at"] > e["status_changed_at"]', ""),
    ("M303", "цель слияния RETIRED в момент слияния (RR-13)", 'and t["status_changed_at"] > e["status_changed_at"]', 'and t["status_changed_at"] >= e["status_changed_at"]'),
    ("M304", "скелет — ошибка и для оборудования (RR-02)", 'soft.append(("equipment", i["site_id"] + "|" + tag_norm(norm(i["tag"]))))', 'strong.append(("equipment", i["site_id"] + "|" + tag_norm(norm(i["tag"]))))'),
    ("M305", "понятие по скелету — ошибка (RR-02)", 'soft.append(("concept", ns + norm(i["label"])))', 'strong.append(("concept", ns + norm(i["label"])))'),
    ("M306", "предупреждение о возможном дубле не выдаётся", 'if len(owners) > 1 and frozenset(owners) not in reported | separated:', "if False:"),
    ("M307", "предупреждение и для различённых аналитиком", 'frozenset(owners) not in reported | separated:', 'frozenset(owners) not in reported:'),
    ("M308", "тег с разделителями — разные (RR-03f)", 'return "".join(ch for ch in base_key(v) if ch not in " -_./")', "return base_key(v)"),
    ("M309", "регистрационные номера без нормализации (RR-03d)", 'return "".join(ch for ch in base_key(unicodedata.normalize("NFKC", v)) if ch not in " -_./")', "return v"),
    ("M310", "без свёртки ширины (N097)", 'unicodedata.normalize("NFKC", ch) if unicodedata.decomposition(ch).startswith(("<wide>", "<narrow>")) else ch', "ch"),
    ("M311", "двойники заменяются после casefold (RR-02)", 'return base_key(unicodedata.normalize("NFKC", s).translate(_CONFUSABLE)).replace("ё", "е")', 'return base_key(base_key(unicodedata.normalize("NFKC", s)).translate(_CONFUSABLE)).replace("ё", "е")'),
    ("M312", "без греческой ο (RR-03k)", '"ο": "о", ', ""),
    ("M313", "только категория Cf (RR-03h-j)", 'return unicodedata.category(ch) == "Cf" or any(a <= cp <= b for a, b in _IGNORABLE)', 'return unicodedata.category(ch) == "Cf"'),
    ("M314", "понятие без casefold", 'weak.append(("concept", ns + base_key(i["label"]), i.get("disambiguator")))', 'weak.append(("concept", ns + base_key(i["label"], fold=False), i.get("disambiguator")))'),
    ("M315", "ОГРНИП не различает тёзок (RR-04)", 'for sch in ("ru.inn", "ru.ogrnip"))', 'for sch in ("ru.inn",))'),
    ("M316", "ОГРНИП не собирается для различения (RR-04)", 'if x[0] in ("ru.inn", "ru.ogrnip"):', 'if x[0] in ("ru.inn",):'),
    ("M317", "без предела глубины (RR-05)", "if depth >= MAX_DEPTH:", "if False:"),
    ("M318", "RecursionError не перехватывается (RR-05)", "    except RecursionError:\n        R.err(\"SCHEMA_INVALID\", \"/\", \"слишком глубокая вложенность\")\n        return R", "    except ZeroDivisionError:\n        return R"),
    ("M319", "ключи доверия глобально (RR-06)", 'key = keys.get((tenant_of(r["project_id"]), r["key_id"]))', 'key = next((k for (tn, kid), k in keys.items() if kid == r["key_id"]), None)'),
    ("M320", "битый tenant отключает всех (RR-06)", 'keys = {kk: k for kk, k in keys.items() if kk[0] not in bad_tenants}', "keys = {} if bad_tenants else keys"),
    ("M321", "источник результата поиска без байтов (RR-08b)", 'if rsid not in source_bytes and rsid not in bad_sources and rsid not in unavailable_reported:', "if False:"),
    ("M322", "маркировка источника результата поиска (RR-08c)", 'if not dominates(k["marking"], rs["marking"]):', "if False:"),
    ("M323", "свободный текст только по имени ключа (RR-10)", ' or (key == "value" and isinstance(parent, dict) and parent.get("type") == "STRING")', ""),
    ("M324", "свободный текст — любое поле value", ' and isinstance(parent, dict) and parent.get("type") == "STRING")', ")"),
    ("M325", "контрольная сумма литерала (RR-11)", 'if not (_ascii_digits(v) and CHECKSUMS[lit["scheme"]](v)):', "if False:"),
    ("M326", "тип сущности не в ключе индекса (RR-12)", 'strong_idx[(e["project_id"], t, x)].add(owner)', 'strong_idx[(e["project_id"], "", x)].add(owner)'),
    ("M327", "одиночное место не отделяет (RR-03a)", "if qa is not None and qb is not None and qa != qb:", "if qa != qb:"),
    ("M328", "нет ни предела глубины, ни перехвата RecursionError (RR-05, пара M317+M318)",
     ["if depth >= MAX_DEPTH:", "    except RecursionError:\n        R.err(\"SCHEMA_INVALID\", \"/\", \"слишком глубокая вложенность\")\n        return R"],
     ["if False:", "    except ZeroDivisionError:\n        return R"]),
]

# Survivors that cannot be killed by ANY input, with the reason (defence in depth, reviewed by hand).
EQUIVALENT = {
    "M001": "float всё равно отвергается последней веткой фазы 0 («недопустимый тип»); отдельная ветка нужна только для понятного сообщения",
    "M005": "ключи-строки с суррогатами/управляющими символами отвергает схема: все объекты закрыты, у qualifiers есть propertyNames",
    "M006": "перевод строки в структурных полях отвергает фаза 0 (управляющие символы); у свободного текста нет якорных шаблонов",
    "M317": "защита в глубину: все объекты схемы закрыты, поэтому вложенность глубже 64 отвергает схема (SCHEMA_INVALID), а глубже предела рекурсии — перехват RecursionError; без обеих защит мутант M328 убит",
    "M318": "защита в глубину: пока действует предел глубины фазы 0, схема не видит глубоких входов и RecursionError не возникает; без обеих защит мутант M328 убит",
}


def load(src):
    mod = types.ModuleType("validator_mut")
    mod.__file__ = str(HERE / "validator.py")
    exec(compile(src, "validator_mut", "exec"), mod.__dict__)
    return mod


CASES = None


def run_one(m):
    mid, desc, old, new = m
    olds, news = (old, new) if isinstance(old, list) else ([old], [new])
    src = SRC
    for o, nw in zip(olds, news):
        n = src.count(o)
        if n != 1:
            return (mid, f"PATTERN x{n}", desc)
        src = src.replace(o, nw)
    try:
        mod = load(src)
    except Exception as ex:  # noqa: BLE001
        return (mid, f"KILLED (не компилируется: {type(ex).__name__})", desc)
    for v, ds, tr, ct in CASES:
        who = killed_by(mod, v, ds, tr, ct)
        if who:
            return (mid, f"KILLED by {who}", desc)
    if mid in EQUIVALENT:
        return (mid, "EQUIVALENT", f"{desc} — {EQUIVALENT[mid]}")
    return (mid, "SURVIVED", desc)


def main():
    global CASES
    from multiprocessing import Pool
    CASES = [(None, *build())] + [(v, *build(v)) for v in VECTORS]
    base_mod = load(SRC)
    for v, ds, tr, ct in CASES:  # sanity: the unmutated validator passes everything
        assert killed_by(base_mod, v, ds, tr, ct) is None, v and v["id"]
    only = [a for a in sys.argv[1:] if a.startswith("M")]
    with Pool() as pool:
        rows = pool.map(run_one, [m for m in M if not only or m[0] in only], chunksize=1)
    bad = sum(1 for r in rows if r[1] == "SURVIVED" or r[1].startswith("PATTERN"))
    for r in rows:
        print(f"{r[0]:<6} {r[1]:<28} {r[2]}")
    k = sum(1 for r in rows if r[1].startswith("KILLED"))
    e = sum(1 for r in rows if r[1] == "EQUIVALENT")
    print(f"\nmutants={len(M)} killed={k} equivalent={e} survived/broken={bad}")
    sys.exit(1 if bad else 0)


def killed_by(mod, v, ds, tr, ct):
    try:
        r = mod.validate(ds, tr, ct)
    except Exception as ex:  # noqa: BLE001
        return (v["id"] if v else "BASE") + f"(исключение {type(ex).__name__})"
    if v is None:
        ok = r.errors == [] and [w["code"] for w in r.warnings] == ["CONTRADICTION_SINGLE_VALUED"]
        return None if ok else "BASE"
    ok = r.codes() == v["expected"] and (v["warn"] is None or [w["code"] for w in r.warnings] == v["warn"])
    return None if ok else v["id"]


if __name__ == "__main__":
    main()

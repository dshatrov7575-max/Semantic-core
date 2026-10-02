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
    ("M048", "пометка у одного тёзки отключает дубль (RR-03c)", "if qa is not None and qb is not None and qa != qb and max(ca, cb) >= max(ta or ca, tb or cb):", "if (qa is not None or qb is not None) and qa != qb and max(ca, cb) >= max(ta or ca, tb or cb):"),
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
    ("M074", "модель не индексируется", 'strong.append(("equipment_model", norm(i["manufacturer"], nfkc=False) + "|" + norm(i["model"], nfkc=False)))', "pass"),
    ("M075", "понятие не индексируется", 'weak.append(("concept", ns + base_key(i["label"]), i.get("disambiguator")))', "pass"),
    # normalisation
    ("M080", "скелет без NFKC", '    if nfkc:\n        s = unicodedata.normalize("NFKC", s)', '    if False:\n        s = unicodedata.normalize("NFKC", s)'),
    ("M081", "без удаления невидимых символов", "s = \"\".join(ch for ch in s if not _ignorable(ch))", "s = s"),
    ("M082", "без конфузаблов", [".translate(_CONFUSABLE)  # before", "_drop_marks(s).translate(_CONFUSABLE))", ".translate(_CONFUSABLE_LOW)"], ["  # before", "_drop_marks(s))", ""]),
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
    ("M304", "скелет — ошибка и для оборудования (RR-02)", 'soft.append(("equipment", i["site_id"] + "|" + tag_compact(norm(i["tag"]))))', 'strong.append(("equipment", i["site_id"] + "|" + tag_compact(norm(i["tag"]))))'),
    ("M305", "понятие по скелету — ошибка (RR-02)", 'soft.append(("concept", ns + norm(i["label"])))', 'strong.append(("concept", ns + norm(i["label"])))'),
    ("M306", "предупреждение о возможном дубле не выдаётся", "        if open_pairs:", "        if False:"),
    ("M307", "предупреждение и для различённых пометками", "- reported - separated - distinct_pairs", "- reported - distinct_pairs"),
    ("M308", "тег с разделителями — разные (RR-03f)", "        if s[i] in _SEP:", "        if False:"),
    ("M309", "регистрационные номера без нормализации (RR-03d)", 'return "".join(ch for ch in base_key(unicodedata.normalize("NFKC", v)) if ch not in " -_./")', "return v"),
    ("M310", "без свёртки ширины (N097)", 'unicodedata.normalize("NFKC", ch) if unicodedata.decomposition(ch).startswith(("<wide>", "<narrow>")) else ch', "ch"),
    ("M311", "двойники заменяются только после casefold (RR-02)", [".translate(_CONFUSABLE)  # before", "_drop_marks(s).translate(_CONFUSABLE))"], ["  # before", "_drop_marks(s))"]),
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
    ("M323", "свободный текст только по имени ключа (RR-10)", '(key == "value" and parent.get("type") == "STRING")', '(key == "value" and False)'),
    ("M324", "свободный текст — любое поле value", '(key == "value" and parent.get("type") == "STRING")', '(key == "value")'),
    ("M325", "контрольная сумма литерала (RR-11)", 'if not (_ascii_digits(lit["value"]) and CHECKSUMS[lit["scheme"]](lit["value"])):', "if False:"),
    ("M326", "тип сущности не в ключе индекса (RR-12)", 'strong_idx[(e["project_id"], t, x)].add(owner)', 'strong_idx[(e["project_id"], "", x)].add(owner)'),
    ("M327", "одиночное место не отделяет (RR-03a)", "if qa is not None and qb is not None and qa != qb and max(ca, cb) >= max(ta or ca, tb or cb):", "if qa != qb and max(ca, cb) >= max(ta or ca, tb or cb):"),
    ("M328", "нет ни предела глубины, ни перехвата RecursionError (RR-05, пара M317+M318)",
     ["if depth >= MAX_DEPTH:", "    except RecursionError:\n        R.err(\"SCHEMA_INVALID\", \"/\", \"слишком глубокая вложенность\")\n        return R"],
     ["if False:", "    except ZeroDivisionError:\n        return R"]),
    # v0.2.2: skeleton (RS-12), tag/model keys (RS-14), identity decisions (RS-13, RS-15)
    ("M400", "комбинирующие ударения не снимаются", 's = "".join(ch for ch in s if not any(a <= ord(ch) <= b for a, b in _MARKS))', "s = s"),
    ("M401", "снимается и бреве (й -> и)", "(0x0300, 0x0305), (0x0307, 0x0307), (0x0309, 0x036F)", "(0x0300, 0x036F)"),
    ("M402", "армянская օ не двойник", '0x0555: "О", 0x0585: "о",', ""),
    ("M403", "капитель ᴏ не двойник", '0x1D0D: "м", 0x1D0F: "о",', '0x1D0D: "м",'),
    ("M404", "лунная сигма не двойник", '0x03F9: "С", 0x03F2: "с",', ""),
    ("M405", "чероки Ꭺ не двойник", '0x13AA: "А", ', ""),
    ("M406", "нет второго прохода таблицы двойников после casefold", ".translate(_CONFUSABLE_LOW).replace", ".replace"),
    ("M407", "пробел Брайля не невидимый", ",\n              (0x2800, 0x2800))", ")"),
    ("M408", "двойники не заменяются до NFKC (Ϲ -> Σ)", 's = _width(unicodedata.normalize("NFC", s)).translate(_CONFUSABLE)  # before', 's = _width(unicodedata.normalize("NFC", s))  # before'),
    ("M409", "ширина не сворачивается до таблицы двойников", 's = _width(unicodedata.normalize("NFC", s)).translate(_CONFUSABLE)  # before', 's = unicodedata.normalize("NFC", s).translate(_CONFUSABLE)  # before'),
    ("M410", "латинская ë не двойник", '0x00EB: "ё", 0x00CB: "Ё", ', ""),
    ("M411", "границы групп в теге не сохраняются (К-1/12 = К-11/2)", 'if out and j < len(s) and (out[-1] in "0123456789") == (s[j] in "0123456789"):', "if False:"),
    ("M412", "любая граница в теге значима (Н101 != Н-101)", 'if out and j < len(s) and (out[-1] in "0123456789") == (s[j] in "0123456789"):', "if out and j < len(s):"),
    ("M413", "мягкий ключ тега с границами групп", 'tag_compact(norm(i["tag"]))', 'tag_norm(norm(i["tag"]))'),
    ("M414", "NFKC в ключе модели (10² = 102)", 'norm(i["manufacturer"], nfkc=False) + "|" + norm(i["model"], nfkc=False)', 'norm(i["manufacturer"], nfkc=False) + "|" + norm(i["model"])'),
    ("M421", "уточнять можно любой тип", 'fits = (t in ("EVENT", "CONFLICT", "CONCEPT") or (t == "PERSON" and "birth_date" in idn)) and field in d', "fits = field in d"),
    ("M422", "уточнение поверх имеющегося поля", "if not fits or field in idn or ", "if not fits or "),
    ("M423", "уточнение слитой сущности", ' or merged_before', ""),
    ("M423b", "уточнение слитой позже сущности отвергается", ' and e["status_changed_at"] <= d["decided_at"]', ""),
    ("M424", "повторное уточнение", " or eid in qualify:", ":"),
    ("M425", "«различны» для разных типов", 'if ents[0]["entity_type"] != ents[1]["entity_type"]:', "if False:"),
    ("M426", "«различны» для слитых", "elif resolve(ids[0]) == resolve(ids[1]):", "elif False:"),
    ("M427", "«различны» не снимает предупреждение", "- reported - separated - distinct_pairs", "- reported - separated"),
    ("M428", "время решения не проверяется", 'if any(d["decided_at"] < x["created_at"] for x in ents):', "if False:"),
    ("M429", "проект сущности решения не проверяется", 'if any(x["project_id"] != d["project_id"] for x in ents):', "if False:"),
    ("M430", "проект решения не проверяется", 'if d["project_id"] not in P or None in ents:', "if None in ents:"),
    ("M432", "у события уточняется disambiguator, а не место", 'field = "place" if t in ("EVENT", "CONFLICT") else "disambiguator"', 'field = "disambiguator"'),
    ("M433", "предупреждение при любом пересечении (без попарного учёта)", "open_pairs = {frozenset((a, b)) for a in owners for b in owners if a < b} - reported - separated - distinct_pairs",
     "open_pairs = {frozenset((a, b)) for a in owners for b in owners if a < b}"),
    ("M434", "уточнение без нужного поля", ') and field in d\n', ')\n'),
    ("M435", "уточнение действует задним числом (омоним до уточнения)", " and max(ca, cb) >= max(ta or ca, tb or cb):", ":"),
    ("M436", "уточнение выжившей не распространяется на ключи слитых в неё", "            if qual is None and owner in qual_at:\n", "            if False:\n"),
    ("M437", "слияние в более широкую маркировку (S22-01)", '            elif not dominates(e["marking"], t["marking"]):', "            elif False:"),
    ("M438", "Проверка уже предыдущей (S22-03)", '            elif not dominates(k["marking"], pv["marking"]):', "            elif False:"),
    ("M439", "предыдущая Проверка не завершена (S23-01)", '            elif pv["status"] != "COMPLETED" or pv["completed_at"] > k["requested_at"]:', "            elif False:"),
]
M += [  # v0.2.4 (S4): artifacts and graph nodes (RR-07)
    ("M500", "нет байтов артефакта — молча", 'R.err("ARTIFACT_INVALID", ref, "нет байтов артефакта в хранилище — receipt не проверяем (RR-07)")\n            return None', "return None"),
    ("M501", "адрес артефакта не сверяется", '"sha256:" + hashlib.sha256(b).hexdigest() != dg', "False"),
    ("M502", "каноническая форма не требуется", 'if canon(art).encode("utf-8") != b:', "if False:"),
    ("M503", "повтор ключей допускается", "object_pairs_hook=_no_dup", "object_pairs_hook=dict"),
    ("M504", "схема артефакта не проверяется", "errs = list(ARTIFACT_V.iter_errors(art))", "errs = []"),
    ("M505", "профиль чисел артефакта не проверяется", 'if raw:\n        return None, "артефакт: "', 'if False:\n        return None, "артефакт: "'),
    ("M506", "неизвестный профиль принимается", 'if prof is None:\n            R.err("ARTIFACT_INVALID", ref, "неизвестный', 'if False:\n            R.err("ARTIFACT_INVALID", ref, "неизвестный'),
    ("M507", "повтор id узла", 'if n["id"] in nodes:\n                bad.append', 'if False:\n                bad.append'),
    ("M508", "якорь вне входов", 'if an["source_id"] not in art["inputs"]:', "if False:"),
    ("M509", "границы якоря", 'ok = an["start"] < an["end"] <= len(sb)', "ok = True"),
    ("M510", "якорь режет UTF-8", 'sb[an["start"]:an["end"]].decode("utf-8")', 'sb[an["start"]:an["end"]]'),
    ("M511", "ссылка на несуществующий узел", "if a0 is None or a1 is None or (", "if ("),
    ("M512", "условие не CONDITION", '("condition" in n and nodes.get(n["condition"], {}).get("type") != "CONDITION")', "False"),
    ("M513", "отношение не по профилю", "if spec is not None and not (", "if False and not ("),
    ("M514", "receipt ↔ артефакт не сверяются", 'if (art["artifact_format"] != r["artifact_schema_version"]', 'if False and (art["artifact_format"] != r["artifact_schema_version"]'),
    ("M515", "служба артефакта", ' or art["producer"] != r["producer"]', ""),
    ("M516", "запуск артефакта", ' or art["run_id"] != r["run_id"]', ""),
    ("M517", "входы артефакта", '\n                or set(art["inputs"]) != set(r["input_source_ids"]))', ")"),
    ("M518", "профиль артефакта", ' or art["semantic_profile"] != r["semantic_profile_version"]', ""),
    ("M519", "формат артефакта", 'art["artifact_format"] != r["artifact_schema_version"] or ', ""),
    ("M520", "утверждение без узла — молча", 'R.err("GRAPH_NODE_INVALID", cid, "доказательство утверждения из артефакта без узла графа")\n                continue', "continue"),
    ("M521", "узел-не-отношение принимается", 'if n is None or n["type"] != "RELATION":', "if n is None:"),
    ("M521b", "несуществующий узел принимается", 'if n is None or n["type"] != "RELATION":', "if False:"),
    ("M522", "фрагмент вне якоря", 'if an["source_id"] != ev["source_id"] or not (an["start"] <= sp["start"] and sp["end"] <= an["end"]):', "if False:"),
    ("M523", "начало фрагмента до якоря", 'an["start"] <= sp["start"] and ', ""),
    ("M524", "конец фрагмента после якоря", 'sp["end"] <= an["end"]', "True"),
    ("M525", "источник фрагмента не сверяется с якорем", 'an["source_id"] != ev["source_id"] or ', ""),
    ("M526", "смысл узла не сверяется", "why = graph_says(c, n, nodes, roles)", "why = None"),
    ("M527", "неотображаемая роль", 'if spec is None:\n            return f"роль', 'if False:\n            return f"роль'),
    ("M528", "предикат по роли", 'if c["predicate"] != spec["predicate"]:', "if False:"),
    ("M529", "субъект по узлу", 'if not same_entity(E.get(c["subject"]), a0, c["recorded_at"]):', "if False:"),
    ("M530", "объект-сущность по узлу", 'ok = "entity" in obj and same_entity(E.get(obj["entity"]), a1, c["recorded_at"])', 'ok = "entity" in obj'),
    ("M531", "величина по узлу", 'ok = obj.get("literal") == {"type": "QUANTITY", "value": a1["value"], "unit": a1["unit"]}', "ok = True"),
    ("M532", "действие по узлу", 'ok = obj.get("literal") == {"type": "STRING", "value": a1["text"]}', "ok = True"),
    ("M533", "уточнения по узлу", 'if c.get("qualifiers", {}) != want:', "if False:"),
    ("M534", "условие по узлу", 'want = {"condition": nodes[n["condition"]]["text"]}', 'want = c.get("qualifiers", {})'),
    ("M535", "параметр по узлу", 'want = {"parameter": n["parameter"]}', 'want = c.get("qualifiers", {})'),
    ("M536", "тип сущности узла", ' or e["entity_type"] != node["entity_type"]:', ":"),
    ("M537", "один узел — одно доказательство", "if len(cids) > 1:", "if False:"),
    ("M538", "текст действия не свободный текст", ' or (key == "text" and parent.get("type") == "ACTION")', ""),
    ("M539", "строгие ключи узла не сверяются", "return bool(nk) and nk <= group", "return True"),
    # review S4
    ("M540", "ключи слитых в группу не входят (S4R-02)", ' or (merged_by(x, t) and x["merged_into"] == owner)', ""),
    ("M544", "группа по итоговому состоянию слияний (S4R-11)", 'return x["status"] == "MERGED" and x["status_changed_at"] <= t', 'return x["status"] == "MERGED"'),
    ("M541", "срок действия у утверждения из узла (S4R-01)", 'if "valid_from" in c or "valid_to" in c:', "if False:"),
    ("M542", "достаточно одного доказательства с узлом (S4R-07)", 'if any("graph_node" not in ev for ev in c["evidence"]):', 'if all("graph_node" not in ev for ev in c["evidence"]):'),
    ("M543", "повтор запуска (S4R-08)", "if len(rids) > 1:", "if False:"),
]

# Survivors that cannot be killed by ANY input, with the reason (defence in depth, reviewed by hand).
M += [  # v0.2.5 (S5): publications
    ('M600', 'адрес публикации не сверяется', 'if publication_address(pb["tenant_id"], pb["outlet"], pb["text_digest"]) != pid:', 'if False:'),
    ('M601', 'канонический адрес не сверяется с нормальной формой', 'if url_norm(pb["canonical_url"]) != pb["canonical_url"] or url_outlet(pb["canonical_url"]) != pb["outlet"]:', 'if url_outlet(pb["canonical_url"]) != pb["outlet"]:'),
    ('M602', 'издание канонического адреса не сверяется', 'if url_norm(pb["canonical_url"]) != pb["canonical_url"] or url_outlet(pb["canonical_url"]) != pb["outlet"]:', 'if url_norm(pb["canonical_url"]) != pb["canonical_url"]:'),
    ('M603', 'основание — и полученные после recorded_at', 'if not seen or min(seen) > pb["recorded_at"]:', 'if not seen:'),
    ('M604', 'текст рендеринга не сверяется', 'if src_text.get(sid) == pb["text_digest"]:', 'if True:'),
    ('M605', 'публикация без оснований принимается', 'R.err("PUBLICATION_INVALID", pid, "нет ни одного источника этого издания с этим текстом, полученного к recorded_at")', 'pass'),
    ('M606', 'маркировка рендерингов', 'if not dominates(pb["marking"], s["marking"]):\n                R.err("MARKING_BROADER_THAN_INPUT", pid', 'if False:\n                R.err("MARKING_BROADER_THAN_INPUT", pid'),
    ('M607', 'дата выхода публикации', 'if "published_at" in pb and pb["published_at"] > min(f for _, f in basis):', 'if False:'),
    ('M608', 'пробелы не схлопываются', '        if ch in _PUB_WS:\n            sp = True\n            continue', '        if False:\n            sp = True\n            continue'),
    ('M609', 'невидимые символы остаются', '"".join(ch for ch in text if not _ignorable(ch))', 'text'),
    ('M610', 'метки utm_ остаются', 'not (p.split("=", 1)[0].lower().startswith("utm_") or ', 'not (False or '),
    ('M611', 'параметры не упорядочиваются', 'keep = sorted(p for p in', 'keep = list(p for p in'),
    ('M612', 'порт по умолчанию остаётся', 'if port and not ((scheme, port) in (("http", "80"), ("https", "443"))):', 'if port:'),
    ('M613', 'мобильная версия — другое издание', 'for pre in ("www.", "m.", "amp."):', 'for pre in ("www.",):'),
    ('M614', 'издание наблюдения не сверяется', 'seen = [o["observed_at"] for o in s["observations"] if url_outlet(o["origin_uri"]) == pb["outlet"]]', 'seen = [o["observed_at"] for o in s["observations"]]'),
    ('M615', 'публикация чужого tenant', '            if s["tenant_id"] != pb["tenant_id"]:\n                continue', '            if False:\n                continue'),
    ("M616", "путь адреса может начинаться не с «/» (S5R-09)", "(?::([0-9]{1,5}))?(/[^?#]*)?(?:", "(?::([0-9]{1,5}))?([^?#]*)(?:"),
]

M += [  # v0.2.6 (S5 part 2): originals
    ('M700', 'оригинала нет в хранилище — молча', 'if ob is None:\n                R.err("ORIGINAL_INVALID", sid, f"observations[{n}]: оригинала нет в хранилище объектов")\n            elif', 'if ob is None:\n                pass\n            elif'),
    ('M701', 'адрес оригинала не сверяется', '"sha256:" + hashlib.sha256(ob).hexdigest() != og["object"] or len(ob)', 'len(ob)'),
    ('M702', 'длина оригинала не сверяется', ' or len(ob) != og["byte_length"]:', ':'),
    # S6R-12: val_mutants.py (independent review mutants) found these three gaps in the VECTOR set, not in the
    # rule itself — the rule already guards against all three; these mutants exist so core/mutants.py also
    # exercises them (N704/N705/N706 are the kills).
    ('M703', 'оригинал проверяется только у первого наблюдения источника', 'for n, o in enumerate(s["observations"]):', 'for n, o in enumerate(s["observations"][:1]):'),
    ('M704', 'длина: не замечает оригинал короче заявленного', '!= og["byte_length"]:', '> og["byte_length"]:'),
    ('M705', 'оригинал не проверяется у источника без байтов текста в хранилище', 'if og is None:\n                continue', 'if og is None or sid not in source_bytes:\n                continue'),
]

M += [  # v0.3 (cycle 9, D27.1): schema as data — ClassDef / LinkDef / IdentifierDef, schema.is_a, tenant predicates «x.…»
    # keys, versions, journal entry of a version
    ("M900", "ключ записи схемы без версии", 'rid = (r["tenant_id"], rid, r["version"])', 'rid = (r["tenant_id"], rid)'),
    ("M901", "ключ записи схемы без tenant", 'rid = (r["tenant_id"], rid, r["version"])', 'rid = (rid, r["version"])'),
    ("M902", "версии подряд не проверяются", 'if [r["version"] for r in lst] != list(range(1, len(lst) + 1)):', "if False:"),
    ("M903", "версия вне цепочки остаётся в схеме", 'del lst[next((n for n, r in enumerate(lst) if r["version"] != n + 1), len(lst)):]', "pass"),
    ("M904", "версии не упорядочиваются", 'lst.sort(key=lambda r: r["version"])', "pass"),
    ("M905", "время версий не сверяется", 'if prev is not None and r["change"]["recorded_at"] <= prev["change"]["recorded_at"]:', "if False:"),
    ("M906", "версии в одну секунду", 'r["change"]["recorded_at"] <= prev["change"]["recorded_at"]:', 'r["change"]["recorded_at"] < prev["change"]["recorded_at"]:'),
    ("M907", "тип изменения берётся на слово", 'if schema_change_of(k, prev, r) != r["change"]["type"]:', "if schema_change_of(k, prev, r) is None:"),
    ("M908", "незаконная версия остаётся в схеме", 'del lst[r["version"] - 1:]      # a version that is not a lawful change is not part of the schema', "pass"),
    ("M909", "тип первой версии не проверяется", "return _FIRST_CHANGE[kind]", 'return cur["change"]["type"]'),
    ("M910", "вывод из употребления не окончателен", 'if prev.get("deprecated"):\n        return None', 'if False:\n        return None'),
    ("M911", "переименование вместе с другим изменением", 'if changed == {"name"}:', 'if "name" in changed:'),
    ("M912", "вывод из употребления вместе с другим изменением", 'if changed == {"deprecated"}:', 'if "deprecated" in changed:'),
    ("M913", "смена силы вместе с другим изменением", 'if kind == "IdentifierDef" and changed == {"strength"}:', 'if kind == "IdentifierDef" and "strength" in changed:'),
    ("M914", "ADD_ATTRIBUTE: несколько атрибутов", "if len(added) == 1 and not removed and not diff:", "if added and not removed and not diff:"),
    ("M915", "ADD_ATTRIBUTE вместе с удалением", "if len(added) == 1 and not removed and not diff:", "if len(added) == 1 and not diff:"),
    ("M916", "REMOVE_ATTRIBUTE: несколько атрибутов", "if len(removed) == 1 and not added and not diff:", "if removed and not added and not diff:"),
    ("M917", "REMOVE_ATTRIBUTE вместе с добавлением", "if len(removed) == 1 and not added and not diff:", "if len(removed) == 1 and not diff:"),
    ("M918", "CHANGE_ATTRIBUTE: тип значения можно менять", " and all(pa[diff[0]].get(f) == ca[diff[0]].get(f) for f in _ATTR_FROZEN):", ":"),
    ("M919", "CHANGE_ATTRIBUTE: несколько атрибутов", "if len(diff) == 1 and not added and not removed and", "if diff and not added and not removed and"),
    ("M920", "CHANGE_ATTRIBUTE вместе с добавлением", "if len(diff) == 1 and not added and not removed and", "if len(diff) == 1 and"),
    # the schema at moment t
    ("M921", "всегда последняя версия", 'ok = [r for r in lst if t is None or r["change"]["recorded_at"] <= t]', "ok = list(lst)"),
    ("M922", "«к моменту t» не включает t", 'ok = [r for r in lst if t is None or r["change"]["recorded_at"] <= t]', 'ok = [r for r in lst if t is None or r["change"]["recorded_at"] < t]'),
    ("M923", "отсутствующий класс — молча", 'R.err("REF_UNRESOLVED", ref, f"{what}: класса {class_id} нет в схеме tenant")', "pass"),
    ("M924", "класс ищется во всех tenant", "lst = CLS.get((tn, class_id))", "lst = next((v for (t2, c2), v in CLS.items() if c2 == class_id), None)"),
    ("M925", "класс записан позже ссылки — молча", 'if v is None:\n            R.err("TEMPORAL_ORDER_INVALID", ref, f"{what}: класс', 'if False:\n            R.err("TEMPORAL_ORDER_INVALID", ref, f"{what}: класс'),
    # one definer of a tenant predicate
    ("M926", "второй определитель предиката", "if (kind, did) != first:", "if False:"),
    ("M927", "предикат достаётся последнему определителю", "first = min(who, key=lambda d: (who[d], d))", "first = max(who, key=lambda d: (who[d], d))"),
    # identifier definitions
    ("M928", "тип идентификатора ищется во всех tenant", 'if tn2 == tn and lst and lst[0]["scheme"] == scheme', 'if lst and lst[0]["scheme"] == scheme'),
    ("M929", "тип идентификатора без учёта корневого типа", ' and lst[0]["applies_to_root_type"] == root_type:', ":"),
    ("M930", "выведенный из употребления тип идентификатора действует", 'if v is not None and not v.get("deprecated"):', "if v is not None:"),
    # ClassDef
    ("M931", "цикл наследования", 'if did in ancestors(tn, first["parent_class_id"]):', "if False:"),
    ("M932", "корневой тип родителя", 'if par["root_type"] != first["root_type"]:', "if False:"),
    ("M933", "родитель выведен из употребления", 'if par.get("deprecated"):', "if False:"),
    ("M934", "маркировка родителя", 'if not dominates(first["marking"], par["marking"]):', "if False:"),
    ("M935", "родитель — по последней версии, а не на момент создания наследника", 'par = class_at(ref, tn, first["parent_class_id"], t1, "родитель")', 'par = class_at(ref, tn, first["parent_class_id"], None, "родитель")'),
    ("M936", "повтор атрибута", 'if len({a["predicate_id"] for a in attrs}) != len(attrs):', "if False:"),
    ("M937", "тип идентификатора атрибута не проверяется", ' \\\n                        and idef_at(tn, a["scheme"], r["root_type"], r["change"]["recorded_at"]) is None:', " and False:"),
    ("M938", "встроенная схема требует определения tenant", ' and a["scheme"] not in CHECKSUMS \\\n', " \\\n"),
    ("M939", "тип идентификатора проверяется у нетронутых атрибутов", 'if a != prev.get(a["predicate_id"]) and a["value_type"] == "IDENTIFIER"', 'if a["value_type"] == "IDENTIFIER"'),
    ("M940", "тип идентификатора атрибута — по последней версии", 'idef_at(tn, a["scheme"], r["root_type"], r["change"]["recorded_at"]) is None:', 'idef_at(tn, a["scheme"], r["root_type"], None) is None:'),
    # LinkDef
    ("M941", "класс-диапазон связи не проверяется", 'for f in ("domain_class_id", "range_class_id"):', 'for f in ("domain_class_id",):'),
    ("M942", "класс-домен связи не проверяется", 'for f in ("domain_class_id", "range_class_id"):', 'for f in ("range_class_id",):'),
    ("M943", "класс связи выведен из употребления", 'if cl.get("deprecated"):\n                    R.err("SCHEMA_DEF_INVALID", ref, f"{f}: класс', 'if False:\n                    R.err("SCHEMA_DEF_INVALID", ref, f"{f}: класс'),
    ("M944", "маркировка класса связи", 'if not dominates(first["marking"], cl["marking"]):', "if False:"),
    ("M945", "симметричная связь разных классов", 'if first.get("symmetric") and first["domain_class_id"] != first["range_class_id"]:', "if False:"),
    ("M946", "класс связи — по последней версии", 'cl = class_at(ref, tn, first[f], first["change"]["recorded_at"], f)', "cl = class_at(ref, tn, first[f], None, f)"),
    # IdentifierDef
    ("M947", "повтор схемы идентификатора", "if seen_scheme.setdefault(k1, did) != did:", "if False:"),
    ("M948", "схема идентификатора без учёта корневого типа", 'k1 = (tn, first["scheme"], first["applies_to_root_type"])', 'k1 = (tn, first["scheme"])'),
    ("M949", "схема идентификатора без учёта tenant", 'k1 = (tn, first["scheme"], first["applies_to_root_type"])', 'k1 = (first["scheme"], first["applies_to_root_type"])'),
    ("M950", "повтор приоритета", "if seen_prio.setdefault(k2, did) != did:", "if False:"),
    ("M951", "приоритет без учёта корневого типа", 'k2 = (tn, first["applies_to_root_type"], first["priority"])', 'k2 = (tn, first["priority"])'),
    ("M952", "формат: min > max", 'any(x["min"] > x["max"] for x in first["format"] if "chars" in x)\n                                  or ', ""),
    ("M953", "формат: длина", '\n                                  or sum(x.get("max", 1) for x in first["format"]) > 64', ""),
    # tenant predicate at the time of the claim
    ("M954", "выведенная из употребления связь действует", 'if v is None or v.get("deprecated"):', "if v is None:"),
    ("M955", "связь — по последней версии", "v = at(LNK[(tn, did)], t)", "v = at(LNK[(tn, did)], None)"),
    ("M956", "атрибут — по последней версии класса", "v = at(CLS[(tn, did)], t)", "v = at(CLS[(tn, did)], None)"),
    # claims
    ("M957", "значение идентификатора tenant не сверяется с форматом", 'elif not re.fullmatch(format_regex(idf["format"]), lit["value"]):', "elif False:"),
    ("M958", "формат — совпадение начала, а не всего значения", 're.fullmatch(format_regex(idf["format"]), lit["value"])', 're.match(format_regex(idf["format"]), lit["value"])'),
    ("M959", "литерал формата не экранируется", 'else re.escape(x["lit"])', 'else x["lit"]'),
    ("M960", "тип идентификатора утверждения — по последней версии", 'idf = idef_at(tn, lit["scheme"], subj["entity_type"], t_rec)', 'idf = idef_at(tn, lit["scheme"], subj["entity_type"], None)'),
    ("M961", "неизвестный предикат tenant — молча", "R.err(\"PREDICATE_UNKNOWN\", cid, f\"{c['predicate']}: в схеме tenant на момент записи такого предиката нет\")", "pass"),
    ("M962", "принадлежность субъекта классу не проверяется", 'if subj is not None and not instance_of(tn, c["project_id"], subj["entity_id"], xp["class_id"], t_rec):', "if False:"),
    ("M963", "принадлежность без учёта времени", "return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k) for rt, k, icid in member.get((prj, eid), ()))", "return any(stands(icid, t) and class_id in ancestors(tn, k) for rt, k, icid in member.get((prj, eid), ()))"),
    ("M964", "принадлежность без наследования", "return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k) for rt, k, icid in member.get((prj, eid), ()))", "return any(rt <= t and stands(icid, t) and class_id == k for rt, k, icid in member.get((prj, eid), ()))"),
    ("M965", "наследование вверх по дереву", "return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k) for rt, k, icid in member.get((prj, eid), ()))", "return any(rt <= t and stands(icid, t) and k in ancestors(tn, class_id) for rt, k, icid in member.get((prj, eid), ()))"),
    ("M966", "тип значения атрибута", 'if (lit is None or lit["type"] != a["value_type"] or lit.get("unit") != a.get("unit")', 'if (lit is None or lit.get("unit") != a.get("unit")'),
    ("M967", "единица атрибута", ' or lit.get("unit") != a.get("unit")', ""),
    ("M968", "схема идентификатора атрибута", '\n                            or (lit["type"] == "IDENTIFIER" and lit["scheme"] != a["scheme"])):', "):"),
    ("M969", "литерал как объект связи", "if lit is not None or (obj_ent is not None", "if (obj_ent is not None"),
    ("M970", "объект связи не проверяется на класс", '\n                                           and not instance_of(tn, c["project_id"], obj_ent["entity_id"], rng_class, t_rec)):', " and False):"),
    ("M971", "квалификаторы у предиката tenant", 'if c.get("qualifiers"):', "if False:"),
    ("M972", "маркировка определения предиката", 'if not dominates(c["marking"], xp["marking"]):', "if False:"),
    # schema.is_a
    ("M973", "schema.is_a не проверяется", 'if c["predicate"] == "schema.is_a" and lit is not None and lit["type"] == "CLASS_REF":', "if False:"),
    ("M974", "абстрактный класс", 'if cl.get("is_abstract") or cl.get("deprecated"):', 'if cl.get("deprecated"):'),
    ("M975", "класс выведен из употребления", 'if cl.get("is_abstract") or cl.get("deprecated"):', 'if cl.get("is_abstract"):'),
    ("M976", "корневой тип класса", 'if subj is not None and subj["entity_type"] != cl["root_type"]:', "if False:"),
    ("M977", "маркировка класса", 'if not dominates(c["marking"], cl["marking"]):', "if False:"),
    ("M978", "класс — по последней версии, а не на момент утверждения", 'cl = class_at(cid, tn, lit["class_id"], t_rec, "schema.is_a")', 'cl = class_at(cid, tn, lit["class_id"], None, "schema.is_a")'),
    # cardinality, dimensions, required attributes
    ("M979", "кардинальность ONE у предиката tenant", 'p = preds.get(c["predicate"]) or xpred_of.get(cid)\n        if p and p["cardinality"]', 'p = preds.get(c["predicate"])\n        if p and p["cardinality"]'),
    ("M980", "предикат tenant в измерении Проверки", 'p = preds.get(c["predicate"]) or xpred_of.get(cid)\n                if p is not None and f["dimension"]', 'p = preds.get(c["predicate"])\n                if p is not None and f["dimension"]'),
    ("M981", "обязательность не проверяется", 'if a["required"]:', "if False:"),
    ("M982", "отозванное утверждение закрывает обязательный атрибут", 'if status_at(cid, None) not in ("REFUTED", "WITHDRAWN")}', "if True}"),
    ("M983", "обязательные атрибуты предков не наследуются", "for anc in ancestors(tn, k):\n                for a in at(CLS[(tn, anc)], None)", "for anc in ancestors(tn, k)[:1]:\n                for a in at(CLS[(tn, anc)], None)"),
    ("M993", "тип значения атрибута не заморожен", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("unit", "scheme")'),
    ("M994", "единица атрибута не заморожена", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("value_type", "scheme")'),
    ("M995", "схема идентификатора атрибута не заморожена", '_ATTR_FROZEN = ("value_type", "unit", "scheme")', '_ATTR_FROZEN = ("value_type", "unit")'),
    ("M996", "опровергнутая принадлежность классу действует", 'return not lst or max(lst)[1] not in ("REFUTED", "WITHDRAWN")', 'return not lst or max(lst)[1] not in ("WITHDRAWN",)'),
    ("M997", "контрольные цифры встроенной схемы только у предикатов реестра", 'if lit is not None and lit["type"] == "IDENTIFIER" and lit["scheme"] in CHECKSUMS:', 'if p is not None and lit is not None and lit["type"] == "IDENTIFIER" and lit["scheme"] in CHECKSUMS:'),
    ("M989", "отозванная принадлежность классу действует", "return any(rt <= t and stands(icid, t) and class_id in ancestors(tn, k)", "return any(rt <= t and class_id in ancestors(tn, k)"),
    ("M990", "отзыв принадлежности действует задним числом", "lst = [x for x in rv_idx.get(cid, ()) if x[0] <= t]", "lst = list(rv_idx.get(cid, ()))"),
    ("M991", "учитывается первая рецензия, а не последняя к моменту t", 'return not lst or max(lst)[1] not in ("REFUTED", "WITHDRAWN")', 'return not lst or min(lst)[1] not in ("REFUTED", "WITHDRAWN")'),
    ("M992", "отозванная принадлежность требует обязательных атрибутов", 'if status_at(icid, None) in ("REFUTED", "WITHDRAWN"):\n                continue                                   # a withdrawn', 'if False:\n                continue                                   # a withdrawn'),
    ("M984", "обязательность — по первой версии класса", 'for a in at(CLS[(tn, anc)], None).get("attributes", []):', 'for a in CLS[(tn, anc)][0].get("attributes", []):'),
    # THING
    ("M985", "ключи вещи не строятся", 'weak.append(("thing", ns + base_key(i["label"]), i.get("disambiguator")))', "pass"),
    ("M986", "пометка вещи не разделяет тёзок", 'weak.append(("thing", ns + base_key(i["label"]), i.get("disambiguator")))', 'weak.append(("thing", ns + base_key(i["label"]), None))'),
    ("M987", "скелет вещи не строится", 'soft.append(("thing", ns + norm(i["label"])))', "pass"),
    ("M988", "уточнение вещи решением аналитика", 'fits = (t in ("EVENT", "CONFLICT", "CONCEPT", "THING")', 'fits = (t in ("EVENT", "CONFLICT", "CONCEPT")'),
]

EQUIVALENT = {
    "M001": "float всё равно отвергается последней веткой фазы 0 («недопустимый тип»); отдельная ветка нужна только для понятного сообщения",
    "M005": "ключи-строки с суррогатами/управляющими символами отвергает схема: все объекты закрыты, у qualifiers есть propertyNames",
    "M006": "перевод строки в структурных полях отвергает фаза 0 (управляющие символы); у свободного текста нет якорных шаблонов",
    "M317": "защита в глубину: все объекты схемы закрыты, поэтому вложенность глубже 64 отвергает схема (SCHEMA_INVALID), а глубже предела рекурсии — перехват RecursionError; без обеих защит мутант M328 убит",
    "M503": "защита в глубину: байты с повторяющимся ключом не могут совпасть с канонической формой (RFC 8785 выводит каждый ключ один раз), поэтому их отвергает проверка канонической формы",
    "M616": "защита в глубину: без требования «/» нормальная форма склеивает хост с мусором («news.exampleevil…», «news.example@…»), такое издание не совпадает ни с одним настоящим, поэтому рендерингом не становится; каноническому адресу «/» требует схема; правило нужно для паритета с базой (parity_s5)",
    "M536": "типы EQUIPMENT и EQUIPMENT_MODEL дают строгие ключи разных схем (equipment / equipment_model), поэтому при разных типах ключи не совпадут и без этого условия",
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

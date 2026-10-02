#!/usr/bin/env python3
"""S9 acceptance (cycle 9, D27.1 «Схема как данные»): the tenant's schema as records in PostgreSQL.

S9-01 the world loads with its schema; the closure of the class tree equals a recursive computation; every tenant
      predicate has one owner.
S9-02 the model projection: classes with own and inherited attributes, links, identifier types, journal; time travel
      (as_of before a change shows the schema of that time); the reader's clearance hides INTERNAL definitions.
S9-03 live: the Model Constructor (ac_modeler) adds a class and an attribute — the database stamps the time itself
      (a supplied time from 1999 is ignored); the loader states membership and writes a claim with the new attribute.
S9-04 back-dating is refused: a claim whose declared time lies before the latest change of the definition it is
      checked against cannot be written live.
S9-05 required attributes: the gap is listed, disappears with the claim, comes back when the claim is withdrawn.
S9-06 the dossier renders schema.is_a and tenant-predicate claims with the names of the schema AT THE TIME asked.
S9-07 roles: the loader cannot change the schema, the modeler cannot write claims, nobody writes derived tables,
      readers have no table access.
S9-08 parity with the validator: every cycle-9 vector is loaded into a fresh database WITHOUT the validator gate —
      what the validator refuses the database refuses, what it accepts the database accepts.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/s9_tests.py [--no-parity]
"""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "store"))
import validator as VAL  # noqa: E402
from jcs import digest  # noqa: E402
from vectors import VECTORS, build  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
import load_s1 as L  # noqa: E402
import s3_tests as S3  # noqa: E402
from schema_s9 import write_schema  # noqa: E402

RES = []
PUB = {"level": "PUBLIC", "categories": []}
INT = {"level": "INTERNAL", "categories": []}
T, WK = "tnt_demo", "prj_wiki_whales"
S10 = "Синий кит — вид усатых китов. Длина синего кита достигает 30 метров, а масса — 150 тонн."
SETUP = """
DO $$ BEGIN CREATE ROLE ac_rd_wiki_int LOGIN IN ROLE ac_reader; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE ac_model_app LOGIN IN ROLE ac_modeler; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SET ROLE ac_trust_admin;
INSERT INTO ac_trust.clearances (role_name, project_id, level, categories, granted_at) VALUES
 ('ac_rd_wiki_int', 'prj_wiki_whales', 'INTERNAL', '{}', '2000-01-01');
RESET ROLE;
"""


def check(tid, cond, desc, detail=""):
    RES.append(bool(cond))
    print(f"{tid:<6} {'PASS' if cond else 'FAIL'} | {desc}" + (f" | {detail}" if detail else ""), flush=True)


def sql1(s, user=None):
    r = S3.psql(s, user)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def js(s, user="ac_rd_public"):
    return json.loads(sql1(s, user).splitlines()[-1])


def err(s, user=None):
    r = S3.psql(s, user)
    return r.stderr.strip().splitlines()[0] if r.returncode else "(принято)"


def sd(kind, did, version, ctype, at=None, marking=PUB, tenant=T, **body):
    idf = {"ClassDef": "class_id", "LinkDef": "link_id", "IdentifierDef": "idef_id"}[kind]
    return {"kind": kind, idf: did, "tenant_id": tenant, "version": version, **body, "marking": marking,
            "change": {"type": ctype, "description": "тест S9", "recorded_at": at or utc(0), "recorded_by": "usr_modeler1"}}


def claim(subj, pred, obj, quote, recorded=None, marking=PUB, prj=WK, text=S10):
    b, qb = text.encode("utf-8"), quote.encode("utf-8")
    st = b.find(qb)
    assert st >= 0
    c = {"kind": "Claim", "schema_version": "core-ontology/0.3", "project_id": prj, "subject": subj, "predicate": pred, "object": obj,
         "evidence": [{"source_id": "src:sha256:" + hashlib.sha256(b).hexdigest(), "span": {"start": st, "end": st + len(qb)},
                       "quote": quote, "quote_sha256": hashlib.sha256(qb).hexdigest()}],
         "produced_by": {"kind": "HUMAN", "actor_id": "usr_analyst1"}, "recorded_at": recorded or utc(0), "marking": marking}
    c["claim_id"] = "clm:sha256:" + digest(c)
    return c


def entity(eid, label, etype="CONCEPT", marking=PUB, prj=WK):
    return {"kind": "Entity", "entity_id": eid, "project_id": prj, "entity_type": etype, "status": "ACTIVE",
            "identity": {"label": label, "lang": "ru", "namespace": "s9test"}, "display_name": label,
            "created_at": utc(0), "marking": marking}


def kref(k):
    return {"literal": {"type": "CLASS_REF", "class_id": k}}


def ingest(*records, user="ac_loader"):
    return psql(ingest_sql(list(records), {}, user=user))


def first_err(r):
    return next((ln for ln in r.stderr.splitlines() if "ERROR" in ln), "(принято)").replace("psql:<stdin>:", "")


def model(user="ac_rd_public", as_of=None):
    a = f", {as_of!r}::timestamptz" if as_of else ""
    return js(f"SELECT ac.model('{WK}'{a});", user)


# vectors whose only defect the database cannot hold at all: the version marker of an entity record and of a schema
# definition is not stored (the tables have no such column) — nothing to refuse
NOT_IN_DB = {"N996": "пометка версии записи сущности в базе не хранится", "N999": "пометка версии записи определения в базе не хранится"}


def parity():
    """S9-08: every cycle-9 vector against a fresh database, no validator in front"""
    rows, wrong = [], []
    for v in VECTORS:
        if not (v["id"][1] == "9" and len(v["id"]) == 4):
            continue
        if v["id"] in NOT_IN_DB:
            rows.append((v["id"], "N/A", NOT_IN_DB[v["id"]]))
            continue
        ds, tr, ct = build(v)
        rep = VAL.validate(ds, tr, ct)
        must_refuse = bool(rep.errors) or any(w["code"] == "POSSIBLE_DUPLICATE" for w in rep.warnings)
        try:
            sql = L.load_sql(ds, tr, ct)
        except Exception as ex:  # noqa: BLE001 - not expressible as SQL at all (e.g. a format that is not a list)
            rows.append((v["id"], "N/A", type(ex).__name__))
            if not must_refuse:
                wrong.append(v["id"])
            continue
        L.psql(L.DDL_ALL)
        L.register_originals(ds, ct)
        r = L.psql(sql)
        refused = r.returncode != 0
        msg = first_err(r)[:120]
        code = next((c for c in VAL.ERROR_CODES + ["POSSIBLE_DUPLICATE"] if c in msg), "")
        same = bool(code) and (code in rep.codes() or code == "POSSIBLE_DUPLICATE")
        rows.append((v["id"], "REFUSED" if refused else "ACCEPTED", ("=" if same else "~") + " " + msg if refused else ""))
        if refused != must_refuse:
            wrong.append(v["id"])
    for r in rows:
        print("   ", " | ".join(r))
    neg = sum(1 for r in rows if r[1] == "REFUSED")
    same = sum(1 for r in rows if r[2].startswith("="))
    check("S9-08", not wrong, "паритет с валидатором на векторах цикла 9: отвергнутое валидатором база отвергает, принятое — принимает",
          f"векторов={len(rows)} отвергнуто={neg} (тем же кодом {same}) принято={sum(1 for r in rows if r[1] == 'ACCEPTED')} "
          f"не представимо в базе={sum(1 for r in rows if r[1] == 'N/A')} расхождений={len(wrong)} {wrong}")
    L.psql(L.DDL_ALL)


def main():
    if "--no-parity" not in sys.argv:
        parity()
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)
    print(r.stdout.strip())
    sql1(S3.SETUP)
    sql1(SETUP)

    # S9-01
    counts = sql1("SELECT (SELECT count(*) FROM ac.class_defs) || ' ' || (SELECT count(*) FROM ac.link_defs) || ' ' || "
                  "(SELECT count(*) FROM ac.identifier_defs) || ' ' || (SELECT count(*) FROM ac.schema_predicates)")
    closure_ok = sql1("""
      WITH RECURSIVE up(a, d, depth) AS (
        SELECT class_id, class_id, 0 FROM ac.class_defs WHERE version = 1 AND tenant_id = 'tnt_demo'
        UNION ALL
        SELECT p.parent_class_id, up.d, up.depth + 1 FROM up JOIN ac.class_defs p ON p.class_id = up.a AND p.version = 1
         AND p.tenant_id = 'tnt_demo' WHERE p.parent_class_id IS NOT NULL)
      SELECT NOT EXISTS (SELECT a, d, depth FROM up EXCEPT SELECT ancestor_id, descendant_id, depth FROM ac.class_closure WHERE tenant_id = 'tnt_demo')
         AND NOT EXISTS (SELECT ancestor_id, descendant_id, depth FROM ac.class_closure WHERE tenant_id = 'tnt_demo' EXCEPT SELECT a, d, depth FROM up)""")
    owners = sql1("SELECT string_agg(predicate_id || '=' || definer_id, ' ' ORDER BY predicate_id) FROM ac.schema_predicates")
    check("S9-01", counts == "5 1 1 4" and closure_ok == "t" and "x.max_length=sdf_whale_species" in owners
          and "x.belongs_to=sdf_belongs_to" in owners,
          "мир: 5 версий классов, 1 связь, 1 тип идентификатора; замыкание = рекурсивный расчёт; у каждого предиката tenant один владелец",
          f"{counts}; {owners}")

    # S9-02 model: inherited attributes, time travel, clearance
    time.sleep(1.1)
    before = utc(0)
    time.sleep(1.1)
    rank = {"predicate_id": "x.rank", "name": "ранг", "value_type": "STRING", "cardinality": "ONE", "required": False}
    w = write_schema([sd("ClassDef", "sdf_taxon", 2, "ADD_ATTRIBUTE", at="1999-12-31T00:00:00Z", root_type="CONCEPT", name="Таксон",
                         parent_class_id="sdf_organism", attributes=[rank]),
                      sd("ClassDef", "sdf_internal_notes", 1, "ADD_CLASS", marking=INT, root_type="CONCEPT", name="Служебный класс")],
                     user="ac_model_app")
    m_now, m_before, m_int = model(), model(as_of=before), model("ac_rd_wiki_int")
    whale = next(k for k in m_now["classes"] if k["class_id"] == "sdf_whale_species")
    whale_b = next(k for k in m_before["classes"] if k["class_id"] == "sdf_whale_species")
    attrs = [(a["predicate_id"], a["declared_in"]) for a in whale["attributes"]]
    check("S9-02a", w.returncode == 0 and ("x.rank", "sdf_taxon") in attrs and ("x.max_length", "sdf_whale_species") in attrs
          and "x.rank" not in [a["predicate_id"] for a in whale_b["attributes"]],
          "модель: атрибут, добавленный родителю, виден у наследника (declared_in = родитель); на момент до изменения его нет",
          f"сейчас {attrs}; до изменения {[a['predicate_id'] for a in whale_b['attributes']]}; {w.stderr.strip()[:100]}")
    ids_pub = {k["class_id"] for k in m_now["classes"]}
    ids_int = {k["class_id"] for k in m_int["classes"]}
    jr = [j for j in m_int["journal"] if j["target_id"] == "sdf_internal_notes"]
    check("S9-02b", "sdf_internal_notes" not in ids_pub and "sdf_internal_notes" in ids_int and len(jr) == 1
          and not [j for j in m_now["journal"] if j["target_id"] == "sdf_internal_notes"],
          "модель: класс с маркировкой INTERNAL и его запись журнала видит только читатель с допуском INTERNAL",
          f"PUBLIC: {len(ids_pub)} классов, INTERNAL: {len(ids_int)}")
    again = model(as_of=before)
    check("S9-02c", again["digest"] == m_before["digest"], "модель на прошлый момент воспроизводима (тот же digest)", m_before["digest"][:23])
    t2 = sql1("SELECT recorded_at > now() - interval '1 minute' FROM ac.class_defs WHERE class_id = 'sdf_taxon' AND version = 2")
    check("S9-02d", t2 == "t", "время версии ставит база: поданное «1999-12-31» заменено системным временем", f"recorded_at свежее минуты: {t2}")

    # S9-03 live claims against the schema
    time.sleep(1.1)
    e = entity("ent_s9_fin", "Финвал")
    r1 = ingest(e)
    c_isa = claim("ent_s9_fin", "schema.is_a", kref("sdf_whale_species"), "вид усатых китов")
    r2 = ingest(c_isa)
    c_rank = claim("ent_s9_fin", "x.rank", {"literal": {"type": "STRING", "value": "вид"}}, "вид")
    r3 = ingest(c_rank)
    rep = VAL.validate  # noqa: F841 (the live path has no dataset; the validator ran on the same shapes in vectors P912/N975)
    check("S9-03", r1.returncode == 0 and r2.returncode == 0 and r3.returncode == 0,
          "вживую: загрузчик заводит сущность, называет её класс (schema.is_a) и пишет утверждение с атрибутом родительского класса",
          "; ".join(first_err(x) for x in (r1, r2, r3)))
    c_bad = claim("ent_wk_baleen", "x.max_length", {"literal": {"type": "QUANTITY", "value": "30", "unit": "m"}}, "усатых китов")
    c_bad2 = claim("ent_s9_fin", "x.rank", {"literal": {"type": "INTEGER", "value": 7}}, "вид")
    c_bad3 = claim("ent_s9_fin", "x.nowhere", {"literal": {"type": "STRING", "value": "вид"}}, "вид")
    e1, e2, e3 = (first_err(ingest(c)) for c in (c_bad, c_bad2, c_bad3))
    check("S9-03n", "PREDICATE_DOMAIN_VIOLATION" in e1 and "PREDICATE_RANGE_VIOLATION" in e2 and "PREDICATE_UNKNOWN" in e3,
          "вживую отвергнуто: атрибут наследника у экземпляра родителя; значение не того типа; предиката нет в схеме", f"{e1[:60]} / {e2[:60]} / {e3[:60]}")

    # S9-04 back-dating
    time.sleep(1.1)
    t_old = utc(0)
    time.sleep(1.1)
    w = write_schema([sd("ClassDef", "sdf_taxon", 3, "CHANGE_ATTRIBUTE", root_type="CONCEPT", name="Таксон", parent_class_id="sdf_organism",
                         attributes=[{**rank, "cardinality": "MANY"}])], user="ac_model_app")
    e4 = first_err(ingest(claim("ent_s9_fin", "x.rank", {"literal": {"type": "STRING", "value": "вид усатых китов"}}, "вид усатых китов",
                                recorded=t_old)))
    time.sleep(1.1)
    r5 = ingest(claim("ent_s9_fin", "x.rank", {"literal": {"type": "STRING", "value": "вид усатых китов"}}, "вид усатых китов"))
    check("S9-04", w.returncode == 0 and "TEMPORAL_ORDER_INVALID" in e4 and r5.returncode == 0,
          "«задним числом» старую схему не выбрать: утверждение с временем до последнего изменения определения отвергнуто, с текущим — принято",
          f"{e4[:90]} / {first_err(r5)}")

    # S9-05 required attributes
    g0 = js(f"SELECT ac.schema_gaps('{WK}');")["gaps"]
    c_len = claim("ent_s9_fin", "x.max_length", {"literal": {"type": "QUANTITY", "value": "27", "unit": "m"}}, "Длина синего кита достигает 30 метров")
    r6 = ingest(c_len)
    g1 = js(f"SELECT ac.schema_gaps('{WK}');")["gaps"]
    sql1(f"INSERT INTO ac.claim_reviews VALUES ('rev_s9_w', '{c_len['claim_id']}', 'WITHDRAWN', 'usr_reviewer1', now(), now());", "ac_loader")
    g2 = js(f"SELECT ac.schema_gaps('{WK}');")["gaps"]
    key = lambda g: [(x["entity_id"], x["predicate_id"]) for x in g]  # noqa: E731
    check("S9-05", key(g0) == [("ent_s9_fin", "x.max_length")] and r6.returncode == 0 and key(g1) == [] and key(g2) == key(g0),
          "обязательный атрибут: пробел показан; закрыт утверждением; снова показан после отзыва утверждения",
          f"{key(g0)} -> {key(g1)} -> {key(g2)}")

    # S9-06 dossier sentences and names of the time asked
    time.sleep(1.1)
    t_name = utc(0)
    time.sleep(1.1)
    w = write_schema([sd("ClassDef", "sdf_whale_species", 3, "RENAME_CLASS", root_type="CONCEPT", name="Вид китообразных",
                         parent_class_id="sdf_taxon",
                         attributes=[x for x in next(k for k in m_now["classes"] if k["class_id"] == "sdf_whale_species")["attributes"]
                                     if x.pop("declared_in") == "sdf_whale_species"][::-1])], user="ac_model_app")
    def texts(as_of=None):
        a = f", {as_of!r}::timestamptz" if as_of else ""
        d = js(f"SELECT ac.dossier('{WK}', 'ent_wk_blue'{a});")
        return [f["text"] for s in d["sections"] for f in s.get("facts", [])]
    now_t, old_t = texts(), texts(t_name)
    check("S9-06", w.returncode == 0 and "Синий кит: класс — «Вид китообразных»." in now_t and "Синий кит: класс — «Вид китов»." in old_t
          and "Синий кит: наибольшая длина — 30 м." in now_t and "Синий кит: входит в таксон — «Усатые киты»." in now_t
          and "Синий кит: номер ITIS — 180528." in now_t,
          "досье: предложения о классе, атрибуте, связи и идентификаторе — с названиями из схемы на запрошенный момент",
          f"{first_err(w)}; сейчас: {[t for t in now_t if 'класс' in t]}; раньше: {[t for t in old_t if 'класс' in t]}")

    # S9-06w a withdrawn membership stops granting the class
    sql1(f"INSERT INTO ac.claim_reviews VALUES ('rev_s9_isa', '{c_isa['claim_id']}', 'WITHDRAWN', 'usr_reviewer1', now(), now());", "ac_loader")
    time.sleep(1.1)
    e5 = first_err(ingest(claim("ent_s9_fin", "x.max_length", {"literal": {"type": "QUANTITY", "value": "26", "unit": "m"}}, "30 метров")))
    g3 = key(js(f"SELECT ac.schema_gaps('{WK}');")["gaps"])
    check("S9-06w", "PREDICATE_DOMAIN_VIOLATION" in e5 and g3 == [],
          "принадлежность классу отозвана рецензией: новое утверждение с атрибутом класса отвергнуто, "
          "обязательных атрибутов от сущности больше не требуется", f"{e5[:70]}; пробелы {g3}")

    # S9-06m markings in the projections: a gap of an INTERNAL class is not shown to a PUBLIC reader
    w = write_schema([sd("ClassDef", "sdf_internal_notes", 2, "ADD_ATTRIBUTE", marking=INT, root_type="CONCEPT", name="Служебный класс",
                         attributes=[{"predicate_id": "x.internal_note", "name": "служебная заметка", "value_type": "STRING",
                                      "cardinality": "ONE", "required": True}])], user="ac_model_app")
    time.sleep(1.1)
    r7 = ingest(claim("ent_wk_baleen", "schema.is_a", kref("sdf_internal_notes"), "усатых китов", marking=INT))
    gp = key(js(f"SELECT ac.schema_gaps('{WK}');")["gaps"])
    gi = key(js(f"SELECT ac.schema_gaps('{WK}');", "ac_rd_wiki_int")["gaps"])
    dos = json.dumps(js(f"SELECT ac.dossier('{WK}', 'ent_wk_baleen');"), ensure_ascii=False)
    check("S9-06m", w.returncode == 0 and r7.returncode == 0 and gp == [] and gi == [("ent_wk_baleen", "x.internal_note")]
          and "Служебный класс" not in dos and "служебная заметка" not in json.dumps(model(), ensure_ascii=False),
          "маркировки в проекциях: пробел и название класса INTERNAL видит читатель с допуском INTERNAL, а читатель PUBLIC — "
          "ни в «пробелах схемы», ни в модели, ни в досье сущности", f"PUBLIC: {gp}; INTERNAL: {gi}; {first_err(w)} {first_err(r7)}")

    # S9-07 roles
    cls_sql = "INSERT INTO ac.class_defs (tenant_id, class_id, version, root_type, name, marking, change_type, description, recorded_at, recorded_by) " \
              "VALUES ('tnt_demo', 'sdf_by_loader', 1, 'CONCEPT', 'x', '{\"level\":\"PUBLIC\",\"categories\":[]}', 'ADD_CLASS', 'x', now(), 'usr_x1');"
    denied = [err(cls_sql, "ac_app"),
              err("INSERT INTO ac.class_closure VALUES ('tnt_demo', 'sdf_taxon', 'sdf_exhibit', 1);", "ac_model_app"),
              err("INSERT INTO ac.class_closure VALUES ('tnt_demo', 'sdf_taxon', 'sdf_exhibit', 1);", "ac_app"),
              err("INSERT INTO ac.schema_predicates VALUES ('tnt_demo', 'x.stolen', 'ClassDef', 'sdf_taxon');", "ac_model_app"),
              err("DELETE FROM ac.class_closure;", "ac_model_app"),
              err("UPDATE ac.class_defs SET name = 'x';", "ac_model_app"),
              err("DELETE FROM ac.class_closure;"), err("UPDATE ac.schema_predicates SET definer_id = 'x';"),
              err("TRUNCATE ac.class_defs;", "ac_model_app"),
              err(ingest_sql([claim("ent_s9_fin", "x.rank", {"literal": {"type": "STRING", "value": "вид"}}, "вид")], {}, user="ac_model_app").split("\n", 1)[1],
                  "ac_model_app"),
              err("SELECT * FROM ac.class_defs;", "ac_rd_public"), err("SELECT * FROM ac.schema_journal;", "ac_rd_public"),
              err(f"SELECT ac.model('{WK}');", "ac_rd_none"), err("SELECT ac.model('prj_dossier');", "ac_rd_wiki_int")]
    check("S9-07", all("permission denied" in d or "APPEND_ONLY" in d or "ACCESS_DENIED" in d for d in denied),
          "роли: загрузчик не меняет схему; конструктор не пишет утверждения и производные таблицы; UPDATE/DELETE/TRUNCATE запрещены; "
          "читатель без SELECT и без допуска не видит модель", f"отказов {sum(1 for d in denied if d != '(принято)')}/{len(denied)}: "
          + "; ".join(d[:40] for d in denied if not ("permission denied" in d or "APPEND_ONLY" in d or "ACCESS_DENIED" in d)))

    print("\nS9:", "ALL PASS" if all(RES) else f"FAILURES: {RES.count(False)}")
    return 0 if all(RES) else 1


if __name__ == "__main__":
    sys.exit(main())

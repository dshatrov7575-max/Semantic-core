#!/usr/bin/env python3
"""S4 attacks on the database (RR-07 and the artifact path), written as the application would write them (ac_loader,
live, one transaction each, rolled back). Each attack must be refused with the expected code; each legitimate
operation must pass. The validator is NOT in front of the database here: this measures what the database holds alone.
Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=<scratch db> python3 slice/attacks_s4.py
"""
import base64
import copy
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "core"))
sys.path.insert(0, str(HERE.parent / "adapter"))
from fixtures import SEEDS  # noqa: E402
from vectors import build  # noqa: E402
from techsense_umr import adapt  # noqa: E402
import samples as SM  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc, q  # noqa: E402

BAD = []


def reload():
    r = subprocess.run([sys.executable, str(HERE / "load_s1.py")], capture_output=True, text=True)
    if r.returncode:
        sys.exit("load failed: " + r.stdout + r.stderr)


DS, TRUST, CONTENT = build()
P = {p["project_id"]: p for p in DS["records"] if p["kind"] == "Project"}
SRCS = {s["source_id"]: s for s in DS["records"] if s["kind"] == "Source"}
ENTS = [e for e in DS["records"] if e["kind"] == "Entity" and e["project_id"] == "prj_ts_pumps"]
VS = None


def run(tweak=None, run_id="run_ts_0003"):
    """a fresh adapter run over the valve instruction (times = now) -> (records, content, digest)"""
    art = SM.valve_artifact(VS["source_id"], run_id=run_id, tweak=tweak)
    now = utc(0)
    res = adapt(art, P["prj_ts_pumps"], {**SRCS, VS["source_id"]: VS}, CONTENT, ENTS, now, now, "key_ts_1", SEEDS["key_ts_1"])
    return res.records, {res.artifact_digest: art}, res.artifact_digest


def art_only(art_bytes, digest=None, tenant="tnt_demo"):
    import hashlib
    dg = digest or "sha256:" + hashlib.sha256(art_bytes).hexdigest()
    return (f"SET SESSION AUTHORIZATION ac_loader;\nBEGIN;\nINSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES "
            f"({q(tenant)},{q(dg)},decode({q(base64.b64encode(art_bytes).decode())},'base64'));\nROLLBACK;")


def raw_art(tweak):
    """artifact bytes with a tweak applied AFTER canonical building (the adapter would refuse such an artifact)"""
    a = json.loads(SM.valve_artifact(VS["source_id"]).decode("utf-8"))
    tweak(a)
    from jcs import canon_bytes
    return canon_bytes(a)


def claim(recs, node):
    return next(r for r in recs if r["kind"] == "Claim" and r["evidence"][0]["graph_node"]["node_id"] == node)


def attack(aid, desc, sql, expect, legit=False):
    r = psql(sql)
    err = r.stderr.strip().splitlines()[0] if r.stderr.strip() else ""
    if legit:
        ok = r.returncode == 0
    else:
        ok = r.returncode != 0 and any(e in r.stderr for e in expect)
    BAD.append(not ok)
    print(f"{aid:<6} {'held' if ok else 'FINDING'} | {'законная: ' if legit else ''}{desc} | {err[:120] or 'принято'}", flush=True)


def tamper_run(fn, extra_sql=""):
    recs, ct, dg = run()
    fn(recs)
    return ingest_sql(recs, ct, artifacts=[dg], commit=False).replace("ROLLBACK;", extra_sql + "ROLLBACK;")


def main():
    global VS
    reload()
    VS = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, utc(0))
    r = psql(ingest_sql([VS], {}))
    if r.returncode:
        sys.exit("source ingest failed: " + r.stderr)
    obs = psql(f"SELECT to_char(min(observed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM ac.source_observations "
               f"WHERE source_id = '{VS['source_id']}'").stdout.strip()
    VS["observations"][0]["observed_at"] = obs
    time.sleep(1.1)
    A, G = ["ARTIFACT_INVALID"], ["GRAPH_NODE_INVALID"]

    # ---- legitimate
    recs, ct, dg = run()
    attack("L1", "полный прогон адаптера (артефакт, модель, 4 утверждения, receipt)", ingest_sql(recs, ct, artifacts=[dg], commit=False), [], True)
    attack("L2", "артефакт с неотображаемым отношением сохраняется (installed-on)", art_only(SM.valve_artifact(VS["source_id"])), [], True)

    # ---- the artifact itself
    good = SM.valve_artifact(VS["source_id"])
    attack("D401", "адрес артефакта не равен sha256 байтов", art_only(good, "sha256:" + "0" * 64), ["artifact_address"])
    attack("D402", "байты не JSON", art_only(b"\xff\xfe not json"), A)
    attack("D403", "неизвестный профиль", art_only(raw_art(lambda a: a.__setitem__("semantic_profile", "ts-semantic/9.9"))), A)
    attack("D404", "вход артефакта — источник, которого нет в tenant",
           art_only(raw_art(lambda a: a["inputs"].append("src:sha256:" + "5" * 64))), A)
    attack("D405", "якорь за концом источника", art_only(raw_art(lambda a: a["nodes"][3]["anchor"].__setitem__("end", 100000))), A)
    attack("D406", "якорь режет символ UTF-8", art_only(raw_art(lambda a: a["nodes"][3]["anchor"].update(start=1, end=4))), A)
    s1 = next(s for s in SRCS if SRCS[s]["title"].startswith("Инструкция по эксплуатации насосной"))
    attack("D407", "якорь в источнике tenant, но вне входов артефакта",
           art_only(raw_art(lambda a: a["nodes"][3].__setitem__("anchor", {"source_id": s1, "start": 0, "end": 10}))), A)
    attack("D408", "отношение к несуществующему узлу", art_only(raw_art(lambda a: a["nodes"][7].__setitem__("args", ["v1", "v99"]))), A)
    attack("D409", "has-parameter с действием вместо величины", art_only(raw_art(lambda a: a["nodes"][9].__setitem__("args", ["v1", "v5"]))), A)
    attack("D410", "has-parameter без parameter", art_only(raw_art(lambda a: a["nodes"][9].pop("parameter"))), A)
    attack("D411", "условие указывает на величину", art_only(raw_art(lambda a: a["nodes"][10].__setitem__("condition", "v4"))), A)
    attack("D412", "повтор id узла", art_only(raw_art(lambda a: a["nodes"][4].__setitem__("id", "v4"))), A)
    attack("D413", "лишнее поле верхнего уровня", art_only(raw_art(lambda a: a.__setitem__("comment", "x"))), A)
    attack("D413b", "лишнее поле узла", art_only(raw_art(lambda a: a["nodes"][0].__setitem__("color", "red"))), A)
    attack("D413c", "дробная граница якоря", art_only(good.replace(b'"end":', b'"end":1.5,"x":', 1)), A)
    attack("D413d", "площадка узла не по шаблону", art_only(raw_art(lambda a: a["nodes"][0]["identity"].__setitem__("site_id", "НС"))), A)
    attack("D413e", "отношение без якоря", art_only(raw_art(lambda a: a["nodes"][7].pop("anchor"))), A)
    attack("D413f", "входы с повтором", art_only(raw_art(lambda a: a["inputs"].append(a["inputs"][0]))), A)
    # ---- immutability and privileges
    import hashlib
    wdg = next(r for r in DS["records"] if r["kind"] == "ArtifactReceipt")["artifact_digest"]
    attack("D414", "изменение байтов сохранённого артефакта",
           f"SET SESSION AUTHORIZATION ac_loader;\nUPDATE ac.artifacts SET bytes = bytes || '\\x20'::bytea WHERE artifact_digest = '{wdg}';",
           ["APPEND_ONLY", "permission denied"])
    attack("D415", "удаление артефакта", f"SET SESSION AUTHORIZATION ac_loader;\nDELETE FROM ac.artifacts WHERE artifact_digest = '{wdg}';",
           ["APPEND_ONLY", "permission denied"])
    attack("D416", "прямая вставка узла графа", f"SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.artifact_nodes VALUES "
           f"('tnt_demo', '{wdg}', 'n99', 'RELATION', NULL, NULL, NULL, '{{}}');", ["permission denied"])
    attack("D417", "тело артефакта подано параметром, а не разобрано базой",
           f"SET SESSION AUTHORIZATION ac_loader;\nINSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes, body) VALUES "
           f"('tnt_demo', 'sha256:{hashlib.sha256(good).hexdigest()}', decode('{base64.b64encode(good).decode()}', 'base64'), '{{}}');",
           ["permission denied"])
    # ---- receipt vs artifact
    def other_digest(recs):
        rc = next(r for r in recs if r["kind"] == "ArtifactReceipt")
        rc["artifact_digest"] = "sha256:" + "1" * 64
    attack("D418", "receipt называет артефакт, которого нет в хранилище", tamper_run(other_digest), A)
    attack("D419", "receipt другого запуска, чем артефакт",
           tamper_run(lambda recs: next(r for r in recs if r["kind"] == "ArtifactReceipt").__setitem__("run_id", "run_ts_0099")), A)
    attack("D420", "у receipt лишний вход", tamper_run(lambda recs: next(r for r in recs if r["kind"] == "ArtifactReceipt")["input_source_ids"].append(s1)), A)
    attack("D420b", "receipt другой версии службы",
           tamper_run(lambda recs: next(r for r in recs if r["kind"] == "ArtifactReceipt")["producer"].__setitem__("version", "1.0.0")), A)
    # ---- claims vs graph nodes
    attack("D421", "узел графа, которого нет (атака RR-07)",
           tamper_run(lambda recs: claim(recs, "r3")["evidence"][0]["graph_node"].__setitem__("node_id", "no-such-node-999")), G)
    attack("D422", "узел — сущность, а не отношение", tamper_run(lambda recs: claim(recs, "r1")["evidence"][0]["graph_node"].__setitem__("node_id", "v1")), G)

    def outside(recs):
        c1, c3 = claim(recs, "r1"), claim(recs, "r3")
        c1["evidence"][0].update({k: copy.deepcopy(c3["evidence"][0][k]) for k in ("span", "quote", "quote_sha256")})
    attack("D423", "фрагмент доказательства вне якоря узла", tamper_run(outside), G)
    attack("D424", "субъект — соседняя задвижка К-11/2 (тот же скелет, другой строгий ключ)",
           tamper_run(lambda recs: claim(recs, "r3").__setitem__("subject", "ent_ts_valve_b")), G)
    attack("D425", "значение 2.5 вместо 1.6", tamper_run(lambda recs: claim(recs, "r3")["object"]["literal"].__setitem__("value", "2.5")), G)
    attack("D426", "уточнение другого параметра", tamper_run(lambda recs: claim(recs, "r3")["qualifiers"].__setitem__("parameter", "max_working_pressure")), G)

    def pred_swap(recs):
        c = claim(recs, "r2")
        model = claim(recs, "r1")["object"]
        c.update(predicate="ts.instance_of", object=copy.deepcopy(model))
    attack("D427", "отношение part-of выдано за instance-of", tamper_run(pred_swap), G)

    def twice(recs):
        c = copy.deepcopy(claim(recs, "r3"))
        c["claim_id"] = "clm:sha256:" + "2" * 64
        c["recorded_at"] = c["recorded_at"]
        recs.insert(recs.index(claim(recs, "r3")) + 1, c)
        next(r for r in recs if r["kind"] == "ArtifactReceipt")["emitted_claim_ids"].append(c["claim_id"])
    attack("D428", "второе утверждение на тот же узел", tamper_run(twice), ["claim_evidence_one_node", "GRAPH_NODE_INVALID"])
    attack("D429", "утверждение receipt без узла графа", tamper_run(lambda recs: claim(recs, "r4")["evidence"][0].pop("graph_node")),
           G + ["RECEIPT_CLAIM_BINDING_INVALID"])

    def human(recs):
        c = claim(recs, "r3")
        c["produced_by"] = {"kind": "HUMAN", "actor_id": "usr_analyst1"}
        rc = next(r for r in recs if r["kind"] == "ArtifactReceipt")
        rc["emitted_claim_ids"].remove(c["claim_id"])
    attack("D430", "утверждение аналитика с узлом графа", tamper_run(human), ["RECEIPT_CLAIM_BINDING_INVALID", "GRAPH_NODE_INVALID"])
    wc2 = next(c for c in DS["records"] if c["kind"] == "Claim" and c["predicate"] == "ts.has_parameter")

    def reuse_world_node(recs):
        c = claim(recs, "r3")
        c["evidence"][0]["graph_node"] = copy.deepcopy(wc2["evidence"][0]["graph_node"])
    attack("D431", "узел n12 чужого артефакта (НС-2) у утверждения о задвижке", tamper_run(reuse_world_node),
           G + ["RECEIPT_CLAIM_BINDING_INVALID", "claim_evidence_one_node"])
    # cross-tenant: the same artifact stored only in another tenant
    other = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, utc(0), tenant="tnt_other")
    recs, ct, dg = run()
    sql = ingest_sql([other], {}, tenant="tnt_other", commit=False).replace("ROLLBACK;", "")
    sql += (f"INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ('tnt_other', {q(dg)}, "
            f"decode({q(base64.b64encode(ct[dg]).decode())}, 'base64'));\n")
    sql += ingest_sql(recs, ct, artifacts=[], commit=False).replace("SET SESSION AUTHORIZATION ac_loader;\nBEGIN;", "")
    attack("D432", "артефакт сохранён только в другом tenant", sql, G + A)

    # ---- review S4 (S4R-01, 02, 03, 07, 08)
    attack("D433", "утверждение из артефакта со сроком действия (S4R-01)",
           tamper_run(lambda recs: claim(recs, "r3").__setitem__("valid_to", "2020-01-01")), G)

    def extra_ev(recs):
        c = claim(recs, "r3")
        e2 = copy.deepcopy(claim(recs, "r1")["evidence"][0])
        e2.pop("graph_node")
        c["evidence"].append(e2)
    attack("D434", "лишнее доказательство без узла (S4R-07)", tamper_run(extra_ev), G)

    recs, ct, dg = run()
    other_bytes = SM.valve_artifact(VS["source_id"], run_id="run_ts_0003",
                                    extra_nodes=({"id": "v9", "type": "CONDITION", "text": "лишний узел",
                                                  "anchor": SM.anchor(SM.VALVE_TEXT, VS["source_id"], "Задвижка")},))
    sql = ingest_sql(recs, ct, artifacts=[dg], commit=False).replace(
        "ROLLBACK;", f"INSERT INTO ac.artifacts (tenant_id, artifact_digest, bytes) VALUES ('tnt_demo', "
                     f"'sha256:{hashlib.sha256(other_bytes).hexdigest()}', decode('{base64.b64encode(other_bytes).decode()}', 'base64'));\nROLLBACK;")
    attack("D435", "повтор того же запуска другими байтами артефакта (S4R-08)", sql, ["artifacts_one_per_run"])
    attack("D436", "TAB в теге узла (S4R-03)", art_only(raw_art(lambda a: a["nodes"][0]["identity"].__setitem__("tag", "К-1/12" + chr(9)))), A)
    attack("D436b", "строка длиннее 2000 в описании узла (S4R-03)",
           art_only(raw_art(lambda a: a["nodes"][0]["identity"].__setitem__("description", "з" * 2001))), A)
    # S4R-02: a node keyed by a merged alias names the survivor
    alias = {"kind": "Entity", "schema_version": "core-ontology/0.2", "entity_id": "ent_ts_valve_alias", "project_id": "prj_ts_pumps",
             "entity_type": "EQUIPMENT", "identity": {"site_id": "site_ns2", "tag": "К-1/12/с"}, "display_name": "Задвижка К-1/12/с",
             "status": "ACTIVE", "created_at": utc(0), "marking": {"level": "INTERNAL", "categories": []}}
    merge_sql = ("UPDATE ac.entities SET status = 'MERGED', merged_into = '{t}', status_changed_at = now() "
                 "WHERE entity_id = 'ent_ts_valve_alias';\n")

    def alias_run(target, subject_from_adapter=True):
        art = SM.valve_artifact(VS["source_id"], run_id="run_ts_0004", tweak=lambda a: a["nodes"][0]["identity"].__setitem__("tag", "К-1/12/с"))
        now = utc(-2)        # recorded after the merge (merge time = transaction start); the SQL waits until it is reached
        merged = {**alias, "status": "MERGED", "merged_into": target, "status_changed_at": now}
        res = adapt(art, P["prj_ts_pumps"], {**SRCS, VS["source_id"]: VS}, CONTENT, ENTS + [merged], now, now, "key_ts_1", SEEDS["key_ts_1"])
        recs = res.records
        if not subject_from_adapter:            # claims say «valve» although the alias was merged into another entity
            for r in recs:
                if r["kind"] == "Claim" and r["subject"] == target:
                    r["subject"] = "ent_ts_valve_a"
        head = ingest_sql([alias], {}, commit=False).replace("ROLLBACK;", merge_sql.format(t=target) + "SELECT pg_sleep(2.2);\n")
        tail = ingest_sql(recs, {res.artifact_digest: art}, artifacts=[res.artifact_digest], commit=False).replace(
            "SET SESSION AUTHORIZATION ac_loader;\nBEGIN;", "")
        return head + tail
    time.sleep(1.1)
    attack("L3", "узел назван ключом слитой сущности, утверждения — о выжившей (S4R-02)", alias_run("ent_ts_valve_a"), [], True)
    attack("D437", "узел назван ключом сущности, слитой в другую (станцию), утверждение — о задвижке",
           alias_run("ent_ts_station", subject_from_adapter=False), G)

    # S4R-13: an artifact cannot be committed without its receipt (it would squat on the run id)
    attack("D438", "артефакт без receipt фиксируется отдельной транзакцией (S4R-13)",
           art_only(SM.valve_artifact(VS["source_id"], run_id="run_ts_0099")).replace("ROLLBACK;", "COMMIT;"), A)

    print(f"\nattacks={sum(1 for _ in BAD)} findings={sum(BAD)}")
    print("S4_ATTACKS=" + ("PASS" if not any(BAD) else "FAIL"))
    return 1 if any(BAD) else 0


if __name__ == "__main__":
    sys.exit(main())

"""Общие функции скриптов a40/a41 (версии своих наборов, утверждение на строке, currency, досье)."""
import json
from rv import *
from dataset import DatasetVersion
from fixtures import DEMO_DATASET_KEY
PUB = {"level": "PUBLIC", "categories": []}
L = "SET SESSION AUTHORIZATION ac_loader;\n"


def ver(dsid, label, columns, keycols, rows, subject=("ogrn",), previous=None, marking=PUB, load=True, seal=True):
    dv = DatasetVersion(dsid, T, label, columns, list(keycols), rows, subject=subject, dataset_key=DEMO_DATASET_KEY, previous=previous)
    src, r = D.register(dv.manifest_bytes, T, f"{dsid} {label}", marking=marking)
    assert r.returncode == 0, first_err(r)
    if load:
        _, bad = D.load_rows(T, dv.source_id, copy_file(dv), columns, seal=seal)
        assert bad is None, first_err(bad)
    return dv


def cols(key_type="STRING", extra=()):
    return [{"name": "code", "type": key_type, "marking": PUB},
            {"name": "ogrn", "type": "STRING", "marking": PUB, "identifier_scheme": "ru.ogrn"},
            {"name": "address", "type": "STRING", "marking": PUB, "predicate": "entity.registered_address"}] + list(extra)


def mk_claim(dv, keyvals, address, quote=("address", "ogrn")):
    c = claim(dv.evidence(list(keyvals), list(quote)), address=address)
    r = psql(ingest_sql([c], {}))
    assert r.returncode == 0, first_err(r)
    return c


def currency(c, t="now()"):
    r = psql(f"SELECT ac.evidence_json('{c['claim_id']}', {t});")
    return json.loads(r.stdout)[0]["currency"] if r.returncode == 0 else "ОШИБКА: " + first_err(r)[:110]


def dossier(t=None, user="ac_rd_cs"):
    return psql(f"SELECT ac.dossier('{PRJ}', 'ent_k_developer'{', ' + t if t else ''});", user)



"""Builder of a dataset version (D27.2, D27.4): rows -> files, manifest, evidence of a row.

The normative part — how a cell, a row and a file are hashed and how a proof is checked — lives in validator.py
(cell_leaf, row_leaf, merkle_root, inclusion_root, parse_manifest); this module only PRODUCES what the validator
checks, so a producer in another language can be compared against it byte for byte.

    v = DatasetVersion("dst_registry", "tnt_demo", "2026-09-01", columns, key=["ogrn"], rows=[{...}, ...])
    v.manifest_bytes          the bytes of the Source of kind DATASET_VERSION (canonical JSON)
    v.source_id               "src:sha256:…" of those bytes
    v.files                   [(object address, bytes)] — row files for the object store (JSON lines, one row per line)
    v.evidence(key, quote)    the ROW evidence of one row: quoted cells with salts, the other cells as leaves, proof

A row file line: {"h": row hash, "k": key, "s": row secret, "v": [values in column order]} (canonical JSON).
The secret of a row is 16 bytes derived from the secret key of the dataset and the key of the row (row_secret);
the salt of a cell is sha256(0x03 || secret || column name) — validator.cell_salt.
"""
import hashlib
import hmac
import os

from jcs import canon
from validator import cell_leaf, cell_salt, cell_value_ok, merkle_root, row_leaf

CHUNK_ROWS = 4096


def row_secret(dataset_key: bytes, dataset_id: str, values) -> bytes:
    """the secret of a row: HMAC-SHA256(key of the dataset, JCS([dataset_id, ALL values of the row]))[:16] (the id of the
    dataset is inside: one key reused for two datasets does not give them the same secrets). The key of the dataset
    is 32 random bytes kept by the loader and never published: without it a hidden cell cannot be guessed from its
    leaf. An unchanged row has the same secret and the same hash in every version (unchanged files are shared between
    versions); a row in which ANY cell changed gets a new secret, i.e. new salts for all its cells — so the leaves of
    two versions say only «the row is the same / not the same» (which its hash says anyway), never which cell changed,
    and a salt learnt from an old version opens nothing in a changed row (S10R-24)."""
    return hmac.new(dataset_key, canon([dataset_id, list(values)]).encode("utf-8"), hashlib.sha256).digest()[:16]


def row_hash(secret: bytes, names, values) -> bytes:
    return merkle_root([cell_leaf(cell_salt(secret, n), n, v) for n, v in zip(names, values)])


def audit_path(leaves, i):
    """sibling hashes from the leaf up to the root (RFC 6962 shape)"""
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if i < k:
        return audit_path(leaves[:k], i) + [merkle_root(leaves[k:])]
    return audit_path(leaves[k:], i - k) + [merkle_root(leaves[:k])]


class DatasetVersion:
    def __init__(self, dataset_id, tenant_id, version_label, columns, key, rows, secret_of=None, chunk_rows=CHUNK_ROWS,
                 previous=None, subject=(), check=True, dataset_key=None):
        """columns: [{"name", "type", "marking"[, "identifier_scheme"][, "predicate"]}]; key: column names ([] = no key);
        subject: the identifier columns of the entity a row is about;
        rows: iterable of dicts name -> value; check=False builds a version from rows the validator must refuse (tests); dataset_key: 32 secret bytes of the dataset (default: random — the hashes are then
        not reproducible); secret_of(key_values, values) -> 16 bytes overrides the derivation (tests)"""
        self.columns, self.key = columns, list(key)
        dataset_key = dataset_key or os.urandom(32)
        self.names = [c["name"] for c in columns]
        kpos = [self.names.index(k) for k in self.key]
        recs = []
        for r in rows:
            values = [r.get(n) for n in self.names]
            for c, v in zip(columns, values):
                if check and not cell_value_ok(c["type"], v):
                    raise ValueError(f"значение колонки {c['name']} не типа {c['type']}: {v!r}")
            kv = [values[p] for p in kpos]
            if check and any(v is None for v in kv):
                raise ValueError("пустое значение в колонке ключа")
            if secret_of:
                secret = secret_of(kv, values)
            else:                                           # a dataset without a key: the row is named by its content
                secret = row_secret(dataset_key, dataset_id, values)
            h = row_hash(secret, self.names, values)
            recs.append((canon(kv) if self.key else h.hex(), kv, secret, h, values))
        recs.sort(key=lambda x: x[0])                      # rows are ordered by key (without a key — by their hash)
        if len({x[0] for x in recs}) != len(recs):
            raise ValueError("ключ строки повторяется")
        self.rows = recs
        self.where = {x[0]: n for n, x in enumerate(recs)}
        self.chunk_rows = chunk_rows
        self.files, files = [], []
        for start in range(0, len(recs), chunk_rows):
            part = recs[start:start + chunk_rows]
            data = "".join(canon({"h": h.hex(), "k": kv, "s": s.hex(), "v": vals}) + "\n" for _, kv, s, h, vals in part).encode("utf-8")
            addr = "sha256:" + hashlib.sha256(data).hexdigest()
            self.files.append((addr, data))
            files.append({"object": addr, "byte_length": len(data), "rows": len(part),
                          "rows_root": merkle_root([row_leaf(x[3]) for x in part]).hex()})
        self.manifest = {"manifest_format": "ac-dataset-manifest/0.1", "dataset_id": dataset_id, "tenant_id": tenant_id,
                         "version_label": version_label, "columns": columns, "key": self.key, "row_count": len(recs), "files": files}
        if previous:
            self.manifest["previous"] = previous
        if subject:
            self.manifest["subject"] = list(subject)
        self.manifest_bytes = canon(self.manifest).encode("utf-8")
        self.source_id = "src:sha256:" + hashlib.sha256(self.manifest_bytes).hexdigest()

    def evidence(self, key_values, quote):
        """ROW evidence of the row with this key (for a dataset without a key: the hex of the row hash); the key
        columns are always quoted"""
        pos = self.where[canon(list(key_values)) if self.key else key_values]
        _, kv, secret, h, values = self.rows[pos]
        shown = set(quote) | set(self.key)
        cells = []
        for n, v in zip(self.names, values):
            salt = cell_salt(secret, n)
            cells.append({"name": n, "value": v, "salt": salt.hex()} if n in shown else {"name": n, "leaf": cell_leaf(salt, n, v).hex()})
        f, i = divmod(pos, self.chunk_rows)
        part = self.rows[f * self.chunk_rows:(f + 1) * self.chunk_rows]
        ev = {"kind": "ROW", "source_id": self.source_id, "row_sha256": h.hex(), "cells": cells,
              "proof": {"file": f, "index": i, "hashes": [x.hex() for x in audit_path([row_leaf(x[3]) for x in part], i)]}}
        if self.key:
            ev["row_key"] = kv
        return ev

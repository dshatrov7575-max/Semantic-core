#!/usr/bin/env python3
"""ac.dataset_subject — «о ком строка в проекте».
U1  статус CONFLICT считается по ВСЕМ владельцам, а список owners — только по видимым читателю: читатель видит
    CONFLICT с одним владельцем и узнаёт, что идентификатор строки несёт сущность выше его допуска.
U2  владельцы разных типов: статус ONE при двух владельцах.
U3  расхождение с правилом записи: проекция «ONE», а правило отвергает (и наоборот) — RETIRED, слитые, время.
U4  существование версии / строки для читателя без допуска к версии.
"""
import copy, json, time
from rv import *
from a40_helpers import *

dv = fresh()
TRUB, BETA, GAMMA, ALFA = REGISTRY_ROWS[1], REGISTRY_ROWS[3], REGISTRY_ROWS[4], REGISTRY_ROWS[2]
CS_PD = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET", "PERSONAL_DATA"]}
sid = dv.source_id


def subj(k, user="ac_rd_cs", s=None):
    r = psql(f"SELECT ac.dataset_subject('{PRJ}', '{s or sid}', {key(k)});", user)
    if r.returncode:
        return "ОШИБКА: " + first_err(r)[:90]
    return json.loads(r.stdout) if r.stdout.strip() else "NULL (строки нет)"


def brief(x):
    return f"{x['status']} {[(o['entity_id'], o['by']) for o in x['owners']]}" if isinstance(x, dict) else x


# U1
a = org("ent_r3_trub", "АО «Трубопроводстрой»", ogrn=TRUB["ogrn"])
assert psql(ingest_sql([a], {})).returncode == 0
s0 = subj(TRUB["ogrn"])
hid = org("ent_r3_trub_hidden", "АО «Трубопроводстрой» (закрытая карточка)", marking=CS_PD, inn=TRUB["inn"])
assert psql(ingest_sql([hid], {})).returncode == 0
s1, s1full = subj(TRUB["ogrn"]), subj(TRUB["ogrn"], "ac_rd_full")
print("U1 читатель без категории ПД, до появления закрытой сущности:", brief(s0))
print("   после (закрытая сущность несёт ИНН строки):              ", brief(s1))
print("   читатель с полным допуском:                              ", brief(s1full))
dos = psql(f"SELECT ac.dossier('{PRJ}', 'ent_r3_trub_hidden');", "ac_rd_cs")
print("   досье закрытой сущности тому же читателю:", first_err(dos)[:70])
report("U1", s0["status"] == "ONE" and s1["status"] == "CONFLICT" and len(s1["owners"]) == 1,
       "статус CONFLICT при одном видимом владельце: читатель узнаёт о существовании сущности выше допуска и что она несёт ИНН этой строки")
# только закрытый владелец
h2 = org("ent_r3_gamma_hidden", "ООО «Гамма» (закрытая)", marking=CS_PD, ogrn=GAMMA["ogrn"])
assert psql(ingest_sql([h2], {})).returncode == 0
print("   единственный владелец закрыт:", brief(subj(GAMMA["ogrn"])), "| полный допуск:", brief(subj(GAMMA["ogrn"], "ac_rd_full")))

# U2 owners of different types
from vectors import cols_with
LEI = "549300123456"
c2 = cols_with({"name": "lei", "type": "STRING", "marking": PUB, "identifier_scheme": "lei"})
rows = [dict(r, lei=LEI if i == 0 else None) for i, r in enumerate(REGISTRY_ROWS)]
v = ver("dst_r_lei", "v1", c2, ["ogrn"], rows, subject=("ogrn", "inn", "lei"))
tr = {"kind": "Entity", "entity_id": "ent_r3_trailer", "project_id": PRJ, "entity_type": "MOVABLE_PROPERTY", "status": "ACTIVE",
      "identity": {"subtype": "OTHER", "description": "прицеп", "registration": {"scheme": "lei", "value": LEI}}, "display_name": "Прицеп",
      "created_at": utc(0), "marking": CONF_CS}
assert psql(ingest_sql([tr], {})).returncode == 0
s2 = subj(OGRN_DEV, s=v.source_id)
print("U2 ОГРН+ИНН у организации, тот же LEI — у прицепа:", brief(s2))
report("U2", isinstance(s2, dict) and s2["status"] == "ONE" and len(s2["owners"]) == 2, "статус ONE при двух владельцах (разные типы): «одна сущность владеет ими (всеми найденными)» неверно")

# U3 projection vs the write rule
b1 = org("ent_r3_beta", "ООО «Бета»", ogrn=BETA["ogrn"])
b2 = org("ent_r3_beta_inn", "ООО «Бета» (по ИНН)", inn=BETA["inn"])
third = org("ent_r3_third", "ООО «Третья»", ogrn=ALFA["ogrn"])
assert psql(ingest_sql([b1, b2, third], {})).returncode == 0
time.sleep(1.2)
assert psql(L + "UPDATE ac.entities SET status = 'MERGED', merged_into = 'ent_r3_third' WHERE entity_id = 'ent_r3_beta_inn';").returncode == 0
time.sleep(1.2)
s3 = subj(BETA["ogrn"])
r = psql(ingest_sql([claim(dv.evidence([BETA["ogrn"]], ["address", "inn"]), subj="ent_r3_beta", address=BETA["address"])], {}, commit=False))
print("U3 ИНН строки — у сущности, слитой в ТРЕТЬЮ:", brief(s3), "| утверждение с ИНН:", first_err(r)[:80])

# U4 existence of a version / a row
vr = ver("dst_r_closed", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": "x"}], marking={"level": "RESTRICTED", "categories": []})
e_closed = subj("A", s=vr.source_id)
e_none = subj("A", s="src:sha256:" + "1" * 64)
e_unsealed_v = ver("dst_r_closed2", "v1", cols(), ["code"], [{"code": "A", "ogrn": OGRN_DEV, "address": "x"}], seal=False)
print("U4 версия выше допуска:", e_closed, "| несуществующая версия:", e_none, "| незапечатанная:", subj("A", s=e_unsealed_v.source_id))
report("U4", e_closed != e_none, "ответ о версии выше допуска отличается от ответа о несуществующей")
print("   строки нет:", subj("0000000000000"), "| читатель без допуска в проекте:", subj(OGRN_DEV, "ac_rd_none"))

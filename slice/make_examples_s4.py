#!/usr/bin/env python3
"""Builds ПРИМЕР_КАРТОЧКИ_S4.md: reload the world, ingest the valve instruction, run the adapter on it (live, through
the validator first), add one analyst claim about the pump model, then render the cards of the pump, the valve, the
station and the model. Usage: PGHOST=... PGDATABASE=<scratch db> python3 slice/make_examples_s4.py"""
import copy
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import s4_tests as T  # noqa: E402
import validator as VAL  # noqa: E402
from vectors import build  # noqa: E402
import samples as SM  # noqa: E402
from ingest_s4 import ingest_sql, psql, utc  # noqa: E402
from render_s4 import card  # noqa: E402


def main():
    T.reload()
    ds, trust, content = build()
    vs0 = SM.make_source(SM.VALVE_TEXT, SM.VALVE_TITLE, utc(0))
    assert psql(ingest_sql([vs0], {})).returncode == 0
    time.sleep(1.1)
    obs = T.sql1(f"SELECT to_char(min(observed_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM ac.source_observations "
                 f"WHERE source_id = '{vs0['source_id']}'")
    now = utc(0)
    vs, art, res = T.valve_run(ds, content, now, now, obs)
    ds2 = copy.deepcopy(ds)
    ds2["records"] += [vs] + res.records
    ct2 = {**content, res.artifact_digest: art}
    rep = VAL.validate(ds2, trust, ct2)
    assert not rep.errors, rep.codes()
    r = psql(ingest_sql(res.records, ct2, artifacts=[res.artifact_digest]))
    assert r.returncode == 0, r.stderr
    time.sleep(1.1)
    hc = T.analyst_model_claim(ds)                      # one analyst claim about the pump model
    assert psql(ingest_sql([hc], {})).returncode == 0
    time.sleep(1.1)
    parts = ["# Примеры карточек оборудования (S4)\n",
             "Построены базой (`ac.equipment_card`) из эталонного мира и живого прогона адаптера TechSense по инструкции "
             "задвижки К-1/12; отрисованы `slice/render_s4.py`. Читатель — роль с допуском «для служебного пользования» "
             "к проекту «Насосная станция НС-2».\n"]
    for eid in ("ent_ts_pump", "ent_ts_valve_a", "ent_ts_station", "ent_ts_model"):
        parts.append("\n---\n\n" + card(eid))
    out = HERE / "ПРИМЕР_КАРТОЧКИ_S4.md"
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print("written", out, len(out.read_bytes()), "bytes")


if __name__ == "__main__":
    main()

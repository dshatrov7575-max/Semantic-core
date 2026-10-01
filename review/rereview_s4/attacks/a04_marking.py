"""S4R: claim marking vs marking of the entities it names (does the validator/DB require claim >= entity?)."""
from harness import run
CONF = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}
run("модель НМ 16-100 CONFIDENTIAL/COMMERCIAL_SECRET, c0 (instance_of) INTERNAL", pre=lambda W: W["ent_ts_model"].__setitem__("marking", CONF))
run("насос CONFIDENTIAL/COMMERCIAL_SECRET, c0..c3 INTERNAL", pre=lambda W: W["ent_ts_pump"].__setitem__("marking", CONF))

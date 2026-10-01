"""S4R: does the claim 'say the same' as the node? Fields graph_says does not compare; marking of named entities."""
from harness import run, art
CONF = {"level": "CONFIDENTIAL", "categories": ["COMMERCIAL_SECRET"]}
# 1. validity interval: the node says nothing about time, the claim limits it (or ends it in the past)
run("c2 с valid_to=2020-01-01 (узел времени не задаёт)", pre=lambda W: W["c2"].__setitem__("valid_to", "2020-01-01"))
run("c2 с valid_from=2030-01-01", pre=lambda W: W["c2"].__setitem__("valid_from", "2030-01-01"))
# 2. extra evidence without graph node, from the same input, about something else
run("c2: второе доказательство без узла (другой фрагмент входа)", pre=lambda W: W["c2"]["evidence"].append({"$ev": ["s1", "Насос Н-101"]}))

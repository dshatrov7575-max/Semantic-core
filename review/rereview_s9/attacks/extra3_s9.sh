#!/bin/bash
# Рецензия цикла 9: контрольные проверки для списка «дефекта не нашёл» (review09e, владелец)
M='{"level":"PUBLIC","categories":[]}'
r() { echo "\$ $1"; psql -X -q -At -v ON_ERROR_STOP=1 -c "$1" 2>&1 | head -2; }
r "INSERT INTO ac.class_defs VALUES ('sdf_selfp','tnt_demo','PERSON','x',NULL,'sdf_selfp',NULL,1,now(),'usr_rev','$M');"
r "INSERT INTO ac.class_defs VALUES ('sdf_cyc_a','tnt_demo','PERSON','x',NULL,'sdf_cyc_b',NULL,1,now(),'usr_rev','$M'), ('sdf_cyc_b','tnt_demo','PERSON','x',NULL,'sdf_cyc_a',NULL,1,now(),'usr_rev','$M');"
r "INSERT INTO ac.class_defs VALUES ('sdf_badroot','tnt_demo','PERSON','x',NULL,'sdf_org_sub',NULL,1,now(),'usr_rev','$M');"
r "UPDATE ac.link_defs SET label_ru='x';"
r "DELETE FROM ac.identifier_defs;"

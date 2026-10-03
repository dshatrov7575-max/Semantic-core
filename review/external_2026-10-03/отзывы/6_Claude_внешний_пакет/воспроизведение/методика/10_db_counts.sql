-- Подсчёт объектов базы по pg_catalog (своя база rev_method после slice/load_s1.py)
SELECT 'schemas', string_agg(nspname, ',' ORDER BY nspname) FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema';
SELECT 'tables by schema', n.nspname, count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' GROUP BY 2 ORDER BY 2;
SELECT 'tables total', count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema';
SELECT 'views/matviews', n.nspname, c.relkind, count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('v','m') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' GROUP BY 2,3 ORDER BY 2;
SELECT 'functions by schema', n.nspname, p.prokind, count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' GROUP BY 2,3 ORDER BY 2,3;
SELECT 'functions total', count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema';
SELECT 'triggers (user, non-internal) by schema', n.nspname, count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE NOT t.tgisinternal GROUP BY 2 ORDER BY 2;
SELECT 'triggers total (non-internal)', count(*) FROM pg_trigger t WHERE NOT t.tgisinternal;
SELECT 'triggers incl. internal (FK)', count(*) FROM pg_trigger t;
SELECT 'constraints by type', contype, count(*) FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace
  WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' GROUP BY 2 ORDER BY 2;

-- Архитектура семантики — S11 (цикл 11): записи ядра пишутся только в READ COMMITTED.
--
-- Класс дефекта S10R-20: страж вида «взять блокировку и прочитать, что зафиксировали другие» верен только тогда, когда
-- снимок берётся ПОСЛЕ блокировки. REPEATABLE READ и SERIALIZABLE держат снимок первого запроса транзакции, поэтому две
-- такие транзакции (или одна из них против READ COMMITTED) друг друга не видят и обе проходят стража: так в срезе S1
-- под REPEATABLE READ фиксировались два физлица с одним ФИО и датой рождения (attacks_s11.py, I1).
-- ac.lock_keys и прямые advisory-блокировки теперь сами требуют READ COMMITTED (ddl_s1.sql, ddl_s9.sql, ddl_s10.sql);
-- здесь — второй рубеж: триггер уровня оператора на КАЖДОЙ таблице ядра, чтобы запись без блокировки тоже не прошла.
-- Этот файл применяется последним.

-- (ac.isolation_guard — в ddl_s1.sql; таблицы строк версий наборов в схеме acd получают его в ac.dataset_open)

DO $$
DECLARE t record;
BEGIN
  FOR t IN SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname IN ('ac', 'ac_trust') AND c.relkind = 'r' ORDER BY 1, 2 LOOP
    EXECUTE format('CREATE TRIGGER a_isolation_guard BEFORE INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH STATEMENT '
                   'EXECUTE FUNCTION ac.isolation_guard()', t.nspname, t.relname);
  END LOOP;
END $$;

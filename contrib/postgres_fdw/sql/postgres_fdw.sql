-- ===================================================================
-- create FDW objects
-- ===================================================================

-- Clean up in case a prior regression run failed

-- Suppress NOTICE messages when roles don't exist
SET client_min_messages TO 'error';

DROP ROLE IF EXISTS postgres_fdw_user;

RESET client_min_messages;

CREATE ROLE postgres_fdw_user LOGIN SUPERUSER;
SET SESSION AUTHORIZATION 'postgres_fdw_user';

CREATE EXTENSION postgres_fdw;

CREATE SERVER loopback1 FOREIGN DATA WRAPPER postgres_fdw;
CREATE SERVER loopback2 FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (dbname 'contrib_regression');

CREATE USER MAPPING FOR public SERVER loopback1
	OPTIONS (user 'value', password 'value');
CREATE USER MAPPING FOR postgres_fdw_user SERVER loopback2;

-- ===================================================================
-- create objects used through FDW
-- ===================================================================
CREATE TYPE user_enum AS ENUM ('foo', 'bar', 'buz');
CREATE SCHEMA "S 1";
CREATE TABLE "S 1"."T 1" (
	"C 1" int NOT NULL,
	c2 int NOT NULL,
	c3 text,
	c4 timestamptz,
	c5 timestamp,
	c6 varchar(10),
	c7 char(10),
	c8 user_enum,
	CONSTRAINT t1_pkey PRIMARY KEY ("C 1")
);
CREATE TABLE "S 1"."T 2" (
	c1 int NOT NULL,
	c2 text,
	CONSTRAINT t2_pkey PRIMARY KEY (c1)
);

BEGIN;
TRUNCATE "S 1"."T 1";
INSERT INTO "S 1"."T 1"
	SELECT id,
	       id % 10,
	       to_char(id, 'FM00000'),
	       '1970-01-01'::timestamptz + ((id % 100) || ' days')::interval,
	       '1970-01-01'::timestamp + ((id % 100) || ' days')::interval,
	       id % 10,
	       id % 10,
	       'foo'::user_enum
	FROM generate_series(1, 1000) id;
TRUNCATE "S 1"."T 2";
INSERT INTO "S 1"."T 2"
	SELECT id,
	       'AAA' || to_char(id, 'FM000')
	FROM generate_series(1, 100) id;
COMMIT;

-- ===================================================================
-- create foreign tables
-- ===================================================================
CREATE FOREIGN TABLE ft1 (
	c0 int,
	c1 int NOT NULL,
	c2 int NOT NULL,
	c3 text,
	c4 timestamptz,
	c5 timestamp,
	c6 varchar(10),
	c7 char(10),
	c8 user_enum
) SERVER loopback2;
ALTER FOREIGN TABLE ft1 DROP COLUMN c0;

CREATE FOREIGN TABLE ft2 (
	c0 int,
	c1 int NOT NULL,
	c2 int NOT NULL,
	c3 text,
	c4 timestamptz,
	c5 timestamp,
	c6 varchar(10),
	c7 char(10),
	c8 user_enum
) SERVER loopback2;
ALTER FOREIGN TABLE ft2 DROP COLUMN c0;

-- ===================================================================
-- tests for validator
-- ===================================================================
-- requiressl, krbsrvname and gsslib are omitted because they depend on
-- configure option
ALTER SERVER loopback1 OPTIONS (
    use_remote_explain 'false',
	fdw_startup_cost '123.456',
	fdw_tuple_cost '0.123',
	authtype 'value',
	service 'value',
	connect_timeout 'value',
	dbname 'value',
	host 'value',
	hostaddr 'value',
	port 'value',
	--client_encoding 'value',
	tty 'value',
	options 'value',
	application_name 'value',
	--fallback_application_name 'value',
	keepalives 'value',
	keepalives_idle 'value',
	keepalives_interval 'value',
	-- requiressl 'value',
	sslcompression 'value',
	sslmode 'value',
	sslcert 'value',
	sslkey 'value',
	sslrootcert 'value',
	sslcrl 'value'
	--requirepeer 'value',
	-- krbsrvname 'value',
	-- gsslib 'value',
	--replication 'value'
);
ALTER USER MAPPING FOR public SERVER loopback1
	OPTIONS (DROP user, DROP password);
ALTER FOREIGN TABLE ft1 OPTIONS (nspname 'S 1', relname 'T 1');
ALTER FOREIGN TABLE ft2 OPTIONS (nspname 'S 1', relname 'T 1');
ALTER FOREIGN TABLE ft1 ALTER COLUMN c1 OPTIONS (colname 'C 1');
ALTER FOREIGN TABLE ft2 ALTER COLUMN c1 OPTIONS (colname 'C 1');
\dew+
\des+
\deu+
\det+

-- Use only Nested loop for stable results.
SET enable_mergejoin TO off;
SET enable_hashjoin TO off;

-- ===================================================================
-- simple queries
-- ===================================================================
-- single table, with/without alias
EXPLAIN (COSTS false) SELECT * FROM ft1 ORDER BY c3, c1 OFFSET 100 LIMIT 10;
SELECT * FROM ft1 ORDER BY c3, c1 OFFSET 100 LIMIT 10;
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 ORDER BY t1.c3, t1.c1 OFFSET 100 LIMIT 10;
SELECT * FROM ft1 t1 ORDER BY t1.c3, t1.c1 OFFSET 100 LIMIT 10;
-- empty result
SELECT * FROM ft1 WHERE false;
-- with WHERE clause
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = 101 AND t1.c6 = '1' AND t1.c7 >= '1';
SELECT * FROM ft1 t1 WHERE t1.c1 = 101 AND t1.c6 = '1' AND t1.c7 >= '1';
-- aggregate
SELECT COUNT(*) FROM ft1 t1;
-- join two tables
SELECT t1.c1 FROM ft1 t1 JOIN ft2 t2 ON (t1.c1 = t2.c1) ORDER BY t1.c3, t1.c1 OFFSET 100 LIMIT 10;
-- subquery
SELECT * FROM ft1 t1 WHERE t1.c3 IN (SELECT c3 FROM ft2 t2 WHERE c1 <= 10) ORDER BY c1;
-- subquery+MAX
SELECT * FROM ft1 t1 WHERE t1.c3 = (SELECT MAX(c3) FROM ft2 t2) ORDER BY c1;
-- used in CTE
WITH t1 AS (SELECT * FROM ft1 WHERE c1 <= 10) SELECT t2.c1, t2.c2, t2.c3, t2.c4 FROM t1, ft2 t2 WHERE t1.c1 = t2.c1 ORDER BY t1.c1;
-- fixed values
SELECT 'fixed', NULL FROM ft1 t1 WHERE c1 = 1;
-- user-defined operator/function
CREATE FUNCTION postgres_fdw_abs(int) RETURNS int AS $$
BEGIN
RETURN abs($1);
END
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE OPERATOR === (
    LEFTARG = int,
    RIGHTARG = int,
    PROCEDURE = int4eq,
    COMMUTATOR = ===,
    NEGATOR = !==
);
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = postgres_fdw_abs(t1.c2);
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 === t1.c2;
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = abs(t1.c2);
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = t1.c2;

-- ===================================================================
-- WHERE push down
-- ===================================================================
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = 1;         -- Var, OpExpr(b), Const
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE t1.c1 = 100 AND t1.c2 = 0; -- BoolExpr
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c1 IS NULL;        -- NullTest
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c1 IS NOT NULL;    -- NullTest
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE round(abs(c1), 0) = 1; -- FuncExpr
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c1 = -c1;          -- OpExpr(l)
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE 1 = c1!;           -- OpExpr(r)
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE (c1 IS NOT NULL) IS DISTINCT FROM (c1 IS NOT NULL); -- DistinctExpr
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c1 = ANY(ARRAY[c2, 1, c1 + 0]); -- ScalarArrayOpExpr
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c1 = (ARRAY[c1,c2,3])[1]; -- ArrayRef
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 t1 WHERE c8 = 'foo';        -- no push-down

-- ===================================================================
-- parameterized queries
-- ===================================================================
-- simple join
PREPARE st1(int, int) AS SELECT t1.c3, t2.c3 FROM ft1 t1, ft2 t2 WHERE t1.c1 = $1 AND t2.c1 = $2;
EXPLAIN (VERBOSE, COSTS false) EXECUTE st1(1, 2);
EXECUTE st1(1, 1);
EXECUTE st1(101, 101);
-- subquery using stable function (can't be pushed down)
PREPARE st2(int) AS SELECT * FROM ft1 t1 WHERE t1.c1 < $2 AND t1.c3 IN (SELECT c3 FROM ft2 t2 WHERE c1 > $1 AND EXTRACT(dow FROM c4) = 6) ORDER BY c1;
EXPLAIN (VERBOSE, COSTS false) EXECUTE st2(10, 20);
EXECUTE st2(10, 20);
EXECUTE st1(101, 101);
-- subquery using immutable function (can be pushed down)
PREPARE st3(int) AS SELECT * FROM ft1 t1 WHERE t1.c1 < $2 AND t1.c3 IN (SELECT c3 FROM ft2 t2 WHERE c1 > $1 AND EXTRACT(dow FROM c5) = 6) ORDER BY c1;
EXPLAIN (VERBOSE, COSTS false) EXECUTE st3(10, 20);
EXECUTE st3(10, 20);
EXECUTE st3(20, 30);
-- custom plan should be chosen
PREPARE st4(int) AS SELECT * FROM ft1 t1 WHERE t1.c1 = $1;
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
EXPLAIN (VERBOSE, COSTS false) EXECUTE st4(1);
-- cleanup
DEALLOCATE st1;
DEALLOCATE st2;
DEALLOCATE st3;
DEALLOCATE st4;

-- ===================================================================
-- used in pl/pgsql function
-- ===================================================================
CREATE OR REPLACE FUNCTION f_test(p_c1 int) RETURNS int AS $$
DECLARE
	v_c1 int;
BEGIN
    SELECT c1 INTO v_c1 FROM ft1 WHERE c1 = p_c1 LIMIT 1;
    PERFORM c1 FROM ft1 WHERE c1 = p_c1 AND p_c1 = v_c1 LIMIT 1;
    RETURN v_c1;
END;
$$ LANGUAGE plpgsql;
SELECT f_test(100);
DROP FUNCTION f_test(int);

-- ===================================================================
-- cost estimation options
-- ===================================================================
ALTER SERVER loopback1 OPTIONS (SET use_remote_explain 'true'); 
ALTER SERVER loopback1 OPTIONS (SET fdw_startup_cost '0'); 
ALTER SERVER loopback1 OPTIONS (SET fdw_tuple_cost '0'); 
EXPLAIN (VERBOSE, COSTS false) SELECT * FROM ft1 ORDER BY c3, c1 OFFSET 100 LIMIT 10;
ALTER SERVER loopback1 OPTIONS (DROP use_remote_explain); 
ALTER SERVER loopback1 OPTIONS (DROP fdw_startup_cost); 
ALTER SERVER loopback1 OPTIONS (DROP fdw_tuple_cost); 

-- ===================================================================
-- connection management
-- ===================================================================
SELECT srvname, usename FROM postgres_fdw_connections;
SELECT postgres_fdw_disconnect(srvid, usesysid) FROM postgres_fdw_get_connections();
SELECT srvname, usename FROM postgres_fdw_connections;

-- ===================================================================
-- conversion error
-- ===================================================================
ALTER FOREIGN TABLE ft1 ALTER COLUMN c8 TYPE int;
SELECT * FROM ft1 WHERE c1 = 1;  -- ERROR
ALTER FOREIGN TABLE ft1 ALTER COLUMN c8 TYPE user_enum;

-- ===================================================================
-- subtransaction
--  + local/remote error doesn't break cursor
--  + remote error discards connection
-- ===================================================================
BEGIN;
DECLARE c CURSOR FOR SELECT * FROM ft1 ORDER BY c1;
FETCH c;
SAVEPOINT s;
ERROR OUT;          -- ERROR
ROLLBACK TO s;
SELECT srvname FROM postgres_fdw_connections;
FETCH c;
SAVEPOINT s;
SELECT * FROM ft1 WHERE 1 / (c1 - 1) > 0;  -- ERROR
ROLLBACK TO s;
SELECT srvname FROM postgres_fdw_connections;
FETCH c;
SELECT * FROM ft1 ORDER BY c1 LIMIT 1;
COMMIT;
SELECT srvname FROM postgres_fdw_connections;
ERROR OUT;          -- ERROR
SELECT srvname FROM postgres_fdw_connections;

-- ===================================================================
-- test for writable foreign table stuff (PoC stage now)
-- ===================================================================
EXPLAIN(verbose) INSERT INTO ft2 (c1,c2,c3) (SELECT c1+1000,c2+100, c3 || c3 FROM ft2 LIMIT 20);
INSERT INTO ft2 (c1,c2,c3) (SELECT c1+1000,c2+100, c3 || c3 FROM ft2 LIMIT 20);
INSERT INTO ft2 (c1,c2,c3) VALUES (1101,201,'aaa'), (1102,202,'bbb'),(1103,203,'ccc') RETURNING *;
INSERT INTO ft2 (c1,c2,c3) VALUES (1104,204,'ddd'), (1105,205,'eee');
UPDATE ft2 SET c2 = c2 + 300, c3 = c3 || '_update3' WHERE c1 % 10 = 3;
UPDATE ft2 SET c2 = c2 + 400, c3 = c3 || '_update7' WHERE c1 % 10 = 7 RETURNING *;
EXPLAIN(verbose) UPDATE ft2 SET c2 = ft2.c2 + 500, c3 = ft2.c3 || '_update9' FROM ft1 WHERE ft1.c1 = ft2.c2 AND ft1.c1 % 10 = 9;
UPDATE ft2 SET c2 = ft2.c2 + 500, c3 = ft2.c3 || '_update9' FROM ft1 WHERE ft1.c1 = ft2.c2 AND ft1.c1 % 10 = 9;
DELETE FROM ft2 WHERE c1 % 10 = 5 RETURNING *;
EXPLAIN(verbose) DELETE FROM ft2 USING ft1 WHERE ft1.c1 = ft2.c2 AND ft1.c1 % 10 = 2;
DELETE FROM ft2 USING ft1 WHERE ft1.c1 = ft2.c2 AND ft1.c1 % 10 = 2;
SELECT c1,c2,c3,c4 FROM ft2 ORDER BY c1;

-- In case of remote table has before-row trigger or default with returning
ALTER TABLE "S 1"."T 1" ALTER c6 SET DEFAULT '(^-^;)';
CREATE OR REPLACE FUNCTION "S 1".F_BRTRIG() RETURNS trigger AS $$
BEGIN
    NEW.c3 = NEW.c3 || '_trig_update';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER t1_br_insert BEFORE INSERT OR UPDATE
    ON "S 1"."T 1" FOR EACH ROW EXECUTE PROCEDURE "S 1".F_BRTRIG();

INSERT INTO ft2 (c1,c2,c3) VALUES (1208, 218, 'fff') RETURNING *;
INSERT INTO ft2 (c1,c2,c3,c6) VALUES (1218, 218, 'ggg', '(--;') RETURNING *;
UPDATE ft2 SET c2 = c2 + 600 WHERE c1 % 10 = 8 RETURNING *;

-- ===================================================================
-- cleanup
-- ===================================================================
DROP OPERATOR === (int, int) CASCADE;
DROP OPERATOR !== (int, int) CASCADE;
DROP FUNCTION postgres_fdw_abs(int);
DROP SCHEMA "S 1" CASCADE;
DROP TYPE user_enum CASCADE;
DROP EXTENSION postgres_fdw CASCADE;
\c
DROP ROLE postgres_fdw_user;

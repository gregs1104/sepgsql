/*-------------------------------------------------------------------------
 *
 * connection.c
 *		  Connection management for postgres_fdw
 *
 * Portions Copyright (c) 2012, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/connection.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "foreign/foreign.h"
#include "funcapi.h"
#include "libpq-fe.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/tuplestore.h"

#include "postgres_fdw.h"
#include "connection.h"

/* ============================================================================
 * Connection management functions
 * ==========================================================================*/

/*
 * Connection cache entry managed with hash table.
 */
typedef struct ConnCacheEntry
{
	/* hash key must be first */
	Oid				serverid;	/* oid of foreign server */
	Oid				userid;		/* oid of local user */

	int				conntx;		/* one of PGSQL_FDW_CONNTX_* */
	int				refs;		/* reference counter */
	PGconn		   *conn;		/* foreign server connection */
} ConnCacheEntry;

/*
 * Hash table which is used to cache connection to PostgreSQL servers, will be
 * initialized before first attempt to connect PostgreSQL server by the backend.
 */
static HTAB *ConnectionHash;

/* ----------------------------------------------------------------------------
 * prototype of private functions
 * --------------------------------------------------------------------------*/
static void
cleanup_connection(ResourceReleasePhase phase,
				   bool isCommit,
				   bool isTopLevel,
				   void *arg);
static PGconn *connect_pg_server(ForeignServer *server, UserMapping *user);
static void begin_remote_tx(PGconn *conn);
static void abort_remote_tx(PGconn *conn);
static void commit_remote_tx(PGconn *conn);
static void deallocate_remote_prepare(PGconn *conn);

/*
 * Get a PGconn which can be used to execute foreign query on the remote
 * PostgreSQL server with the user's authorization.  If this was the first
 * request for the server, new connection is established.
 *
 * When use_tx is true, remote transaction is started if caller is the only
 * user of the connection.  Isolation level of the remote transaction is same
 * as local transaction, and remote transaction will be aborted when last
 * user release.
 *
 * TODO: Note that caching connections requires a mechanism to detect change of
 * FDW object to invalidate already established connections.
 */
PGconn *
GetConnection(ForeignServer *server, UserMapping *user, int conntx)
{
	bool			found;
	ConnCacheEntry *entry;
	ConnCacheEntry	key;

	/* initialize connection cache if it isn't */
	if (ConnectionHash == NULL)
	{
		HASHCTL		ctl;

		/* hash key is a pair of oids: serverid and userid */
		MemSet(&ctl, 0, sizeof(ctl));
		ctl.keysize = sizeof(Oid) + sizeof(Oid);
		ctl.entrysize = sizeof(ConnCacheEntry);
		ctl.hash = tag_hash;
		ctl.match = memcmp;
		ctl.keycopy = memcpy;
		/* allocate ConnectionHash in the cache context */
		ctl.hcxt = CacheMemoryContext;
		ConnectionHash = hash_create("postgres_fdw connections", 32,
									   &ctl,
									   HASH_ELEM | HASH_CONTEXT |
									   HASH_FUNCTION | HASH_COMPARE |
									   HASH_KEYCOPY);

		/*
		 * Register postgres_fdw's own cleanup function for connection
		 * cleanup.  This should be done just once for each backend.
		 */
		RegisterResourceReleaseCallback(cleanup_connection, ConnectionHash);
	}

	/* Create key value for the entry. */
	MemSet(&key, 0, sizeof(key));
	key.serverid = server->serverid;
	key.userid = GetOuterUserId();

	/*
	 * Find cached entry for requested connection.  If we couldn't find,
	 * callback function of ResourceOwner should be registered to clean the
	 * connection up on error including user interrupt.
	 */
	entry = hash_search(ConnectionHash, &key, HASH_ENTER, &found);
	if (!found)
	{
		entry->conntx = PGSQL_FDW_CONNTX_NONE;
		entry->refs = 0;
		entry->conn = NULL;
	}

	/*
	 * We don't check the health of cached connection here, because it would
	 * require some overhead.  Broken connection and its cache entry will be
	 * cleaned up when the connection is actually used.
	 */

	/*
	 * If cache entry doesn't have connection, we have to establish new
	 * connection.
	 */
	if (entry->conn == NULL)
	{
		PGconn *volatile conn = NULL;

		/*
		 * Use PG_TRY block to ensure closing connection on error.
		 */
		PG_TRY();
		{
			/*
			 * Connect to the foreign PostgreSQL server, and store it in cache
			 * entry to keep new connection.
			 * Note: key items of entry has already been initialized in
			 * hash_search(HASH_ENTER).
			 */
			conn = connect_pg_server(server, user);
		}
		PG_CATCH();
		{
			/* Clear connection cache entry on error case. */
			PQfinish(entry->conn);
			entry->conntx = PGSQL_FDW_CONNTX_NONE;
			entry->refs = 0;
			entry->conn = NULL;
			PG_RE_THROW();
		}
		PG_END_TRY();
		entry->conn = conn;
		elog(DEBUG3, "new postgres_fdw connection %p for server %s",
			 entry->conn, server->servername);
	}

	/* Increase connection reference counter. */
	entry->refs++;

	/*
	 * If remote transaction is requested but it has not started, start remote
	 * transaction with the same isolation level as the local transaction we
	 * are in.  We need to remember whether this connection uses remote
	 * transaction to abort it when this connection is released completely.
	 */
	if (conntx > entry->conntx)
	{
		if (entry->conntx == PGSQL_FDW_CONNTX_NONE)
			begin_remote_tx(entry->conn);
		entry->conntx = conntx;
	}

	return entry->conn;
}

/*
 * For non-superusers, insist that the connstr specify a password.	This
 * prevents a password from being picked up from .pgpass, a service file,
 * the environment, etc.  We don't want the postgres user's passwords
 * to be accessible to non-superusers.
 */
static void
check_conn_params(const char **keywords, const char **values)
{
	int			i;

	/* no check required if superuser */
	if (superuser())
		return;

	/* ok if params contain a non-empty password */
	for (i = 0; keywords[i] != NULL; i++)
	{
		if (strcmp(keywords[i], "password") == 0 && values[i][0] != '\0')
			return;
	}

	ereport(ERROR,
		  (errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED),
		   errmsg("password is required"),
		   errdetail("Non-superusers must provide a password in the connection string.")));
}

static PGconn *
connect_pg_server(ForeignServer *server, UserMapping *user)
{
	const char	   *conname = server->servername;
	PGconn		   *conn;
	const char	  **all_keywords;
	const char	  **all_values;
	const char	  **keywords;
	const char	  **values;
	int				n;
	int				i, j;

	/*
	 * Construct connection params from generic options of ForeignServer and
	 * UserMapping.  Those two object hold only libpq options.
	 * Extra 3 items are for:
	 *   *) fallback_application_name
	 *   *) client_encoding
	 *   *) NULL termination (end marker)
	 *
	 * Note: We don't omit any parameters even target database might be older
	 * than local, because unexpected parameters are just ignored.
	 */
	n = list_length(server->options) + list_length(user->options) + 3;
	all_keywords = (const char **) palloc(sizeof(char *) * n);
	all_values = (const char **) palloc(sizeof(char *) * n);
	keywords = (const char **) palloc(sizeof(char *) * n);
	values = (const char **) palloc(sizeof(char *) * n);
	n = 0;
	n += ExtractConnectionOptions(server->options,
								  all_keywords + n, all_values + n);
	n += ExtractConnectionOptions(user->options,
								  all_keywords + n, all_values + n);
	all_keywords[n] = all_values[n] = NULL;

	for (i = 0, j = 0; all_keywords[i]; i++)
	{
		keywords[j] = all_keywords[i];
		values[j] = all_values[i];
		j++;
	}

	/* Use "postgres_fdw" as fallback_application_name. */
	keywords[j] = "fallback_application_name";
	values[j++] = "postgres_fdw";

	/* Set client_encoding so that libpq can convert encoding properly. */
	keywords[j] = "client_encoding";
	values[j++] = GetDatabaseEncodingName();

	keywords[j] = values[j] = NULL;
	pfree(all_keywords);
	pfree(all_values);

	/* verify connection parameters and do connect */
	check_conn_params(keywords, values);
	conn = PQconnectdbParams(keywords, values, 0);
	if (!conn || PQstatus(conn) != CONNECTION_OK)
		ereport(ERROR,
				(errcode(ERRCODE_SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION),
				 errmsg("could not connect to server \"%s\"", conname),
				 errdetail("%s", PQerrorMessage(conn))));
	pfree(keywords);
	pfree(values);

	/*
	 * Check that non-superuser has used password to establish connection.
	 * This check logic is based on dblink_security_check() in contrib/dblink.
	 *
	 * XXX Should we check this even if we don't provide unsafe version like
	 * dblink_connect_u()?
	 */
	if (!superuser() && !PQconnectionUsedPassword(conn))
	{
		PQfinish(conn);
		ereport(ERROR,
				(errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED),
				 errmsg("password is required"),
				 errdetail("Non-superuser cannot connect if the server does not request a password."),
				 errhint("Target server's authentication method must be changed.")));
	}

	return conn;
}

/*
 * Start remote transaction with proper isolation level.
 */
static void
begin_remote_tx(PGconn *conn)
{
	const char	   *sql = NULL;		/* keep compiler quiet. */
	PGresult	   *res;

	switch (XactIsoLevel)
	{
		case XACT_READ_UNCOMMITTED:
		case XACT_READ_COMMITTED:
		case XACT_REPEATABLE_READ:
			sql = "START TRANSACTION ISOLATION LEVEL REPEATABLE READ";
			break;
		case XACT_SERIALIZABLE:
			sql = "START TRANSACTION ISOLATION LEVEL SERIALIZABLE";
			break;
		default:
			elog(ERROR, "unexpected isolation level: %d", XactIsoLevel);
			break;
	}

	elog(DEBUG3, "starting remote transaction with \"%s\"", sql);

	res = PQexec(conn, sql);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not start transaction: %s", PQerrorMessage(conn));
	}
	PQclear(res);
}

static void
abort_remote_tx(PGconn *conn)
{
	PGresult	   *res;

	elog(DEBUG3, "aborting remote transaction");

	res = PQexec(conn, "ABORT TRANSACTION");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not abort transaction: %s", PQerrorMessage(conn));
	}
	PQclear(res);
}

static void
commit_remote_tx(PGconn *conn)
{
	PGresult	   *res;

	elog(DEBUG3, "committing remote transaction");

	res = PQexec(conn, "COMMIT TRANSACTION");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not commit transaction: %s", PQerrorMessage(conn));
	}
	PQclear(res);
}

static void
deallocate_remote_prepare(PGconn *conn)
{
	PGresult	   *res;

	elog(DEBUG3, "deallocating remote prepares");

	res = PQexec(conn, "DEALLOCATE PREPARE ALL");
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not deallocate prepared statement: %s",
			 PQerrorMessage(conn));
	}
	PQclear(res);
}

/*
 * Mark the connection as "unused", and close it if the caller was the last
 * user of the connection.
 */
void
ReleaseConnection(PGconn *conn, bool is_abort)
{
	HASH_SEQ_STATUS		scan;
	ConnCacheEntry	   *entry;

	if (conn == NULL)
		return;

	/*
	 * We need to scan sequentially since we use the address to find
	 * appropriate PGconn from the hash table.
	 */
	hash_seq_init(&scan, ConnectionHash);
	while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
	{
		if (entry->conn == conn)
		{
			hash_seq_term(&scan);
			break;
		}
	}

	/*
	 * If the given connection is an orphan, it must be a dangling pointer to
	 * already released connection.  Discarding connection due to remote query
	 * error would produce such situation (see comments below).
	 */
	if (entry == NULL)
		return;

	/*
	 * If releasing connection is broken or its transaction has failed,
	 * discard the connection to recover from the error.  PQfinish would cause
	 * dangling pointer of shared PGconn object, but they won't double-free'd
	 * because their pointer values don't match any of cached entry and ignored
	 * at the check above.
	 *
	 * Subsequent connection request via GetConnection will create new
	 * connection.
	 */
	if (PQstatus(conn) != CONNECTION_OK ||
		(PQtransactionStatus(conn) != PQTRANS_IDLE &&
		 PQtransactionStatus(conn) != PQTRANS_INTRANS))
	{
		elog(DEBUG3, "discarding connection: %s %s",
			 PQstatus(conn) == CONNECTION_OK ? "OK" : "NG",
			 PQtransactionStatus(conn) == PQTRANS_IDLE ? "IDLE" :
			 PQtransactionStatus(conn) == PQTRANS_ACTIVE ? "ACTIVE" :
			 PQtransactionStatus(conn) == PQTRANS_INTRANS ? "INTRANS" :
			 PQtransactionStatus(conn) == PQTRANS_INERROR ? "INERROR" :
			 "UNKNOWN");
		PQfinish(conn);
		entry->conntx = PGSQL_FDW_CONNTX_NONE;
		entry->refs = 0;
		entry->conn = NULL;
		return;
	}

	/*
	 * Decrease reference counter of this connection.  Even if the caller was
	 * the last referrer, we don't unregister it from cache.
	 */
	entry->refs--;
	if (entry->refs < 0)
		entry->refs = 0;	/* just in case */

	/*
	 * If this connection uses remote transaction and there is no user other
	 * than the caller, abort the remote transaction and forget about it.
	 */
	if (entry->conntx > PGSQL_FDW_CONNTX_NONE && entry->refs == 0)
	{
		if (entry->conntx > PGSQL_FDW_CONNTX_READ_ONLY)
			deallocate_remote_prepare(conn);
		if (is_abort || entry->conntx == PGSQL_FDW_CONNTX_READ_ONLY)
			abort_remote_tx(conn);
		else
			commit_remote_tx(conn);

		entry->conntx = PGSQL_FDW_CONNTX_NONE;
	}
}

/*
 * Clean the connection up via ResourceOwner.
 */
static void
cleanup_connection(ResourceReleasePhase phase,
				   bool isCommit,
				   bool isTopLevel,
				   void *arg)
{
	HASH_SEQ_STATUS	scan;
	ConnCacheEntry *entry = (ConnCacheEntry *) arg;

	/* If the transaction was committed, don't close connections. */
	if (isCommit)
		return;

	/*
	 * We clean the connection up on post-lock because foreign connections are
	 * backend-internal resource.
	 */
	if (phase != RESOURCE_RELEASE_AFTER_LOCKS)
		return;

	/*
	 * We ignore cleanup for ResourceOwners other than transaction.  At this
	 * point, such a ResourceOwner is only Portal.
	 */
	if (CurrentResourceOwner != CurTransactionResourceOwner)
		return;

	/*
	 * We don't need to clean up at end of subtransactions, because they might
	 * be recovered to consistent state with savepoints.
	 */
	if (!isTopLevel)
		return;

	/*
	 * Here, it must be after abort of top level transaction.  Disconnect all
	 * cached connections to clear error status out and reset their reference
	 * counters.
	 */
	hash_seq_init(&scan, ConnectionHash);
	while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
	{
		elog(DEBUG3, "discard postgres_fdw connection %p due to resowner cleanup",
			 entry->conn);
		PQfinish(entry->conn);
		entry->conntx = PGSQL_FDW_CONNTX_NONE;
		entry->refs = 0;
		entry->conn = NULL;
	}
}

/*
 * Get list of connections currently active.
 */
Datum postgres_fdw_get_connections(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(postgres_fdw_get_connections);
Datum
postgres_fdw_get_connections(PG_FUNCTION_ARGS)
{
	ReturnSetInfo	   *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	HASH_SEQ_STATUS		scan;
	ConnCacheEntry	   *entry;
	MemoryContext		oldcontext = CurrentMemoryContext;
	Tuplestorestate	   *tuplestore;
	TupleDesc			tupdesc;

	/* We return list of connection with storing them in a Tuplestore. */
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = NULL;
	rsinfo->setDesc = NULL;

	/* Create tuplestore and copy of TupleDesc in per-query context. */
	MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);

	tupdesc = CreateTemplateTupleDesc(2, false);
	TupleDescInitEntry(tupdesc, 1, "srvid", OIDOID, -1, 0);
	TupleDescInitEntry(tupdesc, 2, "usesysid", OIDOID, -1, 0);
	rsinfo->setDesc = tupdesc;

	tuplestore = tuplestore_begin_heap(false, false, work_mem);
	rsinfo->setResult = tuplestore;

	MemoryContextSwitchTo(oldcontext);

	/*
	 * We need to scan sequentially since we use the address to find
	 * appropriate PGconn from the hash table.
	 */
	if (ConnectionHash != NULL)
	{
		hash_seq_init(&scan, ConnectionHash);
		while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
		{
			Datum		values[2];
			bool		nulls[2];
			HeapTuple	tuple;

			/* Ignore inactive connections */
			if (PQstatus(entry->conn) != CONNECTION_OK)
				continue;

			/*
			 * Ignore other users' connections if current user isn't a
			 * superuser.
			 */
			if (!superuser() && entry->userid != GetUserId())
				continue;

			values[0] = ObjectIdGetDatum(entry->serverid);
			values[1] = ObjectIdGetDatum(entry->userid);
			nulls[0] = false;
			nulls[1] = false;

			tuple = heap_formtuple(tupdesc, values, nulls);
			tuplestore_puttuple(tuplestore, tuple);
		}
	}
	tuplestore_donestoring(tuplestore);

	PG_RETURN_VOID();
}

/*
 * Discard persistent connection designated by given connection name.
 */
Datum postgres_fdw_disconnect(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(postgres_fdw_disconnect);
Datum
postgres_fdw_disconnect(PG_FUNCTION_ARGS)
{
	Oid					serverid = PG_GETARG_OID(0);
	Oid					userid = PG_GETARG_OID(1);
	ConnCacheEntry		key;
	ConnCacheEntry	   *entry = NULL;
	bool				found;

	/* Non-superuser can't discard other users' connection. */
	if (!superuser() && userid != GetOuterUserId())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_RESOURCES),
				 errmsg("only superuser can discard other user's connection")));

	/*
	 * If no connection has been established, or no such connections, just
	 * return "NG" to indicate nothing has done.
	 */
	if (ConnectionHash == NULL)
		PG_RETURN_TEXT_P(cstring_to_text("NG"));

	key.serverid = serverid;
	key.userid = userid;
	entry = hash_search(ConnectionHash, &key, HASH_FIND, &found);
	if (!found)
		PG_RETURN_TEXT_P(cstring_to_text("NG"));

	/* Discard cached connection, and clear reference counter. */
	PQfinish(entry->conn);
	entry->conntx = PGSQL_FDW_CONNTX_NONE;
	entry->refs = 0;
	entry->conn = NULL;

	PG_RETURN_TEXT_P(cstring_to_text("OK"));
}

/*-------------------------------------------------------------------------
 *
 * connection.h
 *		  Connection management for postgres_fdw
 *
 * Portions Copyright (c) 2012, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/connection.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CONNECTION_H
#define CONNECTION_H

#include "foreign/foreign.h"
#include "libpq-fe.h"

#define PGSQL_FDW_CONNTX_NONE			0
#define PGSQL_FDW_CONNTX_READ_ONLY		1
#define PGSQL_FDW_CONNTX_READ_WRITE		2

/*
 * Connection management
 */
PGconn *GetConnection(ForeignServer *server, UserMapping *user, int conntx);
void ReleaseConnection(PGconn *conn, bool is_abort);

#endif /* CONNECTION_H */

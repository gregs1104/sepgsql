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

/*
 * Connection management
 */
PGconn *GetConnection(ForeignServer *server, UserMapping *user, bool use_tx);
void ReleaseConnection(PGconn *conn);

#endif /* CONNECTION_H */

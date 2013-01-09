/*-------------------------------------------------------------------------
 *
 * postgres_fdw.h
 *		  foreign-data wrapper for remote PostgreSQL servers.
 *
 * Copyright (c) 2012, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/postgres_fdw.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef POSTGRESQL_FDW_H
#define POSTGRESQL_FDW_H

#include "postgres.h"
#include "foreign/foreign.h"
#include "nodes/relation.h"
#include "utils/relcache.h"

/* in option.c */
void InitPostgresFdwOptions(void);
int ExtractConnectionOptions(List *defelems,
							 const char **keywords,
							 const char **values);
int GetFetchCountOption(ForeignTable *table, ForeignServer *server);

/* in deparse.c */
void deparseSimpleSql(StringInfo buf,
					  PlannerInfo *root,
					  RelOptInfo *baserel,
					  List *local_conds);
void appendWhereClause(StringInfo buf,
					   bool has_where,
					   List *exprs,
					   PlannerInfo *root);
void classifyConditions(PlannerInfo *root,
						RelOptInfo *baserel,
						List **remote_conds,
						List **param_conds,
						List **local_conds);
void deparseAnalyzeSql(StringInfo buf, Relation rel);

#endif /* POSTGRESQL_FDW_H */

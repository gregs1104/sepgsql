/*-------------------------------------------------------------------------
 *
 * postgres_fdw.h
 *		  Foreign-data wrapper for remote PostgreSQL servers
 *
 * Portions Copyright (c) 2012-2013, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/postgres_fdw.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef POSTGRES_FDW_H
#define POSTGRES_FDW_H

#include "foreign/foreign.h"
#include "lib/stringinfo.h"
#include "nodes/relation.h"
#include "utils/rel.h"

#include "libpq-fe.h"

/* in postgres_fdw.c */

/*
 * FDW-specific planner information kept in RelOptInfo.fdw_private for a
 * foreign table.  This information is collected by postgresGetForeignRelSize.
 */
typedef struct PgFdwRelationInfo
{
	/* baserestrictinfo clauses, broken down into safe and unsafe subsets. */
	List	   *remote_conds;
	List	   *local_conds;

	/* Bitmap of attr numbers we need to fetch from the remote server. */
	Bitmapset  *attrs_used;

	/* Cost and selectivity of local_conds. */
	QualCost	local_conds_cost;
	Selectivity local_conds_sel;

	/* Estimated size and cost for a scan with baserestrictinfo quals. */
	double		rows;
	int			width;
	Cost		startup_cost;
	Cost		total_cost;

	/* Options extracted from catalogs. */
	bool		use_remote_estimate;
	Cost		fdw_startup_cost;
	Cost		fdw_tuple_cost;

	/* Cached catalog information. */
	ForeignTable *table;
	ForeignServer *server;
	UserMapping *user;			/* only set in use_remote_estimate mode */
} PgFdwRelationInfo;

extern int	set_transmission_modes(void);
extern void reset_transmission_modes(int nestlevel);

/* in connection.c */
extern PGconn *GetConnection(ForeignServer *server, UserMapping *user,
			  bool will_prep_stmt);
extern void ReleaseConnection(PGconn *conn);
extern unsigned int GetCursorNumber(PGconn *conn);
extern unsigned int GetPrepStmtNumber(PGconn *conn);
extern void pgfdw_report_error(int elevel, PGresult *res, bool clear,
				   const char *sql);

/* in option.c */
extern int ExtractConnectionOptions(List *defelems,
						 const char **keywords,
						 const char **values);

/* in deparse.c */
extern void classifyConditions(PlannerInfo *root,
				   RelOptInfo *baserel,
				   List *restrictinfo_list,
				   List **remote_conds,
				   List **local_conds);
extern bool is_foreign_expr(PlannerInfo *root,
				RelOptInfo *baserel,
				Expr *expr);
extern void deparseSelectSql(StringInfo buf,
				 PlannerInfo *root,
				 RelOptInfo *baserel,
				 Bitmapset *attrs_used,
				 List **retrieved_attrs);
extern void appendWhereClause(StringInfo buf,
				  PlannerInfo *root,
				  RelOptInfo *baserel,
				  List *exprs,
				  bool is_first,
				  bool is_join_on,
				  bool qualified,
				  List **params);
extern void deparseInsertSql(StringInfo buf, PlannerInfo *root,
				 Index rtindex, Relation rel,
				 List *targetAttrs, List *returningList,
				 List **retrieved_attrs);
extern void deparseUpdateSql(StringInfo buf, PlannerInfo *root,
				 Index rtindex, Relation rel,
				 List *targetAttrs, List *returningList,
				 List **retrieved_attrs);
extern void deparseDeleteSql(StringInfo buf, PlannerInfo *root,
				 Index rtindex, Relation rel,
				 List *returningList,
				 List **retrieved_attrs);
extern void deparseRemoteJoinSql(StringInfo buf, PlannerInfo *root,
								 List *relinfo,
								 List *target_list,
								 List *local_conds,
								 List **select_vars,
								 List **param_list);
extern void deparseAnalyzeSizeSql(StringInfo buf, Relation rel);
extern void deparseAnalyzeSql(StringInfo buf, Relation rel,
				  List **retrieved_attrs);

/* remote join support on top of custom-scan APIs */
typedef struct
{
	Oid			fdw_server_oid;	/* server oid commonly used */
	Oid			fdw_user_oid;	/* user oid commonly used */
	Relids		relids;			/* bitmapset of range table indexes */
	JoinType	jointype;		/* one of JOIN_* */
	Node	   *outer_rel;		/* packed information of outer relation */
	Node	   *inner_rel;		/* packed information of inner relation */
	List	   *remote_conds;	/* condition to be run on remote server */
	List	   *local_conds;	/* condition to be run on local server */
	List	   *select_vars;	/* List of Var nodes to be fetched */
	List	   *select_params;	/* List of Var nodes being parameralized */
	char	   *select_qry;		/* remote query being deparsed */
} PgRemoteJoinInfo;

extern List *packPgRemoteJoinInfo(PgRemoteJoinInfo *jinfo);
extern void unpackPgRemoteJoinInfo(PgRemoteJoinInfo *jinfo,
								   List *custom_private);

#endif   /* POSTGRES_FDW_H */

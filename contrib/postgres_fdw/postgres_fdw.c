/*-------------------------------------------------------------------------
 *
 * postgres_fdw.c
 *		  foreign-data wrapper for remote PostgreSQL servers.
 *
 * Copyright (c) 2012, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/postgres_fdw.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "commands/explain.h"
#include "commands/vacuum.h"
#include "foreign/fdwapi.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"
#include "parser/parsetree.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"

#include "postgres_fdw.h"
#include "connection.h"

PG_MODULE_MAGIC;

/* Defalut cost to establish a connection. */
#define DEFAULT_FDW_STARTUP_COST	100.0

/* Defalut cost to process 1 row, including data transfer. */
#define DEFAULT_FDW_TUPLE_COST		0.001

/*
 * FDW-specific information for RelOptInfo.fdw_private.  This is used to pass
 * information from postgresGetForeignRelSize to postgresGetForeignPaths.
 */
typedef struct PostgresFdwPlanState {
	/*
	 * These are generated in GetForeignRelSize, and also used in subsequent
	 * GetForeignPaths.
	 */
	StringInfoData	sql;
	Cost			startup_cost;
	Cost			total_cost;
	List		   *remote_conds;
	List		   *param_conds;
	List		   *local_conds;
	int				width;			/* obtained by remote EXPLAIN */
	AttrNumber		anum_rowid;

	/* Cached catalog information. */
	ForeignTable   *table;
	ForeignServer  *server;
} PostgresFdwPlanState;

/*
 * Index of FDW-private information stored in fdw_private list.
 *
 * We store various information in ForeignScan.fdw_private to pass them beyond
 * the boundary between planner and executor.  Finally FdwPlan holds items
 * below:
 *
 * 1) plain SELECT statement
 *
 * These items are indexed with the enum FdwPrivateIndex, so an item
 * can be accessed directly via list_nth().  For example of SELECT statement:
 *      sql = list_nth(fdw_private, FdwPrivateSelectSql)
 */
enum FdwPrivateIndex {
	/* SQL statements */
	FdwPrivateSelectSql,

	/* # of elements stored in the list fdw_private */
	FdwPrivateNum,
};

/*
 * Describe the attribute where data conversion fails.
 */
typedef struct ErrorPos {
	Oid			relid;			/* oid of the foreign table */
	AttrNumber	cur_attno;		/* attribute number under process */
} ErrorPos;

/*
 * Describes an execution state of a foreign scan against a foreign table
 * using postgres_fdw.
 */
typedef struct PostgresFdwExecutionState
{
	List	   *fdw_private;	/* FDW-private information */

	/* for remote query execution */
	PGconn	   *conn;			/* connection for the scan */
	Oid		   *param_types;	/* type array of external parameter */
	const char **param_values;	/* value array of external parameter */

	/* for tuple generation. */
	AttrNumber	attnum;			/* # of non-dropped attribute */
	Datum	   *values;			/* column value buffer */
	bool	   *nulls;			/* column null indicator buffer */
	AttInMetadata *attinmeta;	/* attribute metadata */

	/* for storing result tuples */
	MemoryContext scan_cxt;		/* context for per-scan lifespan data */
	MemoryContext temp_cxt;		/* context for per-tuple temporary data */
	Tuplestorestate *tuples;	/* result of the scan */

	/* for error handling. */
	ErrorPos	errpos;
} PostgresFdwExecutionState;

/*
 * Describes a state of analyze request for a foreign table.
 */
typedef struct PostgresAnalyzeState
{
	/* for tuple generation. */
	TupleDesc	tupdesc;
	AttInMetadata *attinmeta;
	Datum	   *values;
	bool	   *nulls;

	/* for random sampling */
	HeapTuple  *rows;			/* result buffer */
	int			targrows;		/* target # of sample rows */
	int			numrows;		/* # of samples collected */
	double		samplerows;		/* # of rows fetched */
	double		rowstoskip;		/* # of rows skipped before next sample */
	double		rstate;			/* random state */

	/* for storing result tuples */
	MemoryContext anl_cxt;		/* context for per-analyze lifespan data */
	MemoryContext temp_cxt;		/* context for per-tuple temporary data */

	/* for error handling. */
	ErrorPos	errpos;
} PostgresAnalyzeState;

/*
 * Describes a state of modify request for a foreign table
 */
typedef struct PostgresFdwModifyState
{
	PGconn	   *conn;
	char	   *query;
	bool		has_returning;
	List	   *target_attrs;
	char	   *p_name;
	int			p_nums;
	Oid		   *p_types;
	FmgrInfo   *p_flinfo;
	Oid		   *r_ioparam;
	FmgrInfo   *r_flinfo;
	MemoryContext	es_query_cxt;
} PostgresFdwModifyState;

/*
 * SQL functions
 */
extern Datum postgres_fdw_handler(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(postgres_fdw_handler);

/*
 * FDW callback routines
 */
static AttrNumber postgresGetForeignRelWidth(PlannerInfo *root,
											 RelOptInfo *baserel,
											 Relation foreignrel,
											 bool inhparent,
											 List *targetList);
static void postgresGetForeignRelSize(PlannerInfo *root,
									  RelOptInfo *baserel,
									  Oid foreigntableid);
static void postgresGetForeignPaths(PlannerInfo *root,
									RelOptInfo *baserel,
									Oid foreigntableid);
static ForeignScan *postgresGetForeignPlan(PlannerInfo *root,
										   RelOptInfo *baserel,
										   Oid foreigntableid,
										   ForeignPath *best_path,
										   List *tlist,
										   List *scan_clauses);
static void postgresExplainForeignScan(ForeignScanState *node,
									   ExplainState *es);
static void postgresBeginForeignScan(ForeignScanState *node, int eflags);
static TupleTableSlot *postgresIterateForeignScan(ForeignScanState *node);
static void postgresReScanForeignScan(ForeignScanState *node);
static void postgresEndForeignScan(ForeignScanState *node);
static bool postgresAnalyzeForeignTable(Relation relation,
										AcquireSampleRowsFunc *func,
										BlockNumber *totalpages);
static List *postgresPlanForeignModify(PlannerInfo *root,
									   ModifyTable *plan,
									   Index resultRelation,
									   Plan *subplan);
static void postgresBeginForeignModify(ModifyTableState *mtstate,
									   ResultRelInfo *resultRelInfo,
									   List *fdw_private,
									   Plan *subplan,
									   int eflags);
static TupleTableSlot *postgresExecForeignInsert(ResultRelInfo *rinfo,
												 TupleTableSlot *slot);
static bool postgresExecForeignDelete(ResultRelInfo *rinfo,
									  const char *rowid);
static TupleTableSlot * postgresExecForeignUpdate(ResultRelInfo *rinfo,
												  const char *rowid,
												  TupleTableSlot *slot);
static void postgresEndForeignModify(ResultRelInfo *rinfo);

/*
 * Helper functions
 */
static void get_remote_estimate(const char *sql,
								PGconn *conn,
								double *rows,
								int *width,
								Cost *startup_cost,
								Cost *total_cost);
static void execute_query(ForeignScanState *node);
static void query_row_processor(PGresult *res, ForeignScanState *node,
								bool first);
static void analyze_row_processor(PGresult *res, PostgresAnalyzeState *astate,
								  bool first);
static void postgres_fdw_error_callback(void *arg);
static int postgresAcquireSampleRowsFunc(Relation relation, int elevel,
										 HeapTuple *rows, int targrows,
										 double *totalrows,
										 double *totaldeadrows);

/* Exported functions, but not written in postgres_fdw.h. */
void _PG_init(void);
void _PG_fini(void);

/*
 * Module-specific initialization.
 */
void
_PG_init(void)
{
	InitPostgresFdwOptions();
}

/*
 * Module-specific clean up.
 */
void
_PG_fini(void)
{
}

/*
 * Foreign-data wrapper handler function: return a struct with pointers
 * to my callback routines.
 */
Datum
postgres_fdw_handler(PG_FUNCTION_ARGS)
{
	FdwRoutine	*routine = makeNode(FdwRoutine);

	/* Required handler functions. */
	routine->GetForeignRelWidth = postgresGetForeignRelWidth;
	routine->GetForeignRelSize = postgresGetForeignRelSize;
	routine->GetForeignPaths = postgresGetForeignPaths;
	routine->GetForeignPlan = postgresGetForeignPlan;
	routine->ExplainForeignScan = postgresExplainForeignScan;
	routine->BeginForeignScan = postgresBeginForeignScan;
	routine->IterateForeignScan = postgresIterateForeignScan;
	routine->ReScanForeignScan = postgresReScanForeignScan;
	routine->EndForeignScan = postgresEndForeignScan;
	routine->PlanForeignModify = postgresPlanForeignModify;
	routine->BeginForeignModify = postgresBeginForeignModify;
	routine->ExecForeignInsert = postgresExecForeignInsert;
	routine->ExecForeignDelete = postgresExecForeignDelete;
	routine->ExecForeignUpdate = postgresExecForeignUpdate;
	routine->EndForeignModify = postgresEndForeignModify;

	/* Optional handler functions. */
	routine->AnalyzeForeignTable = postgresAnalyzeForeignTable;

	PG_RETURN_POINTER(routine);
}

/*
 * postgresGetForeignRelWidth
 *		Informs how many columns (including pseudo ones) are needed.
 */
static AttrNumber
postgresGetForeignRelWidth(PlannerInfo *root,
						   RelOptInfo *baserel,
						   Relation foreignrel,
						   bool inhparent,
						   List *targetList)
{
	PostgresFdwPlanState *fpstate = palloc0(sizeof(PostgresFdwPlanState));

	baserel->fdw_private = fpstate;

	/* does rowid pseudo-column is required? */
	fpstate->anum_rowid = get_pseudo_rowid_column(baserel, targetList);
	if (fpstate->anum_rowid != InvalidAttrNumber)
	{
		RangeTblEntry *rte = rt_fetch(baserel->relid,
									  root->parse->rtable);
		rte->eref->colnames = lappend(rte->eref->colnames,
									  makeString("ctid"));
		return fpstate->anum_rowid;
	}
	return RelationGetNumberOfAttributes(foreignrel);
}

/*
 * postgresGetForeignRelSize
 *		Estimate # of rows and width of the result of the scan
 *
 * Here we estimate number of rows returned by the scan in two steps.  In the
 * first step, we execute remote EXPLAIN command to obtain the number of rows
 * returned from remote side.  In the second step, we calculate the selectivity
 * of the filtering done on local side, and modify first estimate.
 *
 * We have to get some catalog objects and generate remote query string here,
 * so we store such expensive information in FDW private area of RelOptInfo and
 * pass them to subsequent functions for reuse.
 */
static void
postgresGetForeignRelSize(PlannerInfo *root,
						  RelOptInfo *baserel,
						  Oid foreigntableid)
{
	bool			use_remote_explain = false;
	ListCell	   *lc;
	PostgresFdwPlanState *fpstate;
	StringInfo		sql;
	ForeignTable   *table;
	ForeignServer  *server;
	Selectivity		sel;
	double			rows;
	int				width;
	Cost			startup_cost;
	Cost			total_cost;
	List		   *remote_conds = NIL;
	List		   *param_conds = NIL;
	List		   *local_conds = NIL;

	/*
	 * We use PostgresFdwPlanState to pass various information to subsequent
	 * functions.
	 */
	fpstate = baserel->fdw_private;
	initStringInfo(&fpstate->sql);
	sql = &fpstate->sql;

	/*
	 * Determine whether we use remote estimate or not.  Note that per-table
	 * setting overrides per-server setting.
	 */
	table = GetForeignTable(foreigntableid);
	server = GetForeignServer(table->serverid);
	foreach (lc, server->options)
	{
		DefElem	   *def = (DefElem *) lfirst(lc);
		if (strcmp(def->defname, "use_remote_explain") == 0)
		{
			use_remote_explain = defGetBoolean(def);
			break;
		}
	}
	foreach (lc, table->options)
	{
		DefElem	   *def = (DefElem *) lfirst(lc);
		if (strcmp(def->defname, "use_remote_explain") == 0)
		{
			use_remote_explain = defGetBoolean(def);
			break;
		}
	}

	/*
	 * Construct remote query which consists of SELECT, FROM, and WHERE
	 * clauses.  Conditions which contain any Param node are excluded because
	 * placeholder can't be used in EXPLAIN statement.  Such conditions are
	 * appended later.
	 */
	classifyConditions(root, baserel, &remote_conds, &param_conds,
					   &local_conds);
	deparseSimpleSql(sql, root, baserel, local_conds, fpstate->anum_rowid);
	if (list_length(remote_conds) > 0)
		appendWhereClause(sql, true, remote_conds, root);

	/*
	 * If the table or the server is configured to use remote EXPLAIN, connect
	 * the foreign server and execute EXPLAIN with conditions which don't
	 * contain any parameter reference.  Otherwise, estimate rows in the way
	 * similar to ordinary tables.
	 */
	if (use_remote_explain)
	{
		UserMapping	   *user;
		PGconn		   *conn;

		user = GetUserMapping(GetOuterUserId(), server->serverid);
		conn = GetConnection(server, user, PGSQL_FDW_CONNTX_NONE);
		get_remote_estimate(sql->data, conn, &rows, &width,
							&startup_cost, &total_cost);
		ReleaseConnection(conn, false);

		/*
		 * Estimate selectivity of conditions which are not used in remote
		 * EXPLAIN by calling clauselist_selectivity().  The best we can do for
		 * parameterized condition is to estimate selectivity on the basis of
		 * local statistics.  When we actually obtain result rows, such
		 * conditions are deparsed into remote query and reduce rows
		 * transferred.
		 */
		sel = 1;
		sel *= clauselist_selectivity(root, param_conds,
									  baserel->relid, JOIN_INNER, NULL);
		sel *= clauselist_selectivity(root, local_conds,
									  baserel->relid, JOIN_INNER, NULL);

		/* Report estimated numbers to planner. */
		baserel->rows = rows * sel;
	}
	else
	{
		/*
		 * Estimate rows from the result of the last ANALYZE, and all
		 * conditions specified in original query.
		 */
		set_baserel_size_estimates(root, baserel);

		/* Save estimated width to pass it to consequence functions */
		width = baserel->width;
	}

	/*
	 * Finish deparsing remote query by adding conditions which are unavailable
	 * in remote EXPLAIN since they contain parameter references.
	 */
	if (list_length(param_conds) > 0)
		appendWhereClause(sql, !(list_length(remote_conds) > 0), param_conds,
						  root);

	/*
	 * Pack obtained information into a object and store it in FDW-private area
	 * of RelOptInfo to pass them to subsequent functions.
	 */
	fpstate->startup_cost = startup_cost;
	fpstate->total_cost = total_cost;
	fpstate->remote_conds = remote_conds;
	fpstate->param_conds = param_conds;
	fpstate->local_conds = local_conds;
	fpstate->width = width;
	fpstate->table = table;
	fpstate->server = server;
}

/*
 * postgresGetForeignPaths
 *		Create possible scan paths for a scan on the foreign table
 */
static void
postgresGetForeignPaths(PlannerInfo *root,
						RelOptInfo *baserel,
						Oid foreigntableid)
{
	PostgresFdwPlanState *fpstate;
	ForeignPath	   *path;
	ListCell	   *lc;
	double			fdw_startup_cost = DEFAULT_FDW_STARTUP_COST;
	double			fdw_tuple_cost = DEFAULT_FDW_TUPLE_COST;
	Cost			startup_cost;
	Cost			total_cost;
	List		   *fdw_private;

	/* Cache frequently accessed value */
	fpstate  = (PostgresFdwPlanState *) baserel->fdw_private;

	/*
	 * We have cost values which are estimated on remote side, so adjust them
	 * for better estimate which respect various stuffs to complete the scan,
	 * such as sending query, transferring result, and local filtering.
	 */
	startup_cost = fpstate->startup_cost;
	total_cost = fpstate->total_cost;

	/*
	 * Adjust costs with factors of the corresponding foreign server:
	 *   - add cost to establish connection to both startup and total
	 *   - add cost to manipulate on remote, and transfer result to total
	 *   - add cost to manipulate tuples on local side to total
	 */
	foreach(lc, fpstate->server->options)
	{
		DefElem *d = (DefElem *) lfirst(lc);
		if (strcmp(d->defname, "fdw_startup_cost") == 0)
			fdw_startup_cost = strtod(defGetString(d), NULL);
		else if (strcmp(d->defname, "fdw_tuple_cost") == 0)
			fdw_tuple_cost = strtod(defGetString(d), NULL);
	}
	startup_cost += fdw_startup_cost;
	total_cost += fdw_startup_cost;
	total_cost += fdw_tuple_cost * baserel->rows;
	total_cost += cpu_tuple_cost * baserel->rows;

	/* Pass SQL statement from planner to executor through FDW private area. */
	fdw_private = list_make1(makeString(fpstate->sql.data));

	/*
	 * Create simplest ForeignScan path node and add it to baserel.  This path
	 * corresponds to SeqScan path of regular tables.
	 */
	path = create_foreignscan_path(root, baserel,
								   baserel->rows,
								   startup_cost,
								   total_cost,
								   NIL,				/* no pathkeys */
								   NULL,			/* no outer rel either */
								   fdw_private);
	add_path(baserel, (Path *) path); 

	/*
	 * XXX We can consider sorted path or parameterized path here if we know
	 * that foreign table is indexed on remote end.  For this purpose, we
	 * might have to support FOREIGN INDEX to represent possible sets of sort
	 * keys and/or filtering.
	 */
}

/*
 * postgresGetForeignPlan
 *		Create ForeignScan plan node which implements selected best path
 */
static ForeignScan *
postgresGetForeignPlan(PlannerInfo *root,
					   RelOptInfo *baserel,
					   Oid foreigntableid,
					   ForeignPath *best_path,
					   List *tlist,
					   List *scan_clauses)
{
	PostgresFdwPlanState *fpstate;
	Index			scan_relid = baserel->relid;
	List		   *fdw_private = NIL;
	List		   *fdw_exprs = NIL;
	List		   *local_exprs = NIL;
	ListCell	   *lc;

	/* Cache frequently accessed value */
	fpstate  = (PostgresFdwPlanState *) baserel->fdw_private;

	/*
	 * We need lists of Expr other than the lists of RestrictInfo.  Now we can
	 * merge remote_conds and param_conds into fdw_exprs, because they are
	 * evaluated on remote side for actual remote query.
	 */
	foreach(lc, fpstate->remote_conds)
		fdw_exprs = lappend(fdw_exprs, ((RestrictInfo *) lfirst(lc))->clause);
	foreach(lc, fpstate->param_conds)
		fdw_exprs = lappend(fdw_exprs, ((RestrictInfo *) lfirst(lc))->clause);
	foreach(lc, fpstate->local_conds)
		local_exprs = lappend(local_exprs,
							  ((RestrictInfo *) lfirst(lc))->clause);

	/*
	 * Make a list contains SELECT statement to it to executor with plan node
	 * for later use.
	 */
	fdw_private = lappend(fdw_private, makeString(fpstate->sql.data));

	/*
	 * Create the ForeignScan node from target list, local filtering
	 * expressions, remote filtering expressions, and FDW private information.
	 *
	 * We remove expressions which are evaluated on remote side from qual of
	 * the scan node to avoid redundant filtering.  Such filter reduction
	 * can be done only here, done after choosing best path, because
	 * baserestrictinfo in RelOptInfo is shared by all possible paths until
	 * best path is chosen.
	 */
	return make_foreignscan(tlist,
							local_exprs,
							scan_relid,
							fdw_exprs,
							fdw_private);
}

/*
 * postgresExplainForeignScan
 *		Produce extra output for EXPLAIN
 */
static void
postgresExplainForeignScan(ForeignScanState *node, ExplainState *es)
{
	List	   *fdw_private;
	char	   *sql;

	if (es->verbose)
	{
		fdw_private = ((ForeignScan *) node->ss.ps.plan)->fdw_private;
		sql = strVal(list_nth(fdw_private, FdwPrivateSelectSql));
		ExplainPropertyText("Remote SQL", sql, es);
	}
}

/*
 * postgresBeginForeignScan
 *		Initiate access to a foreign PostgreSQL table.
 */
static void
postgresBeginForeignScan(ForeignScanState *node, int eflags)
{
	PostgresFdwExecutionState *festate;
	PGconn		   *conn;
	Oid				relid;
	ForeignTable   *table;
	ForeignServer  *server;
	UserMapping	   *user;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;

	/*
	 * Do nothing in EXPLAIN (no ANALYZE) case.  node->fdw_state stays NULL.
	 */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	/*
	 * Save state in node->fdw_state.
	 */
	festate = (PostgresFdwExecutionState *)
		palloc(sizeof(PostgresFdwExecutionState));
	festate->fdw_private = ((ForeignScan *) node->ss.ps.plan)->fdw_private;

	/*
	 * Create contexts for per-scan tuplestore under per-query context.
	 */
	festate->scan_cxt = AllocSetContextCreate(node->ss.ps.state->es_query_cxt,
											  "postgres_fdw per-scan data",
											  ALLOCSET_DEFAULT_MINSIZE,
											  ALLOCSET_DEFAULT_INITSIZE,
											  ALLOCSET_DEFAULT_MAXSIZE);
	festate->temp_cxt = AllocSetContextCreate(node->ss.ps.state->es_query_cxt,
											  "postgres_fdw temporary data",
											  ALLOCSET_DEFAULT_MINSIZE,
											  ALLOCSET_DEFAULT_INITSIZE,
											  ALLOCSET_DEFAULT_MAXSIZE);

	/*
	 * Get connection to the foreign server.  Connection manager would
	 * establish new connection if necessary.
	 */
	relid = RelationGetRelid(node->ss.ss_currentRelation);
	table = GetForeignTable(relid);
	server = GetForeignServer(table->serverid);
	user = GetUserMapping(GetOuterUserId(), server->serverid);
	conn = GetConnection(server, user, PGSQL_FDW_CONNTX_READ_ONLY);
	festate->conn = conn;

	/* Result will be filled in first Iterate call. */
	festate->tuples = NULL;

	/* Allocate buffers for column values. */
	{
		TupleDesc	tupdesc = slot->tts_tupleDescriptor;
		festate->values = palloc(sizeof(Datum) * tupdesc->natts);
		festate->nulls = palloc(sizeof(bool) * tupdesc->natts);
		festate->attinmeta = TupleDescGetAttInMetadata(tupdesc);
	}

	/*
	 * Allocate buffers for query parameters.
	 *
	 * ParamListInfo might include entries for pseudo-parameter such as
	 * PL/pgSQL's FOUND variable, but we don't care that here, because wasted
	 * area seems not so large.
	 */
	{
		ParamListInfo	params = node->ss.ps.state->es_param_list_info;
		int				numParams = params ? params->numParams : 0;

		if (numParams > 0)
		{
			festate->param_types = palloc0(sizeof(Oid) * numParams);
			festate->param_values = palloc0(sizeof(char *) * numParams);
		}
		else
		{
			festate->param_types = NULL;
			festate->param_values = NULL;
		}
	}

	/* Remember which foreign table we are scanning. */
	festate->errpos.relid = relid;

	/* Store FDW-specific state into ForeignScanState */
	node->fdw_state = (void *) festate;

	return;
}

/*
 * postgresIterateForeignScan
 *		Retrieve next row from the result set, or clear tuple slot to indicate
 *		EOF.
 *
 *		Note that using per-query context when retrieving tuples from
 *		tuplestore to ensure that returned tuples can survive until next
 *		iteration because the tuple is released implicitly via ExecClearTuple.
 *		Retrieving a tuple from tuplestore in CurrentMemoryContext (it's a
 *		per-tuple context), ExecClearTuple will free dangling pointer.
 */
static TupleTableSlot *
postgresIterateForeignScan(ForeignScanState *node)
{
	PostgresFdwExecutionState *festate;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	MemoryContext	oldcontext = CurrentMemoryContext;

	festate = (PostgresFdwExecutionState *) node->fdw_state;

	/*
	 * If this is the first call after Begin or ReScan, we need to execute
	 * remote query and get result set.
	 */
	if (festate->tuples == NULL)
		execute_query(node);

	/*
	 * If tuples are still left in tuplestore, just return next tuple from it.
	 *
	 * It is necessary to switch to per-scan context to make returned tuple
	 * valid until next IterateForeignScan call, because it will be released
	 * with ExecClearTuple then.  Otherwise, picked tuple is allocated in
	 * per-tuple context, and double-free of that tuple might happen.
	 * 
	 * If we don't have any result in tuplestore, clear result slot to tell
	 * executor that this scan is over.
	 */
	MemoryContextSwitchTo(festate->scan_cxt);
	tuplestore_gettupleslot(festate->tuples, true, false, slot);
	MemoryContextSwitchTo(oldcontext);

	return slot;
}

/*
 * postgresReScanForeignScan
 *   - Restart this scan by clearing old results and set re-execute flag.
 */
static void
postgresReScanForeignScan(ForeignScanState *node)
{
	PostgresFdwExecutionState *festate;

	festate = (PostgresFdwExecutionState *) node->fdw_state;

	/* If we haven't have valid result yet, nothing to do. */
	if (festate->tuples == NULL)
		return;

	/*
	 * Only rewind the current result set is enough.
	 */
	tuplestore_rescan(festate->tuples);
}

/*
 * postgresEndForeignScan
 *		Finish scanning foreign table and dispose objects used for this scan
 */
static void
postgresEndForeignScan(ForeignScanState *node)
{
	PostgresFdwExecutionState *festate;

	festate = (PostgresFdwExecutionState *) node->fdw_state;

	/* if festate is NULL, we are in EXPLAIN; nothing to do */
	if (festate == NULL)
		return;

	/*
	 * The connection which was used for this scan should be valid until the
	 * end of the scan to make the lifespan of remote transaction same as the
	 * local query.
	 */
	ReleaseConnection(festate->conn, false);
	festate->conn = NULL;

	/* Discard fetch results */
	if (festate->tuples != NULL)
	{
		tuplestore_end(festate->tuples);
		festate->tuples = NULL;
	}

	/* MemoryContext will be deleted automatically. */
}

/*
 * Estimate costs of executing given SQL statement.
 */
static void
get_remote_estimate(const char *sql, PGconn *conn,
					double *rows, int *width,
					Cost *startup_cost, Cost *total_cost)
{
	PGresult *volatile res = NULL;
	StringInfoData  buf;
	char		   *plan;
	char		   *p;
	int				n;

	/*
	 * Construct EXPLAIN statement with given SQL statement.
	 */
	initStringInfo(&buf);
	appendStringInfo(&buf, "EXPLAIN %s", sql);

	/* PGresult must be released before leaving this function. */
	PG_TRY();
	{
		res = PQexec(conn, buf.data);
		if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0)
			ereport(ERROR,
					(errmsg("could not execute EXPLAIN for cost estimation"),
					 errdetail("%s", PQerrorMessage(conn)),
					 errhint("%s", sql)));

		/*
		 * Find estimation portion from top plan node. Here we search opening
		 * parentheses from the end of the line to avoid finding unexpected
		 * parentheses.
		 */
		plan = PQgetvalue(res, 0, 0);
		p = strrchr(plan, '(');
		if (p == NULL)
			elog(ERROR, "wrong EXPLAIN output: %s", plan);
		n = sscanf(p,
				   "(cost=%lf..%lf rows=%lf width=%d)",
				   startup_cost, total_cost, rows, width);
		if (n != 4)
			elog(ERROR, "could not get estimation from EXPLAIN output");

		PQclear(res);
		res = NULL;
	}
	PG_CATCH();
	{
		PQclear(res);

		/* Release connection and let connection manager cleanup. */
		ReleaseConnection(conn, true);

		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * Execute remote query with current parameters.
 */
static void
execute_query(ForeignScanState *node)
{
	PostgresFdwExecutionState *festate;
	ParamListInfo	params = node->ss.ps.state->es_param_list_info;
	int				numParams = params ? params->numParams : 0;
	Oid			   *types = NULL;
	const char	  **values = NULL;
	char		   *sql;
	PGconn		   *conn;
	PGresult *volatile res = NULL;

	festate = (PostgresFdwExecutionState *) node->fdw_state;
	types = festate->param_types;
	values = festate->param_values;

	/*
	 * Construct parameter array in text format.  We don't release memory for
	 * the arrays explicitly, because the memory usage would not be very large,
	 * and anyway they will be released in context cleanup.
	 *
	 * If this query is invoked from pl/pgsql function, we have extra entry
	 * for dummy variable FOUND in ParamListInfo, so we need to check type oid
	 * to exclude it from remote parameters.
	 */
	if (numParams > 0)
	{
		int i;

		for (i = 0; i < numParams; i++)
		{
			ParamExternData *prm = &params->params[i];

			/* give hook a chance in case parameter is dynamic */
			if (!OidIsValid(prm->ptype) && params->paramFetch != NULL)
				params->paramFetch(params, i + 1);

			/*
			 * Get string representation of each parameter value by invoking
			 * type-specific output function unless the value is null or it's
			 * not used in the query.
			 */
			types[i] = prm->ptype;
			if (!prm->isnull && OidIsValid(types[i]))
			{
				Oid			out_func_oid;	
				bool		isvarlena;
				FmgrInfo	func;

				getTypeOutputInfo(types[i], &out_func_oid, &isvarlena);
				fmgr_info(out_func_oid, &func);
				values[i] = OutputFunctionCall(&func, prm->value);
			}
			else
				values[i] = NULL;

			/*
			 * We use type "text" (groundless but seems most flexible) for
			 * unused (and type-unknown) parameters.  We can't remove entry for 
			 * unused parameter from the arrays, because parameter references
			 * in remote query ($n) have been indexed based on full length
			 * parameter list.
			 */
			if (!OidIsValid(types[i]))
				types[i] = TEXTOID;
		}
	}

	conn = festate->conn;

	/* PGresult must be released before leaving this function. */
	PG_TRY();
	{
		bool	first = true;

		/*
		 * Execute remote query with parameters, and retrieve results with
		 * single-row-mode which returns results row by row.
		 */
		sql = strVal(list_nth(festate->fdw_private, FdwPrivateSelectSql));
		if (!PQsendQueryParams(conn, sql, numParams, types, values, NULL, NULL,
							   0))
			ereport(ERROR,
					(errmsg("could not execute remote query"),
					 errdetail("%s", PQerrorMessage(conn)),
					 errhint("%s", sql)));
		if (!PQsetSingleRowMode(conn))
			ereport(ERROR,
					(errmsg("could not set single-row mode"),
					 errdetail("%s", PQerrorMessage(conn)),
					 errhint("%s", sql)));

		/* Retrieve result rows one by one, and store them into tuplestore. */
		for (;;)
		{
			/* Allow users to cancel long query */
			CHECK_FOR_INTERRUPTS();

			res = PQgetResult(conn);
			if (res == NULL)
				break;

			/* Store the result row into tuplestore */
			if (PQresultStatus(res) == PGRES_SINGLE_TUPLE)
			{
				query_row_processor(res, node, first);
				PQclear(res);
				res = NULL;
				first = false;
			}
			else if (PQresultStatus(res) == PGRES_TUPLES_OK)
			{
				/*
				 * PGresult with PGRES_TUPLES_OK  means EOF, so we need to
				 * initialize tuplestore if we have not retrieved any tuple.
				 */
				if (first)
					query_row_processor(res, node, first);
				PQclear(res);
				res = NULL;
				first = true;
			}
			else
			{
				/* Something wrong happend, report the error. */
				ereport(ERROR,
						(errmsg("could not execute remote query"),
						 errdetail("%s", PQerrorMessage(conn)),
						 errhint("%s", sql)));
			}
		}

		/*
		 * We can't know whether the scan is over or not in custom row
		 * processor, so mark that the result is valid here.
		 */
		tuplestore_donestoring(festate->tuples);

		/* Discard result of SELECT statement. */
		PQclear(res);
		res = NULL;
	}
	PG_CATCH();
	{
		PQclear(res);

		/* Release connection and let connection manager cleanup. */
		ReleaseConnection(conn, true);

		/* propagate error */
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * Create tuples from PGresult and store them into tuplestore.
 *
 * Caller must use PG_TRY block to catch exception and release PGresult
 * surely.
 */
static void
query_row_processor(PGresult *res, ForeignScanState *node, bool first)
{
	int			i;
	int			j;
	int			attnum;		/* number of non-dropped columns */
	TupleTableSlot *slot;
	TupleDesc	tupdesc;
	Form_pg_attribute  *attrs;
	PostgresFdwExecutionState *festate;
	AttInMetadata *attinmeta;
	HeapTuple	tuple;
	ErrorContextCallback errcallback;
	MemoryContext oldcontext;

	/* Cache frequently used values */
	slot = node->ss.ss_ScanTupleSlot;
	tupdesc = slot->tts_tupleDescriptor;
	attrs = tupdesc->attrs;
	festate = (PostgresFdwExecutionState *) node->fdw_state;
	attinmeta = festate->attinmeta;

	if (first)
	{
		int			nfields = PQnfields(res);

		/* count non-dropped columns */
		for (attnum = 0, i = 0; i < tupdesc->natts; i++)
			if (!attrs[i]->attisdropped)
				attnum++;

		/* check result and tuple descriptor have the same number of columns */
		if (attnum > 0 && attnum != nfields)
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("remote query result rowtype does not match "
							"the specified FROM clause rowtype"),
					 errdetail("expected %d, actual %d", attnum, nfields)));

		/* First, ensure that the tuplestore is empty. */
		if (festate->tuples == NULL)
		{

			/*
			 * Create tuplestore to store result of the query in per-query
			 * context.  Note that we use this memory context to avoid memory
			 * leak in error cases.
			 */
			oldcontext = MemoryContextSwitchTo(festate->scan_cxt);
			festate->tuples = tuplestore_begin_heap(false, false, work_mem);
			MemoryContextSwitchTo(oldcontext);
		}
		else
		{
			/* Clear old result just in case. */
			tuplestore_clear(festate->tuples);
		}

		/* Do nothing for empty result */
		if (PQntuples(res) == 0)
			return;
	}

	/* Should have a single-row result if we get here */
	Assert(PQntuples(res) == 1);

	/*
	 * Do the following work in a temp context that we reset after each tuple.
	 * This cleans up not only the data we have direct access to, but any
	 * cruft the I/O functions might leak.
	 */
	oldcontext = MemoryContextSwitchTo(festate->temp_cxt);

	for (i = 0, j = 0; i < tupdesc->natts; i++)
	{
		/* skip dropped columns. */
		if (attrs[i]->attisdropped)
		{
			festate->nulls[i] = true;
			continue;
		}

		/*
		 * Set NULL indicator, and convert text representation to internal
		 * representation if any.
		 */
		if (PQgetisnull(res, 0, j))
			festate->nulls[i] = true;
		else
		{
			Datum	value;

			festate->nulls[i] = false;

			/*
			 * Set up and install callback to report where conversion error
			 * occurs.
			 */
			festate->errpos.cur_attno = i + 1;
			errcallback.callback = postgres_fdw_error_callback;
			errcallback.arg = (void *) &festate->errpos;
			errcallback.previous = error_context_stack;
			error_context_stack = &errcallback;

			value = InputFunctionCall(&attinmeta->attinfuncs[i],
									  PQgetvalue(res, 0, j),
									  attinmeta->attioparams[i],
									  attinmeta->atttypmods[i]);
			festate->values[i] = value;

			/* Uninstall error context callback. */
			error_context_stack = errcallback.previous;
		}
		j++;
	}

	/*
	 * Build the tuple and put it into the slot.
	 * We don't have to free the tuple explicitly because it's been
	 * allocated in the per-tuple context.
	 */
	tuple = heap_form_tuple(tupdesc, festate->values, festate->nulls);
	tuplestore_puttuple(festate->tuples, tuple);

	/* Clean up */
	MemoryContextSwitchTo(oldcontext);
	MemoryContextReset(festate->temp_cxt);

	return;
}

/*
 * Callback function which is called when error occurs during column value
 * conversion.  Print names of column and relation.
 */
static void
postgres_fdw_error_callback(void *arg)
{
	ErrorPos *errpos = (ErrorPos *) arg;
	const char	   *relname;
	const char	   *colname;

	relname = get_rel_name(errpos->relid);
	colname = get_attname(errpos->relid, errpos->cur_attno);
	if (!colname)
		colname = "pseudo-column";
	errcontext("column %s of foreign table %s",
			   quote_identifier(colname), quote_identifier(relname));
}

/*
 * postgresAnalyzeForeignTable
 * 		Test whether analyzing this foreign table is supported
 */
static bool
postgresAnalyzeForeignTable(Relation relation,
							AcquireSampleRowsFunc *func,
							BlockNumber *totalpages)
{
	*totalpages = 0;
	*func = postgresAcquireSampleRowsFunc;

	return true;
}

/*
 * Acquire a random sample of rows from foreign table managed by postgres_fdw.
 *
 * postgres_fdw doesn't provide direct access to remote buffer, so we execute
 * simple SELECT statement which retrieves whole rows from remote side, and
 * pick some samples from them.
 */
static int
postgresAcquireSampleRowsFunc(Relation relation, int elevel,
							  HeapTuple *rows, int targrows,
							  double *totalrows,
							  double *totaldeadrows)
{
	PostgresAnalyzeState astate;
	StringInfoData sql;
	ForeignTable *table;
	ForeignServer *server;
	UserMapping *user;
	PGconn	   *conn = NULL;
	PGresult *volatile res = NULL;

	/*
	 * Only few information are necessary as input to row processor.  Other
	 * initialization will be done at the first row processor call.
	 */
	astate.anl_cxt = CurrentMemoryContext;
	astate.temp_cxt = AllocSetContextCreate(CurrentMemoryContext,
											"postgres_fdw analyze temporary data",
											ALLOCSET_DEFAULT_MINSIZE,
											ALLOCSET_DEFAULT_INITSIZE,
											ALLOCSET_DEFAULT_MAXSIZE);
	astate.rows = rows;
	astate.targrows = targrows;
	astate.tupdesc = relation->rd_att;
	astate.errpos.relid = relation->rd_id;

	/*
	 * Construct SELECT statement which retrieves whole rows from remote.  We
	 * can't avoid running sequential scan on remote side to get practical
	 * statistics, so this seems reasonable compromise.
	 */
	initStringInfo(&sql);
	deparseAnalyzeSql(&sql, relation);
	elog(DEBUG3, "Analyze SQL: %s", sql.data);

	table = GetForeignTable(relation->rd_id);
	server = GetForeignServer(table->serverid);
	user = GetUserMapping(GetOuterUserId(), server->serverid);
	conn = GetConnection(server, user, PGSQL_FDW_CONNTX_READ_ONLY);

	/*
	 * Acquire sample rows from the result set.
	 */
	PG_TRY();
	{
		bool	first = true;

		/* Execute remote query and retrieve results row by row. */
		if (!PQsendQuery(conn, sql.data))
			ereport(ERROR,
					(errmsg("could not execute remote query for analyze"),
					 errdetail("%s", PQerrorMessage(conn)),
					 errhint("%s", sql.data)));
		if (!PQsetSingleRowMode(conn))
			ereport(ERROR,
					(errmsg("could not set single-row mode"),
					 errdetail("%s", PQerrorMessage(conn)),
					 errhint("%s", sql.data)));

		/* Retrieve result rows one by one, and store them into tuplestore. */
		for (;;)
		{
			/* Allow users to cancel long query */
			CHECK_FOR_INTERRUPTS();

			res = PQgetResult(conn);
			if (res == NULL)
				break;

			/* Store the result row into tuplestore */
			if (PQresultStatus(res) == PGRES_SINGLE_TUPLE)
			{
				analyze_row_processor(res, &astate, first);
				PQclear(res);
				res = NULL;
				first = false;
			}
			else if (PQresultStatus(res) == PGRES_TUPLES_OK)
			{
				/*
				 * PGresult with PGRES_TUPLES_OK  means EOF, so we need to
				 * initialize tuplestore if we have not retrieved any tuple.
				 */
				if (first && PQresultStatus(res) == PGRES_TUPLES_OK)
					analyze_row_processor(res, &astate, first);
			
				PQclear(res);
				res = NULL;
				first = true;
			}
			else
			{
				/* Something wrong happend, report the error. */
				ereport(ERROR,
						(errmsg("could not execute remote query for analyze"),
						 errdetail("%s", PQerrorMessage(conn)),
						 errhint("%s", sql.data)));
			}
		}
	}
	PG_CATCH();
	{
		PQclear(res);

		/* Release connection and let connection manager cleanup. */
		ReleaseConnection(conn, true);

		PG_RE_THROW();
	}
	PG_END_TRY();

	ReleaseConnection(conn, false);

	/* We assume that we have no dead tuple. */
	*totaldeadrows = 0.0;

	/* We've retrieved all living tuples from foreign server. */
	*totalrows = astate.samplerows;

	/*
	 * We don't update pg_class.relpages because we don't care that in
	 * planning at all.
	 */

	/*
	 * Emit some interesting relation info
	 */
	ereport(elevel,
			(errmsg("\"%s\": scanned with \"%s\", "
					"containing %.0f live rows and %.0f dead rows; "
					"%d rows in sample, %.0f estimated total rows",
					RelationGetRelationName(relation), sql.data,
					astate.samplerows, 0.0,
					astate.numrows, astate.samplerows)));

	return astate.numrows;
}

/*
 * Custom row processor for acquire_sample_rows.
 *
 * Collect sample rows from the result of query.
 *   - Use all tuples as sample until target rows samples are collected. 
 *   - Once reached the target, skip some tuples and replace already sampled
 *     tuple randomly.
 */
static void
analyze_row_processor(PGresult *res, PostgresAnalyzeState *astate, bool first)
{
	int			targrows = astate->targrows;
	TupleDesc	tupdesc = astate->tupdesc;
	int			i;
	int			j;
	int			pos;	/* position where next sample should be stored. */
	HeapTuple	tuple;
	ErrorContextCallback errcallback;
	MemoryContext callercontext;

	if (first)
	{
		/* Prepare for sampling rows */
		astate->attinmeta = TupleDescGetAttInMetadata(tupdesc);
		astate->values = (Datum *) palloc(sizeof(Datum) * tupdesc->natts);
		astate->nulls = (bool *) palloc(sizeof(bool) * tupdesc->natts);
		astate->numrows = 0;
		astate->samplerows = 0;
		astate->rowstoskip = -1;
		astate->numrows = 0;
		astate->rstate = anl_init_selection_state(astate->targrows);

		/* Do nothing for empty result */
		if (PQntuples(res) == 0)
			return;
	}

	/* Should have a single-row result if we get here */
	Assert(PQntuples(res) == 1);

	/*
	 * Do the following work in a temp context that we reset after each tuple.
	 * This cleans up not only the data we have direct access to, but any
	 * cruft the I/O functions might leak.
	 */
	callercontext = MemoryContextSwitchTo(astate->temp_cxt);

	/*
	 * First targrows rows are once sampled always.  If we have more source
	 * rows, pick up some of them by skipping and replace already sampled
	 * tuple randomly.
	 *
	 * Here we just determine the slot where next sample should be stored.  Set
	 * pos to negative value to indicates the row should be skipped.
	 */
	if (astate->numrows < targrows)
		pos = astate->numrows++;
	else
	{
		/*
		 * The first targrows sample rows are simply copied into
		 * the reservoir.  Then we start replacing tuples in the
		 * sample until we reach the end of the relation.  This
		 * algorithm is from Jeff Vitter's paper, similarly to
		 * acquire_sample_rows in analyze.c.
		 *
		 * We don't have block-wise accessibility, so every row in
		 * the PGresult is possible to be sample.
		 */
		if (astate->rowstoskip < 0)
			astate->rowstoskip = anl_get_next_S(astate->samplerows, targrows,
												&astate->rstate);

		if (astate->rowstoskip <= 0)
		{
			int		k = (int) (targrows * anl_random_fract());

			Assert(k >= 0 && k < targrows);

			/*
			 * Create sample tuple from the result, and replace at
			 * random.
			 */
			heap_freetuple(astate->rows[k]);
			pos = k;
		}
		else
			pos = -1;

		astate->rowstoskip -= 1;
	}

	/* Always increment sample row counter. */
	astate->samplerows += 1;

	if (pos >= 0)
	{
		AttInMetadata *attinmeta = astate->attinmeta;

		/*
		 * Create sample tuple from current result row, and store it into the
		 * position determined above.  Note that i and j point entries in
		 * catalog and columns array respectively.
		 */
		for (i = 0, j = 0; i < tupdesc->natts; i++)
		{
			if (tupdesc->attrs[i]->attisdropped)
				continue;

			if (PQgetisnull(res, 0, j))
				astate->nulls[i] = true;
			else
			{
				Datum	value;

				astate->nulls[i] = false;

				/*
				 * Set up and install callback to report where conversion error
				 * occurs.
				 */
				astate->errpos.cur_attno = i + 1;
				errcallback.callback = postgres_fdw_error_callback;
				errcallback.arg = (void *) &astate->errpos;
				errcallback.previous = error_context_stack;
				error_context_stack = &errcallback;

				value = InputFunctionCall(&attinmeta->attinfuncs[i],
										  PQgetvalue(res, 0, j),
										  attinmeta->attioparams[i],
										  attinmeta->atttypmods[i]);
				astate->values[i] = value;

				/* Uninstall error callback function. */
				error_context_stack = errcallback.previous;
			}
			j++;
		}

		/*
		 * Generate tuple from the result row data, and store it into the give
		 * buffer.  Note that we need to allocate the tuple in the analyze
		 * context to make it valid even after temporary per-tuple context has
		 * been reset.
		 */
		MemoryContextSwitchTo(astate->anl_cxt);
		tuple = heap_form_tuple(tupdesc, astate->values, astate->nulls);
		MemoryContextSwitchTo(astate->temp_cxt);
		astate->rows[pos] = tuple;
	}

	/* Clean up */
	MemoryContextSwitchTo(callercontext);
	MemoryContextReset(astate->temp_cxt);

	return;
}

static List *
postgresPlanForeignModify(PlannerInfo *root,
						  ModifyTable *plan,
						  Index resultRelation,
						  Plan *subplan)
{
	CmdType			operation = plan->operation;
	StringInfoData	sql;
	List		   *targetAttrs = NIL;
	bool			has_returning = (!!plan->returningLists);

	initStringInfo(&sql);

	/*
	 * XXX - In case of UPDATE or DELETE commands are quite "simple",
	 * we will be able to execute raw UPDATE or DELETE statement at
	 * the stage of scan, instead of combination SELECT ... FOR UPDATE
	 * and either of UPDATE or DELETE commands.
	 * It should be an idea of optimization in the future version.
	 *
	 * XXX - FOR UPDATE should be appended on the remote query of scan
	 * stage to avoid unexpected concurrent update on the target rows.
	 */
	if (operation == CMD_UPDATE || operation == CMD_DELETE)
	{
		ForeignScan	   *fscan;
		Value		   *select_sql;

		fscan = lookup_foreign_scan_plan(subplan, resultRelation);
		if (!fscan)
			elog(ERROR, "no underlying scan plan found in subplan tree");

		select_sql = list_nth(fscan->fdw_private,
							  FdwPrivateSelectSql);
		appendStringInfo(&sql, "%s FOR UPDATE", strVal(select_sql));
		strVal(select_sql) = pstrdup(sql.data);

		resetStringInfo(&sql);
	}

	/*
	 * XXX - In case of INSERT or UPDATE commands, it needs to list up
	 * columns to be updated or inserted for performance optimization
	 * and consistent behavior when DEFAULT is set on the remote table.
	 */
	if (operation == CMD_INSERT || operation == CMD_UPDATE)
	{
		RangeTblEntry  *rte = rt_fetch(resultRelation, root->parse->rtable);
		Bitmapset	   *tmpset = bms_copy(rte->modifiedCols);
		AttrNumber		col;

		while ((col = bms_first_member(tmpset)) >= 0)
		{
			col += FirstLowInvalidHeapAttributeNumber;
			if (col <= InvalidAttrNumber)
				elog(ERROR, "system-column update is not supported");
			targetAttrs = lappend_int(targetAttrs, col);
		}
	}

	switch (operation)
	{
		case CMD_INSERT:
			deparseInsertSql(&sql, root, resultRelation,
							 targetAttrs, has_returning);
			elog(DEBUG3, "Remote INSERT query: %s", sql.data);
			break;
		case CMD_UPDATE:
			deparseUpdateSql(&sql, root, resultRelation,
							 targetAttrs, has_returning);
			elog(DEBUG3, "Remote UPDATE query: %s", sql.data);
			break;
		case CMD_DELETE:
			deparseDeleteSql(&sql, root, resultRelation);
			elog(DEBUG3, "Remote DELETE query: %s", sql.data);
			break;
		default:
			elog(ERROR, "unexpected operation: %d", (int) operation);
	}
	return list_make3(makeString(sql.data),
					  makeInteger(has_returning),
					  targetAttrs);
}

static void
postgresBeginForeignModify(ModifyTableState *mtstate,
						   ResultRelInfo *resultRelInfo,
						   List *fdw_private,
						   Plan *subplan,
						   int eflags)
{
	PostgresFdwModifyState *fmstate;
	CmdType			operation = mtstate->operation;
	Relation		frel = resultRelInfo->ri_RelationDesc;
	AttrNumber		n_params;
	ListCell	   *lc;
	ForeignTable   *ftable;
	ForeignServer  *fserver;
	UserMapping	   *fuser;
	Oid				typefnoid;
	bool			isvarlena;

	/*
	 * Construct PostgresFdwExecutionState
	 */
	fmstate = palloc0(sizeof(PostgresFdwExecutionState));

	ftable = GetForeignTable(RelationGetRelid(frel));
	fserver = GetForeignServer(ftable->serverid);
	fuser = GetUserMapping(GetOuterUserId(), fserver->serverid);

	fmstate->query = strVal(linitial(fdw_private));
	fmstate->has_returning = intVal(lsecond(fdw_private));
	fmstate->target_attrs = lthird(fdw_private);
	fmstate->conn = GetConnection(fserver, fuser,
								  PGSQL_FDW_CONNTX_READ_WRITE);
	n_params = list_length(fmstate->target_attrs) + 1;
	fmstate->p_name = NULL;
	fmstate->p_types = palloc0(sizeof(Oid) * n_params);
	fmstate->p_flinfo = palloc0(sizeof(FmgrInfo) * n_params);

	/* 1st parameter should be ctid on UPDATE or DELETE */
	if (operation == CMD_UPDATE || operation == CMD_DELETE)
	{
		fmstate->p_types[fmstate->p_nums] = TIDOID;
		getTypeOutputInfo(TIDOID, &typefnoid, &isvarlena);
		fmgr_info(typefnoid, &fmstate->p_flinfo[fmstate->p_nums]);
		fmstate->p_nums++;
	}
	/* following parameters should be regular columns */
	if (operation == CMD_UPDATE || operation == CMD_INSERT)
	{
		foreach (lc, fmstate->target_attrs)
		{
			Form_pg_attribute attr
				= RelationGetDescr(frel)->attrs[lfirst_int(lc) - 1];

			Assert(!attr->attisdropped);

			fmstate->p_types[fmstate->p_nums] = attr->atttypid;
			getTypeOutputInfo(attr->atttypid, &typefnoid, &isvarlena);
			fmgr_info(typefnoid, &fmstate->p_flinfo[fmstate->p_nums]);
			fmstate->p_nums++;
		}
	}
	Assert(fmstate->p_nums <= n_params);

	/* input handlers for returning clause */
	if (fmstate->has_returning)
	{
		AttrNumber	i, nattrs = RelationGetNumberOfAttributes(frel);

		fmstate->r_ioparam = palloc0(sizeof(Oid) * nattrs);
		fmstate->r_flinfo = palloc0(sizeof(FmgrInfo) * nattrs);
		for (i=0; i < nattrs; i++)
		{
			Form_pg_attribute attr = RelationGetDescr(frel)->attrs[i];

			if (attr->attisdropped)
				continue;

			getTypeInputInfo(attr->atttypid, &typefnoid,
							 &fmstate->r_ioparam[i]);
			fmgr_info(typefnoid, &fmstate->r_flinfo[i]);
		}
	}
	fmstate->es_query_cxt = mtstate->ps.state->es_query_cxt;
	resultRelInfo->ri_fdw_state = fmstate;
}

static void
prepare_foreign_modify(PostgresFdwModifyState *fmstate)
{
	static int	prep_id = 1;
	char		prep_name[NAMEDATALEN];
	PGresult   *res;

	snprintf(prep_name, sizeof(prep_name),
			 "pgsql_fdw_prep_%08x", prep_id++);

	res = PQprepare(fmstate->conn,
					prep_name,
					fmstate->query,
					fmstate->p_nums,
					fmstate->p_types);
	if (!res || PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not prepare statement (%s): %s",
			 fmstate->query, PQerrorMessage(fmstate->conn));
	}
	PQclear(res);

	fmstate->p_name = MemoryContextStrdup(fmstate->es_query_cxt, prep_name);
}

static int
setup_exec_prepared(ResultRelInfo *resultRelInfo,
					const char *rowid, TupleTableSlot *slot,
					const char *p_values[], int p_lengths[])
{
	PostgresFdwModifyState *fmstate = resultRelInfo->ri_fdw_state;
	int			pindex = 0;

	/* 1st parameter should be ctid */
	if (rowid)
	{
		p_values[pindex] = rowid;
		p_lengths[pindex] = strlen(rowid) + 1;
		pindex++;
	}

	/* following parameters are as TupleDesc */
	if (slot != NULL)
	{
		TupleDesc	tupdesc = slot->tts_tupleDescriptor;
		ListCell   *lc;

		foreach (lc, fmstate->target_attrs)
		{
			Form_pg_attribute	attr = tupdesc->attrs[lfirst_int(lc) - 1];
			Datum		value;
			bool		isnull;

			Assert(!attr->attisdropped);

			value = slot_getattr(slot, attr->attnum, &isnull);
			if (isnull)
			{
				p_values[pindex] = NULL;
				p_lengths[pindex] = 0;
			}
			else
			{
				p_values[pindex] =
					OutputFunctionCall(&fmstate->p_flinfo[pindex], value);
				p_lengths[pindex] = strlen(p_values[pindex]) + 1;
			}
			pindex++;
		}
	}
	return pindex;
}

static void
store_returning_result(PostgresFdwModifyState *fmstate,
					   TupleTableSlot *slot, PGresult *res)
{
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	AttrNumber	i, nattrs = tupdesc->natts;
	Datum	   *values = alloca(sizeof(Datum) * nattrs);
	bool	   *isnull = alloca(sizeof(bool) * nattrs);
	HeapTuple	newtup;

	memset(values, 0, sizeof(Datum) * nattrs);
	memset(isnull, 0, sizeof(bool) * nattrs);

	for (i=0; i < nattrs; i++)
	{
		Form_pg_attribute	attr = tupdesc->attrs[i];

		if (attr->attisdropped || PQgetisnull(res, 0, i))
			isnull[i] = true;
		else
		{
			//elog(INFO, "col %d %s %d: value: %s fnoid: %u", i, NameStr(attr->attname), attr->attisdropped, PQgetvalue(res, 0, i), fmstate->r_flinfo[i].fn_oid);
			values[i] = InputFunctionCall(&fmstate->r_flinfo[i],
										  PQgetvalue(res, 0, i),
										  fmstate->r_ioparam[i],
										  attr->atttypmod);
		}
	}
	newtup = heap_form_tuple(tupdesc, values, isnull);
	ExecStoreTuple(newtup, slot, InvalidBuffer, false);
}

static TupleTableSlot *
postgresExecForeignInsert(ResultRelInfo *resultRelInfo,
						  TupleTableSlot *slot)
{
	PostgresFdwModifyState *fmstate = resultRelInfo->ri_fdw_state;
	const char	  **p_values  = alloca(sizeof(char *) * fmstate->p_nums);
	int			   *p_lengths = alloca(sizeof(int) * fmstate->p_nums);
	AttrNumber		nattrs;
	PGresult	   *res;
	int				n_rows;

	if (!fmstate->p_name)
		prepare_foreign_modify(fmstate);

	nattrs = setup_exec_prepared(resultRelInfo,
								 NULL, slot,
								 p_values, p_lengths);
	Assert(fmstate->p_nums == nattrs);

	res = PQexecPrepared(fmstate->conn,
						 fmstate->p_name,
						 nattrs,
						 p_values,
						 p_lengths,
						 NULL, 0);
	if (!res || (!fmstate->has_returning ?
				 PQresultStatus(res) != PGRES_COMMAND_OK :
				 PQresultStatus(res) != PGRES_TUPLES_OK))
		elog(ERROR, "could not execute prepared statement (%s): %s",
			 fmstate->query, PQerrorMessage(fmstate->conn));
	n_rows = atoi(PQcmdTuples(res));
	if (n_rows > 0 && fmstate->has_returning)
		store_returning_result(fmstate, slot, res);
	PQclear(res);

	return (n_rows > 0 ? slot : NULL);
}

static bool
postgresExecForeignDelete(ResultRelInfo *resultRelInfo, const char *rowid)
{
	PostgresFdwModifyState *fmstate = resultRelInfo->ri_fdw_state;
	const char	   *p_values[1];
	int				p_lengths[1];
	AttrNumber		nattrs;
	PGresult	   *res;
	int				n_rows;

	if (!fmstate->p_name)
		prepare_foreign_modify(fmstate);

	nattrs = setup_exec_prepared(resultRelInfo,
								 rowid, NULL,
								 p_values, p_lengths);
	Assert(fmstate->p_nums == nattrs);

	res = PQexecPrepared(fmstate->conn,
						 fmstate->p_name,
						 nattrs,
						 p_values,
						 p_lengths,
						 NULL, 0);
	if (!res ||  PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		PQclear(res);
		elog(ERROR, "could not execute prepared statement (%s): %s",
			 fmstate->query, PQerrorMessage(fmstate->conn));
    }
	n_rows = atoi(PQcmdTuples(res));
    PQclear(res);

	return (n_rows > 0 ? true : false);
}

static TupleTableSlot*
postgresExecForeignUpdate(ResultRelInfo *resultRelInfo,
						  const char *rowid, TupleTableSlot *slot)
{
	PostgresFdwModifyState *fmstate = resultRelInfo->ri_fdw_state;
	const char	  **p_values  = alloca(sizeof(char *) * (fmstate->p_nums + 1));
	int			   *p_lengths = alloca(sizeof(int) * (fmstate->p_nums + 1));
	AttrNumber		nattrs;
	PGresult	   *res;
	int				n_rows;

	if (!fmstate->p_name)
		prepare_foreign_modify(fmstate);

	nattrs = setup_exec_prepared(resultRelInfo,
								 rowid, slot,
								 p_values, p_lengths);
	Assert(fmstate->p_nums == nattrs);

	res = PQexecPrepared(fmstate->conn,
						 fmstate->p_name,
						 nattrs,
						 p_values,
						 p_lengths,
						 NULL, 0);
	if (!res || (!fmstate->has_returning ?
				 PQresultStatus(res) != PGRES_COMMAND_OK :
				 PQresultStatus(res) != PGRES_TUPLES_OK))
	{
		PQclear(res);
		elog(ERROR, "could not execute prepared statement (%s): %s",
			 fmstate->query, PQerrorMessage(fmstate->conn));
	}
	n_rows = atoi(PQcmdTuples(res));
	if (n_rows > 0 && fmstate->has_returning)
		store_returning_result(fmstate, slot, res);
	PQclear(res);

	return (n_rows > 0 ? slot : NULL);
}

static void
postgresEndForeignModify(ResultRelInfo *resultRelInfo)
{
	PostgresFdwModifyState *fmstate = resultRelInfo->ri_fdw_state;

	ReleaseConnection(fmstate->conn, false);
	fmstate->conn = NULL;
}

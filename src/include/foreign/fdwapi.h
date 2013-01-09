/*-------------------------------------------------------------------------
 *
 * fdwapi.h
 *	  API for foreign-data wrappers
 *
 * Copyright (c) 2010-2013, PostgreSQL Global Development Group
 *
 * src/include/foreign/fdwapi.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef FDWAPI_H
#define FDWAPI_H

#include "nodes/execnodes.h"
#include "nodes/relation.h"
#include "utils/rel.h"

/* To avoid including explain.h here, reference ExplainState thus: */
struct ExplainState;


/*
 * Callback function signatures --- see fdwhandler.sgml for more info.
 */
typedef AttrNumber (*GetForeignRelWidth_function) (PlannerInfo *root,
												   RelOptInfo *baserel,
												   Relation foreignrel,
												   bool inhparent,
												   List *targetList);

typedef void (*GetForeignRelSize_function) (PlannerInfo *root,
														RelOptInfo *baserel,
														Oid foreigntableid);

typedef void (*GetForeignPaths_function) (PlannerInfo *root,
													  RelOptInfo *baserel,
													  Oid foreigntableid);

typedef ForeignScan *(*GetForeignPlan_function) (PlannerInfo *root,
														 RelOptInfo *baserel,
														  Oid foreigntableid,
													  ForeignPath *best_path,
															 List *tlist,
														 List *scan_clauses);

typedef void (*ExplainForeignScan_function) (ForeignScanState *node,
													struct ExplainState *es);

typedef void (*BeginForeignScan_function) (ForeignScanState *node,
													   int eflags);

typedef TupleTableSlot *(*IterateForeignScan_function) (ForeignScanState *node);

typedef void (*ReScanForeignScan_function) (ForeignScanState *node);

typedef void (*EndForeignScan_function) (ForeignScanState *node);

typedef int (*AcquireSampleRowsFunc) (Relation relation, int elevel,
											   HeapTuple *rows, int targrows,
												  double *totalrows,
												  double *totaldeadrows);

typedef bool (*AnalyzeForeignTable_function) (Relation relation,
												 AcquireSampleRowsFunc *func,
													BlockNumber *totalpages);
typedef List *(*PlanForeignModify_function) (PlannerInfo *root,
											 ModifyTable *plan,
											 Index resultRelation,
											 Plan *subplan);

typedef void (*BeginForeignModify_function) (ModifyTableState *mtstate,
											 ResultRelInfo *rinfo,
											 List *fdw_private,
											 Plan *subplan,
											 int eflags);
typedef TupleTableSlot *(*ExecForeignInsert_function) (ResultRelInfo *rinfo,
													   TupleTableSlot *slot);
typedef TupleTableSlot *(*ExecForeignUpdate_function) (ResultRelInfo *rinfo,
													   const char *rowid,
													   TupleTableSlot *slot);
typedef bool (*ExecForeignDelete_function) (ResultRelInfo *rinfo,
											const char *rowid);
typedef void (*EndForeignModify_function) (ResultRelInfo *rinfo);

/*
 * FdwRoutine is the struct returned by a foreign-data wrapper's handler
 * function.  It provides pointers to the callback functions needed by the
 * planner and executor.
 *
 * More function pointers are likely to be added in the future.  Therefore
 * it's recommended that the handler initialize the struct with
 * makeNode(FdwRoutine) so that all fields are set to NULL.  This will
 * ensure that no fields are accidentally left undefined.
 */
typedef struct FdwRoutine
{
	NodeTag		type;

	/*
	 * These functions are required.
	 */
	GetForeignRelSize_function GetForeignRelSize;
	GetForeignPaths_function GetForeignPaths;
	GetForeignPlan_function GetForeignPlan;
	ExplainForeignScan_function ExplainForeignScan;
	BeginForeignScan_function BeginForeignScan;
	IterateForeignScan_function IterateForeignScan;
	ReScanForeignScan_function ReScanForeignScan;
	EndForeignScan_function EndForeignScan;

	/*
	 * These functions are optional.  Set the pointer to NULL for any that are
	 * not provided.
	 */
	AnalyzeForeignTable_function AnalyzeForeignTable;
	GetForeignRelWidth_function GetForeignRelWidth;
	PlanForeignModify_function PlanForeignModify;
	BeginForeignModify_function	BeginForeignModify;
	ExecForeignInsert_function ExecForeignInsert;
	ExecForeignDelete_function ExecForeignDelete;
	ExecForeignUpdate_function ExecForeignUpdate;
	EndForeignModify_function EndForeignModify;
} FdwRoutine;


/* Functions in foreign/foreign.c */
extern FdwRoutine *GetFdwRoutine(Oid fdwhandler);
extern FdwRoutine *GetFdwRoutineByRelId(Oid relid);

#endif   /* FDWAPI_H */

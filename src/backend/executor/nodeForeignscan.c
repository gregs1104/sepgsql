/*-------------------------------------------------------------------------
 *
 * nodeForeignscan.c
 *	  Routines to support scans of foreign tables
 *
 * Portions Copyright (c) 1996-2013, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/nodeForeignscan.c
 *
 *-------------------------------------------------------------------------
 */
/*
 * INTERFACE ROUTINES
 *
 *		ExecForeignScan			scans a foreign table.
 *		ExecInitForeignScan		creates and initializes state info.
 *		ExecReScanForeignScan	rescans the foreign relation.
 *		ExecEndForeignScan		releases any resources allocated.
 */
#include "postgres.h"

#include "executor/executor.h"
#include "executor/nodeForeignscan.h"
#include "foreign/fdwapi.h"
#include "nodes/nodeFuncs.h"
#include "utils/rel.h"

static TupleTableSlot *ForeignNext(ForeignScanState *node);
static bool ForeignRecheck(ForeignScanState *node, TupleTableSlot *slot);


/* ----------------------------------------------------------------
 *		ForeignNext
 *
 *		This is a workhorse for ExecForeignScan
 * ----------------------------------------------------------------
 */
static TupleTableSlot *
ForeignNext(ForeignScanState *node)
{
	TupleTableSlot *slot;
	ForeignScan *plan = (ForeignScan *) node->ss.ps.plan;
	ExprContext *econtext = node->ss.ps.ps_ExprContext;
	MemoryContext oldcontext;

	/* Call the Iterate function in short-lived context */
	oldcontext = MemoryContextSwitchTo(econtext->ecxt_per_tuple_memory);
	slot = node->fdwroutine->IterateForeignScan(node);
	MemoryContextSwitchTo(oldcontext);

	/*
	 * If any system columns are requested, we have to force the tuple into
	 * physical-tuple form to avoid "cannot extract system attribute from
	 * virtual tuple" errors later.  We also insert a valid value for
	 * tableoid, which is the only actually-useful system column.
	 */
	if (plan->fsSystemCol && !TupIsNull(slot))
	{
		HeapTuple	tup = ExecMaterializeSlot(slot);

		tup->t_tableOid = RelationGetRelid(node->ss.ss_currentRelation);
	}

	return slot;
}

/*
 * ForeignRecheck -- access method routine to recheck a tuple in EvalPlanQual
 */
static bool
ForeignRecheck(ForeignScanState *node, TupleTableSlot *slot)
{
	/* There are no access-method-specific conditions to recheck. */
	return true;
}

/* ----------------------------------------------------------------
 *		ExecForeignScan(node)
 *
 *		Fetches the next tuple from the FDW, checks local quals, and
 *		returns it.
 *		We call the ExecScan() routine and pass it the appropriate
 *		access method functions.
 * ----------------------------------------------------------------
 */
TupleTableSlot *
ExecForeignScan(ForeignScanState *node)
{
	return ExecScan((ScanState *) node,
					(ExecScanAccessMtd) ForeignNext,
					(ExecScanRecheckMtd) ForeignRecheck);
}

/*
 * pseudo_column_walker
 *
 * helper routine of GetPseudoTupleDesc. It pulls Var nodes that reference
 * pseudo columns from targetlis of the relation
 */
typedef struct
{
	Relation	relation;
	Index		varno;
	List	   *pcolumns;
	AttrNumber	max_attno;
} pseudo_column_walker_context;

static bool
pseudo_column_walker(Node *node, pseudo_column_walker_context *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;
		ListCell   *cell;

		if (var->varno == context->varno && var->varlevelsup == 0 &&
			var->varattno > RelationGetNumberOfAttributes(context->relation))
		{
			foreach (cell, context->pcolumns)
			{
				Var	   *temp = lfirst(cell);

				if (temp->varattno == var->varattno)
				{
					if (!equal(var, temp))
						elog(ERROR, "asymmetric pseudo column appeared");
					break;
				}
			}
			if (!cell)
			{
				context->pcolumns = lappend(context->pcolumns, var);
				if (var->varattno > context->max_attno)
					context->max_attno = var->varattno;
			}
		}
		return false;
	}

	/* Should not find an unplanned subquery */
	Assert(!IsA(node, Query));

	return expression_tree_walker(node, pseudo_column_walker,
								  (void *)context);
}

/*
 * GetPseudoTupleDesc
 *
 * It generates TupleDesc structure including pseudo-columns if required.
 */
static TupleDesc
GetPseudoTupleDesc(ForeignScan *node, Relation relation)
{
	pseudo_column_walker_context context;
	List	   *target_list = node->scan.plan.targetlist;
	TupleDesc	tupdesc;
	AttrNumber	attno;
	ListCell   *cell;
	ListCell   *prev;
	bool		hasoid;

	context.relation = relation;
	context.varno = node->scan.scanrelid;
	context.pcolumns = NIL;
	context.max_attno = -1;

	pseudo_column_walker((Node *)target_list, (void *)&context);
	Assert(context.max_attno > RelationGetNumberOfAttributes(relation));

	hasoid = RelationGetForm(relation)->relhasoids;
	tupdesc = CreateTemplateTupleDesc(context.max_attno, hasoid);

	for (attno = 1; attno <= context.max_attno; attno++)
	{
		/* case of regular columns */
		if (attno <= RelationGetNumberOfAttributes(relation))
		{
			memcpy(tupdesc->attrs[attno - 1],
				   RelationGetDescr(relation)->attrs[attno - 1],
				   ATTRIBUTE_FIXED_PART_SIZE);
			continue;
		}

		/* case of pseudo columns */
		prev = NULL;
		foreach (cell, context.pcolumns)
		{
			Var	   *var = lfirst(cell);

			if (var->varattno == attno)
			{
				char		namebuf[NAMEDATALEN];

				snprintf(namebuf, sizeof(namebuf),
						 "pseudo_column_%d", attno);

				TupleDescInitEntry(tupdesc,
								   attno,
								   namebuf,
								   var->vartype,
								   var->vartypmod,
								   0);
				TupleDescInitEntryCollation(tupdesc,
											attno,
											var->varcollid);
				context.pcolumns
					= list_delete_cell(context.pcolumns, cell, prev);
				break;
			}
			prev = cell;
		}
		if (!cell)
			elog(ERROR, "pseudo column %d of %s not in target list",
				 attno, RelationGetRelationName(relation));
	}
	return tupdesc;
}

/* ----------------------------------------------------------------
 *		ExecInitForeignScan
 * ----------------------------------------------------------------
 */
ForeignScanState *
ExecInitForeignScan(ForeignScan *node, EState *estate, int eflags)
{
	ForeignScanState *scanstate;
	Relation	currentRelation;
	TupleDesc	tupdesc;
	FdwRoutine *fdwroutine;

	/* check for unsupported flags */
	Assert(!(eflags & (EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK)));

	/*
	 * create state structure
	 */
	scanstate = makeNode(ForeignScanState);
	scanstate->ss.ps.plan = (Plan *) node;
	scanstate->ss.ps.state = estate;

	/*
	 * Miscellaneous initialization
	 *
	 * create expression context for node
	 */
	ExecAssignExprContext(estate, &scanstate->ss.ps);

	scanstate->ss.ps.ps_TupFromTlist = false;

	/*
	 * initialize child expressions
	 */
	scanstate->ss.ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->scan.plan.targetlist,
					 (PlanState *) scanstate);
	scanstate->ss.ps.qual = (List *)
		ExecInitExpr((Expr *) node->scan.plan.qual,
					 (PlanState *) scanstate);

	/*
	 * tuple table initialization
	 */
	ExecInitResultTupleSlot(estate, &scanstate->ss.ps);
	ExecInitScanTupleSlot(estate, &scanstate->ss);

	/*
	 * open the base relation and acquire appropriate lock on it.
	 */
	currentRelation = ExecOpenScanRelation(estate, node->scan.scanrelid);
	scanstate->ss.ss_currentRelation = currentRelation;

	/*
	 * get the scan type from the relation descriptor.
	 */
	if (node->fsPseudoCol)
		tupdesc = GetPseudoTupleDesc(node, currentRelation);
	else
		tupdesc = RelationGetDescr(currentRelation);

	ExecAssignScanType(&scanstate->ss, tupdesc);

	/*
	 * Initialize result tuple type and projection info.
	 */
	ExecAssignResultTypeFromTL(&scanstate->ss.ps);
	ExecAssignScanProjectionInfo(&scanstate->ss);

	/*
	 * Acquire function pointers from the FDW's handler, and init fdw_state.
	 */
	fdwroutine = GetFdwRoutineByRelId(RelationGetRelid(currentRelation));
	scanstate->fdwroutine = fdwroutine;
	scanstate->fdw_state = NULL;

	/*
	 * Tell the FDW to initiate the scan.
	 */
	fdwroutine->BeginForeignScan(scanstate, eflags);

	return scanstate;
}

/* ----------------------------------------------------------------
 *		ExecEndForeignScan
 *
 *		frees any storage allocated through C routines.
 * ----------------------------------------------------------------
 */
void
ExecEndForeignScan(ForeignScanState *node)
{
	/* Let the FDW shut down */
	node->fdwroutine->EndForeignScan(node);

	/* Free the exprcontext */
	ExecFreeExprContext(&node->ss.ps);

	/* clean out the tuple table */
	ExecClearTuple(node->ss.ps.ps_ResultTupleSlot);
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	/* close the relation. */
	ExecCloseScanRelation(node->ss.ss_currentRelation);
}

/* ----------------------------------------------------------------
 *		ExecReScanForeignScan
 *
 *		Rescans the relation.
 * ----------------------------------------------------------------
 */
void
ExecReScanForeignScan(ForeignScanState *node)
{
	node->fdwroutine->ReScanForeignScan(node);

	ExecScanReScan(&node->ss);
}

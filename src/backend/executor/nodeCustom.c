/* ------------------------------------------------------------------------
 *
 * nodeCustom.c
 *    Routines to handle execution of custom plan, scan and join node
 *
 * Portions Copyright (c) 1996-2013, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * ------------------------------------------------------------------------
 */
#include "postgres.h"

#include "executor/nodeCustom.h"
#include "parser/parsetree.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/rel.h"

/* static variables */
static HTAB *custom_provider_hash = NULL;

/*
 * register_custom_provider
 *
 * It registers a custom execution provider; that consists of a set of
 * callbacks and is identified with a unique name.
 */
void
register_custom_provider(const CustomProvider *provider)
{
	CustomProvider *entry;
	bool			found;

	if (!custom_provider_hash)
	{
		HASHCTL		ctl;

		memset(&ctl, 0, sizeof(ctl));
		ctl.hcxt = CacheMemoryContext;
		ctl.keysize = NAMEDATALEN;
		ctl.entrysize = sizeof(CustomProvider);

		custom_provider_hash = hash_create("custom execution providers",
										   32,
										   &ctl,
										   HASH_ELEM | HASH_CONTEXT);
	}

	entry = hash_search(custom_provider_hash,
						provider->name,
						HASH_ENTER, &found);
	if (found)
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("duplicate custom execution provider \"%s\"",
						provider->name)));

	Assert(strcmp(provider->name, entry->name) == 0);
	memcpy(entry, provider, sizeof(CustomProvider));
}

/*
 * get_custom_provider
 *
 * It finds a registered custom execution provide by its name
 */
CustomProvider *
get_custom_provider(const char *custom_name)
{
	CustomProvider *entry;

	/* lookup custom execution provider */
	if (!custom_provider_hash)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("no custom execution provider was registered")));

	entry = (CustomProvider *) hash_search(custom_provider_hash,
										   custom_name, HASH_FIND, NULL);
	if (!entry)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("custom execution provider \"%s\" was not registered",
						custom_name)));

	return entry;
}

/*
 * ExecInitCustomScan
 *
 * Allocation of CustomScanState and various initialization stuff.
 * Note that some of initialization jobs are skipped if scanrelid is zero
 * (that means this custom scan plan is not associated with a particular
 * relation in range-table list.)
 */
CustomScanState *
ExecInitCustomScan(CustomScan *node, EState *estate, int eflags)
{
	CustomProvider	   *provider = get_custom_provider(node->custom_name);
	CustomScanState	   *csstate;
	Plan			   *plan = &node->scan.plan;
	Index				scanrelid = node->scan.scanrelid;

	/*
	 * Create state structure
	 */
	csstate = makeNode(CustomScanState);
	csstate->ss.ps.plan = plan;
	csstate->ss.ps.state = estate;
	csstate->custom_provider = provider;
	csstate->custom_flags = node->custom_flags;
	csstate->custom_state = NULL;

	/*
	 * Miscellaneous initialization
	 */
	ExecAssignExprContext(estate, &csstate->ss.ps);

	/*
	 * Initialization of child expressions
	 */
	csstate->ss.ps.targetlist =
		(List *) ExecInitExpr((Expr *) plan->targetlist, &csstate->ss.ps);
	csstate->ss.ps.qual =
		(List *) ExecInitExpr((Expr *) plan->qual, &csstate->ss.ps);

	/*
	 * tuple table initialization
	 *
	 * Note that ss_ScanTupleSlot is set only when scanrelid is associated
	 * with a particular relation. Elsewhere, it needs to be initialized by
	 * custom-scan provider itself if it internally uses ss_ScanTupleSlot.
	 * If it replaces varno of Var node by CUSTOM_VAR, it has to be set to
	 * reference underlying attribute name to generate EXPLAIN output.
	 */
	ExecInitResultTupleSlot(estate, &csstate->ss.ps);
	if (scanrelid > 0)
		ExecInitScanTupleSlot(estate, &csstate->ss);

	/*
	 * open the base relation and acquire appropriate lock on it,
	 * if this custom scan is connected with a particular relaion.
	 * Also, assign its scan type according to the table definition.
	 */
	if (scanrelid > 0)
	{
		Relation	rel = ExecOpenScanRelation(estate, scanrelid, eflags);

		csstate->ss.ss_currentRelation = rel;
		ExecAssignScanType(&csstate->ss, RelationGetDescr(rel));

		csstate->ss.ps.ps_TupFromTlist = false;
	}

	/*
	 * Initialize result tuple type and projection info.
	 */
	ExecAssignResultTypeFromTL(&csstate->ss.ps);

	if (scanrelid > 0)
		ExecAssignScanProjectionInfo(&csstate->ss);
	else
		ExecAssignProjectionInfo(&csstate->ss.ps, NULL);

	/*
	 * Final initialization based on callback of BeginCustomScan method.
	 * Extension may be able to override initialization stuff above, if
	 * needed.
	 */
	csstate->custom_provider->BeginCustomScan(csstate, eflags);

	return csstate;
}

/*
 * ExecCustomScan
 *
 * Just an entrypoint of ExecCustomScan method. All the stuff to fetch
 * a tuple is a job of custom-scan provider.
 */
TupleTableSlot *
ExecCustomScan(CustomScanState *csstate)
{
	return csstate->custom_provider->ExecCustomScan(csstate);
}

/*
 * MultiExecCustomScan
 *
 * Aldo, just an entrypoint of MultiExecCustomScan method. All the stuff
 * to fetch multiple tuples (according to expectation of upper node) is
 * a job of custom-scan provider.
 */
Node *
MultiExecCustomScan(CustomScanState *csstate)
{
	return csstate->custom_provider->MultiExecCustomScan(csstate);
}

/*
 * ExecEndCustomScan
 *
 * It releases all the resources allocated on this scan.
 */
void
ExecEndCustomScan(CustomScanState *csstate)
{
	/* Let the custom-exec shut down */
	csstate->custom_provider->EndCustomScan(csstate);

	/* Free the exprcontext */
	ExecFreeExprContext(&csstate->ss.ps);

	/* Clean out the tuple table, if exists */
	ExecClearTuple(csstate->ss.ps.ps_ResultTupleSlot);
	if (csstate->ss.ss_ScanTupleSlot)
		ExecClearTuple(csstate->ss.ss_ScanTupleSlot);

	/* close the relation, if opened */
	if (csstate->ss.ss_currentRelation)
		ExecCloseScanRelation(csstate->ss.ss_currentRelation);
}

/*
 * ExecReScanCustomScan
 */
void
ExecReScanCustomScan(CustomScanState *csstate)
{
	csstate->custom_provider->ReScanCustomScan(csstate);
}

/*
 * ExecCustomMarkPos
 */
void
ExecCustomMarkPos(CustomScanState *csstate)
{
	Assert((csstate->custom_flags & CUSTOM__SUPPORT_MARK_RESTORE) != 0);
	csstate->custom_provider->ExecMarkPosCustomScan(csstate);
}

/*
 * ExecCustomRestrPos
 */
void
ExecCustomRestrPos(CustomScanState *csstate)
{
	Assert((csstate->custom_flags & CUSTOM__SUPPORT_MARK_RESTORE) != 0);
	csstate->custom_provider->ExecRestorePosCustom(csstate);
}

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
 *
 *
 *
 *
 *
 */
CustomScanState *
ExecInitCustomScan(CustomScan *node, EState *estate, int eflags)
{
	CustomProvider	   *provider = get_custom_provider(node->custom_name);
	CustomScanState	   *csstate;
	Plan			   *plan = &node->scan.plan;

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
	 */
	ExecInitResultTupleSlot(estate, &csstate->ss.ps);

	/*
	 * Final initialization with custom execution provider
	 *
	 * XXX - call ExecInitScanTupleSlot and ExecAssignScanType
	 * if needed.
	 */
	csstate->custom_provider->BeginCustomScan(csstate, eflags);

	/*
	 * Initialize result tuple type and projection info.
	 */
	ExecAssignResultTypeFromTL(&csstate->ss.ps);
	if (node->scan.scanrelid > 0)
		ExecAssignScanProjectionInfo(&csstate->ss);
	else
		ExecAssignProjectionInfo(&csstate->ss.ps, NULL);

	return csstate;
}

TupleTableSlot *
ExecCustomScan(CustomScanState *csstate)
{
	return csstate->custom_provider->ExecCustomScan(csstate);
}


Node *
MultiExecCustomScan(CustomScanState *csstate)
{
	return csstate->custom_provider->MultiExecCustomScan(csstate);
}

/*
 * ExecEndCustomScan
 *
 *
 *
 *
 */
void
ExecEndCustomScan(CustomScanState *csstate)
{
	/* Let the custom-exec shut down */
	csstate->custom_provider->EndCustomScan(csstate);
	/* Free the exprcontext */
	ExecFreeExprContext(&csstate->ss.ps);
	/* Clean out the tuple table */
	ExecClearTuple(csstate->ss.ps.ps_ResultTupleSlot);
}

/*
 * ExecReScanCustomScan
 *
 *
 *
 *
 *
 */
void
ExecReScanCustomScan(CustomScanState *csstate)
{
	csstate->custom_provider->ReScanCustomScan(csstate);
}

void
ExecCustomMarkPos(CustomScanState *csstate)
{
	Assert((csstate->custom_flags & CUSTOM__SUPPORT_MARK_RESTORE) != 0);
	csstate->custom_provider->ExecMarkPosCustomScan(csstate);
}

void
ExecCustomRestrPos(CustomScanState *csstate)
{
	Assert((csstate->custom_flags & CUSTOM__SUPPORT_MARK_RESTORE) != 0);
	csstate->custom_provider->ExecRestorePosCustom(csstate);
}

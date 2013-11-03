/*
 * ctidscan.c
 *
 * Definition of Custom TidScan implementation
 *
 * Portions Copyright (c) 2013, PostgreSQL Global Development Group
 */
#include "postgres.h"
#include "access/relscan.h"
#include "access/sysattr.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_type.h"
#include "executor/nodeCustom.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/clauses.h"
#include "optimizer/cost.h"
#include "optimizer/paths.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"
#include "storage/itemptr.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/spccache.h"

extern void		_PG_init(void);

PG_MODULE_MAGIC;

static add_scan_path_hook_type	add_scan_path_next;

#define IsCTIDVar(node,rtindex)											\
    ((node) != NULL &&													\
	 IsA((node), Var) &&												\
	 ((Var *) (node))->varno == (rtindex) &&							\
	 ((Var *) (node))->varattno == SelfItemPointerAttributeNumber &&	\
	 ((Var *) (node))->varlevelsup == 0)

static List *
CTidQualFromExpr(Node *expr, int varno)
{
	if (is_opclause(expr))
	{
		OpExpr *op = (OpExpr *) expr;
		Node   *arg1;
		Node   *arg2;
		Node   *other = NULL;

		if (op->opno != TIDLessOperator &&
			op->opno != TIDLessEqualOperator &&
			op->opno != TIDGreaterOperator &&
			op->opno != TIDGreaterEqualOperator)
			return NULL;

		if (list_length(op->args) != 2)
			return false;

		arg1 = linitial(op->args);
		arg2 = lsecond(op->args);

		if (IsCTIDVar(arg1, varno))
			other = arg2;
		else if (IsCTIDVar(arg2, varno))
			other = arg1;
		else
			return NULL;
		if (exprType(other) != TIDOID)
			return NULL;	/* probably can't happen */
		/* The other argument must be a pseudoconstant */
		if (!is_pseudo_constant_clause(other))
			return NULL;

		return list_make1(copyObject(op));
	}
	else if (and_clause(expr))
	{
		List	   *rlst = NIL;
		ListCell   *lc;

		foreach(lc, ((BoolExpr *) expr)->args)
		{
			List   *temp = CTidQualFromExpr((Node *) lfirst(lc), varno);

			rlst = list_concat(rlst, temp);
		}
		return rlst;
	}
	return NIL;
}

static void
CTidEstimateCosts(PlannerInfo *root,
				  RelOptInfo *baserel,
				  CustomPath *cpath)
{
	List	   *ctidquals = cpath->custom_private;
	ListCell   *lc;
	double		ntuples;
	ItemPointerData ip_min;
	ItemPointerData ip_max;
	bool		has_min_val = false;
	bool		has_max_val = false;
	BlockNumber	num_pages;
	Cost		startup_cost = 0;
	Cost		run_cost = 0;
	Cost		cpu_per_tuple;
	QualCost	qpqual_cost;
	QualCost	ctid_qual_cost;
	double		spc_random_page_cost;

	/* Should only be applied to base relations */
	Assert(baserel->relid > 0);
	Assert(baserel->rtekind == RTE_RELATION);

	/* Mark the path with the correct row estimate */
	if (cpath->path.param_info)
		ntuples = cpath->path.rows = cpath->path.param_info->ppi_rows;
	else
		ntuples = cpath->path.rows = baserel->rows;

	/* Estimate how many tuples we may retrieve */
	ItemPointerSet(&ip_min, 0, 0);
	ItemPointerSet(&ip_max, MaxBlockNumber, MaxOffsetNumber);
	foreach (lc, ctidquals)
	{
		OpExpr	   *op = lfirst(lc);
		Oid			opno;
		Node	   *other;

		Assert(is_opclause(op));
		if (IsCTIDVar(linitial(op->args), baserel->relid))
		{
			opno = op->opno;
			other = lsecond(op->args);
		}
		else if (IsCTIDVar(lsecond(op->args), baserel->relid))
		{
			opno = get_commutator(op->opno);
			other = linitial(op->args);
		}
		else
			elog(ERROR, "could not identify CTID variable");

		if (IsA(other, Const))
		{
			ItemPointer	ip = (ItemPointer)(((Const *) other)->constvalue);

			switch (opno)
			{
				case TIDLessOperator:
				case TIDLessEqualOperator:
					if (ItemPointerCompare(ip, &ip_max) < 0)
						ItemPointerCopy(ip, &ip_max);
					has_max_val = true;
					break;
				case TIDGreaterOperator:
				case TIDGreaterEqualOperator:
					if (ItemPointerCompare(ip, &ip_min) > 0)
						ItemPointerCopy(ip, &ip_min);
					has_min_val = true;
					break;
				default:
					elog(ERROR, "unexpected operator code: %u", op->opno);
					break;
			}
		}
	}

	if (has_min_val && has_max_val)
	{
		BlockNumber	bnum_max = BlockIdGetBlockNumber(&ip_max.ip_blkid);
		BlockNumber	bnum_min = BlockIdGetBlockNumber(&ip_min.ip_blkid);

		bnum_max = Min(bnum_max, baserel->pages);
		bnum_min = Max(bnum_min, 0);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else if (has_min_val)
	{
		BlockNumber	bnum_max = baserel->pages;
		BlockNumber	bnum_min = BlockIdGetBlockNumber(&ip_min.ip_blkid);

		bnum_min = Max(bnum_min, 0);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else if (has_max_val)
	{
		BlockNumber	bnum_max = BlockIdGetBlockNumber(&ip_max.ip_blkid);
		BlockNumber	bnum_min = 0;

		bnum_max = Min(bnum_max, baserel->pages);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else
	{
		/* just a rough estimation */
		num_pages = Max((baserel->pages + 1) / 2, 1);
	}
	ntuples *= ((double) num_pages) / ((double) baserel->pages);

	/*
	 * The TID qual expressions will be computed once, any other baserestrict
	 * quals once per retrived tuple.
	 */
    cost_qual_eval(&ctid_qual_cost, ctidquals, root);

	/* fetch estimated page cost for tablespace containing table */
	get_tablespace_page_costs(baserel->reltablespace,
							  &spc_random_page_cost,
							  NULL);

	/* disk costs --- assume each tuple on a different page */
	run_cost += spc_random_page_cost * ntuples;

	/* Add scanning CPU costs */
	get_restriction_qual_cost(root, baserel,
							  cpath->path.param_info,
							  &qpqual_cost);

	/* XXX currently we assume TID quals are a subset of qpquals */
	startup_cost += qpqual_cost.startup + ctid_qual_cost.per_tuple;
	cpu_per_tuple = cpu_tuple_cost + qpqual_cost.per_tuple -
		ctid_qual_cost.per_tuple;
	run_cost = cpu_per_tuple * ntuples;

	cpath->path.startup_cost = startup_cost;
	cpath->path.total_cost = startup_cost + run_cost;
}

static void
CTidAddScanPath(PlannerInfo *root,
				RelOptInfo *baserel,
				RangeTblEntry *rte)
{
	char		relkind;
	List	   *rlst = NIL;
	ListCell   *lc;

	/* Gives another extensions chance to add a path */
	if (add_scan_path_next)
		(*add_scan_path_next)(root, baserel, rte);

	/* All we support is regular relations */
	if (rte->rtekind != RTE_RELATION)
		return;
	relkind = get_rel_relkind(rte->relid);
	if (relkind != RELKIND_RELATION &&
		relkind != RELKIND_MATVIEW &&
		relkind != RELKIND_TOASTVALUE)
		return;

	foreach (lc, baserel->baserestrictinfo)
	{
		RestrictInfo *rinfo = (RestrictInfo *) lfirst(lc);
		List		 *temp;

		if (!IsA(rinfo, RestrictInfo))
			continue;		/* probably should never happen */
		temp = CTidQualFromExpr((Node *) rinfo->clause, baserel->relid);
		rlst = list_concat(rlst, temp);
	}
	if (rlst != NIL)
	{
		CustomPath *cpath = makeNode(CustomPath);
		Relids		required_outer;

		/*
		 * We don't support pushing join clauses into the quals of a ctidscan,
		 * but it could still have required parameterization due to LATERAL
		 * refs in its tlist.
		 */
		required_outer = baserel->lateral_relids;

		cpath->path.pathtype = T_CustomScan;
		cpath->path.parent = baserel;
		cpath->path.param_info = get_baserel_parampathinfo(root, baserel,
														   required_outer);
		cpath->custom_name = pstrdup("ctidscan");
		cpath->custom_flags = CUSTOM__SUPPORT_MARK_RESTORE;
		cpath->custom_private = rlst;

		CTidEstimateCosts(root, baserel, cpath);

		add_path(baserel, &cpath->path);
	}
}


static void
CTidInitCustomScanPlan(PlannerInfo *root,
					   CustomScan *cscan_plan,
					   CustomPath *cscan_path,
					   List *tlist,
					   List *scan_clauses)
{
	Index		scan_relid = cscan_path->path.parent->relid;
	List	   *ctidquals = cscan_path->custom_private;

	/* should be a base relation */
	Assert(scan_relid > 0);
	Assert(cscan_path->path.parent->rtekind == RTE_RELATION);

	/* Reduce RestrictInfo list to bare expressions; ignore pseudoconstants */
	scan_clauses = extract_actual_clauses(scan_clauses, false);

	/* Replace any outer-relation variables with nestloop params */
	/* TODO: remove items in ctidquals from scan_clauses */
	if (cscan_path->path.param_info)
	{
		scan_clauses = (List *)
			replace_nestloop_params(root, (Node *) scan_clauses);
		ctidquals = (List *)
			replace_nestloop_params(root, (Node *) ctidquals);
	}

	cscan_plan->scan.plan.targetlist = tlist;
	cscan_plan->scan.plan.qual = scan_clauses;
	cscan_plan->custom_private = ctidquals;
}

typedef struct {
	Index			scanrelid;
	ItemPointerData	ip_min;
	ItemPointerData	ip_max;
	int32			ip_min_comp;
	int32			ip_max_comp;
	bool			ip_needs_eval;
	List		   *ctid_quals;
} CTidScanState;

static bool
CTidEvalScanZone(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;
	ExprContext	   *econtext = node->ss.ps.ps_ExprContext;
	ListCell	   *lc;

	/*
	 * See ItemPointerCompare(), ip_min_comp shall be usually 0 or -1,
	 * if ip_min is valid. "1" means the compared itemptr is either less,
	 * equal or greater, thus, it matches any values; that is equivalent
	 * to open-end. It is similar on "-1" for ip_max_comp.
	 */
	ctss->ip_min_comp = -1;
	ctss->ip_max_comp = 1;

	foreach (lc, ctss->ctid_quals)
	{
		FuncExprState  *fexstate = (FuncExprState *) lfirst(lc);
		OpExpr		   *op = (OpExpr *)fexstate->xprstate.expr;
		Node		   *arg1 = linitial(op->args);
		Node		   *arg2 = lsecond(op->args);
		Oid				opno;
		ExprState	   *exstate;
		ItemPointer		itemptr;
		bool			isnull;

		if (IsCTIDVar(arg1, ctss->scanrelid))
		{
			exstate = (ExprState *) lsecond(fexstate->args);
			opno = op->opno;
		}
		else if (IsCTIDVar(arg2, ctss->scanrelid))
		{
			exstate = (ExprState *) linitial(fexstate->args);
			opno = get_commutator(op->opno);
		}
		else
			elog(ERROR, "could not identify CTID variable");

		itemptr = (ItemPointer)
			DatumGetPointer(ExecEvalExprSwitchContext(exstate,
													  econtext,
													  &isnull,
													  NULL));
		if (!isnull && ItemPointerIsValid(itemptr))
		{
			switch (opno)
			{
				case TIDLessOperator:
					if (ctss->ip_max_comp > 0 ||
						ItemPointerCompare(itemptr, &ctss->ip_max) <= 0)
					{
						ItemPointerCopy(itemptr, &ctss->ip_max);
						ctss->ip_max_comp = -1;
					}
					break;
				case TIDLessEqualOperator:
					if (ctss->ip_max_comp > 0 ||
						ItemPointerCompare(itemptr, &ctss->ip_max) < 0)
					{
						ItemPointerCopy(itemptr, &ctss->ip_max);
						ctss->ip_max_comp = 0;
					}
					break;
				case TIDGreaterOperator:
					if (ctss->ip_min_comp < 0 ||
						ItemPointerCompare(itemptr, &ctss->ip_min) >= 0)
					{
						ItemPointerCopy(itemptr, &ctss->ip_min);
						ctss->ip_min_comp = 0;
					}
					break;
				case TIDGreaterEqualOperator:
					if (ctss->ip_min_comp < 0 ||
						ItemPointerCompare(itemptr, &ctss->ip_min) > 0)
					{
						ItemPointerCopy(itemptr, &ctss->ip_min);
						ctss->ip_min_comp = 1;
					}
					break;
				default:
					elog(ERROR, "unsupported operator");
					break;
			}
		}
		else
		{

			return false;
		}
	}
	return true;
}


static void
CTidBeginCustomScan(CustomScanState *node, int eflags)
{
	CustomScan	   *cscan = (CustomScan *)node->ss.ps.plan;
	Index			scanrelid = ((Scan *)node->ss.ps.plan)->scanrelid;
	EState		   *estate = node->ss.ps.state;
	CTidScanState  *ctss = palloc0(sizeof(CTidScanState));
	TupleDesc		tupdesc;

	ctss->scanrelid = scanrelid;
	ctss->ctid_quals = (List *)
		ExecInitExpr((Expr *)cscan->custom_private, &node->ss.ps);
	ctss->ip_needs_eval = true;

	ExecInitScanTupleSlot(estate, &node->ss);
	ExecInitScanTupleSlot(estate, &node->ss);

	node->ss.ss_currentRelation
		= ExecOpenScanRelation(estate, scanrelid, eflags);
	node->ss.ss_currentScanDesc
		= heap_beginscan(node->ss.ss_currentRelation,
						 estate->es_snapshot, 0, NULL);

	tupdesc = RelationGetDescr(node->ss.ss_currentRelation);
	ExecAssignScanType(&node->ss, tupdesc);

	node->ss.ps.ps_TupFromTlist = false;

	node->custom_state = ctss;
}

static bool
CTidSeekPosition(HeapScanDesc scan, ItemPointer pos, ScanDirection direction)
{
	BlockNumber		bnum = BlockIdGetBlockNumber(&pos->ip_blkid);
	OffsetNumber	offs;
	ItemPointerData	ip;

	Assert(direction == BackwardScanDirection ||
		   direction == ForwardScanDirection);

	/*
	 * In case when block-number is out of the range, it is obvious that
	 * no tuples shall be fetched if forward scan direction. On the other
	 * hand, we have nothing special is backward scan direction.
	 */
	if (bnum >= scan->rs_nblocks)
	{
		if (direction == ForwardScanDirection)
			return false;
		else
		{
			heap_rescan(scan, NULL);
			return true;
		}
	}

	scan->rs_inited = true;
	if (scan->rs_pageatatime)
		offs = FirstOffsetNumber;
	else
		offs = ItemPointerGetOffsetNumber(pos);

	ItemPointerSet(&ip, bnum, offs);
	ItemPointerCopy(&ip, &scan->rs_mctid);
	if (scan->rs_pageatatime)
		scan->rs_mindex = 0;

	heap_restrpos(scan);

	if (scan->rs_pageatatime)
	{
		if (ItemPointerGetOffsetNumber(pos) < FirstOffsetNumber)
			scan->rs_cindex = 0;
		else if (ItemPointerGetOffsetNumber(pos) <= scan->rs_ntuples)
			scan->rs_cindex = ItemPointerGetOffsetNumber(pos) - 1;
		else
			scan->rs_cindex = scan->rs_ntuples - 1;
	}

	if (direction == ForwardScanDirection)
		heap_getnext(scan, BackwardScanDirection);
	else
		heap_getnext(scan, ForwardScanDirection);

	return true;
}

static TupleTableSlot *
CTidAccessCustomScan(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;
	HeapScanDesc	scan = node->ss.ss_currentScanDesc;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	EState		   *estate = node->ss.ps.state;
	HeapTuple		tuple;

	if (ctss->ip_needs_eval)
	{
		if (!CTidEvalScanZone(node))
			return NULL;

		if (estate->es_direction == ForwardScanDirection)
		{
			if (ctss->ip_min_comp != -1)
			{
				if (!CTidSeekPosition(scan, &ctss->ip_min,
									  estate->es_direction))
					return NULL;
			}
			else
				heap_rescan(scan, NULL);
		}
		else if (estate->es_direction == BackwardScanDirection)
		{
			if (ctss->ip_max_comp != 1)
			{
				if (!CTidSeekPosition(scan, &ctss->ip_max,
									  estate->es_direction))
					return NULL;
			}
			else
				heap_rescan(scan, NULL);
		}
		ctss->ip_needs_eval = false;
	}

	/*
	 * get the next tuple from the table
	 */
	tuple = heap_getnext(scan, estate->es_direction);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	if (estate->es_direction == ForwardScanDirection)
	{
		if (ItemPointerCompare(&tuple->t_self,
							   &ctss->ip_max) > ctss->ip_max_comp)
			return NULL;
	}
	else if (estate->es_direction == BackwardScanDirection)
	{
		if (ItemPointerCompare(&scan->rs_ctup.t_self,
							   &ctss->ip_min) < ctss->ip_min_comp)
			return NULL;
	}
	ExecStoreTuple(tuple, slot, scan->rs_cbuf, false);

	return slot;
}

static bool
CTidRecheckCustomScan(CustomScanState *node, TupleTableSlot *slot)
{
	return true;
}

static TupleTableSlot *
CTidExecCustomScan(CustomScanState *node)
{
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) CTidAccessCustomScan,
					(ExecScanRecheckMtd) CTidRecheckCustomScan);
}

static void
CTidEndCustomScan(CustomScanState *node)
{
	heap_endscan(node->ss.ss_currentScanDesc);
	ExecCloseScanRelation(node->ss.ss_currentRelation);
}

static void
CTidReScanCustomScan(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;
	HeapScanDesc	scan = node->ss.ss_currentScanDesc;

	ctss->ip_needs_eval = true;

	heap_rescan(scan, NULL);

	ExecScanReScan(&node->ss);
}

void
_PG_init(void)
{
	CustomProvider		provider;

	/* registration of callback on add scan path */
	add_scan_path_next = add_scan_path_hook;
	add_scan_path_hook = CTidAddScanPath;

	/* registration of custom scan provider */
	memset(&provider, 0, sizeof(provider));
	snprintf(provider.name, sizeof(provider.name), "ctidscan");
	provider.InitCustomScanPlan   = CTidInitCustomScanPlan;
	//provider.SetPlanRefCustomScan = CTidSetPlanRefCustomScan;
	provider.BeginCustomScan      = CTidBeginCustomScan;
	provider.ExecCustomScan       = CTidExecCustomScan;
	provider.EndCustomScan        = CTidEndCustomScan;
	provider.ReScanCustomScan     = CTidReScanCustomScan;
	//provider.ExplainCustomScan    = CTidExplainCustomScan;

	register_custom_provider(&provider);
}

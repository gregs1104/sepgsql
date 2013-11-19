/*
 * ctidscan.c
 *
 * Definition of Custom TidScan implementation.
 *
 * It is designed to demonstrate Custom Scan APIs; that allows to override
 * a part of executor node. This extension focus on a workload that tries
 * to fetch records with tid larger or less than a particular value.
 * In case when inequality operators were given, this module construct
 * a custom scan path that enables to skip records not to be read. Then,
 * if it was the chepest one, it shall be used to run the query.
 * Custom Scan APIs callbacks this extension when executor tries to fetch
 * underlying records, then it utilizes existing heap_getnext() but seek
 * the records to be read prior to fetching the first record.
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
#include "storage/bufmgr.h"
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

/*
 * CTidQualFromExpr
 *
 * It checks whether the given restriction clauses enables to determine
 * the zone to be scanned, or not. If one or more restriction clauses are
 * available, it returns a list of them, or NIL elsewhere.
 * The caller can consider all the conditions are chainned with AND-
 * boolean operator, so all the operator works for narrowing down the
 * scope of custom tid scan.
 */
static List *
CTidQualFromExpr(Node *expr, int varno)
{
	if (is_opclause(expr))
	{
		OpExpr *op = (OpExpr *) expr;
		Node   *arg1;
		Node   *arg2;
		Node   *other = NULL;

		/* only inequality operators are candidate */
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

/*
 * CTidEstimateCosts
 *
 * It estimates cost to scan the target relation according to the given
 * restriction clauses. Its logic to scan relations are almost same as
 * SeqScan doing, because it uses regular heap_getnext(), except for
 * the number of tuples to be scanned if restriction clauses work well.
*/
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
		cpath->path.rows = cpath->path.param_info->ppi_rows;
	else
		cpath->path.rows = baserel->rows;

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
			/* To simplifies, we assume as if Var node is 1st argument */
			opno = get_commutator(op->opno);
			other = linitial(op->args);
		}
		else
			elog(ERROR, "could not identify CTID variable");

		if (IsA(other, Const))
		{
			ItemPointer	ip = (ItemPointer)(((Const *) other)->constvalue);

			/*
			 * Just an rough estimation, we don't distinct inequality and
			 * inequality-or-equal operator.
			 */
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

	/* estimated number of tuples in this relation */
	ntuples = baserel->pages * baserel->tuples;

	if (has_min_val && has_max_val)
	{
		/* case of both side being bounded */
		BlockNumber	bnum_max = BlockIdGetBlockNumber(&ip_max.ip_blkid);
		BlockNumber	bnum_min = BlockIdGetBlockNumber(&ip_min.ip_blkid);

		bnum_max = Min(bnum_max, baserel->pages);
		bnum_min = Max(bnum_min, 0);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else if (has_min_val)
	{
		/* case of only lower side being bounded */
		BlockNumber	bnum_max = baserel->pages;
		BlockNumber	bnum_min = BlockIdGetBlockNumber(&ip_min.ip_blkid);

		bnum_min = Max(bnum_min, 0);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else if (has_max_val)
	{
		/* case of only upper side being bounded */
		BlockNumber	bnum_max = BlockIdGetBlockNumber(&ip_max.ip_blkid);
		BlockNumber	bnum_min = 0;

		bnum_max = Min(bnum_max, baserel->pages);
		num_pages = Min(bnum_max - bnum_min + 1, 1);
	}
	else
	{
		/*
		 * Just a rough estimation. We assume half of records shall be
		 * read using this restriction clause, but undeterministic untill
		 * executor run it actually.
		 */
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

	/*
	 * We don't decrease cost for the inequality operators, because 
	 * it is subset of qpquals and still in.
	 */
	startup_cost += qpqual_cost.startup + ctid_qual_cost.per_tuple;
	cpu_per_tuple = cpu_tuple_cost + qpqual_cost.per_tuple -
		ctid_qual_cost.per_tuple;
	run_cost = cpu_per_tuple * ntuples;

	cpath->path.startup_cost = startup_cost;
	cpath->path.total_cost = startup_cost + run_cost;
}

/*
 * CTidAddScanPath
 *
 * It adds a custom scan path if inequality operators are given on the
 * relation to be scanned and makes sense to reduce number of tuples.
 */
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

	/* walk on the restrict info */
	foreach (lc, baserel->baserestrictinfo)
	{
		RestrictInfo *rinfo = (RestrictInfo *) lfirst(lc);
		List		 *temp;

		if (!IsA(rinfo, RestrictInfo))
			continue;		/* probably should never happen */
		temp = CTidQualFromExpr((Node *) rinfo->clause, baserel->relid);
		rlst = list_concat(rlst, temp);
	}

	/*
	 * OK, it is case when a part of restriction clause makes sense to
	 * reduce number of tuples, so we will add a custom scan path being
	 * provided by this module.
	 */
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
		cpath->custom_flags = CUSTOM__SUPPORT_BACKWARD_SCAN;
		cpath->custom_private = rlst;

		CTidEstimateCosts(root, baserel, cpath);

		add_path(baserel, &cpath->path);
	}
}

/*
 * CTidInitCustomScanPlan
 *
 * It initializes the given CustomScan plan object according to the CustomPath
 * being choosen by the optimizer.
 */
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

	/*
	 * Most of initialization stuff was done at nodeCustomScan.c. So, all
	 * we need to do is to put clauses that were little bit adjusted and
	 * private stuff; list of restriction clauses in this case.
	 */
	cscan_plan->scan.plan.targetlist = tlist;
	cscan_plan->scan.plan.qual = scan_clauses;
	cscan_plan->custom_private = ctidquals;
}

/*
 * CTidScanState
 *
 * State of custom-tid scan during its execution.
 */
typedef struct {
	Index			scanrelid;		/* range table index of the relation */
	ItemPointerData	ip_min;			/* minimum ItemPointer */
	ItemPointerData	ip_max;			/* maximum ItemPointer */
	int32			ip_min_comp;	/* comparison policy to ip_min */
	int32			ip_max_comp;	/* comparison policy to ip_max */
	bool			ip_needs_eval;	/* true, if needs to seek again */
	List		   *ctid_quals;		/* list of ExprState for inequality ops */
} CTidScanState;

static bool
CTidEvalScanZone(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;
	ExprContext	   *econtext = node->ss.ps.ps_ExprContext;
	ListCell	   *lc;

	/*
	 * See ItemPointerCompare(), ip_max_comp shall be usually either 1 or
	 * 0 if tid of fetched records are larger than or equal with ip_min.
	 * To detect end of scan, we shall check whether the result of
	 * ItemPointerCompare() is less than ip_max_comp, so it never touch
	 * the point if ip_max_comp is -1, because all the result is either
	 * 1, 0 or -1. So, it is same as "open ended" as if no termination
	 * condition was set.
	 */
	ctss->ip_min_comp = -1;
	ctss->ip_max_comp = 1;

	/* Walks on the inequality operators */
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
		if (!isnull)
		{
			/*
			 * OK, we could calculate a particular TID that should be
			 * larger than, less than or equal with fetched record, thus,
			 * it allows to determine upper or lower bounds of this scan.
			 */
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
			/*
			 * Whole of the restriction clauses chainned with AND- boolean
			 * operators because false, if one of the clauses has NULL result.
			 * So, we can immediately break the evaluation to inform caller
			 * it does not make sense to scan any more.
			 */
			return false;
		}
	}
	return true;
}

/*
 * CTidBeginCustomScan
 *
 * It initializes the given CustomScanState according to the CustomScan plan.
 */
static void
CTidBeginCustomScan(CustomScanState *node, int eflags)
{
	CustomScan	   *cscan = (CustomScan *)node->ss.ps.plan;
	Index			scanrelid = ((Scan *)node->ss.ps.plan)->scanrelid;
	EState		   *estate = node->ss.ps.state;
	CTidScanState  *ctss;

	/* Do nothing anymore in EXPLAIN (no ANALYZE) case. */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	/* Begin sequential scan, but pointer shall be seeked later */
	node->ss.ss_currentScanDesc
		= heap_beginscan(node->ss.ss_currentRelation,
						 estate->es_snapshot, 0, NULL);

	/* init CTidScanState */
	ctss = palloc0(sizeof(CTidScanState));
	ctss->scanrelid = scanrelid;
	ctss->ctid_quals = (List *)
		ExecInitExpr((Expr *)cscan->custom_private, &node->ss.ps);
	ctss->ip_needs_eval = true;

	node->custom_state = ctss;
}

/*
 * CTidSeekPosition
 *
 * It seeks current scan position into a particular point we specified.
 * Next heap_getnext() will fetch a record from the point we seeked.
 * It returns false, if specified position was out of range thus does not
 * make sense to scan any mode. Elsewhere, true shall be return.
 */
static bool
CTidSeekPosition(HeapScanDesc scan, ItemPointer pos, ScanDirection direction)
{
	BlockNumber		bnum = BlockIdGetBlockNumber(&pos->ip_blkid);
	ItemPointerData	save_mctid;
	int				save_mindex;

	Assert(direction == BackwardScanDirection ||
		   direction == ForwardScanDirection);

	/*
	 * In case when block-number is out of the range, it is obvious that
	 * no tuples shall be fetched if forward scan direction. On the other
	 * hand, we have nothing special for backward scan direction.
	 * Note that heap_getnext() shall return NULL tuple just after
	 * heap_rescan() if NoMovementScanDirection is given. Caller of this
	 * function override scan direction if 'true' was returned, so it makes
	 * this scan terminated immediately.
	 */
	if (bnum >= scan->rs_nblocks)
	{
		heap_rescan(scan, NULL);
		/* Termination of this scan immediately */
		if (direction == ForwardScanDirection)
			return true;
		/* Elsewhere, backward scan from the beginning */
		return false;
	}

	/* save the marked position */
	ItemPointerCopy(&scan->rs_mctid, &save_mctid);
	save_mindex = scan->rs_mindex;

	/*
	 * Ensure the block that includes the position shall be loaded on
	 * heap_restrpos(). Because heap_restrpos() internally calls
	 * heapgettup() or heapgettup_pagemode() that kicks heapgetpage()
	 * when rs_cblock is different from the block number being pointed
	 * by rs_mctid, it makes sense to put invalid block number not to
	 * match previous value.
	 */
	scan->rs_cblock = InvalidBlockNumber;

	/* Put a pseudo value as if heap_markpos() save a position. */
	ItemPointerCopy(pos, &scan->rs_mctid);
	if (scan->rs_pageatatime)
		scan->rs_mindex = ItemPointerGetOffsetNumber(pos) - 1;

	/* Seek to the point */
	heap_restrpos(scan);

	/* restore the marked position */
	ItemPointerCopy(&save_mctid, &scan->rs_mctid);
	scan->rs_mindex = save_mindex;

	return true;
}

/*
 * CTidAccessCustomScan
 *
 * Access method of ExecScan(). It fetches a tuple from the underlying heap
 * scan that was started from the point according to the tid clauses.
 */
static TupleTableSlot *
CTidAccessCustomScan(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;
	HeapScanDesc	scan = node->ss.ss_currentScanDesc;
	TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
	EState		   *estate = node->ss.ps.state;
	ScanDirection	direction = estate->es_direction;
	HeapTuple		tuple;

	if (ctss->ip_needs_eval)
	{
		/* It terminates this scan, if result set shall be obvious empty. */
		if (!CTidEvalScanZone(node))
			return NULL;

		if (direction == ForwardScanDirection)
		{
			/* seek to the point if min-tid was obvious */
			if (ctss->ip_min_comp != -1)
			{
				if (CTidSeekPosition(scan, &ctss->ip_min, direction))
					direction = NoMovementScanDirection;
			}
			else if (scan->rs_inited)
				heap_rescan(scan, NULL);
		}
		else if (direction == BackwardScanDirection)
		{
			/* seel to the point if max-tid was obvious */
			if (ctss->ip_max_comp != 1)
			{
				if (CTidSeekPosition(scan, &ctss->ip_max, direction))
					direction = NoMovementScanDirection;
			}
			else if (scan->rs_inited)
				heap_rescan(scan, NULL);
		}
		else
			elog(ERROR, "unexpected scan direction");

		ctss->ip_needs_eval = false;
	}

	/*
	 * get the next tuple from the table
	 */
	tuple = heap_getnext(scan, direction);
	if (!HeapTupleIsValid(tuple))
		return NULL;

	/*
	 * check whether the fetched tuple reached to the upper bound
	 * if forward scan, or the lower bound if backward scan.
	 */
	if (direction == ForwardScanDirection)
	{
		if (ItemPointerCompare(&tuple->t_self,
							   &ctss->ip_max) > ctss->ip_max_comp)
			return NULL;
	}
	else if (direction == BackwardScanDirection)
	{
		if (ItemPointerCompare(&scan->rs_ctup.t_self,
							   &ctss->ip_min) < ctss->ip_min_comp)
			return NULL;
	}
	ExecStoreTuple(tuple, slot, scan->rs_cbuf, false);

	return slot;
}

/*
 * CTidRecheckCustomScan
 *
 * Recheck method of ExecScan(). We don't need recheck logic.
 */
static bool
CTidRecheckCustomScan(CustomScanState *node, TupleTableSlot *slot)
{
	return true;
}

/*
 * CTidExecCustomScan
 *
 * It fetches a tuple from the underlying heap scan, according to
 * the Execscan() manner.
 */
static TupleTableSlot *
CTidExecCustomScan(CustomScanState *node)
{
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) CTidAccessCustomScan,
					(ExecScanRecheckMtd) CTidRecheckCustomScan);
}

/*
 * CTidEndCustomScan
 *
 * It terminates custom tid scan.
 */
static void
CTidEndCustomScan(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;

	/* if ctss != NULL, we started underlying heap-scan */
	if (ctss)
		heap_endscan(node->ss.ss_currentScanDesc);
}

/*
 * CTidReScanCustomScan
 *
 * It rewinds current position of the scan. Setting ip_needs_eval indicates
 * to calculate the starting point again and rewinds underlying heap scan
 * on the next ExecScan timing.
 */
static void
CTidReScanCustomScan(CustomScanState *node)
{
	CTidScanState  *ctss = node->custom_state;

	ctss->ip_needs_eval = true;

	ExecScanReScan(&node->ss);
}

/*
 * Entrypoint of this extension
 */
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
	provider.BeginCustomScan      = CTidBeginCustomScan;
	provider.ExecCustomScan       = CTidExecCustomScan;
	provider.EndCustomScan        = CTidEndCustomScan;
	provider.ReScanCustomScan     = CTidReScanCustomScan;

	register_custom_provider(&provider);
}

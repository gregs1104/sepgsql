/*
 * optimizer/util/rowsecurity.c
 *    Routines to support row-security feature
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits_fn.h"
#include "catalog/pg_rowsecurity.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/plannodes.h"
#include "optimizer/clauses.h"
#include "optimizer/prep.h"
#include "optimizer/rowsecurity.h"
#include "parser/parsetree.h"
#include "rewrite/rewriteHandler.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "tcop/utility.h"

/* flags to pull row-security policy */
#define RSEC_FLAG_HAS_SUBLINKS			0x0001

/* hook to allow extensions to apply their own security policy */
row_security_policy_hook_type	row_security_policy_hook = NULL;

/*
 * make_artificial_column
 *
 * It makes a target-entry node that references underlying column.
 * Its tle->expr is usualy Var node, but may be Const for dummy NULL
 * if the supplied attribute was already dropped.
 */
static TargetEntry *
make_artificial_column(RangeTblEntry *subrte, AttrNumber attnum)
{
	Expr   *expr;
	char   *resname;

	Assert(subrte->rtekind == RTE_RELATION && OidIsValid(subrte->relid));
	if (attnum == InvalidAttrNumber)
	{
		expr = (Expr *) makeWholeRowVar(subrte, (Index) 1, 0, false);
		resname = get_rel_name(subrte->relid);
	}
	else
	{
		HeapTuple	tuple;
		Form_pg_attribute	attform;

		tuple = SearchSysCache2(ATTNUM,
								ObjectIdGetDatum(subrte->relid),
								Int16GetDatum(attnum));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attnum, subrte->relid);
		attform = (Form_pg_attribute) GETSTRUCT(tuple);

		if (attform->attisdropped)
		{
			char	namebuf[NAMEDATALEN];

			/* Insert NULL just for a placeholder of dropped column */
			expr = (Expr *) makeConst(INT4OID,
									  -1,
									  InvalidOid,
									  sizeof(int32),
									  (Datum) 0,
									  true,		/* isnull */
									  true);	/* byval */
			sprintf(namebuf, "dummy-%d", (int)attform->attnum);
			resname = pstrdup(namebuf);
		}
		else
		{
			expr = (Expr *) makeVar((Index) 1,
									attform->attnum,
									attform->atttypid,
									attform->atttypmod,
									attform->attcollation,
									0);
			resname = pstrdup(NameStr(attform->attname));
		}
		ReleaseSysCache(tuple);
	}
	return makeTargetEntry(expr, -1, resname, false);
}

/*
 * lookup_artificial_column
 *
 * It looks-up resource number of the target-entry relevant to the given
 * Var-node that references the row-security subquery. If required column
 * is not in the subquery's target-list, this function also adds new one
 * and returns its resource number.
 */
static AttrNumber
lookup_artificial_column(PlannerInfo *root,
						 RangeTblEntry *rte, AttrNumber varattno)
{
	Query		   *subqry;
	RangeTblEntry  *subrte;
	TargetEntry	   *subtle;
	ListCell	   *cell;

	Assert(rte->rtekind == RTE_SUBQUERY &&
		   rte->subquery->querySource == QSRC_ROW_SECURITY);

	subqry = rte->subquery;
	foreach (cell, subqry->targetList)
	{
		subtle = lfirst(cell);

		/*
		 * If referenced artifical column is already constructed on the
		 * target-list of row-security subquery, nothing to do any more.
		 *
		 * XXX - Even though it was attached as 'resjunk', this flag
		 * shall be turned off because of references by user's query.
		 */
		if (IsA(subtle->expr, Var))
		{
			Var	   *subvar = (Var *)subtle->expr;

			Assert(subvar->varno == 1);
			if (subvar->varattno == varattno)
			{
				if (subtle->resjunk)
					subtle->resjunk = false;
				return subtle->resno;
			}
		}
	}

	/*
	 * OK, we don't have an artifical column relevant to the required ones,
	 * so let's create a new artifical column on demand.
	 */
	subrte = rt_fetch((Index) 1, subqry->rtable);
	subtle = make_artificial_column(subrte, varattno);
	subtle->resno = list_length(subqry->targetList) + 1;

	subqry->targetList = lappend(subqry->targetList, subtle);
	rte->eref->colnames = lappend(rte->eref->colnames,
								  makeString(pstrdup(subtle->resname)));
	return subtle->resno;
}

/*
 * fixup_varnode_walker
 *
 * It recursively fixes up references to the relation to be replaced by
 * row-security sub-query, and adds artificial columns relevant to the
 * underlying system columns or whole row-reference on demand.
 */
typedef struct {
	PlannerInfo	*root;
	int		varlevelsup;
} fixup_varnode_context;

static bool
fixup_varnode_walker(Node *node, fixup_varnode_context *context)
{
	if (node == NULL)
		return false;

	if (IsA(node, Var))
	{
		Var			   *var = (Var *) node;
		RangeTblEntry  *rte;
		ListCell	   *cell;

		/*
		 * Ignore it, if Var node does not reference the Query currently
		 * we focues on.
		 */
		if (var->varlevelsup != context->varlevelsup)
			return false;

		/*
		 * Var nodes that reference the relation being replaced by row-
		 * security sub-query has to be adjusted; to reference the sub-
		 * query, instead of the original relation.
		 */
		rte = rt_fetch(var->varno, context->root->parse->rtable);
		if (rte->rtekind == RTE_SUBQUERY &&
			rte->subquery->querySource == QSRC_ROW_SECURITY)
		{
			var->varattno = lookup_artificial_column(context->root,
													 rte, var->varattno);
		}
		else if (rte->rtekind == RTE_RELATION && rte->inh)
		{
			foreach (cell, context->root->append_rel_list)
			{
				AppendRelInfo  *appinfo = lfirst(cell);
				RangeTblEntry  *child_rte;

				if (appinfo->parent_relid != var->varno)
					continue;

				child_rte = rt_fetch(appinfo->child_relid,
									 context->root->parse->rtable);
				if (child_rte->rtekind == RTE_SUBQUERY &&
					child_rte->subquery->querySource == QSRC_ROW_SECURITY)
					(void) lookup_artificial_column(context->root,
													child_rte, var->varattno);
			}
		}
	}
	else if (IsA(node, Query))
	{
		bool	result;

		context->varlevelsup++;
		result = query_tree_walker((Query *) node,
								   fixup_varnode_walker,
								   (void *) context, 0);
		context->varlevelsup--;

		return result;
	}
	return expression_tree_walker(node,
								  fixup_varnode_walker,
								  (void *) context);
}

/*
 * check_infinite_recursion
 *
 * It is a wrong row-security configuration, if we try to expand
 * the relation inside of row-security subquery originated from
 * same relation!
 */
static void
check_infinite_recursion(PlannerInfo *root, Oid relid)
{
	PlannerInfo	   *parent = root->parent_root;

	if (parent && parent->parse->querySource == QSRC_ROW_SECURITY)
	{
		RangeTblEntry  *rte = rt_fetch(1, parent->parse->rtable);

		Assert(rte->rtekind == RTE_RELATION && OidIsValid(rte->relid));

		if (relid == rte->relid)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_OBJECT_DEFINITION),
					 errmsg("infinite recursion detected for relation \"%s\"",
							get_rel_name(relid))));
		check_infinite_recursion(parent, relid);
	}
}

/*
 * fixup_plan_rowmark
 *
 * Push down the given PlanRowMark into row-security subquery.
 */
static void
fixup_plan_rowmark(RangeTblEntry *rte, PlanRowMark *rowmark)
{
	Query		   *subqry = rte->subquery;
	RangeTblEntry  *subrte;
	TargetEntry	   *subtle;

	Assert(!rowmark->isParent);
#if 1
	if (rowmark->markType == ROW_MARK_EXCLUSIVE ||
		rowmark->markType == ROW_MARK_SHARE)
	{
		RowMarkClause  *rclause = makeNode(RowMarkClause);

		rclause->rti = (Index) 1;
		if (rowmark->markType == ROW_MARK_EXCLUSIVE)
			rclause->forUpdate = true;
		else
			rclause->forUpdate = false;
		rclause->noWait = rowmark->noWait;
		rclause->pushedDown = true;

		subqry->rowMarks = lappend(subqry->rowMarks, rclause);
	}
#endif
	rowmark->markType = ROW_MARK_REFERENCE;

	/*
	 * Addition of artificial columns relevant to 'ctid' and 'tableoid'
	 * to be required for row-level locks.
	 */
	subrte = rt_fetch(1, subqry->rtable);

	subtle = make_artificial_column(subrte, SelfItemPointerAttributeNumber);
	subtle->resno = list_length(subqry->targetList) + 1;
	subqry->targetList = lappend(subqry->targetList, subtle);
	rte->eref->colnames = lappend(rte->eref->colnames,
		makeString(pstrdup(subtle->resname)));

	subtle = make_artificial_column(subrte, TableOidAttributeNumber);
	subtle->resno = list_length(subqry->targetList) + 1;
	subqry->targetList = lappend(subqry->targetList, subtle);
	rte->eref->colnames = lappend(rte->eref->colnames,
		makeString(pstrdup(subtle->resname)));
}

/*
 * expand_rtentry_with_policy
 *
 * It extends a range-table entry of row-security sub-query with supplied
 * security policy, and append it on the parse->rtable.
 * This sub-query contains artificial columns that reference underlying
 * regular columns (at least, references to system column or whole of
 * table reference shall be added on demand), and simple scan on the
 * target relation.
 * Any Var nodes that referenced the relation pointed by rtindex shall
 * be adjusted to reference this sub-query instead. walker
 *
 */
static void
expand_rtentry_with_policy(PlannerInfo *root,
						   Index rtindex, Expr *qual, int flags)
{
	RangeTblEntry  *rte = rt_fetch(rtindex, root->parse->rtable);
	Query		   *subqry;
	RangeTblEntry  *subrte;
	RangeTblRef	   *subrtr;
	TargetEntry	   *subtle;
	HeapTuple		tuple;
	AttrNumber		nattrs;
	AttrNumber		attnum;
	List		   *targetList = NIL;
	List		   *colNameList = NIL;
	PlanRowMark	   *rowmark;

	Assert(rte->rtekind == RTE_RELATION && !rte->inh);

	/* check recursion to prevent infinite loop */
	check_infinite_recursion(root, rte->relid);

	/* Expand views inside SubLink node */
	if (flags & RSEC_FLAG_HAS_SUBLINKS)
		QueryRewriteExpr((Node *)qual, list_make1_oid(rte->relid));

	/*
	 * Construction of sub-query
	 */
	subqry = (Query *) makeNode(Query);
	subqry->commandType = CMD_SELECT;
	subqry->querySource = QSRC_ROW_SECURITY;

	subrte = copyObject(rte);
	subqry->rtable = list_make1(subrte);

	subrtr = makeNode(RangeTblRef);
	subrtr->rtindex = 1;
	subqry->jointree = makeFromExpr(list_make1(subrtr), (Node *) qual);
	if (flags & RSEC_FLAG_HAS_SUBLINKS)
		subqry->hasSubLinks = true;

	/*
	 * Construction of TargetEntries that reference underlying columns.
	 */
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(rte->relid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", rte->relid);
	nattrs = ((Form_pg_class) GETSTRUCT(tuple))->relnatts;
	ReleaseSysCache(tuple);

	for (attnum = 1; attnum <= nattrs; attnum++)
	{
		subtle = make_artificial_column(subrte, attnum);
		subtle->resno = list_length(targetList) + 1;
		Assert(subtle->resno == attnum);

		targetList = lappend(targetList, subtle);
		colNameList = lappend(colNameList,
							  makeString(pstrdup(subtle->resname)));
	}
	subqry->targetList = targetList;

	/* Replace the original RengeTblEntry by sub-query */
	rte->rtekind = RTE_SUBQUERY;
	rte->subquery = subqry;
	rte->security_barrier = true;
	rte->relid_orig = rte->relid;
	rte->relid = InvalidOid;

	/* no permission checks on subquery itself */
	rte->requiredPerms = 0;
	rte->checkAsUser = InvalidOid;
	rte->selectedCols = NULL;
	rte->modifiedCols = NULL;

	rte->eref = makeAlias(get_rel_name(rte->relid_orig), colNameList);

	/* Push-down of PlanRowMark if needed */
	rowmark = get_plan_rowmark(root->rowMarks, rtindex);
	if (rowmark)
		fixup_plan_rowmark(rte, rowmark);
}

/*
 * pull_row_security_policy
 *
 * It pulls the configured row-security policy of both built-in and
 * extensions. If any, it returns expression tree.
 */
static Expr *
pull_row_security_policy(CmdType cmd, Relation relation, int *p_flags)
{
	Expr   *quals = NULL;
	int		flags = 0;

	/*
	 * Pull the row-security policy configured with built-in features,
	 * if unprivileged users. Please note that superuser can bypass it.
	 */
	if (relation->rsdesc && !superuser())
	{
		RowSecurityDesc *rsdesc = relation->rsdesc;

		quals = copyObject(rsdesc->rsall.qual);
		if (rsdesc->rsall.hassublinks)
			flags |= RSEC_FLAG_HAS_SUBLINKS;
	}

	/*
	 * Also, ask extensions whether they want to apply their own
	 * row-security policy. If both built-in and extension has
	 * their own policy, it shall be merged.
	 */
	if (row_security_policy_hook)
	{
		List   *temp;

		temp = (*row_security_policy_hook)(cmd, relation);
		if (temp != NIL)
		{
			if ((flags & RSEC_FLAG_HAS_SUBLINKS) == 0 &&
				contain_subplans((Node *) temp))
				flags |= RSEC_FLAG_HAS_SUBLINKS;

			if (quals != NULL)
				temp = lappend(temp, quals);

			if (list_length(temp) == 1)
				quals = (Expr *)list_head(temp);
			else if (list_length(temp) > 1)
				quals = makeBoolExpr(AND_EXPR, temp, -1);
		}
	}
	*p_flags = flags;
	return quals;
}

/*
 * copy_row_security_policy
 *
 * It construct a row-security subquery instead of raw COPY TO statement,
 * if target relation has a row-level security policy
 */
bool
copy_row_security_policy(CopyStmt *stmt, Relation rel, List *attnums)
{
	Expr		  *quals;
	int			   flags;
	Query		  *parse;
	RangeTblEntry  *rte;
	RangeTblRef	   *rtr;
	TargetEntry	   *tle;
	Var			   *var;
	ListCell	   *cell;

	if (stmt->is_from)
		return false;

	quals = pull_row_security_policy(CMD_SELECT, rel, &flags);
	if (!quals)
		return false;

	parse = (Query *) makeNode(Query);
	parse->commandType = CMD_SELECT;
	parse->querySource = QSRC_ROW_SECURITY;

	rte = makeNode(RangeTblEntry);
	rte->rtekind = RTE_RELATION;
	rte->relid = RelationGetRelid(rel);
	rte->relkind = RelationGetForm(rel)->relkind;

	foreach (cell, attnums)
	{
		HeapTuple	tuple;
		Form_pg_attribute	attform;
		AttrNumber	attno = lfirst_int(cell);

		tuple = SearchSysCache2(ATTNUM,
								ObjectIdGetDatum(RelationGetRelid(rel)),
								Int16GetDatum(attno));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %s",
				 attno, RelationGetRelationName(rel));
		attform = (Form_pg_attribute) GETSTRUCT(tuple);

		var = makeVar((Index) 1,
					  attform->attnum,
					  attform->atttypid,
					  attform->atttypmod,
					  attform->attcollation,
					  0);
		tle = makeTargetEntry((Expr *) var,
							  list_length(parse->targetList) + 1,
							  pstrdup(NameStr(attform->attname)),
							  false);
		parse->targetList = lappend(parse->targetList, tle);

		ReleaseSysCache(tuple);

		rte->selectedCols = bms_add_member(rte->selectedCols,
								attno - FirstLowInvalidHeapAttributeNumber);
	}
	rte->inFromCl = true;
	rte->requiredPerms = ACL_SELECT;

	rtr = makeNode(RangeTblRef);
	rtr->rtindex = 1;

	parse->jointree = makeFromExpr(list_make1(rtr), (Node *) quals);
	parse->rtable = list_make1(rte);
	if (flags & RSEC_FLAG_HAS_SUBLINKS)
		parse->hasSubLinks = true;

	stmt->query = (Node *) parse;

	return true;
}

static bool
apply_row_security_recursive(PlannerInfo *root, Node *jtnode)
{
	bool	result = false;

	if (jtnode == NULL)
		return false;
	if (IsA(jtnode, RangeTblRef))
	{
		Index			rtindex = ((RangeTblRef *) jtnode)->rtindex;
		Query		   *parse = root->parse;
		RangeTblEntry  *rte = rt_fetch(rtindex, parse->rtable);
		Relation		rel;
		Expr		   *qual;
		CmdType			cmd;
		ListCell	   *cell;

		/* Only relation can have row-security policy */
		if (rte->rtekind != RTE_RELATION)
			return false;

		/*
		 * It does not make sense to apply row-security policy on
		 * the relation underlying row-security sub-query
		 */
		if (parse->querySource == QSRC_ROW_SECURITY && rtindex == 1)
			return false;

		/* Is it a result relation of UPDATE or DELETE command? */
		if (parse->resultRelation == rtindex)
			cmd = parse->commandType;
		else
			cmd = CMD_SELECT;

		if (!rte->inh)
		{
			/*
			 * A simple case - If referenced relation has no inherited
			 * children, all we need to do is 
			 *
			 *
			 *
			 */
			int		flags = 0;

			rel = heap_open(rte->relid, NoLock);

			qual = pull_row_security_policy(cmd, rel, &flags);
			if (qual)
			{
				//rowmark = get_plan_rowmark(root->rowMarks, rtindex);
				expand_rtentry_with_policy(root, rtindex, qual, flags);
				//rowmark->markType = ROW_MARK_COPY;
				result = true;
			}
			heap_close(rel, NoLock);
		}
		else
		{
			/*
			 * In case when 
			 *
			 *
			 *
			 *
			 */
			foreach (cell, root->append_rel_list)
			{
				AppendRelInfo  *apinfo = lfirst(cell);
				RangeTblEntry  *child_rte;
				int				flags = 0;

				if (apinfo->parent_relid != rtindex)
					continue;

				child_rte = rt_fetch(apinfo->child_relid, parse->rtable);
				Assert(!child_rte->inh);
				if (child_rte->rtekind != RTE_RELATION)
					continue;

				rel = heap_open(child_rte->relid, NoLock);

				qual = pull_row_security_policy(cmd, rel, &flags);
				if (qual)
				{
					//rowmark = get_plan_rowmark(root->rowMarks,
					//						   apinfo->child_relid);
					expand_rtentry_with_policy(root, apinfo->child_relid,
											   qual, flags);
					//rowmark->markType = ROW_MARK_COPY;
					result = true;
				}
				heap_close(rel, NoLock);
			}
		}
	}
	else if (IsA(jtnode, FromExpr))
	{
		FromExpr   *f = (FromExpr *) jtnode;
		ListCell   *l;

		foreach (l, f->fromlist)
		{
			if (apply_row_security_recursive(root, lfirst(l)))
				result = true;
		}
	}
	else if (IsA(jtnode, JoinExpr))
	{
		JoinExpr   *j = (JoinExpr *) jtnode;

		if (apply_row_security_recursive(root, j->larg))
			result = true;
		if (apply_row_security_recursive(root, j->rarg))
			result = true;
	}
	else
		elog(ERROR, "unexpected node type: %d", (int) nodeTag(jtnode));

	return result;
}

/*
 * apply_row_security_policy
 *
 * Entrypoint to apply configured row-security policy of the relation.
 *
 * In case when the supplied query references relations with row-security
 * policy, its RangeTblEntry shall be replaced by a row-security subquery
 * that has simple scan on the referenced table with policy qualifiers.
 * Of course, security-barrier shall be set on the subquery to prevent
 * unexpected push-down of functions without leakproof flag.
 *
 * For example, when table t1 has a security policy "(x % 2 = 0)", the
 * following query:
 *   SELECT * FROM t1 WHERE f_leak(y)
 * performs as if
 *   SELECT * FROM (
 *     SELECT x, y FROM t1 WHERE (x % 2 = 0)
 *   ) AS t1 WHERE f_leak(y)
 * would be given. Because the sub-query has security barrier flag, 
 * configured security policy qualifier is always executed prior to
 * user given functions.
 */
void
apply_row_security_policy(PlannerInfo *root)
{
	Query	   *parse = root->parse;
	Oid			curr_userid;
	int			curr_seccxt;

	/*
	 * Mode checks. In case when SECURITY_ROW_LEVEL_DISABLED is set,
	 * no row-level security policy should be applied regardless
	 * whether it is built-in or extension.
	 */
	GetUserIdAndSecContext(&curr_userid, &curr_seccxt);
	if (curr_seccxt & SECURITY_ROW_LEVEL_DISABLED)
		return;

	if (apply_row_security_recursive(root, (Node *)parse->jointree))
	{
		PlannerGlobal  *glob = root->glob;
		PlanInvalItem  *pi_item;
		fixup_varnode_context context;

		/*
		 * XXX - Constructed Plan with row-level security policy depends
		 * on properties of current used (database superuser can bypass
		 * configured row-security policy), thus, it has to be invalidated
		 * when its assumption was changed.
		 */
		if (!OidIsValid(glob->planUserId))
		{
			/* Plan invalidation on session user-id */
			glob->planUserId = GetUserId();

			/* Plan invalidation on catalog updates of pg_authid */
			pi_item = makeNode(PlanInvalItem);
			pi_item->cacheId = AUTHOID;
			pi_item->hashValue =
				GetSysCacheHashValue1(AUTHOID,
									  ObjectIdGetDatum(glob->planUserId));
			glob->invalItems = lappend(glob->invalItems, pi_item);
		}
		else
			Assert(glob->planUserId == GetUserId());

		/*
		 * XXX - Var-nodes that referenced RangeTblEntry to be replaced by
		 * row-security sub-query have to be adjusted for appropriate
		 * reference to the underlying artificial column of the relation.
		 */
		context.root = root;
		context.varlevelsup = 0;
		query_tree_walker(parse,
						  fixup_varnode_walker,
						  (void *) &context,
						  QTW_IGNORE_RETURNING);
	}
}

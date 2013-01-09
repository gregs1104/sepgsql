/*-------------------------------------------------------------------------
 *
 * option.c
 *		  FDW option handling
 *
 * Copyright (c) 2012, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/postgres_fdw/option.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "libpq-fe.h"

#include "access/reloptions.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_user_mapping.h"
#include "commands/defrem.h"
#include "fmgr.h"
#include "foreign/foreign.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "utils/memutils.h"

#include "postgres_fdw.h"

/*
 * SQL functions
 */
extern Datum postgres_fdw_validator(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(postgres_fdw_validator);

/*
 * Describes the valid options for objects that this wrapper uses.
 */
typedef struct PostgresFdwOption
{
	const char *keyword;
	Oid			optcontext;		/* Oid of catalog in which options may appear */
	bool		is_libpq_opt;	/* true if it's used in libpq */
} PostgresFdwOption;

/*
 * Valid options for postgres_fdw.
 * Allocated and filled in InitPostgresFdwOptions.
 */
static PostgresFdwOption *postgres_fdw_options;

/*
 * Valid options of libpq.
 * Allocated and filled in InitPostgresFdwOptions.
 */
static PQconninfoOption *libpq_options;

/*
 * Helper functions
 */
static bool is_valid_option(const char *keyword, Oid context);

/*
 * Validate the generic options given to a FOREIGN DATA WRAPPER, SERVER,
 * USER MAPPING or FOREIGN TABLE that uses postgres_fdw.
 *
 * Raise an ERROR if the option or its value is considered invalid.
 */
Datum
postgres_fdw_validator(PG_FUNCTION_ARGS)
{
	List	   *options_list = untransformRelOptions(PG_GETARG_DATUM(0));
	Oid			catalog = PG_GETARG_OID(1);
	ListCell   *cell;

	/*
	 * Check that only options supported by postgres_fdw, and allowed for the
	 * current object type, are given.
	 */
	foreach(cell, options_list)
	{
		DefElem	   *def = (DefElem *) lfirst(cell);

		if (!is_valid_option(def->defname, catalog))
		{
			PostgresFdwOption *opt;
			StringInfoData buf;

			/*
			 * Unknown option specified, complain about it. Provide a hint
			 * with list of valid options for the object.
			 */
			initStringInfo(&buf);
			for (opt = postgres_fdw_options; opt->keyword; opt++)
			{
				if (catalog == opt->optcontext)
					appendStringInfo(&buf, "%s%s", (buf.len > 0) ? ", " : "",
									 opt->keyword);
			}

			ereport(ERROR,
					(errcode(ERRCODE_FDW_INVALID_OPTION_NAME),
					 errmsg("invalid option \"%s\"", def->defname),
					 errhint("Valid options in this context are: %s",
							 buf.data)));
		}

		if (strcmp(def->defname, "use_remote_explain") == 0)
		{
			/* use_remote_explain accepts only boolean values */
			(void) defGetBoolean(def);
		}
		else if (strcmp(def->defname, "fdw_startup_cost") == 0)
		{
			double		val;
			char	   *endp;
			val = strtod(defGetString(def), &endp);
			if (*endp || val < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
						 errmsg("fdw_startup_cost requires positive numeric value or zero")));
		}
		else if (strcmp(def->defname, "fdw_tuple_cost") == 0)
		{
			double		val;
			char	   *endp;
			val = strtod(defGetString(def), &endp);
			if (*endp || val < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
						 errmsg("fdw_tuple_cost requires positive numeric value or zero")));
		}
	}

	/*
	 * We don't care option-specific limitation here; they will be validated at
	 * the execution time.
	 */

	PG_RETURN_VOID();
}

/*
 * Initialize option check mechanism.  This must be called before any call
 * against other functions in options.c, so _PG_init would be proper timing.
 */
void
InitPostgresFdwOptions(void)
{
	int		libpq_opt_num;
	PQconninfoOption *lopt;
	PostgresFdwOption *popt;
	/* non-libpq FDW-specific FDW options */
	static const PostgresFdwOption non_libpq_options[] = {
		{ "nspname", ForeignTableRelationId, false} ,
		{ "relname", ForeignTableRelationId, false} ,
		{ "colname", AttributeRelationId, false} ,
		/* use_remote_explain is available on both server and table */
		{ "use_remote_explain", ForeignServerRelationId, false} ,
		{ "use_remote_explain", ForeignTableRelationId, false} ,
		/* cost factors */
		{ "fdw_startup_cost", ForeignServerRelationId, false} ,
		{ "fdw_tuple_cost", ForeignServerRelationId, false} ,
		{ NULL, InvalidOid, false },
	};

	/* Prevent redundant initialization. */
	if (postgres_fdw_options)
		return;

	/*
	 * Get list of valid libpq options.
	 *
	 * To avoid unnecessary work, we get the list once and use it throughout
	 * the lifetime of this backend process.  We don't need to care about
	 * memory context issues, because PQconndefaults allocates with malloc.
	 */
	libpq_options = PQconndefaults();
	if (!libpq_options)			/* assume reason for failure is OOM */
		ereport(ERROR,
				(errcode(ERRCODE_FDW_OUT_OF_MEMORY),
				 errmsg("out of memory"),
				 errdetail("could not get libpq's default connection options")));

	/* Count how much libpq options are available. */
	libpq_opt_num = 0;
	for (lopt = libpq_options; lopt->keyword; lopt++)
		libpq_opt_num++;

	/*
	 * Construct an array which consists of all valid options for postgres_fdw,
	 * by appending FDW-specific options to libpq options.
	 *
	 * We use plain malloc here to allocate postgres_fdw_options because it
	 * lives as long as the backend process does.  Besides, keeping
	 * libpq_options in memory allows us to avoid copying every keyword string.
	 */
	postgres_fdw_options = (PostgresFdwOption *)
		malloc(sizeof(PostgresFdwOption) * libpq_opt_num +
			   sizeof(non_libpq_options));
	if (postgres_fdw_options == NULL)
		elog(ERROR, "out of memory");
	popt = postgres_fdw_options;
	for (lopt = libpq_options; lopt->keyword; lopt++)
	{
		/* Disallow some debug options. */
		if (strcmp(lopt->keyword, "replication") == 0 ||
			strcmp(lopt->keyword, "fallback_application_name") == 0 ||
			strcmp(lopt->keyword, "client_encoding") == 0)
			continue;

		/* We don't have to copy keyword string, as described above. */
		popt->keyword = lopt->keyword;

		/* "user" and any secret options are allowed on only user mappings. */
		if (strcmp(lopt->keyword, "user") == 0 || strchr(lopt->dispchar, '*'))
			popt->optcontext = UserMappingRelationId;
		else
			popt->optcontext = ForeignServerRelationId;
		popt->is_libpq_opt = true;

		/* Advance the position where next option will be placed. */
		popt++;
	}

	/* Append FDW-specific options. */
	memcpy(popt, non_libpq_options, sizeof(non_libpq_options));
}

/*
 * Check whether the given option is one of the valid postgres_fdw options.
 * context is the Oid of the catalog holding the object the option is for.
 */
static bool
is_valid_option(const char *keyword, Oid context)
{
	PostgresFdwOption *opt;

	for (opt = postgres_fdw_options; opt->keyword; opt++)
	{
		if (context == opt->optcontext && strcmp(opt->keyword, keyword) == 0)
			return true;
	}

	return false;
}

/*
 * Check whether the given option is one of the valid libpq options.
 * context is the Oid of the catalog holding the object the option is for.
 */
static bool
is_libpq_option(const char *keyword)
{
	PostgresFdwOption *opt;

	for (opt = postgres_fdw_options; opt->keyword; opt++)
	{
		if (opt->is_libpq_opt && strcmp(opt->keyword, keyword) == 0)
			return true;
	}

	return false;
}

/*
 * Generate key-value arrays which includes only libpq options from the list
 * which contains any kind of options.
 */
int
ExtractConnectionOptions(List *defelems, const char **keywords,
						 const char **values)
{
	ListCell *lc;
	int i;

	i = 0;
	foreach(lc, defelems)
	{
		DefElem *d = (DefElem *) lfirst(lc);
		if (is_libpq_option(d->defname))
		{
			keywords[i] = d->defname;
			values[i] = defGetString(d);
			i++;
		}
	}
	return i;
}


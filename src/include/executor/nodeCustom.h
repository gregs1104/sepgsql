/* ------------------------------------------------------------------------
 *
 * nodeCustom.h
 *
 * prototypes for CustomScan nodes
 *
 * Portions Copyright (c) 1996-2013, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * ------------------------------------------------------------------------
 */
#ifndef NODECUSTOM_H
#define NODECUSTOM_H
#include "commands/explain.h"
#include "nodes/plannodes.h"
#include "nodes/relation.h"

/*
 * Definition of the custom execution provider callbacks
 */
typedef void (*SetupCustomScan_function)(PlannerInfo *root,
										 CustomPath *cscan_path,
										 CustomScan *cscan_plan);
typedef void (*BeginCustomScan_function)(CustomScanState *csstate, int eflags);
typedef TupleTableSlot *(*ExecCustomScan_function)(CustomScanState *csstate);
typedef Node *(*MultiExecCustomScan_function)(CustomScanState *csstate);
typedef void (*EndCustomScan_function)(CustomScanState *csstate);

typedef void (*ReScanCustomScan_function)(CustomScanState *csstate);
typedef void (*ExecMarkPosCustomScan_function)(CustomScanState *csstate);
typedef void (*ExecRestorePosCustom_function)(CustomScanState *csstate);

typedef void (*ExplainCustomScan_function)(CustomScanState *csstate,
										   ExplainState *es);

typedef struct CustomProvider
{
	char							name[NAMEDATALEN];

	SetupCustomScan_function		SetupCustomScan;

	BeginCustomScan_function		BeginCustomScan;
	ExecCustomScan_function			ExecCustomScan;
	MultiExecCustomScan_function	MultiExecCustomScan;
	EndCustomScan_function			EndCustomScan;

	ReScanCustomScan_function		ReScanCustomScan;
	ExecMarkPosCustomScan_function	ExecMarkPosCustomScan;
	ExecRestorePosCustom_function	ExecRestorePosCustom;

	ExplainCustomScan_function		ExplainCustomScan;
} CustomProvider;

/* custom_flags */
#define CUSTOM__RETURNS_SYSTEM_COLUMNS			0x0001
#define CUSTOM__EXPLAIN_UNDERLYING_PLANS		0x0002
#define CUSTOM__SUPPORT_BACKWARD_SCAN			0x0004

/*
 * Registration and lookup custom execution provider
 */
extern void register_custom_provider(const CustomProvider *provider);

extern CustomProvider *get_custom_provider(const char *custom_name);

/*
 * General executor code
 */
extern CustomScanState *ExecInitCustomScan(CustomScan *csstate,
										   EState *estate, int eflags);
extern TupleTableSlot *ExecCustomScan(CustomScanState *csstate);
extern Node *MultiExecCustomScan(CustomScanState *csstate);
extern void ExecEndCustomScan(CustomScanState *csstate);

extern void ExecReScanCustomScan(CustomScanState *csstate);

#endif	/* NODECUSTOM_H */

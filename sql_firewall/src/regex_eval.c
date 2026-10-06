/*
 * Regex rule evaluation with a real deadline (README 6.6 "Regex rules").
 *
 * The active rules are matched by one SPI query in an internal
 * subtransaction while a dedicated timeout (RegisterTimeout(USER_TIMEOUT))
 * is armed. When it fires it requests a query cancel, which the regex engine
 * and lock waits honour; the cancel is caught here, the subtransaction rolled
 * back, and the outcome reported as SQLFW_REGEX_DEADLINE. PostgreSQL's own
 * statement_timeout, lock_timeout, and a client's cancel are separate timers
 * and requests: they are not changed, and an error they raise is rethrown
 * unchanged. An invalid stored pattern is reported as SQLFW_REGEX_INVALID.
 * Any other error is rethrown.
 *
 * The rules are read with a snapshot taken for this read (the latest one, or
 * a fresh catalog snapshot while the transaction must not take its first
 * snapshot yet), like the other policy lookups (policy_visibility.rs).
 *
 * The deadline bounds evaluation, not a new session's setup: the query is
 * parsed and planned once per backend before the timer is armed, because in
 * a new session that loads catalog caches and can take longer than the
 * limit on a busy server. The plan is kept (SPI_keepplan); PostgreSQL
 * replans it at execution, under the deadline, after the rules table or the
 * search_path changes. The one-time preparation happens only if the rules
 * table can be locked without waiting; otherwise the query is prepared under
 * the deadline, so a lock held on the table still ends in
 * SQLFW_REGEX_DEADLINE rather than an unbounded wait.
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/namespace.h"
#include "catalog/pg_type_d.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "storage/lmgr.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"

#define SQLFW_REGEX_NOMATCH 0
#define SQLFW_REGEX_MATCH 1
#define SQLFW_REGEX_DEADLINE 2
#define SQLFW_REGEX_INVALID 3

static TimeoutId deadline_id = MAX_TIMEOUTS;
static volatile sig_atomic_t deadline_hit = false;

static void
deadline_handler(void)
{
	deadline_hit = true;
	QueryCancelPending = true;
	InterruptPending = true;
	/* timeout.c sets our latch after the handler. */
}

static const char *const rules_query =
	"SELECT EXISTS (SELECT 1 FROM public.sql_firewall_regex_rules "
	"WHERE is_active OPERATOR(pg_catalog.=) true "
	"AND action OPERATOR(pg_catalog.=) 'BLOCK'::pg_catalog.text "
	"AND $1 OPERATOR(pg_catalog.~*) pattern "
	"AND (allowed_roles IS NULL OR NOT ($2::pg_catalog.text OPERATOR(pg_catalog.=) ANY(allowed_roles))) "
	"LIMIT 1)";

static Oid	rules_types[2] = {TEXTOID, TEXTOID};

/*
 * Whether any rule could refuse a statement at all. Asked, under the same
 * deadline and snapshot, only when the caller may remember a "no active
 * rule" answer (policy_visibility.rs, regex_memo_scope).
 */
static const char *const any_rule_query =
	"SELECT EXISTS (SELECT 1 FROM public.sql_firewall_regex_rules "
	"WHERE is_active OPERATOR(pg_catalog.=) true "
	"AND action OPERATOR(pg_catalog.=) 'BLOCK'::pg_catalog.text)";

/* This backend's kept plans of rules_query and any_rule_query, or NULL until prepared. */
static SPIPlanPtr rules_plan = NULL;
static SPIPlanPtr any_rule_plan = NULL;

/* Prepares rules_plan, before the deadline is armed, if it can without waiting. */
static void
prepare_rules_plan(void)
{
	Oid			relid;
	SPIPlanPtr	plan;

	if (rules_plan != NULL && any_rule_plan != NULL)
		return;
	relid = RangeVarGetRelid(makeRangeVar("public", "sql_firewall_regex_rules", -1), NoLock, true);
	if (!OidIsValid(relid) || !ConditionalLockRelationOid(relid, AccessShareLock))
		return;
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "sql_firewall: SPI_connect failed for the regex rules");
	if (rules_plan == NULL)
	{
		plan = SPI_prepare(rules_query, 2, rules_types);
		if (plan == NULL)
			elog(ERROR, "sql_firewall: SPI_prepare failed for the regex rules (%d)", SPI_result);
		if (SPI_keepplan(plan) != 0)
			elog(ERROR, "sql_firewall: SPI_keepplan failed for the regex rules");
		rules_plan = plan;
	}
	if (any_rule_plan == NULL)
	{
		plan = SPI_prepare(any_rule_query, 0, NULL);
		if (plan == NULL)
			elog(ERROR, "sql_firewall: SPI_prepare failed for the regex rules (%d)", SPI_result);
		if (SPI_keepplan(plan) != 0)
			elog(ERROR, "sql_firewall: SPI_keepplan failed for the regex rules");
		any_rule_plan = plan;
	}
	SPI_finish();
}

static int	run_rules_query(const char *query, const char *role, bool catalog_snapshot);

/* True when an active BLOCK rule exists in the snapshot the rules query uses. */
static bool
run_any_rule_query(bool catalog_snapshot)
{
	SPIPlanPtr	plan = any_rule_plan;
	int			rc;
	bool		isnull = true;
	bool		any = true;

	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "sql_firewall: SPI_connect failed for the regex rules");
	if (plan == NULL)
		plan = SPI_prepare(any_rule_query, 0, NULL);
	if (plan == NULL)
		elog(ERROR, "sql_firewall: SPI_prepare failed for the regex rules (%d)", SPI_result);
	rc = SPI_execute_snapshot(plan, NULL, NULL,
							  catalog_snapshot ? GetCatalogSnapshot(InvalidOid) : GetLatestSnapshot(),
							  InvalidSnapshot, true, false, 1);
	if (rc != SPI_OK_SELECT)
		elog(ERROR, "sql_firewall: regex rules query returned %d", rc);
	if (SPI_processed == 1)
	{
		Datum		result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);

		any = isnull || DatumGetBool(result);
	}
	SPI_finish();
	return any;
}

/*
 * The rules query, preceded by the any-rule query when `no_rules` is not
 * NULL; *no_rules is then true when no active rule existed and the rules
 * query was not run.
 */
static int
run_rules(const char *query, const char *role, bool catalog_snapshot, bool *no_rules)
{
	if (no_rules != NULL && !run_any_rule_query(catalog_snapshot))
	{
		*no_rules = true;
		return SQLFW_REGEX_NOMATCH;
	}
	return run_rules_query(query, role, catalog_snapshot);
}

static int
run_rules_query(const char *query, const char *role, bool catalog_snapshot)
{
	Datum		values[2];
	char		nulls[2] = {' ', ' '};
	SPIPlanPtr	plan = rules_plan;
	int			rc;
	bool		isnull = true;
	int			outcome = SQLFW_REGEX_NOMATCH;

	values[0] = CStringGetTextDatum(query);
	values[1] = CStringGetTextDatum(role);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "sql_firewall: SPI_connect failed for the regex rules");
	if (plan == NULL)
		plan = SPI_prepare(rules_query, 2, rules_types);
	if (plan == NULL)
		elog(ERROR, "sql_firewall: SPI_prepare failed for the regex rules (%d)", SPI_result);
	rc = SPI_execute_snapshot(plan, values, nulls,
							  catalog_snapshot ? GetCatalogSnapshot(InvalidOid) : GetLatestSnapshot(),
							  InvalidSnapshot, true, false, 1);
	if (rc != SPI_OK_SELECT)
		elog(ERROR, "sql_firewall: regex rules query returned %d", rc);
	if (SPI_processed == 1)
	{
		Datum		result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);

		if (!isnull && DatumGetBool(result))
			outcome = SQLFW_REGEX_MATCH;
	}
	SPI_finish();
	return outcome;
}

/*
 * The deadline fired before the end of the evaluation was seen: the rules
 * were not evaluated within the limit, whatever the result. The regex engine
 * checks for interrupts only when its automaton grows, so a long evaluation
 * can run past the deadline without noticing the cancel and then finish; it
 * is refused like one that was interrupted, not decided by its late result.
 * The cancel was ours; withdraw it. Nothing is remembered about the rules.
 */
static int
deadline_overrun(bool *no_rules)
{
	QueryCancelPending = false;
	deadline_hit = false;
	if (no_rules != NULL)
		*no_rules = false;
	return SQLFW_REGEX_DEADLINE;
}

/*
 * Returns an SQLFW_REGEX_* outcome. On SQLFW_REGEX_INVALID, *message is a
 * palloc'd copy of PostgreSQL's message.
 *
 * `in_subtransaction` false: the transaction block cannot start a
 * subtransaction now (BEGIN and START are inspected after PostgreSQL ran
 * them, while the block is still being begun). The query then runs under the
 * same deadline without one, and any error, the deadline's cancel included,
 * propagates: the statement still fails, as 57014 instead of the firewall's
 * message.
 */
int
sqlfw_regex_match(const char *query, const char *role, int timeout_ms,
				  bool catalog_snapshot, bool in_subtransaction, char **message,
				  bool *no_rules)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	volatile int outcome = SQLFW_REGEX_NOMATCH;

	*message = NULL;
	if (no_rules != NULL)
		*no_rules = false;
	if (deadline_id == MAX_TIMEOUTS)
		deadline_id = RegisterTimeout(USER_TIMEOUT, deadline_handler);

	if (!in_subtransaction)
	{
		int			result;

		prepare_rules_plan();
		deadline_hit = false;
		if (timeout_ms > 0)
			enable_timeout_after(deadline_id, timeout_ms);
		result = run_rules(query, role, catalog_snapshot, no_rules);
		disable_timeout(deadline_id, false);
		if (deadline_hit)
			return deadline_overrun(no_rules);
		return result;
	}

	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);

	PG_TRY();
	{
		prepare_rules_plan();
		deadline_hit = false;
		if (timeout_ms > 0)
			enable_timeout_after(deadline_id, timeout_ms);
		outcome = run_rules(query, role, catalog_snapshot, no_rules);

		disable_timeout(deadline_id, false);
		if (deadline_hit)
			outcome = deadline_overrun(no_rules);

		ReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
	}
	PG_CATCH();
	{
		ErrorData  *edata;
		bool		ours = deadline_hit;

		disable_timeout(deadline_id, false);
		deadline_hit = false;
		MemoryContextSwitchTo(oldcontext);
		edata = CopyErrorData();
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;

		if (ours && edata->sqlerrcode == ERRCODE_QUERY_CANCELED)
		{
			QueryCancelPending = false;
			outcome = SQLFW_REGEX_DEADLINE;
			FreeErrorData(edata);
		}
		else if (edata->sqlerrcode == ERRCODE_INVALID_REGULAR_EXPRESSION)
		{
			*message = pstrdup(edata->message ? edata->message : "invalid regular expression");
			outcome = SQLFW_REGEX_INVALID;
			FreeErrorData(edata);
		}
		else
			ReThrowError(edata);
	}
	PG_END_TRY();

	return outcome;
}

/*
 * Canonical token text for fingerprints, produced by PostgreSQL's own core
 * lexer (scanner_init/core_yylex/scanner_finish, as used by PL/pgSQL and
 * pg_stat_statements). The token grammar of the output is documented in
 * fingerprints.rs.
 *
 * Everything the scanner allocates lives in a memory context owned by one
 * call and deleted before it returns, on success and on error. The lexer is
 * reentrant; no scanner state outlives the call.
 */
#include "postgres.h"

#include <ctype.h>

#include "common/keywords.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "parser/parser.h"
#include "parser/scanner.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/memutils.h"

/*
 * Non-keyword token codes of the core lexer. gram.y declares these first so
 * that their values do not depend on the keyword set (scanner.h: "IDENT = 258
 * and so on"); PL/pgSQL relies on the same layout. gram.h is not installed,
 * so the codes are restated here and checked against the lexer once per
 * backend before any statement is rendered.
 */
#define SQLFW_IDENT 258
#define SQLFW_UIDENT 259
#define SQLFW_FCONST 260
#define SQLFW_SCONST 261
#define SQLFW_USCONST 262
#define SQLFW_BCONST 263
#define SQLFW_XCONST 264
#define SQLFW_OP 265
#define SQLFW_ICONST 266
#define SQLFW_PARAM 267
#define SQLFW_TYPECAST 268
#define SQLFW_DOT_DOT 269
#define SQLFW_COLON_EQUALS 270
#define SQLFW_EQUALS_GREATER 271
#define SQLFW_LESS_EQUALS 272
#define SQLFW_GREATER_EQUALS 273
#define SQLFW_NOT_EQUALS 274

static bool layout_checked = false;
static uint8 keyword_codes[(PG_UINT16_MAX + 1) / 8];

static bool
is_keyword_code(int tok)
{
	return tok > 0 && tok <= PG_UINT16_MAX &&
		(keyword_codes[tok / 8] & (1 << (tok % 8))) != 0;
}

static core_yyscan_t
start_scan(const char *text, core_yy_extra_type *extra, bool standard_strings)
{
	core_yyscan_t scanner = scanner_init(text, extra, &ScanKeywords, ScanKeywordTokens);

	/*
	 * Fixed settings, not the session's: the caller decides between the two
	 * standard_conforming_strings readings. backslash_quote = on accepts every
	 * text any setting accepts. Warnings were already given by the parser.
	 */
	extra->standard_conforming_strings = standard_strings;
	extra->backslash_quote = BACKSLASH_QUOTE_ON;
	extra->escape_string_warning = false;
	return scanner;
}

static void
layout_error(const char *what)
{
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("sql_firewall: PostgreSQL lexer token codes do not match this build"),
			 errdetail_internal("%s", what)));
}

/* Runs once per backend, inside the caller's scan context. */
static void
check_layout(void)
{
	static const char probe[] =
		"x U&\"y\" 1.5 's' U&'z' b'1' x'1f' ~ 1 $1 :: .. := => <= >= <> select";
	static const int expected[] = {
		SQLFW_IDENT, SQLFW_UIDENT, SQLFW_FCONST, SQLFW_SCONST, SQLFW_USCONST,
		SQLFW_BCONST, SQLFW_XCONST, SQLFW_OP, SQLFW_ICONST, SQLFW_PARAM,
		SQLFW_TYPECAST, SQLFW_DOT_DOT, SQLFW_COLON_EQUALS, SQLFW_EQUALS_GREATER,
		SQLFW_LESS_EQUALS, SQLFW_GREATER_EQUALS, SQLFW_NOT_EQUALS
	};
	core_yy_extra_type extra;
	core_YYSTYPE yylval;
	YYLTYPE		yylloc;
	core_yyscan_t scanner;
	int			i;
	int			tok;

	memset(keyword_codes, 0, sizeof(keyword_codes));
	for (i = 0; i < ScanKeywords.num_keywords; i++)
	{
		int			code = ScanKeywordTokens[i];

		if (code <= SQLFW_NOT_EQUALS)
			layout_error("a keyword token code overlaps the non-keyword codes");
		keyword_codes[code / 8] |= (uint8) (1 << (code % 8));
	}

	scanner = start_scan(probe, &extra, true);
	for (i = 0; i < (int) lengthof(expected); i++)
	{
		tok = core_yylex(&yylval, &yylloc, scanner);
		if (tok != expected[i])
			layout_error("a non-keyword token code differs from gram.y");
	}
	tok = core_yylex(&yylval, &yylloc, scanner);
	if (!is_keyword_code(tok) || strcmp(yylval.keyword, "select") != 0)
		layout_error("a keyword was not returned as a keyword token");
	if (core_yylex(&yylval, &yylloc, scanner) != 0)
		layout_error("the probe text did not end where expected");
	scanner_finish(scanner);
	layout_checked = true;
}

/* Quote s with q, doubling any q inside, after an optional prefix. */
static void
append_quoted(StringInfo buf, const char *prefix, const char *s, char q)
{
	appendStringInfoString(buf, prefix);
	appendStringInfoChar(buf, q);
	for (; *s; s++)
	{
		if (*s == q)
			appendStringInfoChar(buf, q);
		appendStringInfoChar(buf, *s);
	}
	appendStringInfoChar(buf, q);
}

static bool
keyword_is(int tok, const core_YYSTYPE *yylval, const char *word)
{
	return is_keyword_code(tok) && strcmp(yylval->keyword, word) == 0;
}

/*
 * Statements whose string literals are executable code or server-side
 * resources keep every literal's value: DO, CREATE [OR REPLACE]
 * FUNCTION/PROCEDURE, COPY (server file paths and PROGRAM commands), and
 * LOAD. The decision is taken from the leading keywords; none of these
 * statements has a literal before them.
 */
typedef enum
{
	LEAD_START,
	LEAD_CREATE,
	LEAD_CREATE_OR,
	LEAD_CREATE_OR_REPLACE,
	LEAD_DONE
} LeadState;

static void
render(const char *text, bool standard_strings, bool keep_all, StringInfo out)
{
	core_yy_extra_type extra;
	core_YYSTYPE yylval;
	YYLTYPE		yylloc;
	core_yyscan_t scanner = start_scan(text, &extra, standard_strings);
	LeadState	lead = LEAD_START;
	bool		keep_values = keep_all;
	bool		after_uescape = false;
	int			pending_semicolons = 0;

	for (;;)
	{
		int			tok = core_yylex(&yylval, &yylloc, scanner);
		bool		keyword;
		bool		keep_this;

		CHECK_FOR_INTERRUPTS();
		if (tok == 0)
			break;

		/* A terminating ';' is formatting; one followed by a token is not. */
		if (tok == ';')
		{
			pending_semicolons++;
			continue;
		}
		for (; pending_semicolons > 0; pending_semicolons--)
			appendStringInfoString(out, out->len > 0 ? " ;" : ";");
		if (out->len > 0)
			appendStringInfoChar(out, ' ');

		keyword = is_keyword_code(tok);
		switch (lead)
		{
			case LEAD_START:
				if (keyword_is(tok, &yylval, "do") ||
					keyword_is(tok, &yylval, "copy") ||
					keyword_is(tok, &yylval, "load"))
					keep_values = true;
				lead = keyword_is(tok, &yylval, "create") ? LEAD_CREATE : LEAD_DONE;
				break;
			case LEAD_CREATE:
				if (keyword_is(tok, &yylval, "function") ||
					keyword_is(tok, &yylval, "procedure"))
					keep_values = true;
				lead = keyword_is(tok, &yylval, "or") ? LEAD_CREATE_OR : LEAD_DONE;
				break;
			case LEAD_CREATE_OR:
				lead = keyword_is(tok, &yylval, "replace") ? LEAD_CREATE_OR_REPLACE : LEAD_DONE;
				break;
			case LEAD_CREATE_OR_REPLACE:
				if (keyword_is(tok, &yylval, "function") ||
					keyword_is(tok, &yylval, "procedure"))
					keep_values = true;
				lead = LEAD_DONE;
				break;
			case LEAD_DONE:
				break;
		}

		/* UESCAPE's string selects how the preceding U& text is decoded. */
		keep_this = keep_values || after_uescape;
		after_uescape = keyword && strcmp(yylval.keyword, "uescape") == 0;

		if (keyword)
		{
			const char *k;

			for (k = yylval.keyword; *k; k++)
				appendStringInfoChar(out, (char) pg_ascii_toupper((unsigned char) *k));
			continue;
		}

		switch (tok)
		{
			case SQLFW_IDENT:
				append_quoted(out, "", yylval.str, '"');
				break;
			case SQLFW_UIDENT:
				append_quoted(out, "U&", yylval.str, '"');
				break;
			case SQLFW_SCONST:
				if (keep_this)
					append_quoted(out, "", yylval.str, '\'');
				else
					appendStringInfoString(out, "?str");
				break;
			case SQLFW_USCONST:
				if (keep_this)
					append_quoted(out, "U&", yylval.str, '\'');
				else
					appendStringInfoString(out, "?ustr");
				break;
			case SQLFW_BCONST:
				/* The lexer keeps the b/x prefix as the first character. */
				if (keep_this)
					append_quoted(out, "B", yylval.str + 1, '\'');
				else
					appendStringInfoString(out, "?bits");
				break;
			case SQLFW_XCONST:
				if (keep_this)
					append_quoted(out, "X", yylval.str + 1, '\'');
				else
					appendStringInfoString(out, "?hex");
				break;
			case SQLFW_FCONST:
				if (keep_this)
					appendStringInfoString(out, yylval.str);
				else
					appendStringInfoString(out, "?num");
				break;
			case SQLFW_ICONST:
				if (keep_this)
					appendStringInfo(out, "%d", yylval.ival);
				else
					appendStringInfoString(out, "?int");
				break;
			case SQLFW_PARAM:
				appendStringInfo(out, "$%d", yylval.ival);
				break;
			case SQLFW_OP:
				appendStringInfoString(out, yylval.str);
				break;
			case SQLFW_TYPECAST:
				appendStringInfoString(out, "::");
				break;
			case SQLFW_DOT_DOT:
				appendStringInfoString(out, "..");
				break;
			case SQLFW_COLON_EQUALS:
				appendStringInfoString(out, ":=");
				break;
			case SQLFW_EQUALS_GREATER:
				appendStringInfoString(out, "=>");
				break;
			case SQLFW_LESS_EQUALS:
				appendStringInfoString(out, "<=");
				break;
			case SQLFW_GREATER_EQUALS:
				appendStringInfoString(out, ">=");
				break;
			case SQLFW_NOT_EQUALS:
				/* The lexer returns this for both <> and !=. */
				appendStringInfoString(out, "<>");
				break;
			default:
				if (tok > 0 && tok < 256)
					appendStringInfoChar(out, (char) tok);
				else
					ereport(ERROR,
							(errcode(ERRCODE_INTERNAL_ERROR),
							 errmsg("sql_firewall: PostgreSQL lexer returned an unknown token %d", tok)));
				break;
		}
	}
	scanner_finish(scanner);
}

/* Rejections of the text itself under one standard_conforming_strings reading. */
static bool
is_lexical_rejection(int sqlerrcode)
{
	return sqlerrcode == ERRCODE_SYNTAX_ERROR ||
		sqlerrcode == ERRCODE_FEATURE_NOT_SUPPORTED ||
		ERRCODE_TO_CATEGORY(sqlerrcode) == ERRCODE_DATA_EXCEPTION;
}

/*
 * Canonical token text of `text` read with standard_conforming_strings set to
 * `standard_strings`, palloc'd in the caller's memory context.
 *
 * If the lexer rejects the text under this reading (a syntax, data, or
 * feature error), returns NULL and sets *lexical_error to the message,
 * palloc'd in the caller's context; that error is consumed. Any other error
 * (out of memory, cancel, token-layout mismatch) is re-thrown. Either way the
 * scan context is deleted and the message levels are restored first.
 *
 * The truncation NOTICE for a long identifier was already given when
 * PostgreSQL parsed the statement, so the re-scan runs with NOTICE output
 * suppressed.
 */
static char *scan(const char *text, bool standard_strings, bool keep_all, char **lexical_error);

char *
sqlfw_fingerprint_scan(const char *text, bool standard_strings, char **lexical_error)
{
	return scan(text, standard_strings, false, lexical_error);
}

/*
 * The same token text with every literal's value kept, for the keyword and
 * built-in injection checks (sql_tokens.rs): they must see SQL tokens, not
 * words inside strings or comments, and compare literal values.
 */
char *
sqlfw_policy_scan(const char *text, bool standard_strings, char **lexical_error)
{
	return scan(text, standard_strings, true, lexical_error);
}

static char *
scan(const char *text, bool standard_strings, bool keep_all, char **lexical_error)
{
	MemoryContext caller = CurrentMemoryContext;
	MemoryContext scan_context;
	int			save_client = client_min_messages;
	int			save_log = log_min_messages;
	uint32		save_holdoff = InterruptHoldoffCount;
	uint32		save_cancel_holdoff = QueryCancelHoldoffCount;
	char	   *volatile result = NULL;

	*lexical_error = NULL;
	scan_context = AllocSetContextCreate(caller, "sql_firewall fingerprint scan",
										 ALLOCSET_DEFAULT_SIZES);
	PG_TRY();
	{
		StringInfoData out;

		MemoryContextSwitchTo(scan_context);
		if (client_min_messages < WARNING)
			client_min_messages = WARNING;
		if (log_min_messages < WARNING && log_min_messages != LOG)
			log_min_messages = WARNING;
		if (!layout_checked)
			check_layout();
		initStringInfo(&out);
		render(text, standard_strings, keep_all, &out);
		MemoryContextSwitchTo(caller);
		result = pnstrdup(out.data, out.len);
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(caller);
		client_min_messages = save_client;
		log_min_messages = save_log;
		edata = CopyErrorData();
		if (edata->elevel != ERROR || !is_lexical_rejection(edata->sqlerrcode))
		{
			FreeErrorData(edata);
			MemoryContextDelete(scan_context);
			PG_RE_THROW();
		}

		/*
		 * The lexer holds nothing but memory in scan_context, so the error
		 * can be consumed without a subtransaction. errfinish() reset the
		 * interrupt holdoff counts before the longjmp; restore the caller's.
		 */
		FlushErrorState();
		InterruptHoldoffCount = save_holdoff;
		QueryCancelHoldoffCount = save_cancel_holdoff;
		*lexical_error = pstrdup(edata->message ? edata->message : "lexical error");
		FreeErrorData(edata);
		result = NULL;
	}
	PG_END_TRY();
	client_min_messages = save_client;
	log_min_messages = save_log;
	MemoryContextDelete(scan_context);
	return result;
}

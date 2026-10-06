#!/usr/bin/env bash
# Phase 5C: logical backup and restore of policy data.
#
# Contract: an ordinary pg_dump of a database, restored into a fresh database
# (plain format with psql -v ON_ERROR_STOP=1 --single-transaction, custom
# format with pg_restore --exit-on-error), reproduces the complete contents of
# sql_firewall_command_approvals, sql_firewall_query_fingerprints and
# sql_firewall_regex_rules, their id sequence positions, and the record of
# removed installation defaults. The installation default regex rule is not
# duplicated, keeps its edits, and does not return after it was deleted. The
# consumer checkpoint, audit logs, and shared-memory state are not carried.
#
# Evidence is exact catalog comparison (row_to_json of every row, sequence
# last_value/is_called) between the source, taken while its worker is paused,
# and the restored database before any traffic reaches it. Behavior is
# observed with ordinary roles: enforce-mode command and regex decisions, and
# for fingerprints the established permissive oracle (tests/99). Fingerprint
# rows survive logical restore for inspection, but their source-installation
# approvals must not authorize the new installation.
# Command and regex behavior is checked with fingerprint enforcement disabled
# for those roles; the permissive fingerprint oracle keeps it enabled.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.policy_backup
EV=policy_backup
BIN=$(dirname "$QA_PSQL")
DUMPS=$QA_RUN_DIR/dumps
APP=qa_bk_app OTHER=qa_bk_other FPR=qa_bk_fp LEARN=qa_bk_learn
DEFAULT_KEY=simple_sql_injection
TOKEN_ACTIVE=qa_bk_block_token TOKEN_INACTIVE=qa_bk_inactive_token TOKEN_EXEMPT=qa_bk_exempt_token
FP_A_SQL="SELECT v FROM qa_bk_t WHERE id = 1"
FP_B_SQL="SELECT id FROM qa_bk_t WHERE v = 'b'"
# Matches the installation default's pattern ("OR id = 2"); nothing else does.
# Not a tautology, which the built-in check refuses in every database.
DEFAULT_PROBE="SELECT count(*) FROM qa_bk_t WHERE id = 1 OR id = 2"
ALL_DBS=()
NONPASS=0
mkdir -p "$DUMPS"

ok() { qa_record PASS "$1" "$2"; qa_evidence $EV "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence $EV "- **FAIL** $1: $2"; NONPASS=1; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence $EV "- **INFRA** $1: $2"; NONPASS=1; }
fence() { qa_evidence $EV "$1" '```' "$2" '```'; }

conn=(-h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER")

qa_evidence $EV "# $ID" "" \
    "Sources are built through the management functions, the learn-mode worker, and superuser DML. Each source's worker is paused (sql_firewall_pause_approval_worker) before the policy snapshot and both dumps, and the snapshot is taken again afterwards. Destinations are new databases created with CREATE DATABASE only; the dump itself installs the extension. They are compared before any traffic. Database-level and role-in-database settings are not in a pg_dump without --create; they are re-applied to each destination after the comparison, as the README restore procedure says." \
    "" "- pg_dump: $("$BIN/pg_dump" --version)" "- pg_restore: $("$BIN/pg_restore" --version)" ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Database and role settings used by every source and, after restore, every
# destination. None of them is part of a pg_dump without --create.
settings_steps() { # DB
    printf '%s\n' \
        "ALTER DATABASE $1 SET sql_firewall.mode = 'enforce'" \
        "ALTER DATABASE $1 SET sql_firewall.enable_fingerprint_learning = 'on'" \
        "ALTER DATABASE $1 SET sql_firewall.enable_regex_scan = 'on'" \
        "ALTER DATABASE $1 SET sql_firewall.enable_activity_logging = 'on'" \
        "GRANT CONNECT ON DATABASE $1 TO $QA_CANARY_ROLE" \
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $1 SET sql_firewall.mode = 'enforce'" \
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $1 SET sql_firewall.enable_fingerprint_learning = 'off'" \
        "ALTER ROLE $APP IN DATABASE $1 SET sql_firewall.enable_fingerprint_learning = 'off'" \
        "ALTER ROLE $OTHER IN DATABASE $1 SET sql_firewall.enable_fingerprint_learning = 'off'" \
        "ALTER ROLE $FPR IN DATABASE $1 SET sql_firewall.mode = 'permissive'" \
        "ALTER ROLE $LEARN IN DATABASE $1 SET sql_firewall.mode = 'learn'"
}

apply_settings() { # DB
    local steps
    mapfile -t steps < <(settings_steps "$1")
    qa_admin postgres "${steps[@]}"
}

make_source() { # DB [VERSION]
    ALL_DBS+=("$1")
    qa_admin postgres "CREATE DATABASE $1" || return
    apply_settings "$1" || return
    qa_admin "$1" "CREATE EXTENSION sql_firewall${2:+ VERSION '$2'}" \
        "CREATE TABLE public.qa_bk_t (id integer PRIMARY KEY, v text)" \
        "INSERT INTO public.qa_bk_t VALUES (1, 'a'), (2, 'b')" \
        "GRANT SELECT, INSERT ON public.qa_bk_t TO $APP, $OTHER, $FPR, $LEARN" \
        "SELECT min(id) FROM public.sql_firewall_regex_rules" || return
    DEFAULT_ID=${QA_STEP_OUT[5]}
}

# SNAP: every policy row as JSON, the id sequence positions, and the removal
# records when that table exists. Timestamps print in the server's TimeZone,
# which is the same for every database of this cluster.
snapshot() { # DB
    local db=$1 removals
    qa_admin "$db" "SELECT (pg_catalog.to_regclass('public.sql_firewall_regex_default_removals') IS NOT NULL)::text" || return
    removals=${QA_STEP_OUT[1]}
    local steps=(
        "SELECT 'approvals' || E'\n' || coalesce(string_agg(row_to_json(t)::text, E'\n' ORDER BY t.id), '(none)') FROM public.sql_firewall_command_approvals t"
        "SELECT 'fingerprints' || E'\n' || coalesce(string_agg((to_jsonb(t) || jsonb_build_object('auto_approval_disabled', coalesce(to_jsonb(t)->'auto_approval_disabled', 'false'::jsonb)))::text, E'\n' ORDER BY t.id), '(none)') FROM public.sql_firewall_query_fingerprints t"
        "SELECT 'regex_rules' || E'\n' || coalesce(string_agg(row_to_json(t)::text, E'\n' ORDER BY t.id), '(none)') FROM public.sql_firewall_regex_rules t"
        "SELECT 'sequences approvals=' || (SELECT last_value || '/' || is_called FROM public.sql_firewall_command_approvals_id_seq) || ' fingerprints=' || (SELECT last_value || '/' || is_called FROM public.sql_firewall_query_fingerprints_id_seq) || ' regex_rules=' || (SELECT last_value || '/' || is_called FROM public.sql_firewall_regex_rules_id_seq)"
    )
    if [[ $removals == true ]]; then
        steps+=("SELECT 'removals' || E'\n' || coalesce(string_agg(row_to_json(t)::text, E'\n' ORDER BY t.installation_default), '(none)') FROM public.sql_firewall_regex_default_removals t")
    fi
    qa_admin "$db" "${steps[@]}" || return
    SNAP=$(printf '%s\n' "${QA_STEP_OUT[@]}")
    [[ $removals == true ]] || SNAP+=$'\nremovals (table absent)'
}

acl_snapshot() { # DB -> ACLS
    qa_admin "$1" \
        "SELECT string_agg(c.relname || ' ' || c.relkind::text || ' ' || coalesce(c.relacl::text, '(default)'), E'\n' ORDER BY c.relname) FROM pg_catalog.pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relname LIKE 'sql_firewall%'" \
        "SELECT string_agg(p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ') ' || coalesce(p.proacl::text, '(default)'), E'\n' ORDER BY 1) FROM pg_catalog.pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'sql_firewall%'" || return
    ACLS=$(printf '%s\n' "${QA_STEP_OUT[1]}" "${QA_STEP_OUT[2]}")
}

registration() { # DB -> REG (extconfig relations and their conditions)
    qa_admin "$1" "SELECT coalesce((SELECT string_agg(c.oid::regclass::text || '=' || quote_literal(e.extcondition[c.ord]), ',' ORDER BY c.oid::regclass::text) FROM pg_catalog.pg_extension e, unnest(e.extconfig) WITH ORDINALITY AS c(oid, ord) WHERE e.extname = 'sql_firewall'), '(none)')" || return
    REG=${QA_STEP_OUT[1]}
}
REG_EXPECT="sql_firewall_command_approvals='',sql_firewall_command_approvals_id_seq='',sql_firewall_policy_history='',sql_firewall_query_fingerprints='',sql_firewall_query_fingerprints_id_seq='',sql_firewall_regex_default_removals='',sql_firewall_regex_rules='',sql_firewall_regex_rules_id_seq=''"

# HIST: the decision history rows of one installation, as JSON in change order.
history_rows() { # DB DATABASE_OID EXTENSION_OID
    qa_admin "$1" "SELECT coalesce(string_agg(row_to_json(h)::text, E'\n' ORDER BY h.change_id), '(none)') FROM public.sql_firewall_policy_history h WHERE h.database_oid = $2 AND h.extension_oid = $3" || return
    HIST=${QA_STEP_OUT[1]}
}

checkpoint() { # DB -> CKPT "initialized ring_generation extension_oid next_position" and EXT_OID
    qa_admin "$1" \
        "SELECT initialized || ' ' || coalesce(ring_generation::text, '-') || ' ' || coalesce(extension_oid::text, '-') || ' ' || coalesce(next_position::text, '-') FROM public.sql_firewall_consumer_checkpoint" \
        "SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" || return
    CKPT=${QA_STEP_OUT[1]} EXT_OID=${QA_STEP_OUT[2]}
}

pause_source() { # DB
    local i
    for i in 1 2 3; do
        qa_admin "$1" "SELECT public.sql_firewall_pause_approval_worker()" || return
        [[ ${QA_STEP_OUT[1]} == 'approval worker paused epoch='* ]] && return 0
        sleep 1
    done
    QA_INFRA_REASON="pause of $1 not acknowledged: ${QA_STEP_OUT[1]}"
    return 1
}

dump_source() { # DB
    timeout 120 "$BIN/pg_dump" "${conn[@]}" -d "$1" -f "$DUMPS/$1.sql" 2>"$DUMPS/$1.sql.stderr" &&
        timeout 120 "$BIN/pg_dump" "${conn[@]}" -Fc -d "$1" -f "$DUMPS/$1.dump" 2>"$DUMPS/$1.dump.stderr" ||
        { QA_INFRA_REASON="pg_dump of $1 failed: $(cat "$DUMPS/$1".*.stderr | head -c 400)"; return 1; }
}

# Strict restore into a new database. RESTORE_DETAIL records the command,
# exit status, and anything written to stderr. Formats:
#   plain        psql --single-transaction
#   custom       serial pg_restore
#   parallel     pg_restore --jobs 4 (rules and removal records load concurrently)
#   rules_first  serial pg_restore -L with the rules' data moved before the
#                removal records' data (the opposite of pg_dump's name order)
restore() { # FORMAT SRC DST
    local fmt=$1 src=$2 dst=$3 rc=0 out=$DUMPS/$3.restore
    ALL_DBS+=("$dst")
    qa_admin postgres "CREATE DATABASE $dst" || return 2
    case $fmt in
    plain)
        RESTORE_CMD="psql -X -v ON_ERROR_STOP=1 --single-transaction -d $dst -f $src.sql"
        timeout 120 "$QA_PSQL" -X -q -v ON_ERROR_STOP=1 --single-transaction "${conn[@]}" -d "$dst" \
            -f "$DUMPS/$src.sql" >"$out.stdout" 2>"$out.stderr" || rc=$?
        ;;
    custom)
        RESTORE_CMD="pg_restore --exit-on-error -d $dst $src.dump"
        timeout 120 "$BIN/pg_restore" --exit-on-error "${conn[@]}" -d "$dst" \
            "$DUMPS/$src.dump" >"$out.stdout" 2>"$out.stderr" || rc=$?
        ;;
    parallel)
        RESTORE_CMD="pg_restore --exit-on-error --jobs 4 -d $dst $src.dump"
        timeout 120 "$BIN/pg_restore" --exit-on-error --jobs 4 "${conn[@]}" -d "$dst" \
            "$DUMPS/$src.dump" >"$out.stdout" 2>"$out.stderr" || rc=$?
        ;;
    rules_first)
        "$BIN/pg_restore" -l "$DUMPS/$src.dump" >"$out.toc" || return 2
        awk '/TABLE DATA public sql_firewall_regex_default_removals / { held = $0; next }
             { print } /TABLE DATA public sql_firewall_regex_rules / && held != "" { print held; held = "" }
             END { if (held != "") print held }' "$out.toc" >"$out.list"
        grep -A1 'TABLE DATA public sql_firewall_regex_rules ' "$out.list" | grep -q 'TABLE DATA public sql_firewall_regex_default_removals ' ||
            { QA_INFRA_REASON="could not place the removal records after the rules in $out.list"; return 2; }
        RESTORE_CMD="pg_restore --exit-on-error -L $src.rules_first.list -d $dst $src.dump"
        timeout 120 "$BIN/pg_restore" --exit-on-error -L "$out.list" "${conn[@]}" -d "$dst" \
            "$DUMPS/$src.dump" >"$out.stdout" 2>"$out.stderr" || rc=$?
        ;;
    esac
    RESTORE_DETAIL="$RESTORE_CMD: exit $rc; stderr: $(head -c 400 "$out.stderr" | tr '\n' ' ')"
    [[ $rc -eq 0 && ! -s $out.stderr ]]
}

dst_name() { # SRC FORMAT
    case $2 in plain) echo "${1}_p" ;; custom) echo "${1}_c" ;; parallel) echo "${1}_j" ;; rules_first) echo "${1}_r" ;; esac
}

compare() { # CHECK_ID SOURCE_SNAP DST
    if ! snapshot "$3"; then
        infra "$1" "snapshot of $3: $QA_INFRA_REASON"
        return 1
    fi
    if [[ $SNAP == "$2" ]]; then
        ok "$1" "every policy row, the sequence positions, and the removal records equal the source ($(grep -c '^{' <<<"$SNAP") rows)"
    else
        fence "#### $1 restored snapshot" "$SNAP"
        fence "#### $1 diff (source -> restored)" "$(diff <(printf '%s\n' "$2") <(printf '%s\n' "$SNAP"))"
        fail "$1" "restored policy differs from the source (diff in evidence)"
    fi
}

# OUTCOME: allow, or SQLSTATE:message.
probe() { # ROLE DB SQL
    if ! qa_sql_steps "$1" "$2" qa_bk_client "$3"; then
        OUTCOME="infra: $QA_INFRA_REASON"
        return 1
    fi
    if [[ ${QA_STEP_ERR[1]} == false ]]; then OUTCOME=allow; else OUTCOME="${QA_STEP_STATE[1]}:${QA_STEP_MSG[1]:-}"; fi
}

# Permissive oracle for role FPR: prints approved|unapproved for SQL.
fp_seen() { # DB SQL -> FP_SEEN
    local before
    qa_admin "$1" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$FPR' AND action = 'ALLOWED (PERMISSIVE - FINGERPRINT)'" || return
    before=${QA_STEP_OUT[1]}
    probe "$FPR" "$1" "$2" || return
    [[ $OUTCOME == allow ]] || { QA_INFRA_REASON="permissive statement not allowed: $OUTCOME"; return 1; }
    qa_admin "$1" "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$FPR' AND action = 'ALLOWED (PERMISSIVE - FINGERPRINT)'" || return
    case $((${QA_STEP_OUT[1]} - before)) in
        0) FP_SEEN=approved ;;
        1) FP_SEEN=unapproved ;;
        *) QA_INFRA_REASON="unexpected activity rows: $before -> ${QA_STEP_OUT[1]}"; return 1 ;;
    esac
}

# Representative decisions for ordinary roles, one "label|role|outcome" line
# each. The full set also runs the permissive fingerprint oracle.
behavior() { # DB [full]
    local db=$1 entry label role sql
    local probes=(
        "approved_select|$APP|SELECT count(*) FROM qa_bk_t"
        "default_rule_probe|$APP|$DEFAULT_PROBE"
    )
    if [[ ${2:-} == full ]]; then
        probes+=(
            "pending_insert|$APP|INSERT INTO qa_bk_t VALUES (9, 'pending')"
            "no_rule_delete|$APP|DELETE FROM qa_bk_t WHERE id = 9"
            "active_regex|$APP|SELECT '$TOKEN_ACTIVE'"
            "inactive_regex|$APP|SELECT '$TOKEN_INACTIVE'"
            "exempt_regex_exempt_role|$APP|SELECT '$TOKEN_EXEMPT'"
            "exempt_regex_other_role|$OTHER|SELECT '$TOKEN_EXEMPT'"
        )
    fi
    BEHAVIOR=""
    for entry in "${probes[@]}"; do
        IFS='|' read -r label role sql <<<"$entry"
        probe "$role" "$db" "$sql"
        BEHAVIOR+="$label|$role|$OUTCOME"$'\n'
    done
    if [[ ${2:-} == full ]]; then
        for label in a b; do
            [[ $label == a ]] && sql=$FP_A_SQL || sql=$FP_B_SQL
            if fp_seen "$db" "$sql"; then
                BEHAVIOR+="fingerprint_$label|$FPR|$FP_SEEN"$'\n'
            else
                BEHAVIOR+="fingerprint_$label|$FPR|infra: $QA_INFRA_REASON"$'\n'
            fi
        done
    fi
}

behavior_outcome() { # LABEL -> the recorded outcome
    awk -F'|' -v l="$1" '$1 == l { sub(/^[^|]*\|[^|]*\|/, ""); print }' <<<"$BEHAVIOR"
}

REGEX_MSG="42501:sql_firewall: Query blocked by security regex pattern."

# The id nextval will return, and the largest stored id.
next_sql() { # TABLE
    printf "SELECT (CASE WHEN is_called THEN last_value + 1 ELSE last_value END) || ' ' || coalesce((SELECT max(id) FROM public.%s), 0) FROM public.%s_id_seq" "$1" "$1"
}

# Checks every destination gets: strict restore, exact contents, and the
# default-rule decision the source made.
restore_and_compare() { # SCENARIO SRC SOURCE_SNAP SOURCE_PROBE [FORMAT...]
    local scen=$1 src=$2 snap=$3 src_probe=$4 fmt dst formats
    shift 4
    formats=("$@")
    ((${#formats[@]})) || formats=(plain custom)
    for fmt in "${formats[@]}"; do
        dst=$(dst_name "$src" "$fmt")
        if restore "$fmt" "$src" "$dst"; then
            ok "$ID.$scen.$fmt.restore" "$RESTORE_DETAIL"
        else
            [[ $? -eq 2 ]] && { infra "$ID.$scen.$fmt.restore" "$QA_INFRA_REASON"; continue; }
            fail "$ID.$scen.$fmt.restore" "$RESTORE_DETAIL"
        fi
        compare "$ID.$scen.$fmt.contents" "$snap" "$dst"
        if [[ -n $src_probe ]]; then
            apply_settings "$dst" || { infra "$ID.$scen.$fmt.default_rule" "settings: $QA_INFRA_REASON"; continue; }
            probe "$APP" "$dst" "$DEFAULT_PROBE"
            if [[ $OUTCOME == "$src_probe" ]]; then
                ok "$ID.$scen.$fmt.default_rule" "the default-rule probe gave the source's decision: $OUTCOME"
            elif [[ $OUTCOME == infra:* ]]; then
                infra "$ID.$scen.$fmt.default_rule" "$OUTCOME"
            else
                fail "$ID.$scen.$fmt.default_rule" "source: $src_probe; restored: $OUTCOME"
            fi
        fi
    done
}

# Source checkpoint, paused worker, snapshot, both dumps, snapshot again.
freeze_and_dump() { # SCENARIO DB -> SOURCE_SNAP
    local scen=$1 db=$2
    qa_wait_worker_live "$db" 90 || { infra "$ID.$scen.source" "worker: $QA_INFRA_REASON"; return 1; }
    pause_source "$db" || { infra "$ID.$scen.source" "$QA_INFRA_REASON"; return 1; }
    snapshot "$db" || { infra "$ID.$scen.source" "snapshot: $QA_INFRA_REASON"; return 1; }
    SOURCE_SNAP=$SNAP
    fence "### $scen source snapshot ($db)" "$SOURCE_SNAP"
    dump_source "$db" || { infra "$ID.$scen.source" "$QA_INFRA_REASON"; return 1; }
    snapshot "$db" || { infra "$ID.$scen.source" "snapshot: $QA_INFRA_REASON"; return 1; }
    [[ $SNAP == "$SOURCE_SNAP" ]] || { infra "$ID.$scen.source" "source policy changed while dumping"; return 1; }
}

qa_admin postgres \
    "CREATE ROLE $APP LOGIN NOSUPERUSER" "CREATE ROLE $OTHER LOGIN NOSUPERUSER" \
    "CREATE ROLE $FPR LOGIN NOSUPERUSER" "CREATE ROLE $LEARN LOGIN NOSUPERUSER" ||
    { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }

# ---------------------------------------------------------------------------
# 1. Main fixture: a fresh installation with a modified installation default.
# ---------------------------------------------------------------------------
SRC=qa_bk_main
qa_evidence $EV "" "## main: fresh installation, installation default deactivated and edited"
make_source $SRC || { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live $SRC 90 || { infra "$ID.main.source" "worker: $QA_INFRA_REASON"; exit 0; }
LOG0=$(qa_server_log_offset)

# Product-derived fingerprint identities: a learn-mode helper runs two
# statements and the worker persists their rows (and a SELECT approval).
for s in "$FP_A_SQL" "$FP_B_SQL"; do
    probe "$LEARN" $SRC "$s"
    [[ $OUTCOME == allow ]] || { infra "$ID.main.source" "learn helper: $OUTCOME"; exit 0; }
done
qa_poll $SRC "SELECT (SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$LEARN') || ',' || (SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '$LEARN' AND is_approved)" \
    "2,1" 30 || { infra "$ID.main.source" "learned rows: $QA_INFRA_REASON"; exit 0; }
qa_admin $SRC \
    "SELECT fingerprint || ' ' || normalized_query FROM public.sql_firewall_query_fingerprints WHERE role_name = '$LEARN' AND sample_query = $(qa_sql_quote "$FP_A_SQL")" \
    "SELECT fingerprint || ' ' || normalized_query FROM public.sql_firewall_query_fingerprints WHERE role_name = '$LEARN' AND sample_query = $(qa_sql_quote "$FP_B_SQL")" ||
    { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
FP_A=${QA_STEP_OUT[1]%% *} NORM_A=${QA_STEP_OUT[1]#* } FP_B=${QA_STEP_OUT[2]%% *} NORM_B=${QA_STEP_OUT[2]#* }
[[ $FP_A =~ ^[0-9a-f]{64}$ && $FP_B =~ ^[0-9a-f]{64}$ && $NORM_A == v3:* ]] ||
    { infra "$ID.main.source" "fingerprint identities not established: '${QA_STEP_OUT[1]}' '${QA_STEP_OUT[2]}'"; exit 0; }
qa_evidence $EV "- learned identities: A=$FP_A \`$NORM_A\`; B=$FP_B \`$NORM_B\`"

if ! qa_admin $SRC \
    "SELECT public.sql_firewall_approve_command('$APP', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$OTHER', 'SELECT')" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved, created_at, updated_at) VALUES ('$APP', 'INSERT', false, '2024-01-02 03:04:05.123456+00', '2024-02-03 04:05:06.654321+00')" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$FPR', 'SELECT', false)" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved, first_seen_at, last_seen_at) VALUES ('$FP_A', $(qa_sql_quote "$NORM_A"), '$FPR', 'SELECT', 'seeded approved', 37, true, '2024-03-01 00:00:01+00', '2024-04-01 00:00:02+00')" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('$FP_B', $(qa_sql_quote "$NORM_B"), '$FPR', 'SELECT', 'seeded unapproved', 12, false)" \
    "SELECT public.sql_firewall_block_fingerprint('$FP_B', '$FPR', 'SELECT')" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('8aeaf212cd039fd1', 'SELECT V FROM QA_T WHERE ID = ?;', '$FPR', 'SELECT', 'SELECT v FROM qa_t WHERE id = 1;', 99, true)" \
    "UPDATE public.sql_firewall_query_fingerprints SET hit_count = hit_count + 4 WHERE role_name = '$LEARN'" \
    "SELECT public.sql_firewall_toggle_regex_rule($DEFAULT_ID, false)" \
    "UPDATE public.sql_firewall_regex_rules SET description = 'qa edited default', allowed_roles = ARRAY['$OTHER'] WHERE id = $DEFAULT_ID" \
    "SELECT public.sql_firewall_add_regex_rule('$TOKEN_ACTIVE', 'qa custom active')" \
    "SELECT public.sql_firewall_add_regex_rule('$TOKEN_INACTIVE', 'qa custom inactive')" \
    "SELECT public.sql_firewall_toggle_regex_rule(id, false) FROM public.sql_firewall_regex_rules WHERE pattern = '$TOKEN_INACTIVE'" \
    "SELECT public.sql_firewall_add_regex_rule('$TOKEN_EXEMPT', 'qa custom exempt')" \
    "UPDATE public.sql_firewall_regex_rules SET allowed_roles = ARRAY['$APP'] WHERE pattern = '$TOKEN_EXEMPT'" \
    "SELECT public.sql_firewall_add_regex_rule('qa_bk_deleted_token', 'qa custom deleted')" \
    "SELECT public.sql_firewall_delete_regex_rule(id) FROM public.sql_firewall_regex_rules WHERE pattern = 'qa_bk_deleted_token'"; then
    infra "$ID.main.source" "fixture: $QA_INFRA_REASON"
    exit 0
fi

behavior $SRC full
SOURCE_BEHAVIOR=$BEHAVIOR
EXPECTED_RESTORED_BEHAVIOR=${SOURCE_BEHAVIOR/fingerprint_a|$FPR|approved/fingerprint_a|$FPR|unapproved}
fence "### main source decisions" "$SOURCE_BEHAVIOR"
expect_source() { # LABEL EXPECTED
    local got
    got=$(behavior_outcome "$1")
    [[ $got == "$2" ]] || { infra "$ID.main.source" "source decision $1 is '$got', expected '$2'; the fixture does not exercise it"; exit 0; }
}
expect_source approved_select allow
expect_source default_rule_probe allow
expect_source pending_insert "42501:sql_firewall: BLOCKED - Approval for command 'INSERT' is pending for role '$APP'"
expect_source no_rule_delete "42501:sql_firewall: No rule found for command 'DELETE' for role '$APP'"
expect_source active_regex "$REGEX_MSG"
expect_source inactive_regex allow
expect_source exempt_regex_exempt_role allow
expect_source exempt_regex_other_role "$REGEX_MSG"
expect_source fingerprint_a approved
expect_source fingerprint_b unapproved

checkpoint $SRC || { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
SRC_CKPT=$CKPT SRC_EXT=$EXT_OID
[[ $SRC_CKPT == 'true '* ]] || { infra "$ID.main.source" "source checkpoint not initialized: $SRC_CKPT"; exit 0; }
acl_snapshot $SRC || { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
SRC_ACLS=$ACLS
registration $SRC || { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
if [[ $REG == "$REG_EXPECT" ]]; then
    ok "$ID.fresh.registration" "CREATE EXTENSION registers the three policy tables, their id sequences, and the removal records for pg_dump, all rows ($REG)"
else
    fail "$ID.fresh.registration" "extconfig is $REG"
fi
freeze_and_dump main $SRC || exit 0
MAIN_SNAP=$SOURCE_SNAP
qa_admin $SRC "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()" || { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
SRC_DBOID=${QA_STEP_OUT[1]}
history_rows $SRC "$SRC_DBOID" "$SRC_EXT" || { infra "$ID.main.source" "history: $QA_INFRA_REASON"; exit 0; }
SRC_HIST=$HIST
qa_admin $SRC "SELECT count(*) FILTER (WHERE source = 'learn') || ',' || count(*) FILTER (WHERE source = 'administrator') FROM public.sql_firewall_policy_history" \
    "SELECT (SELECT count(*) FROM public.sql_firewall_command_approvals) + (SELECT count(*) FROM public.sql_firewall_query_fingerprints)" ||
    { infra "$ID.main.source" "$QA_INFRA_REASON"; exit 0; }
SRC_HIST_COUNTS=${QA_STEP_OUT[1]} POLICY_ROWS=${QA_STEP_OUT[2]}
fence "### main source decision history (installation $SRC_DBOID/$SRC_EXT)" "$SRC_HIST"
[[ $SRC_HIST_COUNTS =~ ^[1-9][0-9]*,[1-9][0-9]*$ ]] ||
    { infra "$ID.main.source" "source history lacks learn or administrator rows ($SRC_HIST_COUNTS); the fixture does not exercise it"; exit 0; }
qa_evidence $EV "- source checkpoint: $SRC_CKPT (extension oid $SRC_EXT)"

# What the dumps carry.
plain_has() { grep -c "^COPY public.$1 " "$DUMPS/$SRC.sql"; }
list=$("$BIN/pg_restore" -l "$DUMPS/$SRC.dump" 2>&1)
fence "### main custom-format TOC (data entries)" "$(grep -E 'TABLE DATA|SEQUENCE SET' <<<"$list")"
missing="" extra=""
for t in sql_firewall_command_approvals sql_firewall_query_fingerprints sql_firewall_regex_rules sql_firewall_regex_default_removals sql_firewall_policy_history; do
    [[ $(plain_has $t) == 1 ]] || missing+=" plain:$t"
    grep -qE "TABLE DATA public $t " <<<"$list" || missing+=" custom:$t"
done
for s in sql_firewall_command_approvals_id_seq sql_firewall_query_fingerprints_id_seq sql_firewall_regex_rules_id_seq; do
    grep -q "pg_catalog.setval('public.$s'" "$DUMPS/$SRC.sql" || missing+=" plain:$s"
    grep -qE "SEQUENCE SET public $s " <<<"$list" || missing+=" custom:$s"
done
for t in sql_firewall_consumer_checkpoint sql_firewall_activity_log sql_firewall_blocked_queries sql_firewall_fingerprint_hits sql_firewall_policy_epoch; do
    [[ $(plain_has $t) == 0 ]] || extra+=" plain:$t"
    grep -qE "TABLE DATA public $t " <<<"$list" && extra+=" custom:$t"
done
grep -qE "SEQUENCE SET public sql_firewall_(activity_log|blocked_queries)" <<<"$list" && extra+=" custom:audit sequence"
grep -qE "SEQUENCE SET public sql_firewall_policy_history_change_id_seq" <<<"$list" && extra+=" custom:history sequence"
order_rem=$(grep -n '^COPY public.sql_firewall_regex_default_removals ' "$DUMPS/$SRC.sql" | cut -d: -f1)
order_rules=$(grep -n '^COPY public.sql_firewall_regex_rules ' "$DUMPS/$SRC.sql" | cut -d: -f1)
if [[ -z $missing && -z $extra && -n $order_rem && -n $order_rules && $order_rem -lt $order_rules ]]; then
    ok "$ID.dump_contents" "both dumps carry the four policy tables, three id sequences, and the decision history, removal records before rules; no checkpoint, policy epoch, activity, blocked-query, or fingerprint_hits data, and no history sequence"
else
    fail "$ID.dump_contents" "missing:${missing:- none} unexpected:${extra:- none} removal line ${order_rem:-none} rules line ${order_rules:-none}"
fi

for fmt in plain custom; do
    DST=$(dst_name $SRC $fmt)
    S="$ID.main.$fmt"
    qa_evidence $EV "" "### main -> $DST ($fmt)"
    if restore "$fmt" $SRC $DST; then
        ok "$S.restore" "$RESTORE_DETAIL"
    else
        [[ $? -eq 2 ]] && { infra "$S.restore" "$QA_INFRA_REASON"; continue; }
        fail "$S.restore" "$RESTORE_DETAIL"
    fi
    compare "$S.contents" "$MAIN_SNAP" $DST

    # Decision history: the source installation's rows exactly; the restore's
    # own policy loads are recorded under the destination installation.
    if history_rows $DST "$SRC_DBOID" "$SRC_EXT" &&
        qa_admin $DST "SELECT count(*) FILTER (WHERE source = 'administrator' AND operation = 'INSERT') || ',' || count(*) FROM public.sql_firewall_policy_history WHERE database_oid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) AND extension_oid = (SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') AND system_identifier = (SELECT system_identifier FROM pg_catalog.pg_control_system())"; then
        if [[ $HIST != "$SRC_HIST" ]]; then
            fence "#### $S.history diff (source -> restored)" "$(diff <(printf '%s\n' "$SRC_HIST") <(printf '%s\n' "$HIST"))"
            fail "$S.history" "the source installation's decision history differs after restore (diff in evidence)"
        elif [[ ${QA_STEP_OUT[1]} != "$POLICY_ROWS,$POLICY_ROWS" ]]; then
            fail "$S.history" "destination installation history is ${QA_STEP_OUT[1]} (administrator INSERT rows, all rows); expected one INSERT per restored policy row ($POLICY_ROWS)"
        else
            ok "$S.history" "the source installation's $(grep -c '^{' <<<"$HIST") decision history rows (learn,administrator $SRC_HIST_COUNTS) are unchanged; the restore's $POLICY_ROWS policy row loads are recorded as administrator INSERTs of the destination installation"
        fi
    else
        infra "$S.history" "$QA_INFRA_REASON"
    fi

    # Checkpoint right after the restore, before any traffic.
    if checkpoint $DST; then
        qa_evidence $EV "- checkpoint after restore: $CKPT (destination extension oid $EXT_OID)"
        read -r c_init c_gen c_ext c_pos <<<"$CKPT"
        if [[ $EXT_OID == "$SRC_EXT" ]]; then
            infra "$S.checkpoint_not_restored" "source and destination extension oids are equal ($EXT_OID); the check cannot tell them apart"
        elif [[ $CKPT == "$SRC_CKPT" || $c_ext == "$SRC_EXT" ]]; then
            fail "$S.checkpoint_not_restored" "destination checkpoint carries the source's installation: $CKPT (source $SRC_CKPT)"
        elif [[ $c_init == false && $c_gen == - && $c_ext == - && $c_pos == - ]]; then
            ok "$S.checkpoint_not_restored" "uninitialized after restore (source was '$SRC_CKPT'); the destination worker had not attached yet"
        elif [[ $c_init == true && $c_ext == "$EXT_OID" ]]; then
            ok "$S.checkpoint_not_restored" "already initialized by the destination's own worker for its installation $EXT_OID ($CKPT); source was '$SRC_CKPT'"
        else
            fail "$S.checkpoint_not_restored" "unexpected checkpoint $CKPT (destination extension $EXT_OID, source '$SRC_CKPT')"
        fi
    else
        infra "$S.checkpoint_not_restored" "$QA_INFRA_REASON"
    fi
    DST_EXT=$EXT_OID

    # Privileges: identical ACLs, and an ordinary role cannot manage policy.
    acl_snapshot $DST || { infra "$S.privileges" "$QA_INFRA_REASON"; continue; }
    DST_ACLS=$ACLS
    qa_admin $DST \
        "SELECT string_agg(t || ':' || has_table_privilege('$APP', t, 'INSERT')::text || has_table_privilege('$APP', t, 'UPDATE')::text || has_table_privilege('$APP', t, 'DELETE')::text || has_table_privilege('$APP', t, 'TRUNCATE')::text, ',' ORDER BY t) FROM unnest(ARRAY['public.sql_firewall_command_approvals', 'public.sql_firewall_query_fingerprints', 'public.sql_firewall_regex_rules', 'public.sql_firewall_regex_default_removals', 'public.sql_firewall_consumer_checkpoint']) AS t WHERE pg_catalog.to_regclass(t) IS NOT NULL" \
        "SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'sql_firewall%' AND p.proname <> 'sql_firewall_internal_log_activity' AND p.proname <> 'sql_firewall_status' AND has_function_privilege('$APP', p.oid, 'EXECUTE')" ||
        { infra "$S.privileges" "$QA_INFRA_REASON"; continue; }
    TABLE_PRIVS=${QA_STEP_OUT[1]} EXEC_COUNT=${QA_STEP_OUT[2]}
    apply_settings $DST || { infra "$S.behavior" "settings: $QA_INFRA_REASON"; continue; }
    probe "$APP" $DST "SELECT public.sql_firewall_approve_command('$APP', 'DELETE')"
    DIRECT_CALL=$OUTCOME
    probe "$APP" $DST "SELECT public.sql_firewall_add_regex_rule('qa_bk_self_rule')"
    DIRECT_CALL+=" / $OUTCOME"
    qa_evidence $EV "- ordinary-role table privileges (INSERT UPDATE DELETE TRUNCATE): $TABLE_PRIVS" \
        "- other sql_firewall functions executable by $APP: $EXEC_COUNT" "- direct management calls by $APP: $DIRECT_CALL"
    if [[ $DST_ACLS != "$SRC_ACLS" ]]; then
        fence "#### $S.privileges destination ACLs" "$DST_ACLS"
        fail "$S.privileges" "relation or function ACLs differ from the source"
    elif [[ $TABLE_PRIVS == *true* || $EXEC_COUNT != 0 ||
        $DIRECT_CALL != "42501:permission denied for function sql_firewall_approve_command / 42501:permission denied for function sql_firewall_add_regex_rule" ]]; then
        fail "$S.privileges" "tables=$TABLE_PRIVS functions=$EXEC_COUNT calls=$DIRECT_CALL"
    else
        ok "$S.privileges" "relation and function ACLs equal the source; $APP has no write privilege on policy, removal, or checkpoint tables and no management function; direct calls were denied natively (42501)"
    fi

    # Command and regex decisions survive. The source installation's
    # fingerprint identities are deliberately inert after logical restore.
    behavior $DST full
    if [[ $BEHAVIOR == "$EXPECTED_RESTORED_BEHAVIOR" ]]; then
        ok "$S.behavior" "command and regex decisions match the source; source fingerprint approvals require review in the new installation"
    else
        fence "#### $S.behavior restored decisions" "$BEHAVIOR"
        fail "$S.behavior" "decisions differ from the source (evidence)"
    fi
    if [[ $(behavior_outcome fingerprint_a) == unapproved && $(behavior_outcome fingerprint_b) == unapproved ]]; then
        ok "$S.fingerprint_observation" "permissive oracle: both restored source identities are inert; each statement produced an unapproved activity row"
    else
        fail "$S.fingerprint_observation" "A=$(behavior_outcome fingerprint_a) B=$(behavior_outcome fingerprint_b)"
    fi

    # New policy rows through the management functions: ids continue after
    # the restored sequence positions.
    qa_admin $DST "$(next_sql sql_firewall_command_approvals)" "$(next_sql sql_firewall_query_fingerprints)" \
        "$(next_sql sql_firewall_regex_rules)" ||
        { infra "$S.management_inserts" "$QA_INFRA_REASON"; continue; }
    read -r A_NEXT A_MAX <<<"${QA_STEP_OUT[1]}"
    read -r F_NEXT F_MAX <<<"${QA_STEP_OUT[2]}"
    read -r R_NEXT R_MAX <<<"${QA_STEP_OUT[3]}"
    qa_evidence $EV "- next ids after restore: approvals $A_NEXT (max restored $A_MAX), fingerprints $F_NEXT (max $F_MAX), regex_rules $R_NEXT (max $R_MAX)"
    if qa_sql_steps "$QA_SUPERUSER" $DST qa_admin \
        "SELECT public.sql_firewall_approve_command('$OTHER', 'UPDATE')" \
        "SELECT id FROM public.sql_firewall_command_approvals WHERE role_name = '$OTHER' AND command_type = 'UPDATE'" \
        "SELECT public.sql_firewall_add_regex_rule('qa_bk_after_restore', 'added after restore')"; then
        MGMT="approve_command: ${QA_STEP_STATE[1]} id=${QA_STEP_OUT[2]} (next was $A_NEXT, max restored $A_MAX); add_regex_rule: ${QA_STEP_STATE[3]} id=${QA_STEP_OUT[3]} (next was $R_NEXT, max restored $R_MAX)"
        if [[ ${QA_STEP_ERR[1]} == false && ${QA_STEP_ERR[3]} == false &&
            ${QA_STEP_OUT[2]} == "$A_NEXT" && ${QA_STEP_OUT[3]} == "$R_NEXT" ]] &&
            ((A_NEXT > A_MAX && R_NEXT > R_MAX && F_NEXT > F_MAX)); then
            ok "$S.management_inserts" "$MGMT"
        else
            fail "$S.management_inserts" "$MGMT ${QA_STEP_MSG[1]:-} ${QA_STEP_MSG[3]:-}"
        fi
    else
        infra "$S.management_inserts" "$QA_INFRA_REASON"
    fi

    # The destination worker processes new destination events, and its
    # inserts do not collide with restored ids.
    if ! qa_wait_worker_live $DST 90; then
        infra "$S.worker_event" "$QA_INFRA_REASON"
        continue
    fi
    ok "$S.worker_event" "a canary blocked by the restored installation was delivered by the destination's worker (after $QA_READY_ATTEMPTS attempt(s))"
    LOGW=$(qa_server_log_offset)
    NEW_SELECT="SELECT v FROM qa_bk_t WHERE id = 2 AND v = 'after restore'"
    NEW_INSERT="INSERT INTO qa_bk_t VALUES (3, 'after restore')"
    NEW_SAMPLES="$(qa_sql_quote "$NEW_SELECT"), $(qa_sql_quote "$NEW_INSERT")"
    probe "$LEARN" $DST "$NEW_SELECT"
    W1=$OUTCOME
    probe "$LEARN" $DST "$NEW_INSERT"
    W1+=" / $OUTCOME"
    if [[ $W1 != "allow / allow" ]]; then
        infra "$S.worker_inserts" "learn helper: $W1"
    elif qa_poll $DST "SELECT (SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$LEARN' AND sample_query IN ($NEW_SAMPLES)) || ',' || (SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '$LEARN' AND command_type = 'INSERT' AND is_approved)" "2,1" 30; then
        qa_admin $DST \
            "SELECT string_agg(id::text, ',' ORDER BY id) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$LEARN' AND sample_query IN ($NEW_SAMPLES)" \
            "SELECT id FROM public.sql_firewall_command_approvals WHERE role_name = '$LEARN' AND command_type = 'INSERT'" ||
            { infra "$S.worker_inserts" "$QA_INFRA_REASON"; continue; }
        NEW_FP=${QA_STEP_OUT[1]} NEW_AP=${QA_STEP_OUT[2]}
        bad=0
        for i in ${NEW_FP//,/ }; do ((i >= F_NEXT)) || bad=1; done
        ((NEW_AP > A_NEXT)) || bad=1
        if ((bad == 0)); then
            ok "$S.worker_inserts" "the learn-mode worker inserted fingerprint ids $NEW_FP (next was $F_NEXT, max restored $F_MAX) and approval id $NEW_AP (after the management insert at $A_NEXT)"
        else
            fail "$S.worker_inserts" "new ids overlap the restored range: fingerprints $NEW_FP (next $F_NEXT) approval $NEW_AP (next $A_NEXT)"
        fi
    else
        dup=$(tail -c +"$((LOGW + 1))" "$QA_SERVER_LOG" | grep -m3 'duplicate key value violates unique constraint')
        if [[ -n $dup ]]; then
            fail "$S.worker_inserts" "worker insert collided: $dup"
        else
            infra "$S.worker_inserts" "$QA_INFRA_REASON"
        fi
    fi

    # After its own worker processed events, the checkpoint names this
    # installation.
    if checkpoint $DST; then
        read -r c_init c_gen c_ext c_pos <<<"$CKPT"
        if [[ $c_init == true && $c_ext == "$DST_EXT" && $c_ext != "$SRC_EXT" ]]; then
            ok "$S.checkpoint_own_worker" "initialized by the destination worker: $CKPT (source was '$SRC_CKPT')"
        else
            fail "$S.checkpoint_own_worker" "checkpoint $CKPT; destination extension $DST_EXT; source '$SRC_CKPT'"
        fi
    else
        infra "$S.checkpoint_own_worker" "$QA_INFRA_REASON"
    fi

    # A restored approval is historical only. Discover this installation's
    # identity under enforce, then explicitly approve that new identity.
    if ! qa_admin postgres "ALTER ROLE $FPR IN DATABASE $DST SET sql_firewall.mode = 'enforce'" ||
       ! qa_admin $DST "UPDATE public.sql_firewall_command_approvals SET is_approved = true WHERE role_name = '$FPR' AND command_type = 'SELECT'"; then
        infra "$S.fingerprint_reapproval" "$QA_INFRA_REASON"
    else
        probe "$FPR" "$DST" "$FP_A_SQL"
        FIRST=$OUTCOME
        if [[ $FIRST != 42501:* ]]; then
            fail "$S.fingerprint_reapproval" "source approval allowed before reapproval: $FIRST"
        elif ! qa_poll "$DST" "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$FPR' AND command_type = 'SELECT' AND sample_query = $(qa_sql_quote "$FP_A_SQL") AND fingerprint <> '$FP_A'" 1 30; then
            infra "$S.fingerprint_reapproval" "new fingerprint was not persisted: $QA_INFRA_REASON"
        elif ! qa_admin "$DST" "SELECT fingerprint FROM public.sql_firewall_query_fingerprints WHERE role_name = '$FPR' AND command_type = 'SELECT' AND sample_query = $(qa_sql_quote "$FP_A_SQL") AND fingerprint <> '$FP_A'"; then
            infra "$S.fingerprint_reapproval" "$QA_INFRA_REASON"
        else
            NEW_ID=${QA_STEP_OUT[1]}
            if ! qa_admin "$DST" "SELECT public.sql_firewall_approve_fingerprint('$NEW_ID', '$FPR', 'SELECT')"; then
                infra "$S.fingerprint_reapproval" "$QA_INFRA_REASON"
            else
                probe "$FPR" "$DST" "$FP_A_SQL"
                if [[ $OUTCOME == allow ]]; then
                    ok "$S.fingerprint_reapproval" "source identity $FP_A was denied; explicit approval of destination identity $NEW_ID allowed the query"
                else
                    fail "$S.fingerprint_reapproval" "new identity $NEW_ID approved, but query returned $OUTCOME"
                fi
            fi
        fi
    fi
done
qa_admin $SRC "SELECT public.sql_firewall_resume_approval_worker()" >/dev/null || true
PROBLEMS=$(qa_server_problems_since "$LOG0")
qa_evidence $EV "- logged server problems during main: ${PROBLEMS:-none}"

# ---------------------------------------------------------------------------
# 2. Installation default unchanged, deleted, and deleted then re-added.
# ---------------------------------------------------------------------------
# The installation default's pattern, as a SQL literal.
P0_SQL="'(or|--|#)\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\s*=\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)'"

# SCEN_FORMATS: restore formats for the next scenario (default plain custom).
# SCEN_AFTER_DUMP: optional check run after the dumps, before any restore.
default_scenario() { # SCENARIO DB FIXTURE_STEP...
    local scen=$1 db=$2
    shift 2
    qa_evidence $EV "" "## $scen"
    make_source "$db" || { infra "$ID.$scen.source" "$QA_INFRA_REASON"; return; }
    local steps=("SELECT public.sql_firewall_approve_command('$APP', 'SELECT')"
        "SELECT public.sql_firewall_add_regex_rule('qa_bk_${scen}_token', 'qa $scen custom')")
    for s in "$@"; do steps+=("${s//@DEFAULT_ID@/$DEFAULT_ID}"); done
    qa_admin "$db" "${steps[@]}" || { infra "$ID.$scen.source" "fixture: $QA_INFRA_REASON"; return; }
    probe "$APP" "$db" "$DEFAULT_PROBE"
    local src_probe=$OUTCOME
    qa_evidence $EV "- source default-rule probe: $src_probe"
    [[ $src_probe == allow || $src_probe == "$REGEX_MSG" ]] || { infra "$ID.$scen.source" "probe: $src_probe"; return; }
    freeze_and_dump "$scen" "$db" || return
    if [[ -n ${SCEN_AFTER_DUMP:-} ]]; then
        "$SCEN_AFTER_DUMP" "$scen" "$db" || return
    fi
    # shellcheck disable=SC2086
    restore_and_compare "$scen" "$db" "$SOURCE_SNAP" "$src_probe" ${SCEN_FORMATS:-plain custom}
}

# The ordinary rule with the default's original pattern must come before
# the keyed default in the dumped rows; otherwise the case is not exercised.
ordinary_row_first() { # SCENARIO DB
    local lines ordinary keyed
    lines=$(sed -n '/^COPY public.sql_firewall_regex_rules /,/^\\\.$/p' "$DUMPS/$2.sql")
    ordinary=$(grep -n $'\t(or|--|#)' <<<"$lines" | grep -v $'\tsimple_sql_injection$' | head -1 | cut -d: -f1)
    keyed=$(grep -n $'\tsimple_sql_injection$' <<<"$lines" | head -1 | cut -d: -f1)
    fence "### $1 dumped rule rows (plain)" "$lines"
    if [[ -n $ordinary && -n $keyed && $ordinary -lt $keyed ]]; then
        qa_evidence $EV "- precondition: the ordinary row with the original pattern is dumped at line $ordinary, the keyed default at line $keyed"
        return 0
    fi
    infra "$ID.$1.source" "dump order not established (ordinary line ${ordinary:-none}, keyed line ${keyed:-none})"
    return 1
}

# Ordinary administration on a live installation: new rules, including a
# direct INSERT that names its columns, never displace the installation
# default, and the default's pattern still cannot be added a second time.
admin_inserts() { # CHECK_ID DB
    local id=$1 db=$2 before after
    local default_row="SELECT coalesce((SELECT row_to_json(t)::text FROM public.sql_firewall_regex_rules t WHERE installation_default = 'simple_sql_injection'), 'none') || ' removals=' || (SELECT count(*) FROM public.sql_firewall_regex_default_removals)"
    qa_admin "$db" "$default_row" || { infra "$id" "$QA_INFRA_REASON"; return; }
    before=${QA_STEP_OUT[1]}
    [[ $before == '{'* ]] || { infra "$id" "no installation default in $db: $before"; return; }
    if ! qa_sql_steps "$QA_SUPERUSER" "$db" qa_admin \
        "SELECT public.sql_firewall_add_regex_rule('qa_bk_admin_a', 'admin via function')" \
        "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ('qa_bk_admin_b', 'admin direct insert')" \
        "INSERT INTO public.sql_firewall_regex_rules (pattern, description, is_active, allowed_roles) VALUES ('qa_bk_admin_c', 'admin direct insert', false, ARRAY['$OTHER'])" \
        "SELECT public.sql_firewall_add_regex_rule($P0_SQL, 'duplicate of the default')" \
        "INSERT INTO public.sql_firewall_regex_rules (pattern, description) VALUES ($P0_SQL, 'duplicate of the default')" \
        "$default_row" \
        "SELECT string_agg(pattern || '=' || coalesce(installation_default, 'NULL'), ',' ORDER BY pattern) FROM public.sql_firewall_regex_rules WHERE pattern LIKE 'qa_bk_admin_%'"; then
        infra "$id" "$QA_INFRA_REASON"
        return
    fi
    after=${QA_STEP_OUT[6]}
    local detail="new rules ${QA_STEP_ERR[1]}/${QA_STEP_ERR[2]}/${QA_STEP_ERR[3]} (error?); duplicate pattern: ${QA_STEP_STATE[4]} ${QA_STEP_STATE[5]}; new rows: ${QA_STEP_OUT[7]}"
    qa_evidence $EV "- $id default before: $before" "- $id default after: $after" "- $id: $detail"
    if [[ ${QA_STEP_ERR[1]} == false && ${QA_STEP_ERR[2]} == false && ${QA_STEP_ERR[3]} == false &&
        ${QA_STEP_STATE[4]} == 23505 && ${QA_STEP_STATE[5]} == 23505 && $after == "$before" &&
        ${QA_STEP_OUT[7]} == 'qa_bk_admin_a=NULL,qa_bk_admin_b=NULL,qa_bk_admin_c=NULL' ]]; then
        ok "$id" "three administrator rules were added as ordinary rules, the default's pattern was still refused (23505) through the function and a direct INSERT, and the default row and removal records are unchanged"
    else
        fail "$id" "$detail"
    fi
}

qa_evidence $EV "" "## administration on a fresh installation"
if make_source qa_bk_admin; then
    admin_inserts "$ID.fresh.admin_inserts" qa_bk_admin
else
    infra "$ID.fresh.admin_inserts" "$QA_INFRA_REASON"
fi
default_scenario unchanged qa_bk_unch
# The default is installed inactive; a restore that kept CREATE EXTENSION's
# fresh copy instead of the dumped row would let the probe through.
default_scenario activated qa_bk_act "SELECT public.sql_firewall_toggle_regex_rule(@DEFAULT_ID@, true)"
SCEN_FORMATS="plain custom parallel rules_first" \
    default_scenario deleted qa_bk_del "SELECT public.sql_firewall_delete_regex_rule(@DEFAULT_ID@)"
SCEN_FORMATS="plain custom parallel rules_first" \
    default_scenario readded qa_bk_readd "SELECT public.sql_firewall_delete_regex_rule(@DEFAULT_ID@)" \
    "SELECT public.sql_firewall_add_regex_rule($P0_SQL, 'qa re-added default pattern')"
# Review finding: the keyed default keeps its key with an edited pattern, an
# ordinary rule takes the original pattern, and CLUSTER on a descending-id
# index puts that ordinary row first in scan order (and so in the dump).
SCEN_FORMATS="plain custom parallel" SCEN_AFTER_DUMP=ordinary_row_first \
    default_scenario edited_original qa_bk_edorig \
    "UPDATE public.sql_firewall_regex_rules SET pattern = 'qa_bk_edited_default' WHERE id = @DEFAULT_ID@" \
    "SELECT public.sql_firewall_add_regex_rule($P0_SQL, 'qa ordinary rule with the original default pattern')" \
    "CREATE INDEX qa_bk_desc ON public.sql_firewall_regex_rules (id DESC)" \
    "CLUSTER public.sql_firewall_regex_rules USING qa_bk_desc" \
    "DROP INDEX public.qa_bk_desc"

# Keep the retained cluster small when every check here passed.
if ((NONPASS == 0)); then
    steps=()
    for db in "${ALL_DBS[@]}"; do steps+=("DROP DATABASE IF EXISTS $db WITH (FORCE)"); done
    qa_admin postgres "${steps[@]}" >/dev/null || qa_evidence $EV "- cleanup: $QA_INFRA_REASON"
fi
exit 0

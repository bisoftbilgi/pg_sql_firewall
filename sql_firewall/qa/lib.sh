# shellcheck shell=bash
# Shared helpers for the sql_firewall QA runner. Sourced by run.sh and tests/*.sh.
#
# Result categories (see README.md):
#   PASS          the contract under test was positively observed to hold
#   FAIL          positive evidence that the contract does not hold. baseline.*
#                 IDs are product defects; selftest.* IDs are harness defects
#   INFRA         no verdict: environment/tooling failure, unmet precondition,
#                 or an unexpected error that kept the test from observing
#                 the behaviour under test
#   INCONCLUSIVE  the check ran as designed, but current product interfaces
#                 cannot supply enough evidence for a verdict, e.g. the
#                 absence of an asynchronous effect whose delivery cannot be
#                 established
#   UNSUPPORTED   the check does not apply to this configuration
#
# Only PASS is a pass. Every other category makes the run non-green.

QA_EXIT_INFRA=10    # hard infrastructure failure
QA_EXIT_TIMEOUT=11  # bounded poll expired

# Control traffic role. It is pinned to enforce mode in every disposable
# database (ALTER ROLE ... IN DATABASE), independent of the mode under test.
QA_CANARY_ROLE=qa_canary

qa_record() { # STATUS ID SUMMARY
    local status=$1 id=$2 summary=$3
    case $status in
        PASS | FAIL | INFRA | INCONCLUSIVE | UNSUPPORTED) ;;
        *) summary="invalid status '$status': $summary"; status=INFRA ;;
    esac
    summary=${summary//$'\t'/ }
    summary=${summary//$'\n'/ | }
    printf '%s\t%s\t%s\n' "$status" "$id" "$summary" >>"$QA_RESULTS"
    printf '[%-12s] %s: %s\n' "$status" "$id" "$summary"
}

qa_evidence() { # ID LINE...
    local id=$1
    shift
    mkdir -p "$QA_RUN_DIR/evidence"
    printf '%s\n' "$@" >>"$QA_RUN_DIR/evidence/$id.md"
}

# qa_sql_quote TEXT -> SQL string literal
qa_sql_quote() { printf "'%s'" "${1//\'/\'\'}"; }

# ---------------------------------------------------------------------------
# SQL execution
# ---------------------------------------------------------------------------

# qa_sql_steps ROLE DB APPNAME STEP...
#
# Runs every STEP (exactly one SQL statement each) in ONE psql session, so
# session state (temp objects, SET, ...) carries across steps. psql does not
# stop on SQL errors; each step's outcome is read back from psql's own
# ERROR / SQLSTATE / LAST_ERROR_MESSAGE variables via markers on stdout.
# A step without a trailing ';' gets one appended, and the server receives
# the text *with* that ';'. The firewall inspects PostgreSQL's span for the
# statement, which ends before the ';' (before Phase 4A it saw the whole
# text, ';' included).
#
# On return 0:  QA_STEP_ERR[i] (true|false), QA_STEP_STATE[i] (SQLSTATE),
#               QA_STEP_MSG[i] (primary error message), QA_STEP_OUT[i] (rows, -A -t)
# Otherwise:    QA_EXIT_INFRA and QA_INFRA_REASON. Missing executables,
#               connection failures, timeouts and sessions that end before
#               every step completed are all reported this way.
qa_sql_steps() {
    local role=$1 db=$2 app=$3
    shift 3
    QA_STEP_ERR=() QA_STEP_STATE=() QA_STEP_MSG=() QA_STEP_OUT=() QA_INFRA_REASON=
    local nsteps=$# i=0 step
    local base
    base="$QA_RUN_DIR/logs/sql/$(date +%s%N).$$.$RANDOM.$role"
    mkdir -p "${base%/*}"
    {
        for step in "$@"; do
            i=$((i + 1))
            printf '\\echo @@QA_BEGIN %d\n' "$i"
            printf '%s' "$step"
            [[ $step =~ \;[[:space:]]*$ ]] || printf ';'
            printf '\n\\echo @@QA_END %d :ERROR :SQLSTATE\n' "$i"
            printf '\\if :ERROR\n\\echo @@QA_MSG %d :LAST_ERROR_MESSAGE\n\\endif\n' "$i"
        done
    } >"$base.sql"

    if [[ ! -x $QA_PSQL || -d $QA_PSQL ]]; then
        QA_INFRA_REASON="psql executable not found: $QA_PSQL"
        return $QA_EXIT_INFRA
    fi

    local rc=0
    env PGAPPNAME="$app" PGCONNECT_TIMEOUT=10 \
        timeout "${QA_SQL_TIMEOUT:-60}" \
        "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
        -h "$QA_SOCK" -p "$QA_PORT" -U "$role" -d "$db" -f "$base.sql" \
        >"$base.out" 2>"$base.err" || rc=$?
    case $rc in
        0) ;;
        124) QA_INFRA_REASON="psql timed out after ${QA_SQL_TIMEOUT:-60}s ($base.sql)" ;;
        126 | 127) QA_INFRA_REASON="psql could not be executed (exit $rc): $QA_PSQL" ;;
        2) QA_INFRA_REASON="connection failed or was lost (psql exit 2): $(head -c 400 "$base.err")" ;;
        *) QA_INFRA_REASON="psql failed (exit $rc): $(head -c 400 "$base.err")" ;;
    esac
    [[ $rc -eq 0 ]] || return $QA_EXIT_INFRA

    local line cur=0
    while IFS= read -r line; do
        if [[ $line =~ ^@@QA_BEGIN\ ([0-9]+)$ ]]; then
            cur=${BASH_REMATCH[1]}
            QA_STEP_OUT[cur]=
        elif [[ $line =~ ^@@QA_END\ ([0-9]+)\ (true|false)\ ([0-9A-Z]{5})$ ]]; then
            QA_STEP_ERR[BASH_REMATCH[1]]=${BASH_REMATCH[2]}
            QA_STEP_STATE[BASH_REMATCH[1]]=${BASH_REMATCH[3]}
            cur=0
        elif [[ $line =~ ^@@QA_MSG\ ([0-9]+)\ (.*)$ ]]; then
            QA_STEP_MSG[BASH_REMATCH[1]]=${BASH_REMATCH[2]}
        elif ((cur > 0)); then
            QA_STEP_OUT[cur]+="${QA_STEP_OUT[cur]:+$'\n'}$line"
        fi
    done <"$base.out"

    for ((i = 1; i <= nsteps; i++)); do
        if [[ -z ${QA_STEP_ERR[i]:-} ]]; then
            QA_INFRA_REASON="step $i did not complete (session ended early): $(head -c 400 "$base.err")"
            return $QA_EXIT_INFRA
        fi
    done
    return 0
}

# qa_activity_sync DB [TIMEOUT_SECONDS]
# Activity rows are written asynchronously by the database's approval worker
# from the activity queue (README 6.7). Waits until that worker's committed
# activity position, for the current queue generation and installation, has
# reached the queue's write position read now. Every activity record
# published before the call has then been written, or counted as lost in
# sql_firewall_queue_statistics(). A paused, stalled, or absent worker is a
# timeout (INFRA), never a silent pass.
qa_activity_sync() {
    local db=$1 timeout=${2:-30} target generation deadline
    qa_sql_steps "$QA_SUPERUSER" "$db" qa_admin \
        "SELECT activity_write_position || ' ' || activity_generation FROM public.sql_firewall_queue_statistics()" || return $?
    if [[ ${QA_STEP_ERR[1]} != false ]]; then
        QA_INFRA_REASON="activity sync in $db: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
        return $QA_EXIT_INFRA
    fi
    read -r target generation <<<"${QA_STEP_OUT[1]}"
    deadline=$((SECONDS + timeout))
    while :; do
        qa_sql_steps "$QA_SUPERUSER" "$db" qa_admin \
            "SELECT coalesce((SELECT next_position >= $target AND ring_generation = $generation AND extension_oid = (SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') FROM public.sql_firewall_activity_checkpoint), false)" ||
            return $?
        [[ ${QA_STEP_ERR[1]} == false && ${QA_STEP_OUT[1]} == t ]] && return 0
        if ((SECONDS >= deadline)); then
            QA_INFRA_REASON="activity records up to queue position $target were not written in $db within ${timeout}s (worker paused, stalled, or absent): ${QA_STEP_MSG[1]:-}"
            return $QA_EXIT_TIMEOUT
        fi
        sleep 0.1
    done
}

# qa_admin DB STEP...  Superuser setup/verification; any SQL error is INFRA.
# A step that names sql_firewall_activity_log first waits for the activity
# records published so far (qa_activity_sync), so it reads them written.
qa_admin() {
    local db=$1 step
    shift
    for step in "$@"; do
        if [[ $step == *sql_firewall_activity_log* ]]; then
            qa_activity_sync "$db" || return $?
            break
        fi
    done
    qa_sql_steps "$QA_SUPERUSER" "$db" qa_admin "$@" || return $?
    local i
    for i in "${!QA_STEP_ERR[@]}"; do
        if [[ ${QA_STEP_ERR[i]} == true ]]; then
            QA_INFRA_REASON="admin step $i failed in $db: ${QA_STEP_STATE[i]} ${QA_STEP_MSG[i]:-}"
            return $QA_EXIT_INFRA
        fi
    done
}

# ---------------------------------------------------------------------------
# Verdicts. Each sets QA_VERDICT and QA_DETAIL.
# ---------------------------------------------------------------------------

# qa_judge_rejection STEP SQLSTATE MSG_REGEX
# PASS only for the expected SQLSTATE together with the expected firewall
# diagnostic. An allowed statement is FAIL. Any other error (syntax, missing
# object, native permission denial, a different firewall reason) is INFRA:
# the decision under test was not observed.
qa_judge_rejection() {
    local i=$1 state=$2 regex=$3
    local st=${QA_STEP_STATE[i]} msg=${QA_STEP_MSG[i]:-}
    if [[ ${QA_STEP_ERR[i]} == false ]]; then
        QA_VERDICT=FAIL
        QA_DETAIL="statement was allowed; expected rejection $state /$regex/"
    elif [[ $st == "$state" && $msg =~ $regex ]]; then
        QA_VERDICT=PASS
        QA_DETAIL="rejected: $st $msg"
    else
        QA_VERDICT=INFRA
        QA_DETAIL="unexpected error $st: $msg (expected $state /$regex/); decision under test not observed"
    fi
}

# qa_judge_success STEP [EXPECTED_OUTPUT]
# A firewall rejection ("sql_firewall:" diagnostic) is FAIL; any other error or
# an unexpected result is INFRA.
qa_judge_success() {
    local i=$1
    local st=${QA_STEP_STATE[i]} msg=${QA_STEP_MSG[i]:-} out=${QA_STEP_OUT[i]}
    if [[ ${QA_STEP_ERR[i]} == false ]]; then
        if [[ $# -ge 2 && $out != "$2" ]]; then
            QA_VERDICT=INFRA
            QA_DETAIL="statement succeeded but returned '$out' (expected '$2')"
        else
            QA_VERDICT=PASS
            QA_DETAIL="allowed${out:+, returned '$out'}"
        fi
    elif [[ $msg == sql_firewall:* ]]; then
        QA_VERDICT=FAIL
        QA_DETAIL="rejected by firewall: $st $msg"
    else
        QA_VERDICT=INFRA
        QA_DETAIL="unexpected error $st: $msg"
    fi
}

# qa_judge_absence VIOLATIONS_OBSERVED DESCRIPTION
# For contracts of the form "asynchronous processing must NOT produce X".
# Observed X is positive evidence (FAIL). Unobserved X is INCONCLUSIVE, never
# PASS: the worker can skip events silently (its cursor advances when an event
# cannot be read), and no product interface proves that a given event was
# delivered, so absence cannot be told apart from loss.
qa_judge_absence() {
    if (($1 > 0)); then
        QA_VERDICT=FAIL
        QA_DETAIL="observed: $2"
    else
        QA_VERDICT=INCONCLUSIVE
        QA_DETAIL="not observed: $2; absence is not evidence here (event delivery cannot be established)"
    fi
}

# qa_check_rejection ROLE DB APP SQL SQLSTATE MSG_REGEX
qa_check_rejection() {
    if ! qa_sql_steps "$1" "$2" "$3" "$4"; then
        QA_VERDICT=INFRA
        QA_DETAIL=$QA_INFRA_REASON
        return
    fi
    qa_judge_rejection 1 "$5" "$6"
}

# qa_check_success ROLE DB APP SQL [EXPECTED_OUTPUT]
qa_check_success() {
    if ! qa_sql_steps "$1" "$2" "$3" "$4"; then
        QA_VERDICT=INFRA
        QA_DETAIL=$QA_INFRA_REASON
        return
    fi
    qa_judge_success 1 "${@:5}"
}

# ---------------------------------------------------------------------------
# Asynchronous processing
# ---------------------------------------------------------------------------

# qa_poll DB SQL EXPECTED TIMEOUT_SECONDS  (superuser; bounded)
qa_poll() {
    local db=$1 sql=$2 expected=$3 deadline=$((SECONDS + $4))
    while :; do
        qa_admin "$db" "$sql" || return $?
        [[ ${QA_STEP_OUT[1]} == "$expected" ]] && return 0
        if ((SECONDS >= deadline)); then
            QA_INFRA_REASON="condition not reached within $4s: $sql (last: '${QA_STEP_OUT[1]}')"
            return $QA_EXIT_TIMEOUT
        fi
        sleep 0.2
    done
}

QA_CANARY_REJECTION="^sql_firewall: No rule found for command 'SELECT' for role '$QA_CANARY_ROLE'$"

# qa_canary_emit DB -> QA_CANARY_TOKEN
# The canary role runs in enforce mode without any approval, so a plain SELECT
# is rejected with "No rule found" and its blocked-query event is enqueued.
# That path creates no approvals or fingerprints.
qa_canary_emit() {
    QA_CANARY_TOKEN="qa_canary_$(date +%s%N)_$RANDOM"
    qa_check_rejection "$QA_CANARY_ROLE" "$1" qa_canary "SELECT '$QA_CANARY_TOKEN' AS marker" \
        42501 "$QA_CANARY_REJECTION"
    if [[ $QA_VERDICT != PASS ]]; then
        QA_INFRA_REASON="canary not rejected as expected: $QA_DETAIL"
        return $QA_EXIT_INFRA
    fi
}

# qa_canary_delivered DB TOKEN TIMEOUT_SECONDS  (bounded poll for the canary's row)
qa_canary_delivered() {
    qa_poll "$1" \
        "SELECT count(*) > 0 FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '$2') > 0" \
        t "$3"
}

# qa_worker_progress DB TIMEOUT_SECONDS
#
# LIVENESS/PROGRESS ONLY. A delivered canary proves that a worker is attached
# to DB and processed the ring at least up to the canary's own event. It does
# NOT prove that any earlier event was delivered: the worker advances its
# cursor past slots it cannot read, and it starts from the current write
# position. Use it to wait for asynchronous effects before inspecting them,
# never to turn their absence into a PASS (see qa_judge_absence).
qa_worker_progress() {
    qa_canary_emit "$1" || return $?
    qa_canary_delivered "$1" "$QA_CANARY_TOKEN" "${2:-30}"
}

# qa_wait_worker_live DB TIMEOUT_SECONDS
# Retries canaries (bounded) until one is delivered, i.e. a worker is live.
qa_wait_worker_live() {
    local db=$1 deadline=$((SECONDS + ${2:-90})) attempts=0 rc
    while ((SECONDS < deadline)); do
        attempts=$((attempts + 1))
        if qa_worker_progress "$db" 3; then
            QA_READY_ATTEMPTS=$attempts
            qa_assert_worker_library "$db" || return $?
            return 0
        else
            rc=$?
            [[ $rc -eq $QA_EXIT_TIMEOUT ]] || return $rc
        fi
    done
    QA_INFRA_REASON="no approval worker became live for $db within ${2:-90}s ($attempts canaries)"
    return $QA_EXIT_TIMEOUT
}

# ---------------------------------------------------------------------------
# Fingerprint identity
# ---------------------------------------------------------------------------

# qa_fp_identify DB ROLE COMMAND STATEMENT...
#
# Locates the catalog fingerprint row for the exact statement texts a test
# sent, as the product records them: PostgreSQL's statement span, without
# the terminating ';' the harness appends. It does not re-implement the
# product's normaliser. The test role must be isolated and
# issue only these statements for COMMAND. The row's sample_query is the text
# of its first observation, so identity is an exact sample_query match.
#   QA_FP_STATE = absent     no rows at all for ROLE/COMMAND
#               = found      exactly one row, and its sample_query is one of the
#                            STATEMENTs; QA_FP_FINGERPRINT QA_FP_NORMALIZED
#                            QA_FP_APPROVED (t|f) QA_FP_HITS are set
#               = ambiguous  rows exist but identity is not established
# QA_FP_DUMP always lists every ROLE/COMMAND row (fingerprint | normalized |
# sample | approved | hits), so a mismatch is visible and never reads as absent.
qa_fp_identify() {
    local db=$1 role=$2 cmd=$3 s arr=""
    shift 3
    for s in "$@"; do arr+="${arr:+, }$(qa_sql_quote "$s")"; done
    local where
    where="role_name = $(qa_sql_quote "$role") AND command_type = $(qa_sql_quote "$cmd")"
    QA_FP_STATE="" QA_FP_FINGERPRINT="" QA_FP_NORMALIZED="" QA_FP_APPROVED="" QA_FP_HITS="" QA_FP_DUMP=""
    qa_admin "$db" \
        "SELECT count(*) || ',' || count(*) FILTER (WHERE sample_query = ANY (ARRAY[$arr]::text[])) FROM public.sql_firewall_query_fingerprints WHERE $where" \
        "SELECT coalesce(string_agg(format('%s | %L | %L | approved=%s | hits=%s', fingerprint, normalized_query, sample_query, is_approved, hit_count), E'\n' ORDER BY id), '(no rows)') FROM public.sql_firewall_query_fingerprints WHERE $where" \
        "SELECT coalesce((SELECT concat_ws(E'\x1f', fingerprint, normalized_query, is_approved, hit_count) FROM public.sql_firewall_query_fingerprints WHERE $where AND sample_query = ANY (ARRAY[$arr]::text[]) LIMIT 1), '')" ||
        return $?
    QA_FP_DUMP=${QA_STEP_OUT[2]}
    local total=${QA_STEP_OUT[1]%,*} matching=${QA_STEP_OUT[1]#*,}
    if [[ $total == 0 ]]; then
        QA_FP_STATE=absent
    elif [[ $total == 1 && $matching == 1 ]]; then
        QA_FP_STATE=found
        IFS=$'\x1f' read -r QA_FP_FINGERPRINT QA_FP_NORMALIZED QA_FP_APPROVED QA_FP_HITS <<<"${QA_STEP_OUT[3]}"
    else
        QA_FP_STATE=ambiguous
    fi
}

# ---------------------------------------------------------------------------
# Learn-threshold boundary verdict
# Shared by tests/30_learn_threshold.sh (real catalog) and
# tests/01_verdict_regressions.sh (deterministic observations).
# ---------------------------------------------------------------------------
#
# The caller defines two hooks:
#   qa_thr_execute I  send execution I; return 0 if it was allowed, else set
#                     QA_THR_DETAIL and return nonzero
#   qa_thr_observe I  identify the catalog row for executions 1..I and set
#                     QA_THR_STATE (found|absent|ambiguous), QA_THR_APPROVED
#                     (t|f) and QA_THR_HITS; nonzero return plus QA_THR_DETAIL
#                     means the observation itself failed
# Poll bound per execution: QA_THR_POLL_ATTEMPTS (default 100) x
# QA_THR_POLL_INTERVAL seconds (default 0.2).
#
# Evidence basis, from the actual implementation (approval_worker.rs):
#  - Each delivered fingerprint event is persisted by one upsert. It either
#    inserts the row with hit_count = 1, or increments hit_count on an
#    existing row. is_approved is written only on insert, in the same
#    statement. Nothing else writes the row in this test.
#  - So hit_count = h means exactly h observation events were delivered, and
#    is_approved was written together with one of them.
#  - Processing of execution i is evidenced only by hit_count >= i on the
#    identified row. An existing row is not assumed to be fresh.
#  - hit_count > i means observations this test did not send, which is INFRA.
#  - The current implementation stops emitting events once its shared-memory
#    cache approves a fingerprint, so later executions can stay unevidenced.
#  - An approved row visible while only i < N executions have been sent is
#    approval before the threshold. That is FAIL, whatever the hit counter
#    says, and whether or not execution i itself is evidenced yet.
#  - An approved row visible after execution N proves approval at N only if
#    two things hold: every execution i < N was evidenced unapproved at
#    hit_count = i, and the approved row has hit_count = N. Seeing an approved
#    row after sending N is not enough by itself.
#  - A threshold execution evidenced at hit_count = N that stays unapproved
#    for the poll bound is FAIL.
#  - An execution whose processing is not evidenced within the bound is
#    INCONCLUSIVE, and the sequence stops there: no later execution is sent,
#    so no later observation can be misattributed.
# A delivered canary is not used here; it only shows that a worker is live.
#
# Sets QA_VERDICT, QA_DETAIL, QA_THR_TRACE (one line per execution).
qa_threshold_verdict() {
    local n=$1 i a attempts=${QA_THR_POLL_ATTEMPTS:-100} interval=${QA_THR_POLL_INTERVAL:-0.2}
    local seen obs last
    QA_THR_TRACE=()
    for ((i = 1; i <= n; i++)); do
        if ! qa_thr_execute "$i"; then
            QA_VERDICT=INFRA QA_DETAIL="execution $i was not allowed (not a threshold verdict): $QA_THR_DETAIL"
            QA_THR_TRACE+=("execution $i: not allowed")
            return
        fi
        seen="" last=""
        for ((a = 1; a <= attempts; a++)); do
            if ! qa_thr_observe "$i"; then
                QA_VERDICT=INFRA QA_DETAIL="observation after execution $i failed: $QA_THR_DETAIL"
                QA_THR_TRACE+=("execution $i: ${seen:-no observation} -> observation failed")
                return
            fi
            case $QA_THR_STATE in
                found) obs="approved=$QA_THR_APPROVED hits=$QA_THR_HITS" ;;
                absent) obs="absent" ;;
                ambiguous)
                    QA_VERDICT=INFRA QA_DETAIL="fingerprint identity not established after execution $i"
                    QA_THR_TRACE+=("execution $i: ${seen:+$seen -> }ambiguous")
                    return
                    ;;
                *)
                    QA_VERDICT=INFRA QA_DETAIL="invalid observation state '$QA_THR_STATE' after execution $i"
                    return
                    ;;
            esac
            [[ $obs == "$last" ]] || seen+="${seen:+ -> }$obs"
            last=$obs
            if [[ $QA_THR_STATE == found ]]; then
                if [[ $QA_THR_APPROVED == t ]] && ((i < n)); then
                    QA_VERDICT=FAIL
                    QA_DETAIL="approved row visible after only $i of $n executions were sent ($obs)"
                    QA_THR_TRACE+=("execution $i: $seen -> APPROVED BEFORE THRESHOLD")
                    return
                fi
                if ((QA_THR_HITS > i)); then
                    QA_VERDICT=INFRA QA_DETAIL="hit_count $QA_THR_HITS exceeds the $i execution(s) sent (isolation broken)"
                    QA_THR_TRACE+=("execution $i: $seen -> too many hits")
                    return
                fi
                if ((QA_THR_HITS == i)) && { ((i < n)) || [[ $QA_THR_APPROVED == t ]]; }; then
                    break
                fi
            fi
            ((a < attempts)) && sleep "$interval"
        done
        if [[ $QA_THR_STATE != found ]] || ((QA_THR_HITS < i)); then
            QA_VERDICT=INCONCLUSIVE
            QA_DETAIL="processing of execution $i not evidenced within $attempts polls (last: $last); sequence stopped"
            QA_THR_TRACE+=("execution $i: $seen -> not evidenced (stopped)")
            return
        fi
        if ((i < n)); then
            QA_THR_TRACE+=("execution $i: $seen -> held (evidenced unapproved at hits=$i)")
        elif [[ $QA_THR_APPROVED == t ]]; then
            QA_THR_TRACE+=("execution $i: $seen -> approved at hits=$n")
            QA_VERDICT=PASS
            if ((n > 1)); then
                QA_DETAIL="every execution evidenced: unapproved at hits 1..$((n - 1)), approved at hits=$n"
            else
                QA_DETAIL="every execution evidenced: approved at hits=1"
            fi
            return
        else
            QA_THR_TRACE+=("execution $i: $seen -> NOT APPROVED at threshold")
            QA_VERDICT=FAIL
            QA_DETAIL="threshold execution $n evidenced (hits=$n) but still unapproved after $attempts polls"
            return
        fi
    done
}

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

# qa_create_db DB [GUC=VALUE ...]
# Fresh database, extension, per-database GUCs, and the canary role pinned to
# enforce mode in this database only.
qa_create_db() {
    local db=$1 kv steps=()
    shift
    qa_admin postgres "CREATE DATABASE $db" || return $?
    for kv in "$@"; do
        steps+=("ALTER DATABASE $db SET ${kv%%=*} = '${kv#*=}'")
    done
    qa_admin postgres "${steps[@]}" \
        "GRANT CONNECT ON DATABASE $db TO $QA_CANARY_ROLE" \
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $db SET sql_firewall.mode = 'enforce'" || return $?
    qa_admin "$db" "CREATE EXTENSION sql_firewall"
}

# qa_mapped_extension_so PID
# Prints the single mapped sql_firewall.so path. Fails if that library is
# absent or if sql_firewall_rs.so is also mapped.
qa_mapped_extension_so() {
    local pid=$1 maps
    [[ -r /proc/$pid/maps ]] || { QA_INFRA_REASON="cannot read /proc/$pid/maps"; return 1; }
    if grep -qE '/sql_firewall_rs\.so( |$)' "/proc/$pid/maps"; then
        QA_INFRA_REASON="pid $pid mapped sql_firewall_rs.so"
        return 1
    fi
    maps=$(grep -oE '/[^ ]*/sql_firewall\.so' "/proc/$pid/maps" | sort -u)
    [[ -n $maps && $maps != *$'\n'* ]] || { QA_INFRA_REASON="pid $pid did not map exactly one sql_firewall.so"; return 1; }
    printf '%s\n' "$maps"
}

# After a delivered canary, the approval worker for this database must be
# the renamed library. The canary itself is the evidence that it processed work.
qa_assert_worker_library() {
    local db=$1 pid mapped pm
    qa_admin "$db" "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    pid=${QA_STEP_OUT[1]}
    [[ $pid =~ ^[0-9]+$ ]] || {
        QA_INFRA_REASON="approval worker for $db not uniquely present after canary delivery (pid='$pid')"
        return $QA_EXIT_INFRA
    }
    mapped=$(qa_mapped_extension_so "$pid") || {
        QA_INFRA_REASON=${QA_INFRA_REASON:-"worker $pid did not map sql_firewall.so"}
        return $QA_EXIT_INFRA
    }
    pm=$(qa_mapped_extension_so "$QA_PM_PID") || return $QA_EXIT_INFRA
    [[ $mapped == "$pm" ]] || {
        QA_INFRA_REASON="worker mapped $mapped, postmaster mapped $pm"
        return $QA_EXIT_INFRA
    }
    printf 'db=%s pid=%s library=%s\n' "$db" "$pid" "$mapped" >>"$QA_RUN_DIR/worker-library.txt"
}

# qa_verify_mode_context DB ROLE EXPECTED_MODE
# Confirms from pg_db_role_setting that:
#  - the database-level mode is EXPECTED_MODE
#  - ROLE has no role-level or role-in-database sql_firewall.mode override, so
#    it runs under the database mode
#  - the canary's override is enforce and is scoped to this database
# Sets QA_MODE_CONTEXT (for evidence). Returns QA_EXIT_INFRA on mismatch.
qa_verify_mode_context() {
    local db=$1 role=$2 expected=$3
    qa_admin postgres \
        "SELECT coalesce((SELECT string_agg(c, ',') FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase, unnest(s.setconfig) c WHERE d.datname = '$db' AND s.setrole = 0 AND c LIKE 'sql_firewall.mode=%'), 'unset')" \
        "SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole, unnest(s.setconfig) c WHERE r.rolname = '$role' AND c LIKE 'sql_firewall.mode=%'" \
        "SELECT coalesce((SELECT string_agg(coalesce(d.datname, '*') || ':' || c, ',') FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole LEFT JOIN pg_database d ON d.oid = s.setdatabase, unnest(s.setconfig) c WHERE r.rolname = '$QA_CANARY_ROLE' AND c LIKE 'sql_firewall.mode=%' AND (d.datname = '$db' OR s.setdatabase = 0)), 'unset')" ||
        return $?
    QA_MODE_CONTEXT="database $db: ${QA_STEP_OUT[1]}; $role overrides: ${QA_STEP_OUT[2]}; $QA_CANARY_ROLE: ${QA_STEP_OUT[3]}"
    if [[ ${QA_STEP_OUT[1]} != "sql_firewall.mode=$expected" || ${QA_STEP_OUT[2]} != 0 ||
        ${QA_STEP_OUT[3]} != "$db:sql_firewall.mode=enforce" ]]; then
        QA_INFRA_REASON="mode context not as required: $QA_MODE_CONTEXT"
        return $QA_EXIT_INFRA
    fi
}

qa_server_log_offset() { stat -c %s "$QA_SERVER_LOG"; }

# qa_server_problems_since OFFSET  prints logged worker/audit failures and
# crashes; returns 0 when none were logged. A clean window is NOT evidence
# that no event was lost: some losses are silent.
qa_server_problems_since() {
    local hits
    hits=$(tail -c +"$(($1 + 1))" "$QA_SERVER_LOG" | grep -E \
        'worker failed|failed to enqueue|failed to decode|worker too slow|failed to log activity|terminated by signal|exited with exit code|PANIC:|launcher scan failed|failed to spawn worker' |
        head -20)
    if ! kill -0 "$QA_PM_PID" 2>/dev/null; then
        hits+="${hits:+$'\n'}postmaster (pid $QA_PM_PID) is no longer running"
    fi
    [[ -z $hits ]] && return 0
    printf '%s\n' "$hits"
    return 1
}

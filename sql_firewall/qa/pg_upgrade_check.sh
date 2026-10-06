#!/usr/bin/env bash
# sql_firewall across a PostgreSQL major upgrade with pg_upgrade (Phase 9,
# P9-02/P9-04; README 6.9b).
#
# Usage: qa/pg_upgrade_check.sh OLD_MAJOR NEW_MAJOR      e.g. 16 17
#
# Builds the release package for both majors with run.sh --build-only --keep
# (each build is recorded in its own run directory and manifest), stages two
# private installation copies, creates a cluster with the old major, installs
# policy, upgrades it with the new major's pg_upgrade (--check, then copy
# mode), starts the new cluster and checks what the README says survives.
# Like run.sh it never touches ~/.pgrx data directories, shared installations
# or running clusters, and it must not run at the same time as run.sh (both
# compare the list of other postgres processes).
#
# Contract (README 6.9b):
#   check            pg_upgrade --check and the upgrade succeed with the
#                    extension installed and preloaded in both clusters
#   catalog          extension version, policy rows, history, regex rules and
#                    default-rule removal records are identical
#   commands         command approvals and refusals decide as before
#   regex            regex rules still refuse
#   fingerprint      an approval made before the upgrade does not authorize
#                    the upgraded cluster (new installation identity, as after
#                    a logical restore); re-approval of the newly observed
#                    identity works
#   worker           the consumer starts and persists events
#   old_cluster      after a copy-mode upgrade the old cluster starts again
#                    with its catalog unchanged and its own approvals deciding
#                    (the roll-back path)
# Exit codes: 0 all PASS, 1 FAIL, 2 INFRA, 3 build failed.
set -uo pipefail

QA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
source "$QA_DIR/lib.sh"
for v in $(compgen -e | grep -E '^PG'); do unset "$v"; done

OLD=${1:?old major}
NEW=${2:?new major}
pg_config_for() { ls -d "$HOME"/.pgrx/"$1".*/pgrx-install/bin/pg_config 2>/dev/null | head -1; }
OLD_PGC=$(pg_config_for "$OLD") NEW_PGC=$(pg_config_for "$NEW")
[[ -x $OLD_PGC && -x $NEW_PGC ]] || { echo "pg_config for $OLD or $NEW not found under ~/.pgrx" >&2; exit 2; }

QA_WORK_ROOT=${QA_WORK_ROOT:-${TMPDIR:-/tmp}}
QA_SOCKET_ROOT=${QA_SOCKET_ROOT:-/tmp}
WORK=$(mktemp -d "$QA_WORK_ROOT/sqlfw-upgrade.XXXXXX") || exit 2
export QA_RUN_DIR=$WORK QA_RESULTS=$WORK/results.tsv QA_SUPERUSER=qa_admin
QA_SERVER_LOG=$WORK/logs/new.log
mkdir -p "$WORK/logs" "$WORK/evidence"
: >"$QA_RESULTS"
MANIFEST=$WORK/manifest.txt
m() { printf '%s=%s\n' "$1" "$2" >>"$MANIFEST"; }
echo "run directory: $WORK"
m started_at "$(date -Is)"
m upgrade "$OLD -> $NEW"

ID=baseline.pg_upgrade
EV=pg_upgrade
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }
qa_evidence "$EV" "# $ID ($OLD -> $NEW)" ""

# --- builds -------------------------------------------------------------------
build() { # MAJOR PGC -> sets PKG_<MAJOR> and SO_<MAJOR>
    local out run
    out=$(QA_WORK_ROOT=$WORK/builds QA_ALLOW_OTHER_MAJOR=1 QA_PG_CONFIG=$2 "$QA_DIR/run.sh" --build-only --keep 2>&1)
    local rc=$?
    run=$(sed -n 's/^run directory: //p' <<<"$out")
    printf '%s\n' "$out" >"$WORK/logs/build$1.log"
    [[ $rc == 0 && -d $run/pkg ]] || { echo "build for $1 failed (rc $rc): $run" >&2; exit 3; }
    printf -v "PKG_$1" '%s' "$run/pkg"
    m "build_${1}_run" "$run"
    m "build_${1}_so_sha256" "$(sed -n 's/^artifact_so_sha256=//p' "$run/manifest.txt")"
}
build "$OLD" "$OLD_PGC"
build "$NEW" "$NEW_PGC"
PKG_OLD_VAR=PKG_$OLD PKG_NEW_VAR=PKG_$NEW

stage() { # PGC PKG DEST
    local prefix lib share
    prefix=$(dirname "$("$1" --bindir)")
    cp -a "$prefix" "$3" || return 1
    lib=$("$3/bin/pg_config" --pkglibdir) share=$("$3/bin/pg_config" --sharedir)
    rm -f "$lib"/sql_firewall*.so "$share"/extension/sql_firewall*
    cp "$2$("$1" --pkglibdir)/sql_firewall.so" "$lib/" &&
        cp "$2$("$1" --sharedir)"/extension/sql_firewall* "$share/extension/"
}
stage "$OLD_PGC" "${!PKG_OLD_VAR}" "$WORK/old" || { infra "$ID" "staging $OLD failed"; exit 2; }
stage "$NEW_PGC" "${!PKG_NEW_VAR}" "$WORK/new" || { infra "$ID" "staging $NEW failed"; exit 2; }
m old_so_sha256 "$(sha256sum "$("$WORK/old/bin/pg_config" --pkglibdir)/sql_firewall.so" | cut -d' ' -f1)"
m new_so_sha256 "$(sha256sum "$("$WORK/new/bin/pg_config" --pkglibdir)/sql_firewall.so" | cut -d' ' -f1)"

QA_SOCK=$(mktemp -d "$QA_SOCKET_ROOT/sfup.XXXXXX") || exit 2
chmod 700 "$QA_SOCK"
OLD_PORT=$((20000 + RANDOM % 8000)) NEW_PORT=$((OLD_PORT + 1))
export QA_SOCK
make_cluster() { # BIN DATA PORT
    # Data checksums in both clusters: initdb enables them by default from
    # PostgreSQL 18, and pg_upgrade requires the same setting on both sides.
    "$1/initdb" -D "$2" -U "$QA_SUPERUSER" --auth=trust --no-sync -E UTF8 --locale=C --data-checksums \
        >"$WORK/logs/initdb.$(basename "$2").log" 2>&1 || return 1
    cat >>"$2/postgresql.conf" <<EOF
listen_addresses = ''
port = $3
unix_socket_directories = '$QA_SOCK'
unix_socket_permissions = 0700
logging_collector = off
shared_preload_libraries = 'sql_firewall'
max_worker_processes = 16
lc_messages = 'C'
fsync = off
log_line_prefix = '%m [%p] %q%u@%d app=%a '
EOF
}
start() { "$1/pg_ctl" -D "$2" -l "$3" -w -t 60 start >>"$WORK/logs/pg_ctl.log" 2>&1; }
stop() { [[ -f $2/postmaster.pid ]] || return 0; "$1/pg_ctl" -D "$2" -m fast -w -t 60 stop >>"$WORK/logs/pg_ctl.log" 2>&1; }
finish() {
    stop "$WORK/new/bin" "$WORK/newdata"
    stop "$WORK/old/bin" "$WORK/olddata"
    local left
    left=$(pgrep -f "$WORK/(old|new)/bin/postgres" | tr '\n' ' ')
    m surviving_processes "${left:-none}"
    [[ -z $left ]] && rm -rf -- "$QA_SOCK"
    local P F I
    P=$(awk -F'\t' '$1 == "PASS"' "$QA_RESULTS" | wc -l)
    F=$(awk -F'\t' '$1 == "FAIL"' "$QA_RESULTS" | wc -l)
    I=$(awk -F'\t' '$1 == "INFRA" || $1 == "INCONCLUSIVE"' "$QA_RESULTS" | wc -l)
    local final=0
    ((I > 0 || P == 0)) && final=2
    ((final == 0 && F > 0)) && final=1
    if ((final == 0)) && [[ -z $left ]]; then
        rm -rf -- "$WORK/old" "$WORK/new" "$WORK/olddata" "$WORK/newdata" "$WORK"/builds/*/pkg
        m cleanup_status "OK (clusters, staged installs and packages removed)"
    else
        m cleanup_status "retained for diagnostics"
    fi
    {
        echo "# sql_firewall pg_upgrade check $OLD -> $NEW"
        echo
        echo "PASS=$P FAIL=$F INFRA/INCONCLUSIVE=$I exit=$final"
        echo
        echo '| status | id | detail |'
        echo '|---|---|---|'
        awk -F'\t' '{ gsub(/\|/, "\\|", $3); printf "| %s | %s | %s |\n", $1, $2, $3 }' "$QA_RESULTS"
    } >"$WORK/summary.md"
    m final_exit_code "$final"
    echo "PASS=$P FAIL=$F INFRA/INCONCLUSIVE=$I; report: $WORK/summary.md (exit $final)"
    exit "$final"
}
trap finish EXIT

make_cluster "$WORK/old/bin" "$WORK/olddata" "$OLD_PORT" || { infra "$ID" "initdb $OLD failed"; exit; }
start "$WORK/old/bin" "$WORK/olddata" "$WORK/logs/old.log" || { infra "$ID" "start $OLD failed"; exit; }
use_old() { QA_PSQL=$WORK/old/bin/psql QA_PORT=$OLD_PORT; QA_PM_PID=$(head -1 "$WORK/olddata/postmaster.pid"); QA_SERVER_LOG=$WORK/logs/old.log; }
use_new() { QA_PSQL=$WORK/new/bin/psql QA_PORT=$NEW_PORT; QA_PM_PID=$(head -1 "$WORK/newdata/postmaster.pid"); QA_SERVER_LOG=$WORK/logs/new.log; }
use_old

DB=qa_pgu APP=qa_pgu_app NOP=qa_pgu_none FPR=qa_pgu_fp
FP_SQL="SELECT v FROM public.qa_pgu_t WHERE id = 1"
qa_admin postgres "CREATE ROLE $QA_CANARY_ROLE LOGIN NOSUPERUSER" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_create_db "$DB" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_admin postgres "CREATE ROLE $APP LOGIN" "CREATE ROLE $NOP LOGIN" "CREATE ROLE $FPR LOGIN" \
    "GRANT CONNECT ON DATABASE $DB TO $APP, $NOP, $FPR" \
    "ALTER DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE $APP IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" \
    "ALTER ROLE $NOP IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_admin "$DB" "CREATE TABLE public.qa_pgu_t (id integer PRIMARY KEY, v text)" \
    "INSERT INTO public.qa_pgu_t SELECT g, 'v' || g FROM generate_series(1, 3) g" \
    "GRANT SELECT ON public.qa_pgu_t TO $APP, $NOP, $FPR" \
    "SELECT public.sql_firewall_approve_command('$APP', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$FPR', 'SELECT')" \
    "SELECT public.sql_firewall_add_regex_rule('qa_pgu_forbidden_[0-9]+', 'upgrade test')" \
    "DELETE FROM public.sql_firewall_regex_rules WHERE installation_default = 'simple_sql_injection'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_sql_steps "$FPR" "$DB" qa_pgu "$FP_SQL" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_wait_worker_live "$DB" 60 || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_fp_identify "$DB" "$FPR" SELECT "$FP_SQL"
[[ $QA_FP_STATE == found ]] || { infra "$ID" "pending fingerprint not located: $QA_FP_DUMP"; exit; }
FP_OLD=$QA_FP_FINGERPRINT
qa_admin "$DB" "SELECT public.sql_firewall_approve_fingerprint('$FP_OLD', '$FPR', 'SELECT')" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_check_success "$FPR" "$DB" qa_pgu "SELECT v FROM public.qa_pgu_t WHERE id = 2" v2
[[ $QA_VERDICT == PASS ]] || { infra "$ID" "approved fingerprint not allowed before the upgrade: $QA_DETAIL"; exit; }

CATALOG="SELECT md5(string_agg(t, E'\n' ORDER BY t)) FROM (
    SELECT 'e' || extversion AS t FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'
    UNION ALL SELECT 'a' || row_to_json(a)::text FROM public.sql_firewall_command_approvals a
    UNION ALL SELECT 'f' || row_to_json(f)::text FROM public.sql_firewall_query_fingerprints f
    UNION ALL SELECT 'r' || row_to_json(r)::text FROM public.sql_firewall_regex_rules r
    UNION ALL SELECT 'd' || row_to_json(d)::text FROM public.sql_firewall_regex_default_removals d
    UNION ALL SELECT 'h' || row_to_json(h)::text FROM public.sql_firewall_policy_history h) s"
IDENT="SELECT (SELECT system_identifier FROM pg_catalog.pg_control_system()) || ' ' || (SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') || ' ' || (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())"
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" "$CATALOG" "$IDENT" \
    "SELECT count(*) FROM public.sql_firewall_policy_history" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
CAT_BEFORE=${QA_STEP_OUT[2]} IDENT_BEFORE=${QA_STEP_OUT[3]} HIST_BEFORE=${QA_STEP_OUT[4]}
qa_evidence "$EV" "- old cluster ($("$WORK/old/bin/postgres" --version)): catalog digest $CAT_BEFORE; system identifier, extension oid, database oid: $IDENT_BEFORE; history rows $HIST_BEFORE; fingerprint $FP_OLD approved"
stop "$WORK/old/bin" "$WORK/olddata" || { infra "$ID" "stop $OLD failed"; exit; }

# --- pg_upgrade ---------------------------------------------------------------
make_cluster "$WORK/new/bin" "$WORK/newdata" "$NEW_PORT" || { infra "$ID" "initdb $NEW failed"; exit; }
mkdir -p "$WORK/upgrade" && cd "$WORK/upgrade" || exit
upgrade_args=(-b "$WORK/old/bin" -B "$WORK/new/bin" -d "$WORK/olddata" -D "$WORK/newdata"
    -U "$QA_SUPERUSER" -p "$OLD_PORT" -P "$NEW_PORT" -s "$QA_SOCK")
"$WORK/new/bin/pg_upgrade" "${upgrade_args[@]}" --check >"$WORK/logs/pg_upgrade_check.log" 2>&1
check_rc=$?
"$WORK/new/bin/pg_upgrade" "${upgrade_args[@]}" >"$WORK/logs/pg_upgrade.log" 2>&1
upgrade_rc=$?
cd "$WORK" || exit
if [[ $check_rc == 0 && $upgrade_rc == 0 ]]; then
    ok "$ID.check" "pg_upgrade --check and the copy-mode upgrade $OLD -> $NEW succeeded with sql_firewall installed and preloaded"
else
    fail "$ID.check" "pg_upgrade --check rc $check_rc, upgrade rc $upgrade_rc (logs/pg_upgrade*.log, upgrade/)"
    exit
fi
start "$WORK/new/bin" "$WORK/newdata" "$WORK/logs/new.log" || { infra "$ID" "start $NEW failed"; exit; }
use_new
qa_admin "$DB" "$CATALOG" "$IDENT" "SELECT public.sql_firewall_status()" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
CAT_AFTER=${QA_STEP_OUT[1]} IDENT_AFTER=${QA_STEP_OUT[2]} STATUS=${QA_STEP_OUT[3]}
qa_evidence "$EV" "- new cluster ($("$WORK/new/bin/postgres" --version)): system identifier, extension oid, database oid: $IDENT_AFTER; status '$STATUS'"
if [[ $CAT_AFTER == "$CAT_BEFORE" ]]; then
    ok "$ID.catalog" "extension version, approvals, fingerprints, regex rules, default-rule removals and history identical (digest $CAT_AFTER)"
else
    fail "$ID.catalog" "catalog digest $CAT_BEFORE -> $CAT_AFTER"
fi

qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
if qa_wait_worker_live "$DB" 90; then
    ok "$ID.worker" "the consumer started on the upgraded cluster and persisted a canary"
else
    fail "$ID.worker" "$QA_INFRA_REASON"
fi

qa_check_success "$APP" "$DB" qa_pgu "SELECT count(*) FROM public.qa_pgu_t" 3
a="$QA_VERDICT: $QA_DETAIL"
qa_check_rejection "$NOP" "$DB" qa_pgu "SELECT count(*) FROM public.qa_pgu_t" 42501 "^sql_firewall: No rule found for command 'SELECT' for role '$NOP'$"
b="$QA_VERDICT: $QA_DETAIL"
if [[ $a == PASS:* && $b == PASS:* ]]; then ok "$ID.commands" "approved: $a; unapproved: $b"; else fail "$ID.commands" "approved: $a; unapproved: $b"; fi
qa_check_rejection "$APP" "$DB" qa_pgu "SELECT 'qa_pgu_forbidden_7'" 42501 "^sql_firewall: Query blocked by security regex pattern\.$"
if [[ $QA_VERDICT == PASS ]]; then ok "$ID.regex" "$QA_DETAIL"; else fail "$ID.regex" "$QA_VERDICT: $QA_DETAIL"; fi

# Fingerprints: the old approval is historical; the newly observed identity
# is approved explicitly (README 6.9b procedure).
qa_check_rejection "$FPR" "$DB" qa_pgu "$FP_SQL" 42501 "^sql_firewall: Fingerprint"
refused="$QA_VERDICT: $QA_DETAIL"
qa_worker_progress "$DB" 30 || true
qa_admin "$DB" "SELECT coalesce(string_agg(fingerprint, ',' ORDER BY id), '') FROM public.sql_firewall_query_fingerprints WHERE role_name = '$FPR' AND fingerprint <> '$FP_OLD' AND NOT is_approved" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit; }
FP_NEW=${QA_STEP_OUT[1]}
reapproved="no new pending identity"
if [[ $FP_NEW =~ ^[0-9a-f]{64}$ ]]; then
    qa_admin "$DB" "SELECT public.sql_firewall_approve_fingerprint('$FP_NEW', '$FPR', 'SELECT')" || { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit; }
    qa_check_success "$FPR" "$DB" qa_pgu "SELECT v FROM public.qa_pgu_t WHERE id = 3" v3
    reapproved="$QA_VERDICT: $QA_DETAIL"
fi
if [[ $refused == PASS:* && $reapproved == PASS:* ]]; then
    ok "$ID.fingerprint" "pre-upgrade approval $FP_OLD did not authorize ($refused); new identity $FP_NEW approved explicitly ($reapproved)"
else
    fail "$ID.fingerprint" "old approval: $refused; re-approval of '$FP_NEW': $reapproved"
fi
problems=$(grep -E 'PANIC:|terminated by signal|sql_firewall.*(failed|could not)' "$WORK/logs/new.log" | head -5)
if [[ -z $problems ]]; then
    ok "$ID.log" "no crash or firewall failure in the upgraded server's log"
else
    fail "$ID.log" "$problems"
fi

# Roll-back path: after a copy-mode upgrade the old cluster still starts and
# its own approvals, including the fingerprint, still decide there.
stop "$WORK/new/bin" "$WORK/newdata" || { infra "$ID.old_cluster" "stop $NEW failed"; exit; }
start "$WORK/old/bin" "$WORK/olddata" "$WORK/logs/old.log" || { infra "$ID.old_cluster" "restart of $OLD failed"; exit; }
use_old
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" "$CATALOG" || { infra "$ID.old_cluster" "$QA_INFRA_REASON"; exit; }
old_cat=${QA_STEP_OUT[2]}
qa_check_success "$FPR" "$DB" qa_pgu "SELECT v FROM public.qa_pgu_t WHERE id = 3" v3
if [[ $QA_VERDICT == PASS && $old_cat == "$CAT_BEFORE" ]]; then
    ok "$ID.old_cluster" "the old $OLD cluster restarted after the copy-mode upgrade with its catalog unchanged; its fingerprint approval still decides ($QA_DETAIL)"
else
    fail "$ID.old_cluster" "old cluster catalog $old_cat (before $CAT_BEFORE); fingerprint: $QA_VERDICT $QA_DETAIL"
fi
exit

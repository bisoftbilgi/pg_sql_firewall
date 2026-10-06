#!/usr/bin/env bash
# Packages, the preload requirement, and the update tool end to end
# (README 4, 6.9a; packaging/).
#
# Usage: qa/package_upgrade_check.sh [PG_CONFIG]   (default: the pgrx PostgreSQL 16)
#
# Builds the package of the current source (0.0.0) and of a copy of it made
# into release 0.0.1 (version bumped, the update script
# qa/fixtures/sql_firewall--0.0.0--0.0.1.sql added), installs them with their
# install.sh into a private copy of the PostgreSQL installation, and drives a
# disposable cluster on a private socket. Like run.sh it touches no existing
# cluster or installation; it must not run at the same time as run.sh.
#
# Contract:
#   preload_required        CREATE EXTENSION without preload is refused (55000)
#                           and leaves nothing behind
#   install_while_running   installing the 0.0.1 package into a running 0.0.0
#                           server changes nothing until a restart: the
#                           running library is still 0.0.0 and policy decides
#   not_ready               before the restart the tool reports NOT READY
#                           (exit 3) and changes nothing
#   update_script_guard     a manual ALTER EXTENSION UPDATE before the restart
#                           is refused by the update script (55000), version kept
#   ready                   after the restart the library runs 0.0.1 and the
#                           tool's --check lists both databases with their path
#   backup_private          the backup directory is 0700 and its files 0600
#                           although the tool ran under umask 022 (dumps and
#                           roles.sql hold data and password hashes)
#   update                  --yes backs up (roles and each database, checked),
#                           updates the databases and template1, and verifies
#   policy_guard            an update that changes the policy (here an event
#                           trigger on ALTER EXTENSION flips an approval) is
#                           rolled back before COMMIT: that database keeps
#                           0.0.0 and its policy; without the trigger it updates
#   template                template1, where the extension is installed, is
#                           updated too, and a database created from it gets 0.0.1
#   preserved               extension OIDs, policy, history and fingerprint
#                           approvals are unchanged; the script's change is
#                           present; approved statements run, others are
#                           refused; each consumer is live
#   idempotent              a second --check finds nothing to update
#   no_path                 --check --target 0.0.0 (no downgrade script) lists
#                           NO UPDATE PATH for both databases and is NOT READY
# Exit codes: 0 all PASS, 1 FAIL, 2 INFRA, 3 build failed.
set -uo pipefail

QA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXT=$(dirname "$QA_DIR")
# shellcheck source=lib.sh
source "$QA_DIR/lib.sh"
for v in $(compgen -e | grep -E '^PG'); do unset "$v"; done
PGC=${1:-$HOME/.pgrx/16.15/pgrx-install/bin/pg_config}
[[ -x $PGC ]] || { echo "pg_config not found: $PGC" >&2; exit 2; }
QA_WORK_ROOT=${QA_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p "$QA_WORK_ROOT"
WORK=$(mktemp -d "$QA_WORK_ROOT/sqlfw-pkgupgrade.XXXXXX") || exit 2
export QA_RUN_DIR=$WORK QA_RESULTS=$WORK/results.tsv QA_SUPERUSER=qa_admin
export QA_SERVER_LOG=$WORK/logs/server.log
mkdir -p "$WORK/logs" "$WORK/evidence" "$WORK/dist"
: >"$QA_RESULTS"
m() { printf '%s=%s\n' "$1" "$2" >>"$WORK/manifest.txt"; }
echo "run directory: $WORK"
m started_at "$(date -Is)"
m pg_config "$PGC"
ID=baseline.package_upgrade
EV=package_upgrade
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }
qa_evidence "$EV" "# $ID ($("$PGC" --version))" ""

# --- packages -------------------------------------------------------------------
build() { # LABEL SOURCE -> PACKAGE path in $LABEL
    local out
    out=$("$EXT/packaging/build-package.sh" --pg-config "$PGC" --source "$2" --out "$WORK/dist" 2>&1)
    local rc=$?
    printf '%s\n' "$out" >"$WORK/logs/build-$1.log"
    [[ $rc == 0 ]] || { echo "package $1 failed (rc $rc), see logs/build-$1.log" >&2; exit 3; }
    printf -v "PACKAGE_$1" '%s' "$(sed -n 's/^package: //p' <<<"$out")"
}
build current "$EXT"
# Release 0.0.1: the same source with its version and an update script. A
# fixed path keeps its cargo target directory reusable between runs.
NEXT=$EXT/target/package-next-source
rm -rf "$NEXT" && mkdir -p "$NEXT"
(cd "$EXT" && tar --exclude=./target --exclude=./.git -cf - .) | (cd "$NEXT" && tar -xf -) || exit 2
sed -i '0,/^version = "0.0.0"$/s//version = "0.0.1"/' "$NEXT/Cargo.toml"
python3 - "$NEXT/Cargo.lock" <<'PY' || exit 2
import sys
p = sys.argv[1]
s = open(p).read()
old = 'name = "sql_firewall"\nversion = "0.0.0"'
assert old in s
open(p, "w").write(s.replace(old, 'name = "sql_firewall"\nversion = "0.0.1"', 1))
PY
sed -i "s/^default_version = '0.0.0'$/default_version = '0.0.1'/" "$NEXT/sql_firewall.control"
cp "$EXT/qa/fixtures/sql_firewall--0.0.0--0.0.1.sql" "$NEXT/sql/"
build next "$NEXT"
for p in current next; do
    var=PACKAGE_$p
    mkdir -p "$WORK/$p" && tar -C "$WORK/$p" -xzf "${!var}" || exit 2
    m "package_$p" "${!var} $(cut -d' ' -f1 "${!var}.sha256")"
done
PKG_CURRENT=$(ls -d "$WORK"/current/sql_firewall-*) PKG_NEXT=$(ls -d "$WORK"/next/sql_firewall-*)

# --- installation and cluster ------------------------------------------------------
INST=$WORK/inst DATA=$WORK/data
cp -a "$(dirname "$("$PGC" --bindir)")" "$INST" || exit 2
SPGC=$INST/bin/pg_config
rm -f "$("$SPGC" --pkglibdir)"/sql_firewall*.so "$("$SPGC" --sharedir)"/extension/sql_firewall*
"$PKG_CURRENT/install.sh" --pg-config "$SPGC" >"$WORK/logs/install-current.log" 2>&1 ||
    { infra "$ID" "install.sh of 0.0.0 failed: $(tail -3 "$WORK/logs/install-current.log")"; exit 2; }
export QA_PSQL=$INST/bin/psql
QA_SOCK=$(mktemp -d "${QA_SOCKET_ROOT:-/tmp}/sfpu.XXXXXX") && chmod 700 "$QA_SOCK"
export QA_SOCK QA_PORT=$((20000 + RANDOM % 8000))
"$INST/bin/initdb" -D "$DATA" -U "$QA_SUPERUSER" --auth=trust --no-sync -E UTF8 --locale=C >"$WORK/logs/initdb.log" 2>&1 || exit 2
cat >>"$DATA/postgresql.conf" <<EOF
listen_addresses = ''
port = $QA_PORT
unix_socket_directories = '$QA_SOCK'
unix_socket_permissions = 0700
logging_collector = off
max_worker_processes = 16
lc_messages = 'C'
fsync = off
log_line_prefix = '%m [%p] %q%u@%d app=%a '
EOF
start() { "$INST/bin/pg_ctl" -D "$DATA" -l "$QA_SERVER_LOG" -w -t 60 start >>"$WORK/logs/pg_ctl.log" 2>&1 && QA_PM_PID=$(head -1 "$DATA/postmaster.pid") && export QA_PM_PID; }
stop() { [[ -f $DATA/postmaster.pid ]] && "$INST/bin/pg_ctl" -D "$DATA" -m fast -w -t 60 stop >>"$WORK/logs/pg_ctl.log" 2>&1; }
finish() {
    stop
    local left P F I final=0
    left=$(pgrep -f "$INST/bin/postgres" | tr '\n' ' ')
    m surviving_processes "${left:-none}"
    [[ -z $left ]] && rm -rf "$QA_SOCK"
    P=$(awk -F'\t' '$1 == "PASS"' "$QA_RESULTS" | wc -l)
    F=$(awk -F'\t' '$1 == "FAIL"' "$QA_RESULTS" | wc -l)
    I=$(awk -F'\t' '$1 != "PASS" && $1 != "FAIL"' "$QA_RESULTS" | wc -l)
    ((I > 0 || P == 0)) && final=2
    ((final == 0 && F > 0)) && final=1
    if ((final == 0)) && [[ -z $left ]]; then
        rm -rf "$INST" "$DATA" "$WORK/current" "$WORK/next"
        m cleanup_status "OK (cluster, installation and unpacked packages removed; packages kept in dist/)"
    else
        m cleanup_status "retained for diagnostics"
    fi
    {
        echo "# sql_firewall package and update check ($("$PGC" --version))"
        echo
        echo "PASS=$P FAIL=$F INFRA=$I exit=$final"
        echo
        echo '| status | id | detail |'
        echo '|---|---|---|'
        awk -F'\t' '{ gsub(/\|/, "\\|", $3); printf "| %s | %s | %s |\n", $1, $2, $3 }' "$QA_RESULTS"
    } >"$WORK/summary.md"
    m final_exit_code "$final"
    echo "PASS=$P FAIL=$F INFRA=$I; report: $WORK/summary.md (exit $final)"
    exit "$final"
}
trap finish EXIT
start || { infra "$ID" "server start failed"; exit; }

DB1=qa_pu_one DB2=qa_pu_two DB3=qa_pu_three TPL=template1 NEWDB=qa_pu_fromtpl APP=qa_pu_app FPR=qa_pu_fp
TOOL=(--bindir "$INST/bin" -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER")
residue() { qa_admin "$1" "SELECT (SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') || '/' || (SELECT count(*) FROM pg_catalog.pg_class WHERE relname LIKE 'sql\\_firewall%')" && RESIDUE=${QA_STEP_OUT[1]}; }

# --- preload required -----------------------------------------------------------
qa_admin postgres "CREATE ROLE $QA_CANARY_ROLE LOGIN NOSUPERUSER" "CREATE DATABASE $DB1" "CREATE DATABASE $DB2" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_sql_steps "$QA_SUPERUSER" "$DB1" qa_pu "CREATE EXTENSION sql_firewall" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
refused="${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}" refused_err=${QA_STEP_ERR[1]}
residue "$DB1" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
if [[ $refused_err == true && $refused == "55000 sql_firewall: the library is not loaded through shared_preload_libraries; add sql_firewall to shared_preload_libraries, restart PostgreSQL, and run the command again" && $RESIDUE == 0/0 ]]; then
    ok "$ID.preload_required" "without preload: $refused; nothing left behind"
else
    fail "$ID.preload_required" "outcome '$refused' (error $refused_err), residue $RESIDUE"
fi
qa_admin postgres "ALTER SYSTEM SET shared_preload_libraries = 'sql_firewall'" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
stop; start || { infra "$ID" "restart with preload failed"; exit; }

# --- 0.0.0 with policy --------------------------------------------------------------
setup=("CREATE ROLE $APP LOGIN NOSUPERUSER" "CREATE ROLE $FPR LOGIN NOSUPERUSER")
for db in $DB1 $DB2; do
    setup+=("GRANT CONNECT ON DATABASE $db TO $APP, $FPR, $QA_CANARY_ROLE"
        "ALTER DATABASE $db SET sql_firewall.mode = 'enforce'"
        "ALTER ROLE $APP IN DATABASE $db SET sql_firewall.enable_fingerprint_learning = off"
        "ALTER ROLE $QA_CANARY_ROLE IN DATABASE $db SET sql_firewall.mode = 'enforce'")
done
qa_admin postgres "${setup[@]}" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
declare -A FP
for db in $DB1 $DB2; do
    qa_admin "$db" "CREATE EXTENSION sql_firewall" "CREATE TABLE public.qa_pu_t (id integer, v text)" \
        "INSERT INTO public.qa_pu_t VALUES (1, 'a'), (2, 'b')" "GRANT SELECT ON public.qa_pu_t TO $APP, $FPR" \
        "SELECT public.sql_firewall_approve_command('$APP', 'SELECT')" \
        "SELECT public.sql_firewall_approve_command('$FPR', 'SELECT')" \
        "SELECT public.sql_firewall_add_regex_rule('qa_pu_forbidden_[0-9]+', 'package test')" ||
        { infra "$ID" "$QA_INFRA_REASON"; exit; }
    qa_sql_steps "$FPR" "$db" qa_pu "SELECT v FROM public.qa_pu_t WHERE id = 1" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
    qa_wait_worker_live "$db" 90 || { infra "$ID" "$QA_INFRA_REASON"; exit; }
    qa_fp_identify "$db" "$FPR" SELECT "SELECT v FROM public.qa_pu_t WHERE id = 1"
    [[ $QA_FP_STATE == found ]] || { infra "$ID" "pending fingerprint not located in $db: $QA_FP_DUMP"; exit; }
    FP[$db]=$QA_FP_FINGERPRINT
    qa_admin "$db" "SELECT public.sql_firewall_approve_fingerprint('${FP[$db]}', '$FPR', 'SELECT')" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
done
# Extension OID and the policy as decisions (hit counters excluded: the
# decision checks below advance them).
SNAPSHOT="SELECT (SELECT oid FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall') || ' ' || count(*) || ' ' || md5(string_agg(r, E'\\n' ORDER BY r)) FROM (
    SELECT ROW('a', id, role_name, command_type, is_approved, created_at, updated_at)::text AS r FROM public.sql_firewall_command_approvals
    UNION ALL SELECT ROW('f', id, fingerprint, normalized_query, role_name, command_type, sample_query, is_approved, auto_approval_disabled, first_seen_at)::text FROM public.sql_firewall_query_fingerprints
    UNION ALL SELECT ROW('r', r.*)::text FROM public.sql_firewall_regex_rules r
    UNION ALL SELECT ROW('h', h.*)::text FROM public.sql_firewall_policy_history h) s"
decisions() { # DB -> DEC
    local out=()
    qa_check_success "$APP" "$1" qa_pu "SELECT count(*) FROM public.qa_pu_t" 2; out+=("approved=$QA_VERDICT")
    qa_check_rejection "$APP" "$1" qa_pu "SELECT 'qa_pu_forbidden_1'" 42501 "^sql_firewall: Query blocked by security regex pattern\.$"; out+=("regex=$QA_VERDICT")
    qa_check_success "$FPR" "$1" qa_pu "SELECT v FROM public.qa_pu_t WHERE id = 2" b; out+=("fingerprint=$QA_VERDICT")
    qa_check_rejection "$FPR" "$1" qa_pu "SELECT id FROM public.qa_pu_t WHERE v = 'b'" 42501 "^sql_firewall: Fingerprint"; out+=("other_shape=$QA_VERDICT")
    DEC="${out[*]}"
}
ALL="approved=PASS regex=PASS fingerprint=PASS other_shape=PASS"
declare -A BEFORE
for db in $DB1 $DB2; do
    decisions "$db"
    [[ $DEC == "$ALL" ]] || { infra "$ID" "decisions on 0.0.0 in $db: $DEC"; exit; }
    # The rejected shape's pending row is written by the consumer; a later
    # canary delivered means it is written.
    qa_wait_worker_live "$db" 60 || { infra "$ID" "$QA_INFRA_REASON"; exit; }
    qa_admin "$db" "$SNAPSHOT" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
    BEFORE[$db]=${QA_STEP_OUT[1]}
done
# A database whose update changes the policy: an event trigger on ALTER
# EXTENSION flips its approvals inside the update's transaction. Created
# before the extension goes into template1, which it would otherwise copy.
qa_admin postgres "CREATE DATABASE $DB3" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_admin "$DB3" "CREATE EXTENSION sql_firewall" "SELECT public.sql_firewall_approve_command('$APP', 'SELECT')" \
    "CREATE FUNCTION public.qa_pu_flip() RETURNS event_trigger LANGUAGE plpgsql AS \$f\$ BEGIN UPDATE public.sql_firewall_command_approvals SET is_approved = NOT is_approved; END \$f\$" \
    "CREATE EVENT TRIGGER qa_pu_flip ON ddl_command_end WHEN TAG IN ('ALTER EXTENSION') EXECUTE FUNCTION public.qa_pu_flip()" \
    "$SNAPSHOT" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
BEFORE[$DB3]=${QA_STEP_OUT[5]}
qa_admin "$TPL" "CREATE EXTENSION sql_firewall" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
qa_evidence "$EV" "- 0.0.0 installed in $DB1, $DB2, $DB3 and $TPL (extension oid + policy digest): ${BEFORE[$DB1]} / ${BEFORE[$DB2]} / ${BEFORE[$DB3]}"

version_row() { qa_admin "$DB1" "SELECT library_version || '/' || coalesce(running_version, '-') FROM public.sql_firewall_library_version()" && VERSIONS=${QA_STEP_OUT[1]}; }

# --- install 0.0.1 while 0.0.0 runs ----------------------------------------------------------
"$PKG_NEXT/install.sh" --pg-config "$SPGC" >"$WORK/logs/install-next.log" 2>&1 ||
    { infra "$ID" "install.sh of 0.0.1 failed: $(tail -3 "$WORK/logs/install-next.log")"; exit; }
version_row || { infra "$ID" "$QA_INFRA_REASON"; exit; }
decisions "$DB1"
if [[ $VERSIONS == 0.0.0/0.0.0 && $DEC == "$ALL" ]] && kill -0 "$QA_PM_PID"; then
    ok "$ID.install_while_running" "after install.sh of 0.0.1 the running server still runs library 0.0.0 ($VERSIONS) and decides as before ($DEC)"
else
    fail "$ID.install_while_running" "versions $VERSIONS; decisions $DEC"
fi

tool_out=$("$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --check 2>&1); tool_rc=$?
qa_evidence "$EV" "- tool --check before the restart (exit $tool_rc):" '```' "$tool_out" '```'
if [[ $tool_rc == 3 && $tool_out != *ERROR* && $tool_out == *"$DB1"*"update via 0.0.0 -> 0.0.1"* && $tool_out == *"the server runs library 0.0.0, not 0.0.1"* ]]; then
    ok "$ID.not_ready" "before the restart the tool reported NOT READY (exit 3): the server runs library 0.0.0, not 0.0.1"
else
    fail "$ID.not_ready" "exit $tool_rc: $(tr '\n' ' ' <<<"$tool_out")"
fi

qa_sql_steps "$QA_SUPERUSER" "$DB1" qa_pu "ALTER EXTENSION sql_firewall UPDATE TO '0.0.1'" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
guard="${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
qa_admin "$DB1" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" || { infra "$ID" "$QA_INFRA_REASON"; exit; }
if [[ ${QA_STEP_OUT[1]} == 0.0.0 && $guard == "55000 sql_firewall: the server runs library 0.0.0, not 0.0.1; install the 0.0.1 package, restart PostgreSQL, and update again" ]]; then
    ok "$ID.update_script_guard" "a manual update before the restart was refused by the update script ($guard); the version stayed 0.0.0"
else
    fail "$ID.update_script_guard" "outcome '$guard'; version ${QA_STEP_OUT[1]}"
fi

# --- restart, check, update ------------------------------------------------------------------
stop; start || { infra "$ID" "restart with 0.0.1 failed"; exit; }
version_row || { infra "$ID" "$QA_INFRA_REASON"; exit; }
tool_out=$("$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --check 2>&1); tool_rc=$?
qa_evidence "$EV" "- after the restart, library versions $VERSIONS; tool --check (exit $tool_rc):" '```' "$tool_out" '```'
if [[ $VERSIONS == 0.0.1/0.0.1 && $tool_rc == 0 && $tool_out != *ERROR* && $tool_out == *"$DB1"*"update via 0.0.0 -> 0.0.1"* && $tool_out == *"$DB2"*"update via 0.0.0 -> 0.0.1"* &&
    $tool_out == *"$DB3"*"update via 0.0.0 -> 0.0.1"* && $tool_out == *"$TPL (template)"*"update via 0.0.0 -> 0.0.1"* && $tool_out == *"ready: 4 database(s)"* ]]; then
    ok "$ID.ready" "after the restart the server runs library 0.0.1 and --check listed $DB1, $DB2, $DB3 and $TPL (template) with path 0.0.0 -> 0.0.1"
else
    fail "$ID.ready" "versions $VERSIONS; exit $tool_rc: $(tr '\n' ' ' <<<"$tool_out")"
fi

# The caller's umask is the common 022: the backup must still be private.
tool_out=$(umask 022 && "$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --backup-dir "$WORK/backups" --yes 2>&1); tool_rc=$?
qa_evidence "$EV" "- tool --yes under umask 022 (exit $tool_rc):" '```' "$tool_out" '```'
bdir=$(ls -d "$WORK"/backups/sql_firewall-0.0.1-* 2>/dev/null | head -1)
modes=$( [[ -n $bdir ]] && { stat -c '%a %n' "$bdir"; stat -c '%a %n' "$bdir"/*; } )
qa_evidence "$EV" "- backup modes:" '```' "$modes" '```'
backups_ok=0
if [[ -n $bdir && -s $bdir/roles.sql && -s $bdir/$DB1.dump && -s $bdir/$DB2.dump && -s $bdir/$DB3.dump && -s $bdir/$TPL.dump ]] && (cd "$bdir" && sha256sum --quiet -c SHA256SUMS) &&
    "$INST/bin/pg_restore" --list "$bdir/$DB1.dump" | grep -q "TABLE DATA public sql_firewall_command_approvals"; then
    backups_ok=1
fi
bad_modes=$(awk '($2 ~ /sql_firewall-0\.0\.1-[0-9T]+$/ && $1 != "700") || ($2 !~ /sql_firewall-0\.0\.1-[0-9T]+$/ && $1 != "600")' <<<"$modes")
if [[ $backups_ok == 1 && -n $modes && -z $bad_modes ]]; then
    ok "$ID.backup_private" "under umask 022 the backup directory was 0700 and roles.sql, the four dumps and SHA256SUMS 0600; checksums and pg_restore --list verified, policy rows in the dump"
else
    fail "$ID.backup_private" "backups ok $backups_ok; modes: $(tr '\n' ' ' <<<"$modes")"
fi
if [[ $tool_rc == 1 && $tool_out == *"$DB1: updated to 0.0.1; policy unchanged"* && $tool_out == *"$DB2: updated to 0.0.1; policy unchanged"* &&
    $tool_out == *"$TPL: updated to 0.0.1; policy unchanged"*"template database, no consumer"* && $tool_out == *"update finished with failures"* ]]; then
    ok "$ID.update" "--yes updated $DB1, $DB2 and $TPL to 0.0.1 and verified them (no consumer expected in the template); it exited 1 for $DB3 (below)"
else
    fail "$ID.update" "exit $tool_rc: $(tr '\n' ' ' <<<"$tool_out")"
fi
qa_admin "$DB3" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" "$SNAPSHOT" ||
    { infra "$ID.policy_guard" "$QA_INFRA_REASON"; exit; }
guard3="${QA_STEP_OUT[1]} ${QA_STEP_OUT[2]}"
qa_admin "$DB3" "DROP EVENT TRIGGER qa_pu_flip" "DROP FUNCTION public.qa_pu_flip()" || { infra "$ID.policy_guard" "$QA_INFRA_REASON"; exit; }
retry_out=$(umask 022 && "$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --backup-dir "$WORK/backups2" --yes 2>&1); retry_rc=$?
qa_evidence "$EV" "- after dropping the event trigger, tool --yes (exit $retry_rc):" '```' "$retry_out" '```'
qa_admin "$DB3" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" || { infra "$ID.policy_guard" "$QA_INFRA_REASON"; exit; }
if [[ $tool_out == *"$DB3: update FAILED and rolled back"*"the update changed the policy"* && $guard3 == "0.0.0 ${BEFORE[$DB3]}" &&
    $retry_rc == 0 && $retry_out == *"update finished: 1 database(s) at 0.0.1"* && ${QA_STEP_OUT[1]} == 0.0.1 ]]; then
    ok "$ID.policy_guard" "the update whose transaction changed the policy was refused before COMMIT and rolled back: $DB3 kept 0.0.0 and its policy (${BEFORE[$DB3]}); without the trigger the next run updated it"
else
    fail "$ID.policy_guard" "after the first run: $guard3 (before ${BEFORE[$DB3]}); retry exit $retry_rc, version ${QA_STEP_OUT[1]}: $(tr '\n' ' ' <<<"$retry_out")"
fi
qa_admin postgres "CREATE DATABASE $NEWDB" || { infra "$ID.template" "$QA_INFRA_REASON"; exit; }
qa_admin "$NEWDB" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" || { infra "$ID.template" "$QA_INFRA_REASON"; exit; }
new_version=${QA_STEP_OUT[1]}
qa_admin "$TPL" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" || { infra "$ID.template" "$QA_INFRA_REASON"; exit; }
if [[ ${QA_STEP_OUT[1]} == 0.0.1 && $new_version == 0.0.1 ]]; then
    ok "$ID.template" "$TPL was updated to 0.0.1, and $NEWDB created from it has 0.0.1"
else
    fail "$ID.template" "$TPL ${QA_STEP_OUT[1]}, $NEWDB $new_version"
fi

problems=()
for db in $DB1 $DB2; do
    qa_admin "$db" "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" \
        "SELECT obj_description('public.sql_firewall_command_approvals'::regclass, 'pg_class')" "$SNAPSHOT" ||
        { infra "$ID.preserved" "$QA_INFRA_REASON"; exit; }
    [[ ${QA_STEP_OUT[1]} == 0.0.1 ]] || problems+=("$db version ${QA_STEP_OUT[1]}")
    [[ ${QA_STEP_OUT[2]} == "Command approvals per role (sql_firewall 0.0.1)" ]] || problems+=("$db comment '${QA_STEP_OUT[2]}'")
    [[ ${QA_STEP_OUT[3]} == "${BEFORE[$db]}" ]] || problems+=("$db oid/policy ${BEFORE[$db]} -> ${QA_STEP_OUT[3]}")
    decisions "$db"
    [[ $DEC == "$ALL" ]] || problems+=("$db decisions $DEC")
    qa_wait_worker_live "$db" 60 || problems+=("$db consumer: $QA_INFRA_REASON")
done
if ((${#problems[@]} == 0)); then
    ok "$ID.preserved" "both databases at 0.0.1 with the update script's change; extension OIDs, policy, history and fingerprint approvals unchanged; approved statements ran, the regex rule and an unapproved shape refused; consumers live"
else
    fail "$ID.preserved" "${problems[*]}"
fi

tool_out=$("$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --check 2>&1); tool_rc=$?
if [[ $tool_rc == 0 && $tool_out != *ERROR* && $tool_out == *"nothing to update"* ]]; then
    ok "$ID.idempotent" "a second --check found nothing to update"
else
    fail "$ID.idempotent" "exit $tool_rc: $(tr '\n' ' ' <<<"$tool_out")"
fi
tool_out=$("$PKG_NEXT/sql_firewall_upgrade" "${TOOL[@]}" --check --target 0.0.0 2>&1); tool_rc=$?
qa_evidence "$EV" "- tool --check --target 0.0.0 (exit $tool_rc):" '```' "$tool_out" '```'
if [[ $tool_rc == 3 && $tool_out == *"$DB1"*"NO UPDATE PATH from 0.0.1 to 0.0.0"* && $tool_out == *"$DB2"*"NO UPDATE PATH from 0.0.1 to 0.0.0"* && $tool_out != *ERROR* ]]; then
    ok "$ID.no_path" "a target without an update path (0.0.1 -> 0.0.0) was listed as NO UPDATE PATH for both databases and reported NOT READY (exit 3)"
else
    fail "$ID.no_path" "exit $tool_rc: $(tr '\n' ' ' <<<"$tool_out")"
fi
problems=$(grep -E 'PANIC:|terminated by signal|sql_firewall.*(failed|could not)' "$QA_SERVER_LOG" | head -5)
if [[ -z $problems ]]; then
    ok "$ID.log" "no crash or firewall failure in the server log across both libraries"
else
    fail "$ID.log" "$problems"
fi
exit

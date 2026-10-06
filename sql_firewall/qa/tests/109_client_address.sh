#!/usr/bin/env bash
# Phase 8: the client address policy uses (README 6.1c "Client address").
#
# The disposable cluster normally has no TCP listener. This test opens one on
# 127.0.0.1 and ::1 for two password-authenticated roles only (every other TCP
# connection is rejected by pg_hba), restarts the server, and restores the
# listener, pg_hba.conf, and the settings afterwards.
#
# Contract:
#   ipv4          blocked_ips compares the connection's numeric address
#   log_hostname  with log_hostname on (the server resolves the client to a
#                 name), the same address is still blocked
#   ipv6          ::1 matches an equivalent spelling (0:0:0:0:0:0:0:1)
#   other         another address in the list does not block
#   binding       a role bound to 127.0.0.1 connects over it; the same role
#                 is refused over ::1 and over the Unix socket (no address)
#   settings      a non-address entry in blocked_ips or role_ip_bindings is
#                 rejected by the setting itself
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.client_address
EV=client_address
DB=qa_netpol
IPR=qa_net_ip BOUND=qa_net_bound PW=qa_net_pw_7741

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""
qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE $IPR LOGIN NOSUPERUSER PASSWORD '$PW'" "CREATE ROLE $BOUND LOGIN NOSUPERUSER PASSWORD '$PW'" \
    "GRANT CONNECT ON DATABASE $DB TO $IPR, $BOUND" \
    "ALTER ROLE $IPR IN DATABASE $DB SET sql_firewall.enable_ip_blocking = 'on'" \
    "ALTER ROLE $BOUND IN DATABASE $DB SET sql_firewall.enable_role_ip_binding = 'on'" \
    "ALTER ROLE $BOUND IN DATABASE $DB SET sql_firewall.role_ip_bindings = '$BOUND@127.0.0.1'" \
    "SHOW hba_file" "SHOW data_directory" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
HBA=${QA_STEP_OUT[7]} DATA=${QA_STEP_OUT[8]}
qa_admin "$DB" "SELECT public.sql_firewall_approve_command('$IPR', 'SELECT')" "SELECT public.sql_firewall_approve_command('$BOUND', 'SELECT')" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

pg_ctl=$(dirname "$(readlink "/proc/$QA_PM_PID/exe")")/pg_ctl
restart() {
    "$pg_ctl" -D "$DATA" -l "$QA_SERVER_LOG" -w -t 60 restart >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 || return 1
    QA_PM_PID=$(head -1 "$DATA/postmaster.pid")
}
cp "$HBA" "$QA_RUN_DIR/pg_hba.conf.orig"
restore() {
    cp "$QA_RUN_DIR/pg_hba.conf.orig" "$HBA"
    qa_admin postgres "ALTER SYSTEM RESET listen_addresses" "ALTER SYSTEM RESET log_hostname" >/dev/null || true
    restart || true
}
trap restore EXIT
{
    printf 'host all %s,%s 127.0.0.1/32 scram-sha-256\n' "$IPR" "$BOUND"
    printf 'host all %s,%s ::1/128 scram-sha-256\n' "$IPR" "$BOUND"
    printf 'host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n'
    cat "$QA_RUN_DIR/pg_hba.conf.orig"
} >"$HBA"
qa_admin postgres "ALTER SYSTEM SET listen_addresses = '127.0.0.1,::1'" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
restart || { infra "$ID" "restart with TCP failed: $(tail -5 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID" "worker after restart: $QA_INFRA_REASON"; exit 0; }

tcp() { # HOST ROLE -> TCP_OUT (allow | SQLSTATE: message)
    local out
    out=$(env PGPASSWORD=$PW PGCONNECT_TIMEOUT=10 "$QA_PSQL" -X -A -t -v ON_ERROR_STOP=1 -v VERBOSITY=default \
        "host=$1 port=$QA_PORT dbname=$DB user=$2 sslmode=disable" -c "SELECT 1 AS ok" 2>&1)
    if [[ $out == 1 ]]; then TCP_OUT=allow; else TCP_OUT=$(grep -o 'ERROR: .*' <<<"$out" | head -1); TCP_OUT=${TCP_OUT:-$out}; fi
}
set_blocked() { qa_admin postgres "ALTER ROLE $IPR IN DATABASE $DB SET sql_firewall.blocked_ips = '$1'"; }

set_blocked 127.0.0.1 || { infra "$ID.ipv4" "$QA_INFRA_REASON"; exit 0; }
tcp 127.0.0.1 $IPR
if [[ $TCP_OUT == "ERROR:  sql_firewall: Connection from blocked IP address '127.0.0.1' is not allowed." ]]; then
    ok "$ID.ipv4" "a TCP connection from 127.0.0.1 was refused by blocked_ips"
else
    fail "$ID.ipv4" "$TCP_OUT"
fi

qa_admin postgres "ALTER SYSTEM SET log_hostname = on" "SELECT pg_reload_conf()" || { infra "$ID.log_hostname" "$QA_INFRA_REASON"; exit 0; }
sleep 1
tcp 127.0.0.1 $IPR
blocked_out=$TCP_OUT
names=$(env PGPASSWORD=$PW "$QA_PSQL" -X -A -t "host=127.0.0.1 port=$QA_PORT dbname=postgres user=$IPR sslmode=disable" \
    -c "SELECT coalesce(client_hostname, '(none)') || ' ' || host(client_addr) FROM pg_stat_activity WHERE pid = pg_backend_pid()" 2>&1)
qa_evidence "$EV" "- with log_hostname on, pg_stat_activity shows: $names"
if [[ $blocked_out == "ERROR:  sql_firewall: Connection from blocked IP address '127.0.0.1' is not allowed." && $names != "(none) "* ]]; then
    ok "$ID.log_hostname" "with log_hostname on (the server named the client '${names%% *}') the connection was still refused by its numeric address"
else
    fail "$ID.log_hostname" "outcome: $blocked_out; pg_stat_activity: $names"
fi

if set_blocked 0:0:0:0:0:0:0:1; then
    tcp ::1 $IPR
    if [[ $TCP_OUT == "ERROR:  sql_firewall: Connection from blocked IP address '::1' is not allowed." ]]; then
        ok "$ID.ipv6" "a connection from ::1 matched the listed 0:0:0:0:0:0:0:1"
    elif [[ $TCP_OUT == *"could not connect"* || $TCP_OUT == *"Cannot assign"* || $TCP_OUT == *"Connection refused"* ]]; then
        infra "$ID.ipv6" "no IPv6 loopback listener: $TCP_OUT"
    else
        fail "$ID.ipv6" "$TCP_OUT"
    fi
else
    infra "$ID.ipv6" "$QA_INFRA_REASON"
fi

set_blocked 127.0.0.2 || { infra "$ID.other" "$QA_INFRA_REASON"; exit 0; }
tcp 127.0.0.1 $IPR
[[ $TCP_OUT == allow ]] && ok "$ID.other" "127.0.0.1 was allowed while only 127.0.0.2 was listed" || fail "$ID.other" "$TCP_OUT"

tcp 127.0.0.1 $BOUND; b4=$TCP_OUT
tcp ::1 $BOUND; b6=$TCP_OUT
qa_sql_steps $BOUND "$DB" qa_net "SELECT 1" || { infra "$ID.binding" "$QA_INFRA_REASON"; exit 0; }
bsock="${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
qa_evidence "$EV" "- bound role: 127.0.0.1 $b4; ::1 $b6; socket $bsock"
if [[ $b4 == allow && $b6 == "ERROR:  sql_firewall: Role '$BOUND' is not allowed to connect from IP '::1'." &&
    $bsock == "42501 sql_firewall: Role '$BOUND' is not allowed to connect from IP '[local]'." ]]; then
    ok "$ID.binding" "the bound role connected from 127.0.0.1 and was refused from ::1 and over the Unix socket, which has no address"
elif [[ $b6 == *"could not connect"* ]]; then
    infra "$ID.binding" "no IPv6 loopback listener: $b6"
else
    fail "$ID.binding" "127.0.0.1: $b4; ::1: $b6; socket: $bsock"
fi

qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin "SET sql_firewall.blocked_ips = '10.0.0.1, localhost'" \
    "SET sql_firewall.role_ip_bindings = 'app@not-an-ip'" || { infra "$ID.settings" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_STATE[1]} == 22023 && ${QA_STEP_STATE[2]} == 22023 ]]; then
    ok "$ID.settings" "a host name in blocked_ips and a non-address binding were rejected (22023): ${QA_STEP_MSG[1]}"
else
    fail "$ID.settings" "blocked_ips: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}; bindings: ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}"
fi

trap - EXIT
restore
qa_admin postgres "SHOW listen_addresses" || { infra "$ID.restore" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == "" ]] && ok "$ID.restore" "TCP listener, pg_hba.conf, and settings restored; the server runs socket-only again" ||
    fail "$ID.restore" "listen_addresses is '${QA_STEP_OUT[1]}'"
exit 0

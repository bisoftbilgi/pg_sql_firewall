#!/usr/bin/env bash
# Lifecycle fault-injection self-test for run.sh (all resources task-owned).
#
# Runs `run.sh --no-tests` (build, stage, start, verify, stop) under:
#   control                 no fault: exit 0, clean stop, resources removed
#   start_bad_config        server never starts: exit 2, nothing survives
#   start_fail_after_spawn  start reported failed while the child runs:
#                           exit 2, the live child is found and stopped
#   stop_fail               both stop attempts fail: exit 2, cleanup FAILED,
#                           survivors reported, socket/data NOT removed
#   stale_pidfile           postmaster.pid names an unrelated (decoy) process:
#                           exit 2, nothing signalled, decoy untouched
# Servers deliberately left running by a fault are stopped here afterwards,
# after this script re-verifies ownership (staged binary path + data dir argv).
set -uo pipefail
QA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d "${QA_WORK_ROOT:-${TMPDIR:-/tmp}}/sqlfw-qa-lifecycle.XXXXXX") || exit 2
echo "work directory: $WORK"
FAILS=0

check() { # DESCRIPTION CONDITION...
    local d=$1
    shift
    if "$@"; then echo "  ok    $d"; else echo "  FAIL  $d"; FAILS=$((FAILS + 1)); fi
}
mf() { sed -n "s/^$1=//p" "$RUN/manifest.txt" | tail -1; }

owned_by() { # STAGE -> pids running that staged postgres under our uid
    local p exe
    for p in /proc/[0-9]*; do
        exe=$(readlink "$p/exe" 2>/dev/null) || continue
        [[ $exe == "$1/bin/postgres" || $exe == "$1/bin/postgres (deleted)" ]] || continue
        [[ $(awk '/^Uid:/ { print $2 }' "$p/status") == "$(id -u)" ]] && echo "${p#/proc/}"
    done
}

# Stop a server a fault left running. Ownership re-verified here.
driver_stop() { # RUN
    local stage=$1/pginstall pid pm="" deadline
    for pid in $(owned_by "$stage"); do
        tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -qxF "$1/pgdata" && pm=$pid
    done
    [[ -n $pm ]] || return 0
    kill -INT "$pm"
    deadline=$((SECONDS + 30))
    while [[ -n $(owned_by "$stage") ]] && ((SECONDS < deadline)); do sleep 0.2; done
    [[ -z $(owned_by "$stage") ]] || kill -QUIT "$pm"
    deadline=$((SECONDS + 15))
    while [[ -n $(owned_by "$stage") ]] && ((SECONDS < deadline)); do sleep 0.2; done
    [[ -z $(owned_by "$stage") ]] || return 1
    # The runner kept the socket dir because the server was alive; remove it
    # now, only if its owner marker names this run.
    local sock
    sock=$(sed -n 's/^socket_dir=//p' "$1/manifest.txt" | tail -1)
    if [[ -n $sock && -f $sock/.sqlfw-qa-owner && $(cat "$sock/.sqlfw-qa-owner") == "$(basename "$1")" ]]; then
        rm -rf -- "$sock"
    fi
    [[ ! -e $sock ]]
}

scenario() { # NAME FAULT [extra env...]
    local name=$1 fault=$2
    shift 2
    echo "== $name"
    env QA_WORK_ROOT="$WORK" QA_FAULT_INJECT="$fault" "$@" timeout 600 "$QA_DIR/run.sh" --no-tests \
        >"$WORK/$name.out" 2>&1
    RC=$?
    RUN=$(sed -n 's/^run directory: //p' "$WORK/$name.out")
    echo "  run: $RUN (exit $RC)"
    echo "  $(grep -E '^(startup_status|surviving_processes|cleanup_status)=' "$RUN/manifest.txt" | tr '\n' ' ')"
}

scenario control ""
check "exit code 0" test "$RC" -eq 0
check "startup OK" test "$(mf startup_status)" = OK
check "no surviving processes" test "$(mf surviving_processes)" = none
check "cleanup removed cluster" test ! -e "$RUN/pgdata"
check "socket dir removed" test ! -e "$(mf socket_dir)"

scenario start_bad_config start_bad_config
check "exit code 2" test "$RC" -eq 2
check "startup recorded FAILED" grep -q '^startup_status=FAILED' "$RUN/manifest.txt"
check "no surviving processes" test "$(mf surviving_processes)" = none
check "cleanup OK" grep -q '^cleanup_status=OK' "$RUN/manifest.txt"
check "no owned process now" test -z "$(owned_by "$RUN/pginstall")"

scenario start_fail_after_spawn start_fail_after_spawn
check "exit code 2" test "$RC" -eq 2
check "a child existed at failure time" test -n "$(mf startup_owned_processes)"
check "no surviving processes" test "$(mf surviving_processes)" = none
check "cleanup OK" grep -q '^cleanup_status=OK' "$RUN/manifest.txt"
check "no owned process now" test -z "$(owned_by "$RUN/pginstall")"

scenario stop_fail stop_fail
check "exit code 2" test "$RC" -eq 2
check "survivors reported" test "$(mf surviving_processes)" != none
check "cleanup recorded FAILED" grep -q '^cleanup_status=FAILED' "$RUN/manifest.txt"
check "stop failure recorded as INFRA" grep -q $'^INFRA\tlifecycle.finalize\tserver stop failed' "$RUN/results.tsv"
check "data dir retained while server alive" test -d "$RUN/pgdata"
check "socket dir retained while server alive" test -d "$(mf socket_dir)"
check "reported survivors are really alive" bash -c "kill -0 $(mf surviving_processes | cut -d' ' -f1)"
check "driver stopped the surviving owned server" driver_stop "$RUN"

sleep 600 &
DECOY=$!
scenario stale_pidfile stale_pidfile QA_FAULT_DECOY_PID="$DECOY"
check "exit code 2" test "$RC" -eq 2
check "refusal recorded" grep -q 'not this run.s postmaster.*signalled nothing' "$RUN/results.tsv"
check "decoy process untouched" kill -0 "$DECOY"
check "survivors reported" test "$(mf surviving_processes)" != none
check "cleanup recorded FAILED" grep -q '^cleanup_status=FAILED' "$RUN/manifest.txt"
check "driver stopped the surviving owned server" driver_stop "$RUN"
kill "$DECOY" 2>/dev/null
wait "$DECOY" 2>/dev/null

echo "== final process check"
LEFT="" SOCKS=""
for r in "$WORK"/sqlfw-qa.*; do
    LEFT+=$(owned_by "$r/pginstall" | tr '\n' ' ')
    s=$(sed -n 's/^socket_dir=//p' "$r/manifest.txt" | tail -1)
    [[ -n $s && -e $s ]] && SOCKS+="$s "
done
check "no PostgreSQL process from any lifecycle run remains" test -z "${LEFT// /}"
[[ -n ${LEFT// /} ]] && echo "  surviving: $LEFT"
check "no socket directory from any lifecycle run remains" test -z "$SOCKS"
[[ -n $SOCKS ]] && echo "  remaining: $SOCKS"

if ((FAILS == 0)); then
    echo "PASS selftest.lifecycle ($WORK)"
    exit 0
fi
echo "FAIL selftest.lifecycle: $FAILS check(s) failed ($WORK)"
exit 1

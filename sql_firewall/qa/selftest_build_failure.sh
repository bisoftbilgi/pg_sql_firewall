#!/usr/bin/env bash
# Demonstrates that a failed build is never accepted, even when a usable
# artifact for the same PostgreSQL target and build profile exists.
#
# 1. Prerequisite: an isolated successful `run.sh --build-only --keep` from the
#    real source produces the stale candidates (its package .so and the cargo
#    target library). Without them the stale-fallback scenario is NOT TESTED.
# 2. The same runner settings (QA_PG_CONFIG, QA_BUILD_PROFILE, QA_TARGET_DIR
#    as inherited from the caller) are used against a scratch copy of the
#    source with an injected compile error.
# 3. Verified: the intended compile error occurred, the run stopped with the
#    build-failure code, no artifact was accepted, no cluster started, no test
#    executed, and the stale candidates still existed but were not used.
# The working tree is not modified.
set -uo pipefail
QA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXT_DIR=$(dirname "$QA_DIR")
WORK=$(mktemp -d "${QA_WORK_ROOT:-${TMPDIR:-/tmp}}/sqlfw-qa-buildfail.XXXXXX") || exit 2
trap 'rm -rf -- "$WORK/src-copy"' EXIT
echo "work directory: $WORK"
mfv() { sed -n "s/^$2=//p" "$1" | tail -1; }

# --- 1. prerequisite: a real, current, usable artifact for this target/profile
QA_WORK_ROOT=$WORK "$QA_DIR/run.sh" --build-only --keep >"$WORK/prereq.out" 2>&1
PRE_RC=$?
PRE_RUN=$(sed -n 's/^run directory: //p' "$WORK/prereq.out")
PRE=$PRE_RUN/manifest.txt
PRE_SO=$(mfv "$PRE" artifact_so)
PRE_LIB=$(mfv "$PRE" target_library)
if [[ $PRE_RC -ne 0 || ! -f $PRE_SO || ! -f $PRE_LIB ]]; then
    echo "NOT TESTED selftest.failed_build_not_accepted: prerequisite build did not produce a usable artifact (rc=$PRE_RC, run $PRE_RUN)"
    exit 2
fi
PRE_SO_SHA=$(sha256sum "$PRE_SO" | cut -d' ' -f1)
PRE_LIB_SHA=$(sha256sum "$PRE_LIB" | cut -d' ' -f1)
echo "prerequisite run: $PRE_RUN"
echo "  target=$(mfv "$PRE" pg_feature) profile=$(mfv "$PRE" build_profile) target_dir=$(mfv "$PRE" cargo_target_dir)"
echo "  package artifact: $PRE_SO sha256=$PRE_SO_SHA"
echo "  target library:   $PRE_LIB sha256=$PRE_LIB_SHA"

# --- 2. same settings, broken source copy
mkdir "$WORK/src-copy"
tar -C "$EXT_DIR" --exclude=./target --exclude=./qa -cf - . | tar -C "$WORK/src-copy" -xf - || exit 2
MARK="sqlfw-qa: intentional build failure (harness self-test)"
printf '\ncompile_error!("%s");\n' "$MARK" >>"$WORK/src-copy/src/lib.rs"
QA_SOURCE_DIR=$WORK/src-copy QA_WORK_ROOT=$WORK "$QA_DIR/run.sh" >"$WORK/fail.out" 2>&1
RC=$?
RUN=$(sed -n 's/^run directory: //p' "$WORK/fail.out")
M=$RUN/manifest.txt
echo "failing run: $RUN (exit $RC)"
grep -E '^(pg_feature|build_profile|cargo_target_dir|build_exit_code|build_status|build_failure)=' "$M" | sed 's/^/  /'

# --- 3. verification
ok=1
check() { if "${@:2}"; then echo "  ok    $1"; else echo "  FAIL  $1"; ok=0; fi; }
for k in pg_config pg_feature build_profile cargo_target_dir; do
    check "same $k as prerequisite ($(mfv "$M" $k))" test "$(mfv "$M" $k)" = "$(mfv "$PRE" $k)"
done
check "exit code 3 (build failure)" test "$RC" -eq 3
check "manifest build_status=FAILED" grep -qx 'build_status=FAILED' "$M"
check "intended compile error occurred" grep -qF "error: $MARK" "$RUN/logs/build.log"
check "sql_firewall itself failed to compile" grep -qE 'could not compile `sql_firewall`($| )' "$RUN/logs/build.log"
check "no artifact accepted" bash -c "! grep -qE '^(artifact_so|staged_so|runtime_mapped_library)=' '$M'"
check "no cluster started" bash -c "! grep -qE '^(postmaster_pid|startup_status|socket_dir)=' '$M' && [[ ! -e '$RUN/pgdata' && ! -e '$RUN/pginstall' ]]"
check "no runtime tests executed" bash -c "! grep -qE $'\\t(selftest|baseline)[.]' '$RUN/results.tsv'"
check "stale package artifact still present and unchanged" test "$(sha256sum "$PRE_SO" | cut -d' ' -f1)" = "$PRE_SO_SHA"
check "stale target library still present and unchanged" test "$(sha256sum "$PRE_LIB" | cut -d' ' -f1)" = "$PRE_LIB_SHA"
check "stale paths not referenced by the failing run" bash -c "! grep -qF -e '$PRE_SO' -e 'libsql_firewall.so' '$M'"
if ((ok)); then
    echo "PASS selftest.failed_build_not_accepted (stale-artifact scenario tested)"
    exit 0
fi
echo "FAIL selftest.failed_build_not_accepted"
exit 1

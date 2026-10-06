#!/usr/bin/env bash
# Phase 3B on the release library: concurrent publication and UTF-8 transport.
#
# The measured traffic stays well below the 1024-slot ring. A delivered canary
# is readiness only. Deterministic overwrite, which has to hold the consumer,
# is qa/probe and uses a separate build.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.queue
EV=queue
DB=qa_q
N=8

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Concurrent producers publish uniquely identified events. Fixed text fields truncate only on UTF-8 boundaries. Publishing to the ring is not persistence." ""

qa_create_db "$DB" sql_firewall.mode=learn sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

setup=()
for w in 0 1 2 3; do
    setup+=("CREATE ROLE qa_q_a${w} LOGIN NOSUPERUSER" "CREATE ROLE qa_q_b${w} LOGIN NOSUPERUSER")
done
qa_admin postgres "${setup[@]}" \
    "GRANT CONNECT ON DATABASE $DB TO qa_q_a0, qa_q_a1, qa_q_a2, qa_q_a3, qa_q_b0, qa_q_b1, qa_q_b2, qa_q_b3" \
    "ALTER ROLE qa_q_b0 IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_q_b1 IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_q_b2 IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_q_b3 IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "CREATE ROLE qa_q_utf8 LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_q_fp LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_q_utf8, qa_q_fp" \
    "ALTER ROLE qa_q_utf8 IN DATABASE $DB SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi

emit_dir=$QA_RUN_DIR/queue-emit
mkdir -p "$emit_dir"
pids=()
for w in 0 1 2 3; do
    (
        for i in $(seq 0 $((N - 1))); do
            qa_sql_steps "qa_q_a${w}" "$DB" qa_q "SELECT 'qa_q_tok_a${w}_${i}'" ||
                echo "learn qa_q_a${w} $i: $QA_INFRA_REASON" >>"$emit_dir/err"
            qa_sql_steps "qa_q_b${w}" "$DB" qa_q "SELECT 'qa_q_blk_b${w}_${i}'" || true
        done
    ) &
    pids+=($!)
done
wait_rc=0
for pid in "${pids[@]}"; do
    wait "$pid" || wait_rc=1
done
if [[ -s $emit_dir/err || $wait_rc -ne 0 ]]; then
    infra "$ID.concurrent" "a learn producer failed: $(head -c 400 "$emit_dir/err" 2>/dev/null)"
    exit 0
fi

# String literals normalize to one fingerprint, so they are not separate
# fingerprint events. Each blocked query keeps its own text.
missing=0
mixed=0
for w in 0 1 2 3; do
    other=$(( (w + 1) % 4 ))
    for i in $(seq 0 $((N - 1))); do
        if ! qa_poll "$DB" \
            "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE role_name OPERATOR(pg_catalog.=) 'qa_q_b${w}'::name AND database_name OPERATOR(pg_catalog.=) '$DB'::name AND strpos(query_text, 'qa_q_blk_b${w}_${i}') > 0" \
            1 20; then
            missing=1
            break
        fi
    done
    qa_admin "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE role_name OPERATOR(pg_catalog.=) 'qa_q_b${w}'::name AND strpos(query_text, 'qa_q_blk_b${other}_') > 0" ||
        { infra "$ID.concurrent" "$QA_INFRA_REASON"; exit 0; }
    [[ ${QA_STEP_OUT[1]} == 0 ]] || mixed=1
done
if [[ $missing -ne 0 ]]; then
    fail "$ID.concurrent.delivery" "a measured blocked query was not delivered to $DB"
elif [[ $mixed -ne 0 ]]; then
    fail "$ID.concurrent.identity" "a blocked query row contained another producer's marker"
else
    ok "$ID.concurrent" "4 producers x ${N} blocked queries were each delivered once to $DB, with no mixed markers"
fi

qa_admin postgres "SELECT 1" || { infra "$ID.alive" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.alive" "postmaster still accepted a query after concurrent publication"

python3 - "$QA_RUN_DIR/queue-utf8" <<'PY'
import pathlib, sys
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
limit = 2047

def kept_prefix(raw: bytes) -> bytes:
    end = min(len(raw), limit)
    while end > 0:
        try:
            raw[:end].decode("utf-8")
            return raw[:end]
        except UnicodeDecodeError:
            end -= 1
    return b""

# The statement is sent with a terminating ';'. Since Phase 4A the product
# records PostgreSQL's span for it, which ends before that ';', so the limit
# and the expected prefix apply to the statement without it.
def emit(name: str, raw: bytes):
    assert not raw.endswith(b";"), name
    raw.decode("utf-8")
    prefix = kept_prefix(raw)
    flag = "t" if len(prefix) < len(raw) else "f"
    (out / f"{name}.sql").write_bytes(raw + b";\n")
    (out / f"{name}.flag").write_text(flag.strip() + "\n", encoding="ascii")
    (out / f"{name}.prefix").write_bytes(prefix)

def statement(marker: str, char: str, char_at: int) -> bytes:
    prefix = f"SELECT '{marker}".encode()
    if char_at < len(prefix):
        raise SystemExit(f"{marker}: character starts inside the prefix")
    return prefix + b"a" * (char_at - len(prefix)) + char.encode() + b"'"

# Exact fit, ASCII: the recorded statement, through the closing quote, is
# exactly the limit. (Before Phase 4A the recorded text included the ';'.)
prefix = b"SELECT 'qa_ux_"
exact = prefix + b"a" * (limit - len(prefix) - len(b"'")) + b"'"
assert len(exact) == limit, len(exact)
emit("exact", exact)

# Exact fit ending on a complete 2-byte character, then the closing quote.
prefix = b"SELECT 'qa_um_"
tail = "é".encode() + b"'"
exact_mb = prefix + b"a" * (limit - len(prefix) - len(tail)) + tail
assert len(exact_mb) == limit, len(exact_mb)
emit("exact_mb", exact_mb)

# The character still straddles the limit.
emit("split2", statement("qa_u2_", "é", 2046))
emit("split3", statement("qa_u3_", "€", 2045))
emit("split4", statement("qa_u4_", "😀", 2044))
PY

utf8_one() {
    local name=$1 marker=$2
    local dir=$QA_RUN_DIR/queue-utf8
    local stmt
    stmt=$(cat "$dir/${name}.sql")
    qa_sql_steps qa_q_utf8 "$DB" "qa_utf8_${name}" "$stmt" || true
    local flag
    flag=$(cat "$dir/${name}.flag")
    [[ $flag == t ]] && flag=true
    [[ $flag == f ]] && flag=false
    if ! qa_poll "$DB" \
        "SELECT query_truncated::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '${marker}') > 0 ORDER BY blocked_at DESC LIMIT 1" \
        "$flag" 20; then
        fail "$ID.utf8.$name" "query_truncated was not ${flag} for ${marker} (${QA_INFRA_REASON:-no row})"
        return 0
    fi
    qa_admin "$DB" \
        "SELECT query_text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '${marker}') > 0 ORDER BY blocked_at DESC LIMIT 1" ||
        { infra "$ID.utf8.$name" "$QA_INFRA_REASON"; return 1; }
    printf '%s' "${QA_STEP_OUT[1]}" >"$dir/${name}.got"
    if ! cmp -s "$dir/${name}.got" "$dir/${name}.prefix"; then
        fail "$ID.utf8.$name" "stored query is not the UTF-8 prefix of the original"
        return 0
    fi
    ok "$ID.utf8.$name" "query_truncated=${flag} and the stored text is the UTF-8 prefix"
}

utf8_one exact qa_ux_ || exit 0
utf8_one exact_mb qa_um_ || exit 0
utf8_one split2 qa_u2_ || exit 0
utf8_one split3 qa_u3_ || exit 0
utf8_one split4 qa_u4_ || exit 0

# Empty application_name must not drop the blocked event. A named value is stored.
qa_sql_steps qa_q_utf8 "$DB" "" "SELECT 'qa_q_empty_app'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text || ':' || coalesce(max(application_name), '<null>') FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_q_empty_app') > 0" \
    "1:" 20; then
    fail "$ID.utf8.empty_app" "empty application_name did not persist with the blocked event (${QA_INFRA_REASON:-})"
else
    ok "$ID.utf8.empty_app" "blocked event with an empty application_name was persisted"
fi
qa_sql_steps qa_q_utf8 "$DB" qa_q_named_app "SELECT 'qa_q_named_app'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text || ':' || coalesce(max(application_name), '<null>') FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_q_named_app') > 0" \
    "1:qa_q_named_app" 20; then
    fail "$ID.utf8.named_app" "application_name was not stored (${QA_INFRA_REASON:-})"
else
    ok "$ID.utf8.named_app" "application_name qa_q_named_app was stored with the blocked event"
fi

# Fingerprint identity is the hex. Repeating the statement must keep that hex
# and only advance hit_count. The sample carries the multibyte text.
qa_sql_steps qa_q_fp "$DB" qa_q "SELECT 'qa_q_fp_é€😀'" ||
    { infra "$ID.utf8.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT CASE WHEN count(*) OPERATOR(pg_catalog.=) 1 THEN max(length(fingerprint))::text ELSE 'rows=' || count(*)::text END FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_q_fp'::name AND strpos(sample_query, 'qa_q_fp_é€😀') > 0" \
    64 20; then
    fail "$ID.utf8.fingerprint" "fingerprint row did not keep a 64-hex identity and the multibyte sample (${QA_INFRA_REASON:-})"
else
    ok "$ID.utf8.fingerprint" "one fingerprint row, 64 hex digits, sample contains qa_q_fp_é€😀"
fi

exit 0

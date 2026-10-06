#!/usr/bin/env bash
# UTF8 is the only supported database encoding.
#
# Diagnostics:
#   install in a non-UTF8 database, and runtime inspection of an
#   already-installed non-UTF8 database:
#     0A000 sql_firewall: UTF8 database encoding is required; server_encoding is <name>
#   invalid UTF8 in a policy-relevant identifier (not in the query text):
#     22021 sql_firewall: invalid UTF8 byte sequence
#   a database without the extension follows PostgreSQL, including real
#   non-UTF8 bytes. Native permission errors stay native.
#
# The historical fixture is staged only in this disposable cluster under
# a separate version label; the packaged 0.0.0 installer is untouched.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.encoding
EV=encoding
ROLE=qa_enc_app
APP=qa_enc_app
UTF=qa_enc_utf8
LATIN=qa_enc_latin5
ASCII=qa_enc_ascii
OLD=qa_enc_old
FIX_SHA=3adef75a0c858be0ae508fd18f152223b1b7c9574bba853958f9d4b4163834d8
MSG_LATIN='sql_firewall: UTF8 database encoding is required; server_encoding is LATIN5'
MSG_ASCII='sql_firewall: UTF8 database encoding is required; server_encoding is SQL_ASCII'

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "server_encoding must be UTF8. client_encoding may differ. Preload does not inspect a database that has not installed sql_firewall." ""
log_at=$(qa_server_log_offset)

# Generated install script must run the encoding gate before any object.
if ! qa_admin postgres "SELECT setting FROM pg_config WHERE name = 'SHAREDIR'"; then
    infra "$ID.script" "$QA_INFRA_REASON"
    exit 0
fi
SHARE=${QA_STEP_OUT[1]}
INSTALL_SQL=$SHARE/extension/sql_firewall--0.0.0.sql
do_at=$(grep -nF 'DO $sqlfw_utf8$' "$INSTALL_SQL" | head -1 | cut -d: -f1)
table_at=$(grep -nF 'CREATE TABLE' "$INSTALL_SQL" | head -1 | cut -d: -f1)
if [[ -n ${do_at:-} && -n ${table_at:-} && $do_at -lt $table_at ]]; then
    ok "$ID.script_order" "install DO at line $do_at before CREATE TABLE at $table_at"
else
    fail "$ID.script_order" "install do=$do_at table=$table_at"
fi

qa_admin postgres "CREATE ROLE $ROLE LOGIN NOSUPERUSER" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

# ---------------------------------------------------------------------------
# A. UTF8 installation and ordinary enforce behavior
# ---------------------------------------------------------------------------
qa_create_db "$UTF" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID.utf8" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$UTF" \
    "GRANT CONNECT ON DATABASE $UTF TO $ROLE" \
    "CREATE TABLE public.qa_enc_t (id integer)" \
    "GRANT SELECT ON public.qa_enc_t TO $ROLE" \
    "INSERT INTO public.qa_enc_t VALUES (1)" \
    "SELECT current_setting('server_encoding')" ||
    { infra "$ID.utf8" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[5]} != UTF8 ]]; then
    infra "$ID.utf8" "server_encoding is '${QA_STEP_OUT[5]}'"
    exit 0
fi
qa_check_rejection "$ROLE" "$UTF" "$APP" "SELECT id FROM public.qa_enc_t" 42501 \
    "^sql_firewall: No rule found for command 'SELECT' for role '$ROLE'$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.utf8.enforce" "$QA_DETAIL"
else
    fail "$ID.utf8.enforce" "$QA_DETAIL"
fi

# ---------------------------------------------------------------------------
# B. Installation rejected in LATIN5 (enabled off) and SQL_ASCII (bypass off)
# ---------------------------------------------------------------------------
create_encoded() { # db encoding extra-alter...
    local db=$1 enc=$2
    shift 2
    qa_admin postgres \
        "CREATE DATABASE $db WITH TEMPLATE template0 ENCODING '$enc' LC_COLLATE 'C' LC_CTYPE 'C'" \
        "GRANT CONNECT ON DATABASE $db TO $ROLE" \
        "$@" || return $?
}

if ! create_encoded "$LATIN" LATIN5 "ALTER DATABASE $LATIN SET sql_firewall.enabled = off"; then
    infra "$ID.install.latin5" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_sql_steps "$QA_SUPERUSER" "$LATIN" qa_admin \
    "SELECT current_setting('server_encoding')" \
    "SHOW client_encoding" \
    "CREATE EXTENSION sql_firewall"; then
    infra "$ID.install.latin5" "$QA_INFRA_REASON"
    exit 0
fi
qa_evidence "$EV" "- latin5 server=${QA_STEP_OUT[1]} client=${QA_STEP_OUT[2]} create=${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
if [[ ${QA_STEP_OUT[1]} == LATIN5 && ${QA_STEP_ERR[3]} == true && ${QA_STEP_STATE[3]} == 0A000 && ${QA_STEP_MSG[3]:-} == "$MSG_LATIN" ]]; then
    ok "$ID.install.latin5" "${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]} (client_encoding ${QA_STEP_OUT[2]})"
else
    fail "$ID.install.latin5" "server=${QA_STEP_OUT[1]} client=${QA_STEP_OUT[2]} err=${QA_STEP_ERR[3]} ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}"
fi
qa_admin "$LATIN" \
    "SELECT count(*) FROM pg_extension WHERE extname = 'sql_firewall'" \
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname LIKE 'sql_firewall%'" \
    "SELECT 1" ||
    { infra "$ID.install.latin5.clean" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == 0 && ${QA_STEP_OUT[2]} == 0 && ${QA_STEP_OUT[3]} == 1 ]]; then
    ok "$ID.install.latin5.clean" "no extension row or objects; native SELECT 1 returned 1"
else
    fail "$ID.install.latin5.clean" "ext=${QA_STEP_OUT[1]} objects=${QA_STEP_OUT[2]} select=${QA_STEP_OUT[3]}"
fi

if ! create_encoded "$ASCII" SQL_ASCII \
    "ALTER DATABASE $ASCII SET sql_firewall.mode = 'enforce'" \
    "ALTER DATABASE $ASCII SET sql_firewall.allow_superuser_auth_bypass = off"; then
    infra "$ID.install.ascii" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_sql_steps "$QA_SUPERUSER" "$ASCII" qa_admin \
    "SELECT current_setting('server_encoding')" \
    "CREATE EXTENSION sql_firewall"; then
    infra "$ID.install.ascii" "$QA_INFRA_REASON"
    exit 0
fi
if [[ ${QA_STEP_OUT[1]} == SQL_ASCII && ${QA_STEP_ERR[2]} == true && ${QA_STEP_STATE[2]} == 0A000 && ${QA_STEP_MSG[2]:-} == "$MSG_ASCII" ]]; then
    ok "$ID.install.ascii" "${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]}"
else
    fail "$ID.install.ascii" "server=${QA_STEP_OUT[1]} err=${QA_STEP_ERR[2]} ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}"
fi
qa_admin "$ASCII" "SELECT count(*) FROM pg_extension WHERE extname = 'sql_firewall'" "SELECT 1" ||
    { infra "$ID.install.ascii.clean" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == 0 && ${QA_STEP_OUT[2]} == 1 ]]; then
    ok "$ID.install.ascii.clean" "no extension row; native SELECT 1 returned 1"
else
    fail "$ID.install.ascii.clean" "ext=${QA_STEP_OUT[1]} select=${QA_STEP_OUT[2]}"
fi

# ---------------------------------------------------------------------------
# D. No extension: real non-UTF8 bytes and a native permission error
# ---------------------------------------------------------------------------
byte_select() { # role db encoding outfile
    local role=$1 db=$2 enc=$3 out=$4 err=$5
    {
        printf '\\echo @@QA_BEGIN 1\n'
        printf "SELECT length('"
        printf '\376'
        printf "'), current_setting('server_encoding'), current_setting('client_encoding');\n"
        printf '\\echo @@QA_END 1 :ERROR :SQLSTATE\n'
        printf '\\if :ERROR\n\\echo @@QA_MSG 1 :LAST_ERROR_MESSAGE\n\\endif\n'
    } >"$out.sql"
    env PGCLIENTENCODING="$enc" PGAPPNAME="$APP" \
        "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
        -h "$QA_SOCK" -p "$QA_PORT" -U "$role" -d "$db" -f "$out.sql" \
        >"$out.out" 2>"$err"
}

parse_byte() { # out file -> QA_BYTE_*
    QA_BYTE_ERR= QA_BYTE_STATE= QA_BYTE_MSG= QA_BYTE_OUT=
    local line cur=0
    while IFS= read -r line; do
        if [[ $line =~ ^@@QA_BEGIN\ ([0-9]+)$ ]]; then
            cur=${BASH_REMATCH[1]}
            QA_BYTE_OUT=
        elif [[ $line =~ ^@@QA_END\ ([0-9]+)\ (true|false)\ ([0-9A-Z]{5})$ ]]; then
            QA_BYTE_ERR=${BASH_REMATCH[2]}
            QA_BYTE_STATE=${BASH_REMATCH[3]}
            cur=0
        elif [[ $line =~ ^@@QA_MSG\ ([0-9]+)\ (.*)$ ]]; then
            QA_BYTE_MSG=${BASH_REMATCH[2]}
        elif ((cur > 0)); then
            QA_BYTE_OUT+="${QA_BYTE_OUT:+$'\n'}$line"
        fi
    done <"$1"
}

parse_marked() { # out file -> QA_STEP_*
    QA_STEP_ERR=() QA_STEP_STATE=() QA_STEP_MSG=() QA_STEP_OUT=()
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
    done <"$1"
}

BYTE=$QA_RUN_DIR/encoding-byte
mkdir -p "$BYTE"
byte_select "$ROLE" "$LATIN" LATIN5 "$BYTE/latin" "$BYTE/latin.err"
parse_byte "$BYTE/latin.out"
qa_evidence "$EV" "- no-extension latin5 byte: err=$QA_BYTE_ERR state=$QA_BYTE_STATE out=$QA_BYTE_OUT msg=${QA_BYTE_MSG:-}"
if [[ $QA_BYTE_ERR == false && $QA_BYTE_OUT == $'1|LATIN5|LATIN5' ]]; then
    ok "$ID.absent.latin5_bytes" "LATIN5 byte 0xFE returned length 1; server_encoding LATIN5 client_encoding LATIN5"
elif [[ ${QA_BYTE_MSG:-} == sql_firewall:* ]]; then
    fail "$ID.absent.latin5_bytes" "firewall diagnostic on an uninstalled database: $QA_BYTE_STATE ${QA_BYTE_MSG:-}"
else
    fail "$ID.absent.latin5_bytes" "err=$QA_BYTE_ERR state=$QA_BYTE_STATE out=$QA_BYTE_OUT msg=${QA_BYTE_MSG:-}"
fi
byte_select "$ROLE" "$ASCII" SQL_ASCII "$BYTE/ascii" "$BYTE/ascii.err"
parse_byte "$BYTE/ascii.out"
if [[ $QA_BYTE_ERR == false && $QA_BYTE_OUT == $'1|SQL_ASCII|SQL_ASCII' ]]; then
    ok "$ID.absent.ascii_bytes" "SQL_ASCII byte 0xFE returned length 1"
elif [[ ${QA_BYTE_MSG:-} == sql_firewall:* ]]; then
    fail "$ID.absent.ascii_bytes" "firewall diagnostic on an uninstalled database: $QA_BYTE_STATE ${QA_BYTE_MSG:-}"
else
    fail "$ID.absent.ascii_bytes" "err=$QA_BYTE_ERR state=$QA_BYTE_STATE out=$QA_BYTE_OUT msg=${QA_BYTE_MSG:-}"
fi
qa_admin "$LATIN" "CREATE TABLE public.qa_enc_secret (id integer)" ||
    { infra "$ID.absent.native" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$ROLE" "$LATIN" "$APP" "SELECT id FROM public.qa_enc_secret" 42501 \
    '^permission denied for table qa_enc_secret$'
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.absent.native" "$QA_DETAIL"
elif [[ $QA_DETAIL == *sql_firewall:* ]]; then
    fail "$ID.absent.native" "$QA_DETAIL"
else
    infra "$ID.absent.native" "$QA_DETAIL"
fi

# ---------------------------------------------------------------------------
# C. A historical, unsupported installation in a LATIN5 database is rejected
#    at runtime in every mode. The fixture uses a test-only version label so
#    it cannot replace the packaged 0.0.0 installer.
# ---------------------------------------------------------------------------
FIX=$(cd "$(dirname "$0")/../fixtures" && pwd)/sql_firewall_rs--0.0.0.sql
fix_sha=$(sha256sum "$FIX" | awk '{print $1}')
if [[ $fix_sha != "$FIX_SHA" ]]; then
    infra "$ID.runtime" "fixture hash is $fix_sha"
    exit 0
fi
cp "$FIX" "$SHARE/extension/sql_firewall--legacy-nonutf8.sql" ||
    { infra "$ID.runtime" "could not stage historical SQL"; exit 0; }
if ! create_encoded "$OLD" LATIN5 "ALTER DATABASE $OLD SET sql_firewall.mode = 'enforce'"; then
    infra "$ID.runtime" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$OLD" "CREATE EXTENSION sql_firewall VERSION 'legacy-nonutf8'" ||
    { infra "$ID.runtime" "historical install: $QA_INFRA_REASON"; exit 0; }

qa_admin "$OLD" "GRANT CONNECT ON DATABASE $OLD TO $ROLE" "CREATE TABLE public.qa_enc_t (id integer)" "GRANT SELECT ON public.qa_enc_t TO $ROLE" ||
    { infra "$ID.runtime" "$QA_INFRA_REASON"; exit 0; }

check_mode() { # mode id
    qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $OLD SET sql_firewall.mode = '$1'" ||
        { infra "$ID.runtime.$2" "$QA_INFRA_REASON"; return 1; }
    qa_check_rejection "$ROLE" "$OLD" "$APP" "SELECT id FROM public.qa_enc_t" 0A000 "^${MSG_LATIN}$"
    if [[ $QA_VERDICT == PASS ]]; then
        ok "$ID.runtime.$2" "$QA_DETAIL"
    else
        fail "$ID.runtime.$2" "$QA_DETAIL"
    fi
}
check_mode enforce enforce || exit 0
check_mode learn learn || exit 0
check_mode permissive permissive || exit 0
qa_admin postgres "ALTER ROLE $ROLE IN DATABASE $OLD SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.runtime" "$QA_INFRA_REASON"; exit 0; }

qa_check_rejection "$ROLE" "$OLD" "$APP" "CREATE TEMP TABLE qa_enc_utility (id integer)" 0A000 "^${MSG_LATIN}$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.runtime.utility" "$QA_DETAIL"
else
    fail "$ID.runtime.utility" "$QA_DETAIL"
fi
byte_select "$ROLE" "$OLD" LATIN5 "$BYTE/installed" "$BYTE/installed.err"
parse_byte "$BYTE/installed.out"
if [[ $QA_BYTE_ERR == true && $QA_BYTE_STATE == 0A000 && $QA_BYTE_MSG == "$MSG_LATIN" ]]; then
    ok "$ID.runtime.bytes" "LATIN5 byte 0xFE rejected before decoding: $QA_BYTE_STATE $QA_BYTE_MSG"
else
    fail "$ID.runtime.bytes" "err=$QA_BYTE_ERR state=$QA_BYTE_STATE msg=${QA_BYTE_MSG:-} out=$QA_BYTE_OUT"
fi

# Same superuser backend: bypass lets it open a transaction, the role hits
# the encoding error, ROLLBACK TO SAVEPOINT still works, and the enable
# switch lets the role through without a new connection.
if ! qa_sql_steps "$QA_SUPERUSER" "$OLD" qa_admin \
    "SELECT pg_backend_pid()" \
    "BEGIN" \
    "SAVEPOINT qa_enc" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 1" \
    "ROLLBACK TO SAVEPOINT qa_enc" \
    "SELECT pg_backend_pid()" \
    "SET sql_firewall.enabled = off" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 1" \
    "RESET ROLE" \
    "SET sql_firewall.enabled = on" \
    "SET LOCAL ROLE $ROLE" \
    "SELECT 1" \
    "ROLLBACK"; then
    infra "$ID.runtime.recover" "$QA_INFRA_REASON"
    exit 0
fi
# 1 pid, 2 BEGIN, 3 SAVEPOINT, 4 SET LOCAL, 5 SELECT rejected,
# 6 ROLLBACK TO SAVEPOINT, 7 pid, 8 enabled off, 9 SET LOCAL, 10 SELECT ok,
# 11 RESET, 12 enabled on, 13 SET LOCAL, 14 SELECT rejected, 15 ROLLBACK
if [[ ${QA_STEP_ERR[5]} == true && ${QA_STEP_STATE[5]} == 0A000 && ${QA_STEP_MSG[5]:-} == "$MSG_LATIN" &&
      ${QA_STEP_ERR[6]} == false && ${QA_STEP_OUT[1]} == "${QA_STEP_OUT[7]}" && -n ${QA_STEP_OUT[1]} ]]; then
    ok "$ID.runtime.recover" "pid ${QA_STEP_OUT[1]} rejected ${QA_STEP_STATE[5]}, then ROLLBACK TO SAVEPOINT returned to the same backend"
else
    fail "$ID.runtime.recover" "pid ${QA_STEP_OUT[1]:-}/${QA_STEP_OUT[7]:-} select=${QA_STEP_ERR[5]} ${QA_STEP_STATE[5]} ${QA_STEP_MSG[5]:-} rollback=${QA_STEP_ERR[6]} ${QA_STEP_MSG[6]:-}"
fi
if [[ ${QA_STEP_ERR[10]} == false && ${QA_STEP_OUT[10]} == 1 &&
      ${QA_STEP_ERR[14]} == true && ${QA_STEP_STATE[14]} == 0A000 ]]; then
    ok "$ID.runtime.repair" "enabled=off allowed SELECT 1; enabled=on rejected again with ${QA_STEP_STATE[14]}"
else
    fail "$ID.runtime.repair" "off=${QA_STEP_ERR[10]}/${QA_STEP_OUT[10]:-} on=${QA_STEP_ERR[14]} ${QA_STEP_STATE[14]} ${QA_STEP_MSG[14]:-}"
fi

if [[ ! -d /proc/$QA_PM_PID ]]; then
    fail "$ID.runtime.postmaster" "postmaster pid $QA_PM_PID is gone"
elif tail -c +"$((log_at + 1))" "$QA_SERVER_LOG" | grep -q 'PANIC:'; then
    fail "$ID.runtime.postmaster" "PANIC in server log"
else
    ok "$ID.runtime.postmaster" "postmaster $QA_PM_PID still running and the log has no PANIC"
fi

# ---------------------------------------------------------------------------
# F. One LATIN5 client session against the UTF8 database.
# The permitted SELECT and the unapproved INSERT both carry byte 0xFE.
# ---------------------------------------------------------------------------
qa_admin "$UTF" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" \
    "GRANT INSERT ON public.qa_enc_t TO $ROLE" ||
    { infra "$ID.client" "$QA_INFRA_REASON"; exit 0; }
{
    printf '\\echo @@QA_BEGIN 1\n'
    printf "SELECT length('"
    printf '\376'
    printf "'), current_setting('server_encoding'), current_setting('client_encoding');\n"
    printf '\\echo @@QA_END 1 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 1 :LAST_ERROR_MESSAGE\n\\endif\n'
    printf '\\echo @@QA_BEGIN 2\n'
    printf 'INSERT INTO public.qa_enc_t VALUES (pg_catalog.length('"'"
    printf '\376'
    printf "'));\n"
    printf '\\echo @@QA_END 2 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 2 :LAST_ERROR_MESSAGE\n\\endif\n'
} >"$BYTE/client.sql"
client_log=$(qa_server_log_offset)
client_rc=0
env PGCLIENTENCODING=LATIN5 PGAPPNAME="$APP" \
    "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
    -h "$QA_SOCK" -p "$QA_PORT" -U "$ROLE" -d "$UTF" -f "$BYTE/client.sql" \
    >"$BYTE/client.out" 2>"$BYTE/client.err" || client_rc=$?
if [[ $client_rc -eq 2 ]]; then
    infra "$ID.client" "LATIN5 client connection failed: $(head -c 300 "$BYTE/client.err")"
    exit 0
fi
parse_marked "$BYTE/client.out"
# LATIN5 0xFE converts to UTF8. The server log's STATEMENT line is what
# PostgreSQL executed, not the client input file.
converted=$(printf '\376' | iconv -f LATIN5 -t UTF-8)
server_stmt=$(tail -c +"$((client_log + 1))" "$QA_SERVER_LOG" | grep -a -F "STATEMENT:" | grep -a -F "pg_catalog.length(" | grep -a -F "$converted" | head -1 || true)
printf '%s\n' "$server_stmt" >"$BYTE/client.server-statement"
qa_evidence "$EV" "- latin5 client step1 err=${QA_STEP_ERR[1]:-} ${QA_STEP_STATE[1]:-} out=${QA_STEP_OUT[1]:-} step2 err=${QA_STEP_ERR[2]:-} ${QA_STEP_STATE[2]:-} ${QA_STEP_MSG[2]:-}" \
    "- server statement: ${server_stmt:-<none>}"
if [[ ${QA_STEP_ERR[1]:-} == false && ${QA_STEP_OUT[1]:-} == $'1|UTF8|LATIN5' ]]; then
    ok "$ID.client.allowed" "same LATIN5 session: server_encoding=UTF8 client_encoding=LATIN5 length 1"
else
    fail "$ID.client.allowed" "err=${QA_STEP_ERR[1]:-} state=${QA_STEP_STATE[1]:-} out=${QA_STEP_OUT[1]:-} msg=${QA_STEP_MSG[1]:-}"
fi
if [[ ${QA_STEP_ERR[2]:-} == true && ${QA_STEP_STATE[2]:-} == 42501 && ${QA_STEP_MSG[2]:-} == "sql_firewall: No rule found for command 'INSERT' for role '$ROLE'" && $server_stmt == *"pg_catalog.length("* && $server_stmt == *"$converted"* ]]; then
    ok "$ID.client.blocked" "same LATIN5 session: ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]}; server statement contains the converted character"
else
    fail "$ID.client.blocked" "err=${QA_STEP_ERR[2]:-} state=${QA_STEP_STATE[2]:-} msg=${QA_STEP_MSG[2]:-} server='${server_stmt:-}'"
fi

# ---------------------------------------------------------------------------
# Invalid role-name bytes, not invalid query bytes.
# The role is created in SQL_ASCII so 0xFE is stored raw, then used against
# the UTF8 database. decode_palloc/decode_bytes raises 22021.
# ---------------------------------------------------------------------------
BADROLE=$(printf 'bad_%b' '\376')
{
    printf '\\echo @@QA_BEGIN 1\n'
    printf 'CREATE ROLE "'
    printf '%s' "$BADROLE"
    printf '" LOGIN NOSUPERUSER;\n'
    printf '\\echo @@QA_END 1 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 1 :LAST_ERROR_MESSAGE\n\\endif\n'
    printf '\\echo @@QA_BEGIN 2\n'
    printf 'GRANT CONNECT ON DATABASE %s TO "' "$UTF"
    printf '%s' "$BADROLE"
    printf '";\n'
    printf '\\echo @@QA_END 2 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 2 :LAST_ERROR_MESSAGE\n\\endif\n'
    printf '\\echo @@QA_BEGIN 3\n'
    printf 'SELECT ascii(substr(rolname::text, 5, 1)) FROM pg_catalog.pg_authid WHERE rolname = '"'"
    printf '%s' "$BADROLE"
    printf "'"';\n'
    printf '\\echo @@QA_END 3 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 3 :LAST_ERROR_MESSAGE\n\\endif\n'
} >"$BYTE/role.sql"
role_rc=0
env PGCLIENTENCODING=SQL_ASCII PGAPPNAME=qa_admin \
    "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
    -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$ASCII" -f "$BYTE/role.sql" \
    >"$BYTE/role.out" 2>"$BYTE/role.err" || role_rc=$?
if [[ $role_rc -eq 2 ]]; then
    infra "$ID.decoder.setup" "SQL_ASCII setup connection failed: $(head -c 300 "$BYTE/role.err")"
    exit 0
fi
parse_marked "$BYTE/role.out"
if [[ ${QA_STEP_ERR[1]:-} != false || ${QA_STEP_ERR[2]:-} != false || ${QA_STEP_OUT[3]:-} != 254 ]]; then
    infra "$ID.decoder.setup" "role create=${QA_STEP_ERR[1]:-}/${QA_STEP_STATE[1]:-}/${QA_STEP_MSG[1]:-} grant=${QA_STEP_ERR[2]:-}/${QA_STEP_STATE[2]:-}/${QA_STEP_MSG[2]:-} fifth-byte=${QA_STEP_OUT[3]:-}"
    exit 0
fi
ok "$ID.decoder.setup" "SQL_ASCII role bad_<0xFE> exists; fifth byte ascii()=254"
{
    printf '\\echo @@QA_BEGIN 1\n'
    printf 'SELECT 1;\n'
    printf '\\echo @@QA_END 1 :ERROR :SQLSTATE\n'
    printf '\\if :ERROR\n\\echo @@QA_MSG 1 :LAST_ERROR_MESSAGE\n\\endif\n'
} >"$BYTE/decode.sql"
dec_rc=0
env PGCLIENTENCODING=SQL_ASCII PGAPPNAME=qa_decode \
    "$QA_PSQL" -X -q -A -t -v ON_ERROR_STOP=0 -v VERBOSITY=default \
    -h "$QA_SOCK" -p "$QA_PORT" -U "$BADROLE" -d "$UTF" -f "$BYTE/decode.sql" \
    >"$BYTE/decode.out" 2>"$BYTE/decode.err" || dec_rc=$?
if [[ $dec_rc -eq 2 ]]; then
    infra "$ID.decoder.statement" "connection as bad_<0xFE> to $UTF failed: $(head -c 300 "$BYTE/decode.err")"
    exit 0
fi
parse_marked "$BYTE/decode.out"
qa_evidence "$EV" "- decoder SELECT 1 err=${QA_STEP_ERR[1]:-} ${QA_STEP_STATE[1]:-} ${QA_STEP_MSG[1]:-} out=${QA_STEP_OUT[1]:-}"
if [[ -z ${QA_STEP_ERR[1]:-} ]]; then
    infra "$ID.decoder.statement" "no statement result: $(head -c 300 "$BYTE/decode.err")"
elif [[ ${QA_STEP_ERR[1]} == true && ${QA_STEP_STATE[1]} == 22021 && ${QA_STEP_MSG[1]:-} == 'sql_firewall: invalid UTF8 byte sequence' ]]; then
    ok "$ID.decoder.statement" "ASCII SELECT 1 as bad_<0xFE> on UTF8: ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]}"
else
    fail "$ID.decoder.statement" "err=${QA_STEP_ERR[1]} state=${QA_STEP_STATE[1]:-} msg=${QA_STEP_MSG[1]:-} out=${QA_STEP_OUT[1]:-}"
fi

# ---------------------------------------------------------------------------
# G. Non-ASCII UTF8 role name and query text are preserved.
# ---------------------------------------------------------------------------
UNI=qa_enc_ış
qa_admin "$UTF" \
    "CREATE ROLE \"$UNI\" LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $UTF TO \"$UNI\"" \
    "GRANT SELECT ON public.qa_enc_t TO \"$UNI\"" ||
    { infra "$ID.unicode" "$QA_INFRA_REASON"; exit 0; }
qa_check_rejection "$UNI" "$UTF" "uygulama_ış" "SELECT id FROM public.qa_enc_t" 42501 \
    "^sql_firewall: No rule found for command 'SELECT' for role '${UNI}'$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.unicode.role" "$QA_DETAIL"
elif [[ $QA_DETAIL == *$'\uFFFD'* || $QA_DETAIL == *'?'* ]]; then
    fail "$ID.unicode.role" "$QA_DETAIL"
else
    fail "$ID.unicode.role" "$QA_DETAIL"
fi
qa_admin "$UTF" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$UNI', 'SELECT', true)" ||
    { infra "$ID.unicode.log" "$QA_INFRA_REASON"; exit 0; }
qa_check_success "$UNI" "$UTF" "uygulama_ış" "SELECT 'ış'" "ış"
if [[ $QA_VERDICT != PASS ]]; then
    infra "$ID.unicode.log" "$QA_DETAIL"
    exit 0
fi
qa_admin "$UTF" \
    "SELECT application_name || '|' || query_text FROM public.sql_firewall_activity_log WHERE role_name = '$UNI' AND action = 'ALLOWED' ORDER BY log_id DESC LIMIT 1" ||
    { infra "$ID.unicode.log" "$QA_INFRA_REASON"; exit 0; }
# PostgreSQL rewrites startup application_name with pg_clean_ascii before
# the extension reads it, so non-ASCII becomes \xHH. The query text is the
# statement itself and must stay the original UTF8 characters. The harness
# sends "SELECT 'ış';"; the recorded statement is PostgreSQL's span for it,
# which ends before the terminating ';'.
row=${QA_STEP_OUT[1]}
query=${row#*|}
app=${row%%|*}
if [[ $query == "SELECT 'ış'" && $app == *\\xc4\\xb1\\xc5\\x9f* && $app != *$'\uFFFD'* && $query != *$'\uFFFD'* ]]; then
    ok "$ID.unicode.log" "query text preserved '$query'; application_name is PostgreSQL's escaped form '$app'"
else
    fail "$ID.unicode.log" "activity row is '$row'"
fi

exit 0

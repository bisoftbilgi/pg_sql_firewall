#!/usr/bin/env bash
# Builds a ready-to-install sql_firewall package for one PostgreSQL major
# version (README 4, 6.9a).
#
# Usage: packaging/build-package.sh [--pg-config PATH] [--out DIR] [--source DIR]
#
# The library is built by qa/run.sh --build-only (release profile, locked and
# offline, C files checked against the selected server headers), whose
# manifest is copied into the package. The package holds the library, the
# control file, the install script and every update script, install.sh, the
# update tool sql_firewall_upgrade, INSTALL.md, PACKAGE (version and
# provenance), and SHA256SUMS. Output:
#   <out>/sql_firewall-<version>-pg<major>-<os>-<arch>.tar.gz
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXT=$(dirname "$HERE")
PGC=$(command -v pg_config || true)
OUT=$EXT/target/dist
SOURCE=$EXT
while (($#)); do
    case $1 in
        --pg-config) PGC=$2; shift ;;
        --out) OUT=$2; shift ;;
        --source) SOURCE=$(cd "$2" && pwd); shift ;;
        -h | --help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
[[ -x $PGC ]] || { echo "pg_config not found; pass --pg-config" >&2; exit 2; }
PG_VERSION=$("$PGC" --version)
MAJOR=$(sed -E 's/^PostgreSQL ([0-9]+).*/\1/' <<<"$PG_VERSION")
VERSION=$(sed -nE "s/^default_version = '([^']+)'/\1/p" "$SOURCE/sql_firewall.control")
[[ -n $VERSION ]] || { echo "no default_version in $SOURCE/sql_firewall.control" >&2; exit 2; }
NAME=sql_firewall-$VERSION-pg$MAJOR-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sqlfw-package.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# A target directory per pg_config: the same crate built against different
# server headers must not share build outputs.
TARGET=$EXT/target/package-pg$MAJOR-$(printf '%s' "$(cd "$(dirname "$PGC")" && pwd)/$(basename "$PGC")$SOURCE" | sha256sum | cut -c1-12)
echo "building sql_firewall $VERSION for $PG_VERSION ($PGC) ..."
if ! build_out=$(QA_WORK_ROOT=$WORK/build QA_ALLOW_OTHER_MAJOR=1 QA_PG_CONFIG=$PGC QA_SOURCE_DIR=$SOURCE \
    QA_TARGET_DIR=$TARGET "$EXT/qa/run.sh" --build-only --keep 2>&1); then
    printf '%s\n' "$build_out" | tail -20 >&2
    echo "build failed" >&2
    exit 3
fi
RUN=$(sed -n 's/^run directory: //p' <<<"$build_out")
PKG=$RUN/pkg
STAGE=$WORK/$NAME
mkdir -p "$STAGE/lib" "$STAGE/extension"
cp "$PKG$("$PGC" --pkglibdir)/sql_firewall.so" "$STAGE/lib/"
cp "$PKG$("$PGC" --sharedir)"/extension/sql_firewall.control "$PKG$("$PGC" --sharedir)"/extension/sql_firewall--*.sql "$STAGE/extension/"
cp "$HERE/install.sh" "$HERE/sql_firewall_upgrade" "$HERE/INSTALL.md" "$STAGE/"
chmod 755 "$STAGE/install.sh" "$STAGE/sql_firewall_upgrade"
cp "$RUN/manifest.txt" "$STAGE/BUILD-MANIFEST.txt"
{
    echo "name=sql_firewall"
    echo "version=$VERSION"
    echo "pg_major=$MAJOR"
    echo "built_against=$PG_VERSION"
    echo "built_at=$(date -Is)"
    echo "source_digest=$(sed -n 's/^source_digest=//p' "$RUN/manifest.txt")"
    echo "git_head=$(sed -n 's/^git_head=//p' "$RUN/manifest.txt")"
    echo "library_sha256=$(sha256sum "$STAGE/lib/sql_firewall.so" | cut -d' ' -f1)"
    echo "update_scripts=$(cd "$STAGE/extension" && ls sql_firewall--*--*.sql 2>/dev/null | tr '\n' ' ')"
} >"$STAGE/PACKAGE"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum >SHA256SUMS)
mkdir -p "$OUT"
tar -C "$WORK" -czf "$OUT/$NAME.tar.gz" "$NAME"
sha256sum "$OUT/$NAME.tar.gz" >"$OUT/$NAME.tar.gz.sha256"
echo "package: $OUT/$NAME.tar.gz"

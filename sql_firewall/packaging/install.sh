#!/usr/bin/env bash
# Installs this sql_firewall package into a PostgreSQL installation.
#
# Usage: ./install.sh [--pg-config PATH] [--dry-run]
#
# Checks SHA256SUMS and that the package was built for this PostgreSQL major
# version, then copies the extension files and the library. The library is
# written to a new file and renamed into place, so a running server keeps the
# library it loaded at start; the new one takes effect only after a restart.
# Needs write access to the server's library and extension directories
# (usually root). It does not restart PostgreSQL or change any database.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PGC=$(command -v pg_config || true)
DRY=0
while (($#)); do
    case $1 in
        --pg-config) PGC=$2; shift ;;
        --dry-run) DRY=1 ;;
        -h | --help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
[[ -x $PGC ]] || { echo "pg_config not found; pass --pg-config /path/to/pg_config" >&2; exit 2; }
cd "$HERE"
sha256sum --quiet -c SHA256SUMS || { echo "package checksum mismatch (SHA256SUMS)" >&2; exit 2; }
version=$(sed -n 's/^version=//p' PACKAGE)
want=$(sed -n 's/^pg_major=//p' PACKAGE)
have=$("$PGC" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[[ $want == "$have" ]] || { echo "this package is for PostgreSQL $want; $PGC is $("$PGC" --version)" >&2; exit 2; }
LIBDIR=$("$PGC" --pkglibdir)
EXTDIR=$("$PGC" --sharedir)/extension
echo "sql_firewall $version -> PostgreSQL $have ($PGC)"
echo "  library:   $LIBDIR/sql_firewall.so"
echo "  extension: $EXTDIR/"
((DRY)) && { echo "dry run: nothing copied"; exit 0; }
[[ -w $LIBDIR && -w $EXTDIR ]] || { echo "no write access to $LIBDIR or $EXTDIR (run as the installation owner or root)" >&2; exit 2; }

previous=""
[[ -f $LIBDIR/sql_firewall.so ]] && previous=$(sha256sum "$LIBDIR/sql_firewall.so" | cut -d' ' -f1)
for f in extension/*; do
    tmp=$EXTDIR/.$(basename "$f").new.$$
    install -m 644 "$f" "$tmp"
    mv -f "$tmp" "$EXTDIR/$(basename "$f")"
done
tmp=$LIBDIR/.sql_firewall.so.new.$$
install -m 755 lib/sql_firewall.so "$tmp"
mv -f "$tmp" "$LIBDIR/sql_firewall.so"
echo "installed (library sha256 $(sha256sum "$LIBDIR/sql_firewall.so" | cut -d' ' -f1))"
cat <<EOF

Next steps (INSTALL.md):
  New installation:
    1. ALTER SYSTEM SET shared_preload_libraries = 'sql_firewall'  (keep other entries)
    2. restart PostgreSQL
    3. in each database: CREATE EXTENSION sql_firewall;
  Update of an existing installation${previous:+ (the previous library was $previous)}:
    1. restart PostgreSQL in a maintenance window (the running server still uses the old library)
    2. $HERE/sql_firewall_upgrade --check   then   --backup-dir DIR --yes
EOF

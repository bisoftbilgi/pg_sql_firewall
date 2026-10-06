# sql_firewall package

This package holds one release of sql_firewall for one PostgreSQL major
version (see `PACKAGE`). `SHA256SUMS` covers every file; `BUILD-MANIFEST.txt`
records how the library was built (source digest, toolchain, header check).

## New installation

1. `./install.sh --pg-config /usr/pgsql-NN/bin/pg_config` (as the owner of the
   PostgreSQL installation, usually root).
2. Add the library to `shared_preload_libraries` (keep existing entries), for
   example `ALTER SYSTEM SET shared_preload_libraries = 'sql_firewall';`, and
   restart PostgreSQL.
3. In each database to protect, as a superuser: `CREATE EXTENSION sql_firewall;`
   and check `SELECT sql_firewall_status();`.

`CREATE EXTENSION` is refused (`55000`) until the server was started with the
library preloaded; a refused attempt leaves nothing behind.

## Update to this release

1. `./install.sh --pg-config ...` installs the new library and the update
   scripts. The running server keeps using the library it started with.
2. Restart PostgreSQL in a maintenance window; this loads the new library.
3. `./sql_firewall_upgrade -h HOST -p PORT -U SUPERUSER --check` shows every
   database with the extension, its version, the update path, and whether the
   server is ready (preloaded, running this release's library).
4. `./sql_firewall_upgrade ... --backup-dir /backups --yes` backs up the roles
   and each database (`pg_dump -Fc`, checked with `pg_restore --list`), runs
   `ALTER EXTENSION sql_firewall UPDATE` in each, and verifies the version,
   the firewall status, and that each database's consumer is running again.
   Exit codes: 0 done, ready, or nothing to do; 1 failure; 2 usage or
   connection error; 3 not ready.

   - The backup holds table data and role password hashes: its directory is
     created with mode 0700 and its files 0600, whatever your umask. Keep it
     on storage only administrators can read.
   - Each database is updated in one transaction that compares every policy
     decision and the history before and after the update script, and
     commits only if they are equal. Otherwise the update is rolled back and
     that database keeps its version (the tool exits 1).
   - Template databases that allow connections (`template1`) are updated
     too, so new databases created from them get the new version. Databases
     that do not allow connections are listed as not checked.

The update keeps the installation (extension OID): command and fingerprint
approvals, rules, history, and checkpoints stay valid. Update scripts refuse
to run until the server runs this release's library, so an update cannot be
applied to a server that was not restarted. Do not update by `DROP EXTENSION`
and `CREATE EXTENSION`: that is a new installation, and fingerprint approvals
would have to be approved again.

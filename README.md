# SQL Firewall for PostgreSQL

`sql_firewall` controls which SQL commands and query shapes application roles
may execute. It learns from committed traffic, records approval violations,
and enforces reviewed approvals inside PostgreSQL.

Version **0.0.0** · PostgreSQL **16–18** · **Linux** · **UTF8 databases**

## Features

- Command approvals per role and SHA-256 query fingerprints.
- Keyword, regex, and built-in tautology checks.
- Rate limits, quiet hours, and IP/application rules.
- Activity and blocked-query logs, alerts, and automatic audit retention.
- Policy backup/restore, an update tool, and hot standby enforcement.

## Modes

| Mode | Command and fingerprint approval violations | Learning |
|---|---|---|
| `learn` | Allow | Learn committed executions; fingerprints require a hit threshold |
| `permissive` | Allow and log | No new approvals |
| `enforce` | Reject | No automatic approvals |

Other enabled protections, including regex and rate limits, block in all modes.
Only superuser sessions can administer policy. Superusers bypass inspection
by default; applications should use ordinary roles.

## Install

Build a package against your PostgreSQL installation's `pg_config`:

```bash
./sql_firewall/packaging/build-package.sh --pg-config /usr/pgsql-17/bin/pg_config
tar -xzf sql_firewall/target/dist/sql_firewall-0.0.0-pg17-linux-x86_64.tar.gz
sudo ./sql_firewall-0.0.0-pg17-linux-x86_64/install.sh --pg-config /usr/pgsql-17/bin/pg_config
```

Building requires Rust, `cargo-pgrx` **0.16.1**, PostgreSQL development headers,
and a C toolchain. See [build requirements](sql_firewall/docs/REFERENCE.md#3-requirements)
and [package installation/update](sql_firewall/packaging/INSTALL.md).

Add `sql_firewall` to `shared_preload_libraries` in `postgresql.conf`, preserving
any existing entries, then **restart PostgreSQL**:

```ini
shared_preload_libraries = 'sql_firewall'
```

As a superuser, connect to each database you want to protect:

```sql
CREATE EXTENSION sql_firewall;
SELECT sql_firewall_status();
```

Installation is refused with a clear error if the running server did not
preload the library. Databases without the extension are not inspected.

## Start using it

For an existing role `app_user` and database `app_db`, start with controlled
traffic in `learn` mode. Run these commands as a superuser:

```sql
ALTER ROLE app_user IN DATABASE app_db SET sql_firewall.mode = 'learn';
```

After running representative application traffic, review the learned policy
in `app_db`:

```sql
SELECT * FROM public.sql_firewall_command_approvals WHERE role_name = 'app_user';
SELECT * FROM public.sql_firewall_query_fingerprints WHERE role_name = 'app_user';
```

Remove unwanted approvals. Switch to `permissive` to observe approval
violations without learning, then to `enforce` when the policy is ready:

```sql
ALTER ROLE app_user IN DATABASE app_db SET sql_firewall.mode = 'permissive';
-- After reviewing violations:
ALTER ROLE app_user IN DATABASE app_db SET sql_firewall.mode = 'enforce';
```

Reconnect application sessions after changing role defaults. Learning is
asynchronous: wait for the consumer to persist approvals before enforcing.
See [policy management](sql_firewall/docs/REFERENCE.md#6-operational-workflow)
for approval functions, logging, and recovery.

## Before production use

- Audit queues are held in memory. Overload or a server restart can lose
  unprocessed records; this is not a guaranteed complete audit channel.
- Logical restore and `pg_upgrade` require new fingerprint approvals.
- Hot standby applies replicated policy; learning and audit records cannot
  be written to tables until promotion.
- `application_name` is client-supplied. IP blocklists do not cover Unix sockets.
- Some SQL forms that cannot be inspected safely are rejected.

See [support boundaries and limits](sql_firewall/docs/REFERENCE.md#9-troubleshooting-and-known-limits).

## Documentation

[Configuration and operations](sql_firewall/docs/REFERENCE.md) ·
[Installation and updates](sql_firewall/packaging/INSTALL.md) ·
[QA](sql_firewall/qa/README.md) ·
[Performance](sql_firewall/docs/PERFORMANCE.md) ·
[All documents](sql_firewall/docs/README.md)

License: [GPL v3](LICENSE).

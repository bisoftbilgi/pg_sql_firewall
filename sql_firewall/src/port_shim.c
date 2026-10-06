#include "postgres.h"
#include "libpq/libpq-be.h"
#include "libpq/pqcomm.h"
#include "libpq/pqformat.h"
#include "lib/stringinfo.h"
#include <netdb.h>
#include <stdbool.h>
#include <string.h>

extern int pg_getnameinfo_all(const struct sockaddr *addr,
                              socklen_t salen,
                              char *node,
                              size_t nodelen,
                              char *service,
                              size_t servicelen,
                              int flags);

const char *
sqlfw_port_application_name(Port *port)
{
    if (port == NULL || port->application_name == NULL || port->application_name[0] == '\0')
        return NULL;
    return port->application_name;
}

/*
 * The connection's numeric address, never a host name: remote_host holds a
 * resolved name when log_hostname is on, and policy must not depend on DNS.
 * A Unix-domain socket gives "[local]".
 */
bool
sqlfw_port_client_addr(Port *port, char *destination, size_t destination_len)
{
    if (port == NULL || destination == NULL || destination_len == 0)
        return false;

    if (pg_getnameinfo_all((const struct sockaddr *) &port->raddr.addr,
                           port->raddr.salen,
                           destination,
                           destination_len,
                           NULL,
                           0,
                           NI_NUMERICHOST) == 0)
    {
        return true;
    }

    return false;
}

/*
 * Catalog change counter (activation.rs, policy_visibility.rs).
 *
 * Every syscache invalidation of the catalogs the firewall's per-statement
 * catalog checks read, and every relcache invalidation, increments a counter
 * in this process. Backend-local results of those checks are kept only
 * while the counter is unchanged, so they follow the same invalidation
 * protocol as PostgreSQL's own syscache and relcache entries: changes
 * committed by other sessions are seen once this backend processes their
 * invalidation messages (transaction start, lock acquisition), and the
 * transaction's own changes, or the undoing of them by an abort, at the next
 * command. A cache reset after an invalidation queue overflow calls every
 * callback too.
 *
 * Registered once in the postmaster from _PG_init, so every backend and
 * background worker inherits the registrations, and a preloaded library
 * takes its slots before other code can exhaust them.
 */
#include "catalog/pg_extension.h"
#include "utils/inval.h"
#include "utils/syscache.h"

static uint64 sqlfw_catalog_changes = 0;

static void
sqlfw_syscache_changed(Datum arg, int cacheid, uint32 hashvalue)
{
	sqlfw_catalog_changes++;
}

static void
sqlfw_relcache_changed(Datum arg, Oid relid)
{
	sqlfw_catalog_changes++;
}

void
sqlfw_register_catalog_callbacks(void)
{
	/*
	 * pg_extension (the installation), pg_namespace (schema and its ACL),
	 * pg_class (relations, their ACLs, renames, drops), pg_attribute
	 * (column names and types), pg_proc (the invalidation trigger
	 * function), pg_authid and pg_auth_members (privilege checks). An
	 * invalidated tuple sends messages for every syscache on its catalog,
	 * so one cache per catalog is enough. Trigger changes reach relations
	 * as relcache invalidations.
	 */
	static const int caches[] = {
		EXTENSIONOID, NAMESPACEOID, RELOID, ATTNUM, PROCOID, AUTHOID, AUTHMEMROLEMEM
	};

	for (size_t i = 0; i < lengthof(caches); i++)
		CacheRegisterSyscacheCallback(caches[i], sqlfw_syscache_changed, (Datum) 0);
	CacheRegisterRelcacheCallback(sqlfw_relcache_changed, (Datum) 0);
}

uint64
sqlfw_catalog_change_count(void)
{
	return sqlfw_catalog_changes;
}

/* Handle pending invalidation messages (activation.rs, install_state). */
void
sqlfw_accept_invalidation_messages(void)
{
	AcceptInvalidationMessages();
}

/*
 * ALTER EXTENSION ... ADD/DROP changes only pg_depend, which sends no
 * invalidation, so the cached extension-membership checks of other backends
 * (activation.rs) would not notice. A relcache invalidation of pg_extension
 * is registered in the altering transaction: it is sent to every backend of
 * this database when the transaction commits, handled by this backend at
 * its next command, and its local effect is replayed on abort, so each of
 * those cases runs the catalog checks again.
 */
#include "catalog/pg_extension_d.h"

void
sqlfw_invalidate_extension_membership(void)
{
	CacheInvalidateRelcacheByRelid(ExtensionRelationId);
}

# 0032: PostgreSQL Row-Level Security for installation tenancy

**Status:** Accepted
**Date:** November 27, 2026

## Context

One external-storage process serves the Orvex installation and every tenant
organization from one Postgres database and one connection pool. Each
installation's rows carry `installation_id`. Until now, isolation depended on
every query including the right `WHERE installation_id = ...` clause. One
missed clause, raw operator SQL, or a future table would expose or change
another tenant's rows, and nothing in the database would stop it.

The production application role owns every table. It is not a superuser and
does not bypass Row-Level Security. Test and Compose databases often connect as
the image superuser, which always bypasses Row-Level Security.

## Decision

1. **Every tenant table enforces isolation in the database engine.**
   - Every table with an `installation_id` column has Row-Level Security both
     enabled and forced. Forcing makes it apply to the owning role as well.
   - It has one policy for all commands.
     `USING` and `WITH CHECK` are both
     `installation_id = NULLIF(current_setting('app.installation_id', true), '')`.
   - No tenant-table policy has a bypass, platform or wildcard branch.
2. **The two platform tables are reachable only in platform mode.**
   - `artifact_platform_sessions` is visible only when
     `current_setting('app.rls_mode', true) = 'platform'`.
   - `artifact_installations` is visible in platform mode, or for the row whose
     `id` equals the current installation setting.
   - `artifact_server_postgres_migrations` stays outside the policy. The tenant
     role is never granted access to it.
3. **Tenant context is transaction-local.**
   - All application SQL runs through one of two entry points on
     `PostgresDatabase`:
     - `runInInstallation(installationId, program)`;
     - `runAsPlatform(program)`.
   - Each opens a transaction and sets its context with
     `set_config(..., true)` before the program runs. The context ends with the
     transaction, including on error or rollback, so a pooled connection never
     carries one request's tenant into another.
   - Nested `withTransaction` calls become savepoints on the same connection. A
     savepoint rollback does not undo context set before the savepoint.
   - Unscoped execution is removed from the public API. Repositories receive an
     installation-bound handle, so an unscoped query does not compile.
4. **Platform work that touches one tenant narrows explicitly.**
   - Registry operations that change a tenant's rows (suspend, resume,
     operator member deactivation) run in platform mode.
   - They call `withInstallationScope(id)` inside the same transaction before
     they touch tenant tables.
   - Platform mode alone grants nothing on tenant tables.
5. **The effective role never bypasses Row-Level Security.**
   - Migration 0037 creates a `NOLOGIN NOSUPERUSER NOBYPASSRLS` role,
     `artifact_server_tenant`, with table privileges. It does so only when the
     migrating role is allowed to create roles.
   - When the session role is a superuser or bypasses Row-Level Security, every
     scoped transaction first runs `SET LOCAL ROLE artifact_server_tenant`.
   - At startup the server runs one scoped probe transaction. It refuses to
     serve if either of these holds:
     - the effective role is a superuser or bypasses Row-Level Security;
     - any table with `installation_id` lacks enabled and forced Row-Level
       Security with its policy.
6. **Future schema keeps the rule.**
   - Any migration that adds a table with `installation_id` must enable and
     force Row-Level Security with the standard policy in the same migration.
     The startup probe and a schema test fail otherwise.
   - A data migration that spans installations runs in platform mode and
     narrows to each installation in turn. No migration disables Row-Level
     Security.

## Consequences

- A missed `WHERE` clause, a raw-SQL mistake or a new code path can no longer
  read or write another installation's rows. Without context it reads nothing
  and cannot insert.
- Every repository call is one short transaction plus one `set_config` round
  trip. Code inside a scoped program must not do network or object-storage I/O
  while it holds the transaction.
- Global unique indexes that do not lead with `installation_id` still enforce
  uniqueness across tenants. Today these are only platform tables, audit-event
  random ids and the Git history provider identity, which tenants cannot use
  (ADR 0031).
- Compact SQLite installations are single-installation and unchanged.
- Operators who need cross-tenant diagnostics use the CLI, which iterates the
  registry in platform mode and narrows per installation. A direct `psql`
  session as the application role sees no tenant rows unless it sets the
  context itself.

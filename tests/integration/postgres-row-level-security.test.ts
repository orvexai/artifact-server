import {randomUUID} from "node:crypto";
import {readFile} from "node:fs/promises";

import {Effect, Option, Redacted, Schema} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {afterAll, beforeAll, describe, expect, test} from "vitest";

import {
  type PostgresDatabase,
  PostgresRowSecurityUnavailableError,
  withInstallationScope,
} from "../../src/storage/postgres-database.js";
import {PostgresDatabase as PostgresDatabaseRuntime} from "../../src/storage/postgres-database.js";
import {
  ROW_SECURITY_TENANT_TABLES,
  runPostgresMigrations,
} from "../../src/storage/postgres-migrations.js";
import {
  createOwnerRole,
  seedTenantRows,
  withMigrationFixtureConnection,
  withTenant,
} from "../support/postgres-rls.js";

const databaseUrl = process.env["ARTIFACT_SERVER_TEST_DATABASE_URL"];
const installations = [
  `rls-orvex-${randomUUID()}`,
  `rls-a-${randomUUID()}`,
  `rls-b-${randomUUID()}`,
] as const;
const [orvexId, installationA, installationB] = installations;
const deleteInstallation = `rls-delete-${randomUUID()}`;
const now = "2026-01-01T00:00:00.000Z";
let database: PostgresDatabase;

beforeAll(async() => {
  if (databaseUrl === undefined || databaseUrl.trim() === "") {
    throw new Error("ARTIFACT_SERVER_TEST_DATABASE_URL is required for Postgres RLS tests.");
  }
  database = await PostgresDatabaseRuntime.open({
    maxConnections: 2,
    url: Redacted.make(databaseUrl),
  }, "apply");
  await database.runAsPlatform(Effect.gen(function*() {
    const sql = yield* SqlClient;
    for (const [index, installationId] of [...installations, deleteInstallation].entries()) {
      yield* sql`INSERT INTO artifact_installations (id, created_at, slug, display_name, status, route_id)
        VALUES (${installationId}, ${now}, ${`rls-${index}-${randomUUID().slice(0, 8)}`},
         'RLS fixture', 'active', ${randomUUID().slice(0, 8)}) ON CONFLICT DO NOTHING`;
    }
    yield* sql`INSERT INTO artifact_platform_sessions
      (token_digest, organizations_json, identity_json, provider, subject, created_at, expires_at)
      VALUES (${`rls-platform-${randomUUID()}`}, '[]', '{}', 'rls-fixture', 'rls-fixture',
       ${now}, '2099-01-01T00:00:00.000Z') ON CONFLICT DO NOTHING`;
  }));
  await Promise.all(installations.map((installationId) => seedTenantRows(database, installationId)));
  // D is only for the rolled-back delete pass and omits immutable responses; dropping the deferrable
  // artifacts.current_version_id edge orders versions before artifacts without retaining that cycle.
  await seedTenantRows(database, deleteInstallation, {includeArtifactResponses: false});
});

afterAll(async() => {
  if (database !== undefined) await database.close();
});

describe("Postgres row-level security", () => {
  test("SEC-005-B scopes raw SQL across all tenant and platform tables", async() => {
    const catalog = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{
        readonly table_name: string;
        readonly relrowsecurity: boolean;
        readonly relforcerowsecurity: boolean;
        readonly policy_name: string | null;
      }>`
        SELECT cls.relname AS table_name, cls.relrowsecurity, cls.relforcerowsecurity,
          policy.polname AS policy_name
        FROM pg_class cls
        JOIN pg_namespace ns ON ns.oid = cls.relnamespace
        LEFT JOIN pg_policy policy ON policy.polrelid = cls.oid
        WHERE ns.nspname = 'public' AND cls.relkind = 'r'
          AND EXISTS (
            SELECT 1 FROM pg_attribute attr WHERE attr.attrelid = cls.oid
              AND attr.attname = 'installation_id' AND NOT attr.attisdropped
          )
        ORDER BY cls.relname
      `.withoutTransform;
    }));
    const catalogTables = catalog.map((table) => table.table_name).toSorted();
    expect(catalogTables).toEqual([...ROW_SECURITY_TENANT_TABLES].toSorted());
    expect(catalog).toHaveLength(39);
    expect(catalog.every((table) =>
      table.relrowsecurity && table.relforcerowsecurity && table.policy_name === "tenant_isolation"
    )).toBe(true);
    const platformCatalog = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{
        readonly table_name: string;
        readonly relrowsecurity: boolean;
        readonly relforcerowsecurity: boolean;
        readonly policy_name: string | null;
      }>`
        SELECT cls.relname AS table_name, cls.relrowsecurity, cls.relforcerowsecurity,
          policy.polname AS policy_name
        FROM pg_class cls
        JOIN pg_namespace ns ON ns.oid = cls.relnamespace
        LEFT JOIN pg_policy policy ON policy.polrelid = cls.oid
        WHERE ns.nspname = 'public' AND cls.relname IN ('artifact_installations', 'artifact_platform_sessions')
        ORDER BY cls.relname
      `.withoutTransform;
    }));
    expect(platformCatalog).toHaveLength(2);
    expect(platformCatalog.every((table) =>
      table.relrowsecurity && table.relforcerowsecurity && table.policy_name === "platform_access"
    )).toBe(true);

    const installationE = `rls-positive-${randomUUID()}`;
    await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`INSERT INTO artifact_installations (id, created_at, slug, display_name, status, route_id)
        VALUES (${installationE}, ${now}, ${`rls-positive-${randomUUID().slice(0, 8)}`},
         'RLS positive fixture', 'active', ${randomUUID().slice(0, 8)})`;
    }));
    await seedTenantRows(database, installationE);
    const positiveRows = await database.runInInstallation(installationE, Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rowsByTable = new Map<string, readonly {readonly installation_id: string}[]>();
      for (const table of ROW_SECURITY_TENANT_TABLES) {
        rowsByTable.set(table, yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${table}`,
        ).withoutTransform);
      }
      return rowsByTable;
    }));
    for (const table of ROW_SECURITY_TENANT_TABLES) {
      expect(positiveRows.get(table)).toEqual([{installation_id: installationE}]);
    }

    await Promise.all(ROW_SECURITY_TENANT_TABLES.map(async(table) => {
      const rows = await withTenant(database, installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${table}`,
        ).withoutTransform;
      }));
      expect(rows.map((row) => row.installation_id)).toEqual([installationA]);

      let positiveMutationCount = 0;
      if (table === "artifact_responses") {
        // The migration 0024 artifact_responses_immutable trigger fires only for policy-visible rows.
        await expectImmutableResponseFailure(withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          yield* sql`UPDATE artifact_responses SET question_id = question_id
            WHERE id = ${`${installationA}-response`}`;
        })));
        await expectImmutableResponseFailure(withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          yield* sql`DELETE FROM artifact_responses WHERE id = ${`${installationA}-response`}`;
        })));
        const stillVisible = await withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          return yield* sql<{readonly id: string; readonly installation_id: string}>`
            SELECT id, installation_id FROM artifact_responses
          `.withoutTransform;
        }));
        expectVisibleResponse(stillVisible, installationA);
        positiveMutationCount = stillVisible.length;
      } else {
        const updated = await withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          return yield* sql.unsafe<{readonly installation_id: string}>(
            `UPDATE ${table} SET installation_id = installation_id RETURNING installation_id`,
          ).withoutTransform;
        }));
        positiveMutationCount = updated.length;
      }
      expect(positiveMutationCount).toBe(1);
    }));

    const deleteOrder = await tenantDeleteOrder(database);
    const expectedDeleteTables = ROW_SECURITY_TENANT_TABLES.filter((table) => table !== "artifact_responses").toSorted();
    expect(deleteOrder.toSorted()).toEqual(expectedDeleteTables);
    const observedDeleteCounts = new Map<string, number>();
    await expect(database.runInInstallation(deleteInstallation, Effect.gen(function*() {
      const sql = yield* SqlClient;
      for (const table of deleteOrder) {
        const rows = yield* sql.unsafe<{readonly installation_id: string}>(
          `DELETE FROM ${table} RETURNING installation_id`,
        ).withoutTransform;
        observedDeleteCounts.set(table, rows.length);
      }
      return yield* Effect.fail(new Error("deliberate rollback of RLS delete proof"));
    }))).rejects.toThrow("deliberate rollback of RLS delete proof");
    for (const table of deleteOrder) expect(observedDeleteCounts.get(table)).toBe(1);

    await Promise.all([deleteInstallation, installationB, orvexId].map(async(installationId) => {
      const rowsByTable = await database.runInInstallation(installationId, Effect.gen(function*() {
        const sql = yield* SqlClient;
        const rows = new Map<string, readonly {readonly installation_id: string}[]>();
        for (const table of ROW_SECURITY_TENANT_TABLES) {
          const tableRows = yield* sql.unsafe<{readonly installation_id: string}>(
            `SELECT installation_id FROM ${table}`,
          ).withoutTransform;
          rows.set(table, tableRows);
        }
        return rows;
      }));
      for (const table of ROW_SECURITY_TENANT_TABLES) {
        const expectedCount = installationId === deleteInstallation && table === "artifact_responses" ? 0 : 1;
        expect(rowsByTable.get(table)).toHaveLength(expectedCount);
        expect(rowsByTable.get(table)?.every((row) => row.installation_id === installationId)).toBe(true);
      }
    }));

    const platform = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const installationsVisible = yield* sql<{readonly id: string}>`
        SELECT id FROM artifact_installations WHERE id IN (${orvexId}, ${installationA}, ${installationB})
      `.withoutTransform;
      const sessionsVisible = yield* sql<{readonly token_digest: string}>`
        SELECT token_digest FROM artifact_platform_sessions WHERE token_digest LIKE 'rls-platform-%'
      `.withoutTransform;
      yield* withInstallationScope(installationA);
      const ownInstallation = yield* sql<{readonly id: string}>`
        SELECT id FROM artifact_installations WHERE id = ${installationA}
      `.withoutTransform;
      return {installationsVisible, ownInstallation, sessionsVisible};
    }));
    expect(platform.installationsVisible.map((row) => row.id).toSorted()).toEqual([...installations].toSorted());
    expect(platform.ownInstallation.map((row) => row.id)).toEqual([installationA]);
    expect(platform.sessionsVisible.length).toBeGreaterThan(0);
    const platformWriteCounts = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      let writeCounts = {registry: 0, sessions: 0};
      yield* sql.withTransaction(Effect.gen(function*() {
        const registryRows = yield* sql`UPDATE artifact_installations
          SET display_name = display_name RETURNING id`;
        const sessions = yield* sql`UPDATE artifact_platform_sessions
          SET expires_at = expires_at RETURNING token_digest`;
        const token = `rls-platform-write-${randomUUID()}`;
        yield* sql`INSERT INTO artifact_platform_sessions
          (token_digest, organizations_json, identity_json, provider, subject, created_at, expires_at)
          VALUES (${token}, '[]', '{}', 'rls-fixture', 'rls-fixture', ${now},
           '2099-01-01T00:00:00.000Z')`;
        yield* sql`DELETE FROM artifact_platform_sessions WHERE token_digest = ${token}`;
        writeCounts = {registry: registryRows.length, sessions: sessions.length};
        return yield* Effect.fail(new Error("rollback platform write proof"));
      })).pipe(Effect.catch(() => Effect.void));
      return writeCounts;
    }));
    expect(platformWriteCounts.registry).toBeGreaterThan(0);
    expect(platformWriteCounts.sessions).toBeGreaterThan(0);
  });

  test("SEC-005-F hides other installations and rejects unauthorized inserts", async() => {
    await Promise.all(ROW_SECURITY_TENANT_TABLES.map(async(table) => {
      const visible = await withTenant(database, installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${table}`,
        ).withoutTransform;
      }));
      expect(visible.map((row) => row.installation_id)).toEqual([installationA]);

      let updatedCount: number;
      let deletedCount: number;
      let hiddenUpdateCount = 0;
      if (table === "artifact_responses") {
        const hiddenMutation = await withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          const updated = yield* sql`
            UPDATE artifact_responses SET question_id = question_id
            WHERE id IN (${`${installationB}-response`}, ${`${orvexId}-response`})
            RETURNING id
          `.withoutTransform;
          const deleted = yield* sql`
            DELETE FROM artifact_responses
            WHERE id IN (${`${installationB}-response`}, ${`${orvexId}-response`})
            RETURNING id
          `.withoutTransform;
          return {deleted, updated};
        }));
        updatedCount = hiddenMutation.updated.length;
        deletedCount = hiddenMutation.deleted.length;
      } else {
        const mutationCounts = await withTenant(database, installationA, Effect.gen(function*() {
          const sql = yield* SqlClient;
          const updated = yield* sql.unsafe<{readonly installation_id: string}>(
            "UPDATE " + table + " SET installation_id = installation_id RETURNING installation_id",
          ).withoutTransform;
          const hiddenUpdate = yield* sql.unsafe<{readonly installation_id: string}>(
            "UPDATE " + table + " SET installation_id = installation_id " +
              "WHERE installation_id IN ($1, $2) RETURNING installation_id",
            [installationB, orvexId],
          ).withoutTransform;
          const hiddenDelete = yield* sql.unsafe<{readonly installation_id: string}>(
            "DELETE FROM " + table + " " +
              "WHERE installation_id IN ($1, $2) RETURNING installation_id",
            [installationB, orvexId],
          ).withoutTransform;
          return {deleted: hiddenDelete.length, hiddenUpdate: hiddenUpdate.length, updated: updated.length};
        }));
        updatedCount = mutationCounts.updated;
        deletedCount = mutationCounts.deleted;
        hiddenUpdateCount = mutationCounts.hiddenUpdate;
      }
      expect(updatedCount).toBe(table === "artifact_responses" ? 0 : 1);
      expect(hiddenUpdateCount).toBe(0);
      expect(deletedCount).toBe(0);

      const sourceColumns = await database.runAsPlatform(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql<{readonly column_name: string}>`
          SELECT column_name FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = ${table} AND is_generated = 'NEVER'
          ORDER BY ordinal_position
        `.withoutTransform;
      }));
      const insertColumns = sourceColumns.map((column) => column.column_name);
      const fixture = await database.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly row_json: string}>(
          `SELECT row_to_json(fixture)::text AS row_json FROM ${table} AS fixture LIMIT 1`,
        ).withoutTransform;
      }));
      const fixtureRow = fixture[0]?.row_json;
      if (fixtureRow === undefined) throw new Error(`Missing cross-installation insert fixture for ${table}.`);
      const candidateColumns = insertColumns.map((column) => `candidate.${column}`).join(", ");
      const insertSql = `INSERT INTO ${table} (${insertColumns.join(", ")}) OVERRIDING SYSTEM VALUE
        SELECT ${candidateColumns} FROM jsonb_populate_record(
          NULL::${table}, ($1::jsonb || '{"installation_id":"${installationB}"}'::jsonb)
        ) AS candidate`;
      await expectSqlState(withTenant(database, installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql.unsafe(insertSql, [fixtureRow]);
        })), "42501");

      const bRows = await withTenant(database, installationB, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${table}`,
        ).withoutTransform;
      }));
      expect(bRows.map((row) => row.installation_id)).toEqual([installationB]);
    }));

    const withoutInstallation = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`SELECT set_config('app.installation_id', '', true), set_config('app.rls_mode', '', true)`;
      const emptyByTable = new Map<string, readonly {readonly installation_id: string}[]>();
      for (const table of ROW_SECURITY_TENANT_TABLES) {
        emptyByTable.set(table, yield* sql.unsafe<{readonly installation_id: string}>(`SELECT installation_id FROM ${table}`).withoutTransform);
      }
      return emptyByTable;
    }));
    for (const rows of withoutInstallation.values()) expect(rows).toHaveLength(0);

    await Promise.all(ROW_SECURITY_TENANT_TABLES.map(async(table) => {
      const columns = await database.runAsPlatform(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`SELECT set_config('app.installation_id', '', true), set_config('app.rls_mode', '', true)`;
        return yield* sql<{readonly column_name: string}>`
          SELECT column_name FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = ${table} AND is_generated = 'NEVER'
          ORDER BY ordinal_position
        `.withoutTransform;
      }));
      const columnNames = columns.map((column) => column.column_name);
      const fixture = await database.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly row_json: string}>(
          `SELECT row_to_json(fixture)::text AS row_json FROM ${table} AS fixture LIMIT 1`,
        ).withoutTransform;
      }));
      const fixtureRow = fixture[0]?.row_json;
      if (fixtureRow === undefined) throw new Error(`Missing no-context insert fixture for ${table}.`);
      const candidateColumns = columnNames.map((column) => `candidate.${column}`).join(", ");
      const insertWithoutContext = `INSERT INTO ${table} (${columnNames.join(", ")}) OVERRIDING SYSTEM VALUE
        SELECT ${candidateColumns} FROM jsonb_populate_record(
          NULL::${table}, ($1::jsonb || '{"installation_id":"no-context"}'::jsonb)
        ) AS candidate`;
      await expectSqlState(database.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`SELECT set_config('app.installation_id', '', true), set_config('app.rls_mode', '', true)`;
        yield* sql.unsafe(insertWithoutContext, [fixtureRow]);
      })), "42501");
    }));

    const tenantCannotReadPlatform = await database.runInInstallation(installationA, Effect.gen(function*() {
      const sql = yield* SqlClient;
      const sessions = yield* sql`SELECT token_digest FROM artifact_platform_sessions`;
      const otherRegistry = yield* sql`SELECT id FROM artifact_installations WHERE id <> ${installationA}`;
      return {otherRegistry, sessions};
    }));
    expect(tenantCannotReadPlatform.sessions).toHaveLength(0);
    expect(tenantCannotReadPlatform.otherRegistry).toHaveLength(0);

    const platformCannotReadTenant = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const counts: number[] = [];
      for (const table of ROW_SECURITY_TENANT_TABLES) {
        const rows = yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${table}`,
        ).withoutTransform;
        counts.push(rows.length);
      }
      return counts;
    }));
    expect(platformCannotReadTenant.every((count) => count === 0)).toBe(true);
  });

  test("SEC-006-B demotes privileged sessions and keeps scopes isolated in nested transactions", async() => {
    const role = await database.runInInstallation(installationA, Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{readonly current_user: string; readonly rolsuper: boolean; readonly rolbypassrls: boolean}>`
        SELECT current_user, role.rolsuper, role.rolbypassrls
        FROM pg_roles role WHERE role.rolname = current_user
      `.withoutTransform;
    }));
    expect(role[0]?.current_user).toBe("artifact_server_tenant");
    expect(role[0]?.rolsuper).toBe(false);
    expect(role[0]?.rolbypassrls).toBe(false);

    const owner = await createOwnerRole();
    let ownerDatabase: PostgresDatabase | undefined;
    const ownerInstallation = `rls-owner-${randomUUID()}`;
    try {
      ownerDatabase = await PostgresDatabaseRuntime.open(owner.config, "apply");
      await ownerDatabase.runAsPlatform(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`INSERT INTO artifact_installations
          (id, created_at, slug, display_name, status, route_id)
          VALUES (${ownerInstallation}, ${now}, ${`rls-owner-${randomUUID().slice(0, 8)}`},
           'RLS owner fixture', 'active', ${randomUUID().slice(0, 8)})`;
      }));
      await seedTenantRows(ownerDatabase, ownerInstallation);
      const ownerRole = await ownerDatabase.runInInstallation(ownerInstallation, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql<{
          readonly current_user: string;
          readonly rolsuper: boolean;
          readonly rolbypassrls: boolean;
        }>`
          SELECT current_user, role.rolsuper, role.rolbypassrls
          FROM pg_roles role WHERE role.rolname = current_user
        `.withoutTransform;
      }));
      expect(ownerRole[0]?.current_user).not.toBe("artifact_server_tenant");
      expect(ownerRole[0]?.rolsuper).toBe(false);
      expect(ownerRole[0]?.rolbypassrls).toBe(false);

      await ownerDatabase.runAsPlatform(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`ALTER TABLE projects NO FORCE ROW LEVEL SECURITY`;
      }));
      await ownerDatabase.close();
      ownerDatabase = undefined;
      await expect(PostgresDatabaseRuntime.open(owner.config, "validate"))
        .rejects.toBeInstanceOf(PostgresRowSecurityUnavailableError);
      const repairDatabase = await PostgresDatabaseRuntime.inspect(owner.config);
      try {
        await repairDatabase.runAsPlatform(Effect.gen(function*() {
          const sql = yield* SqlClient;
          yield* sql`ALTER TABLE projects FORCE ROW LEVEL SECURITY`;
        }));
      } finally {
        await repairDatabase.close();
      }
      ownerDatabase = await PostgresDatabaseRuntime.open(owner.config, "validate");

      const ownerScopeAfterSavepointRollback = await ownerDatabase.runInInstallation(
        ownerInstallation,
        Effect.gen(function*() {
          const sql = yield* SqlClient;
          yield* sql.withTransaction(Effect.gen(function*() {
            yield* sql`SELECT set_config('app.installation_id', 'nested-wrong-scope', true)`;
            yield* Effect.fail(new Error("nested owner rollback probe"));
          })).pipe(Effect.catch(() => Effect.void));
          return yield* sql.unsafe<{readonly installation_id: string}>(
            `SELECT installation_id FROM ${ROW_SECURITY_TENANT_TABLES[0]}`,
          ).withoutTransform;
        }),
      );
      expect(ownerScopeAfterSavepointRollback.map((row) => row.installation_id)).toEqual([ownerInstallation]);
    } finally {
      if (ownerDatabase !== undefined) await ownerDatabase.close();
      await owner.cleanup();
    }

    const scopedAfterRollback = await database.runInInstallation(installationA, Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql.withTransaction(Effect.gen(function*() {
        yield* sql`SELECT set_config('app.installation_id', 'nested-wrong-scope', true)`;
        yield* Effect.fail(new Error("nested rollback probe"));
      })).pipe(Effect.catch(() => Effect.void));
      return yield* sql.unsafe<{readonly installation_id: string}>(
        `SELECT installation_id FROM ${ROW_SECURITY_TENANT_TABLES[0]}`,
      ).withoutTransform;
    }));
    expect(scopedAfterRollback.map((row) => row.installation_id)).toEqual([installationA]);

    const requests = Array.from({length: 50}, (_, index) => {
      const installationId = index % 2 === 0 ? installationA : installationB;
      return database.runInInstallation(installationId, Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql.unsafe<{readonly installation_id: string}>(
          `SELECT installation_id FROM ${ROW_SECURITY_TENANT_TABLES[0]}`,
        ).withoutTransform;
      }));
    });
    const results = await Promise.all(requests);
    expect(results.every((rows, index) =>
      rows.length === 1 && rows[0]?.installation_id === (index % 2 === 0 ? installationA : installationB)
    )).toBe(true);
  });

  test("SEC-006-F clears transaction context and rejects empty scopes", async() => {
    await withMigrationFixtureConnection(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`ALTER ROLE artifact_server_tenant NOBYPASSRLS`;
    }));
    await expect(database.runInInstallation("  ", Effect.void)).rejects.toThrow(
      "Installation id must not be empty or whitespace.",
    );
    const afterCommit = await withTenant(database, installationA, Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{readonly installation_id: string}>`
        SELECT installation_id FROM ${sql.unsafe(ROW_SECURITY_TENANT_TABLES[0])}
      `.withoutTransform;
    }));
    expect(afterCommit).toHaveLength(1);

    const single = await PostgresDatabaseRuntime.open({
      applicationName: "artifact-server-rls-single-connection-test",
      maxConnections: 1,
      url: Redacted.make(databaseUrl ?? ""),
    }, "validate");
    try {
      const committedPid = await single.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        const rows = yield* sql<{readonly pid: number}>`SELECT pg_backend_pid()::integer AS pid`.withoutTransform;
        return rows[0]?.pid;
      }));
      if (committedPid === undefined) throw new Error("Missing committed pool backend pid.");

      let failedPid: number | undefined;
      await expect(single.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        const rows = yield* sql<{readonly pid: number}>`SELECT pg_backend_pid()::integer AS pid`.withoutTransform;
        failedPid = rows[0]?.pid;
        return yield* Effect.fail(new Error("deliberate outer transaction failure"));
      }))).rejects.toThrow("deliberate outer transaction failure");

      let nestedFailurePid: number | undefined;
      await expect(single.runInInstallation(installationA, Effect.gen(function*() {
        const sql = yield* SqlClient;
        const rows = yield* sql<{readonly pid: number}>`SELECT pg_backend_pid()::integer AS pid`.withoutTransform;
        nestedFailurePid = rows[0]?.pid;
        yield* sql.withTransaction(Effect.fail(new Error("deliberate nested savepoint failure")))
          .pipe(Effect.catch(() => Effect.void));
        return yield* Effect.fail(new Error("deliberate outer failure after nested rollback"));
      }))).rejects.toThrow("deliberate outer failure after nested rollback");

      const pids = [committedPid, failedPid, nestedFailurePid];
      expect(pids.every((pid) => pid !== undefined)).toBe(true);
      expect(new Set(pids).size).toBe(1);
      await [...new Set(pids)].reduce(async(previous, pid) => {
        await previous;
        if (pid === undefined) throw new Error("Missing scoped pool backend pid.");
        const activity = await withMigrationFixtureConnection(Effect.gen(function*() {
          const sql = yield* SqlClient;
          return yield* sql<{readonly idle: boolean; readonly no_backend_xid: boolean}>`
            SELECT state = 'idle' AS idle, backend_xid IS NULL AS no_backend_xid
            FROM pg_stat_activity WHERE pid = ${pid}
          `.withoutTransform;
        }));
        expect(activity).toEqual([{idle: true, no_backend_xid: true}]);

        const platformRows = await single.runAsPlatform(Effect.gen(function*() {
          const sql = yield* SqlClient;
          const backend = yield* sql<{readonly pid: number}>`SELECT pg_backend_pid()::integer AS pid`.withoutTransform;
          const counts: number[] = [];
          for (const table of ROW_SECURITY_TENANT_TABLES) {
            const rows = yield* sql.unsafe<{readonly installation_id: string}>(
              `SELECT installation_id FROM ${table}`,
            ).withoutTransform;
            counts.push(rows.length);
          }
          return {counts, pid: backend[0]?.pid};
        }));
        expect(platformRows.pid).toBe(pid);
        expect(platformRows.counts).toEqual(ROW_SECURITY_TENANT_TABLES.map(() => 0));

        const tenantRows = await single.runInInstallation(installationB, Effect.gen(function*() {
          const sql = yield* SqlClient;
          const backend = yield* sql<{readonly pid: number}>`SELECT pg_backend_pid()::integer AS pid`.withoutTransform;
          const installationsByTable: string[][] = [];
          for (const table of ROW_SECURITY_TENANT_TABLES) {
            const rows = yield* sql.unsafe<{readonly installation_id: string}>(
              `SELECT installation_id FROM ${table}`,
            ).withoutTransform;
            installationsByTable.push(rows.map((row) => row.installation_id));
          }
          return {installationsByTable, pid: backend[0]?.pid};
        }));
        expect(tenantRows.pid).toBe(pid);
        expect(tenantRows.installationsByTable).toEqual(ROW_SECURITY_TENANT_TABLES.map(() => [installationB]));
      }, Promise.resolve());
    } finally {
      await single.close();
    }

    try {
      await withMigrationFixtureConnection(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`ALTER ROLE artifact_server_tenant BYPASSRLS`;
      }));
      await expect(PostgresDatabaseRuntime.open({
        maxConnections: 2,
        url: Redacted.make(databaseUrl ?? ""),
      }, "validate")).rejects.toBeInstanceOf(PostgresRowSecurityUnavailableError);
    } finally {
      await withMigrationFixtureConnection(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`ALTER ROLE artifact_server_tenant NOBYPASSRLS`;
      }));
    }
    const restoredRoleDatabase = await PostgresDatabaseRuntime.open({
      maxConnections: 2,
      url: Redacted.make(databaseUrl ?? ""),
    }, "validate");
    await restoredRoleDatabase.close();

    const bypassOwner = await createOwnerRole({bypassRls: true});
    try {
      const ownerMembership = await withMigrationFixtureConnection(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql<{readonly is_member: boolean}>`
          SELECT pg_has_role(${bypassOwner.roleName}, 'artifact_server_tenant', 'MEMBER') AS is_member
        `.withoutTransform;
      }));
      expect(ownerMembership[0]?.is_member).toBe(false);
      await expect(PostgresDatabaseRuntime.open(bypassOwner.config, "apply")).rejects.toSatisfy((cause) =>
        cause instanceof PostgresRowSecurityUnavailableError && cause.message.includes("artifact_server_tenant")
      );
    } finally {
      await bypassOwner.cleanup();
    }

    await database.close();
    const downScript = await readFile(
      new URL("../../project/ops/0037-row-level-security-down.sql", import.meta.url),
      "utf8",
    );
    const previousBehavior = await withMigrationFixtureConnection(Effect.gen(function*() {
      const sql = yield* SqlClient;
      for (const statement of downScript.split(";").map((part) => part.trim()).filter((part) => part.length > 0)) {
        yield* sql.unsafe(statement);
      }
      const catalog = yield* sql<{readonly relrowsecurity: boolean; readonly relforcerowsecurity: boolean}>`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.projects'::regclass`;
      const visible = yield* sql<{readonly count: number}>`
        SELECT count(*)::integer AS count FROM projects
      `.withoutTransform;
      const highestMigration = yield* sql<{readonly migration_id: number}>`
        SELECT max(migration_id)::integer AS migration_id FROM artifact_server_postgres_migrations
      `.withoutTransform;
      const highestMigrationId = highestMigration[0]?.migration_id;
      yield* runPostgresMigrations;
      return {catalog: catalog[0], highestMigrationId, visibleCount: visible[0]?.count ?? 0};
    }));
    expect(previousBehavior.catalog?.relrowsecurity).toBe(false);
    expect(previousBehavior.catalog?.relforcerowsecurity).toBe(false);
    expect(previousBehavior.visibleCount).toBeGreaterThan(0);
    expect(previousBehavior.highestMigrationId).toBe(36);
    database = await PostgresDatabaseRuntime.open({
      maxConnections: 2,
      url: Redacted.make(databaseUrl ?? ""),
    }, "apply");
    const restored = await database.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{readonly relrowsecurity: boolean; readonly relforcerowsecurity: boolean}>`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.projects'::regclass`;
    }));
    expect(restored[0]?.relrowsecurity).toBe(true);
    expect(restored[0]?.relforcerowsecurity).toBe(true);
  });
});

const postgresErrorNode = Schema.Struct({
  cause: Schema.optional(Schema.Unknown),
  code: Schema.optional(Schema.String),
  message: Schema.optional(Schema.String),
  reason: Schema.optional(Schema.Unknown),
});

function postgresFailureMatches(failure: Error, expectedCode: string, expectedMessage?: string): boolean {
  const pending: unknown[] = [failure];
  const visited = new Set<object>();
  let foundCode = false;
  let foundMessage = expectedMessage === undefined;
  while (pending.length > 0) {
    const candidate = pending.pop();
    const node = Option.getOrUndefined(Schema.decodeUnknownOption(postgresErrorNode)(candidate));
    if (node === undefined) continue;
    if (node.code === expectedCode) foundCode = true;
    if (node.message?.includes(expectedMessage ?? "")) foundMessage = true;
    for (const nested of [node.cause, node.reason]) {
      if (nested === undefined) continue;
      const nestedObject = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.instanceOf(Object))(nested));
      if (nestedObject !== undefined && !visited.has(nestedObject)) {
        visited.add(nestedObject);
        pending.push(nestedObject);
      }
    }
  }
  return foundCode && foundMessage;
}

async function expectSqlState<A>(program: Promise<A>, expectedCode: string): Promise<void> {
  await expect(program).rejects.toSatisfy((value) => {
    const failure = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.instanceOf(Error))(value));
    return failure !== undefined && postgresFailureMatches(failure, expectedCode);
  });
}

async function expectImmutableResponseFailure(program: Promise<unknown>): Promise<void> {
  await expect(program).rejects.toSatisfy((value) => {
    const failure = Option.getOrUndefined(Schema.decodeUnknownOption(Schema.instanceOf(Error))(value));
    return failure !== undefined && postgresFailureMatches(
      failure,
      "P0001",
      "artifact responses are immutable",
    );
  });
}

function expectVisibleResponse(
  rows: readonly {readonly id: string; readonly installation_id: string}[],
  installationId: string,
): void {
  expect(rows).toEqual([{id: `${installationId}-response`, installation_id: installationId}]);
}

async function tenantDeleteOrder(connection: PostgresDatabase): Promise<string[]> {
  const tables = ROW_SECURITY_TENANT_TABLES.filter((table) => table !== "artifact_responses");
  const quotedTables = tables.map((table) => "'" + table + "'").join(", ");
  const constraints = await connection.runAsPlatform(Effect.gen(function*() {
    const sql = yield* SqlClient;
    return yield* sql.unsafe<{
      readonly child_table: string;
      readonly parent_table: string;
    }>(
      "SELECT child.relname AS child_table, parent.relname AS parent_table " +
        "FROM pg_constraint constraint_row " +
        "JOIN pg_class child ON child.oid = constraint_row.conrelid " +
        "JOIN pg_namespace child_ns ON child_ns.oid = child.relnamespace " +
        "JOIN pg_class parent ON parent.oid = constraint_row.confrelid " +
        "JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace " +
        "WHERE constraint_row.contype = 'f' AND constraint_row.condeferrable = false " +
        "AND child_ns.nspname = 'public' AND parent_ns.nspname = 'public' " +
        "AND child.relname IN (" + quotedTables + ") " +
        "AND parent.relname IN (" + quotedTables + ") " +
        "AND child.relname <> parent.relname",
    ).withoutTransform;
  }));
  const parentsByChild = new Map<string, string[]>(tables.map((table) => [table, []]));
  const childCountByParent = new Map<string, number>(tables.map((table) => [table, 0]));
  for (const constraint of constraints) {
    parentsByChild.get(constraint.child_table)?.push(constraint.parent_table);
    childCountByParent.set(
      constraint.parent_table,
      (childCountByParent.get(constraint.parent_table) ?? 0) + 1,
    );
  }
  const ready: string[] = tables.filter((table) => childCountByParent.get(table) === 0);
  const order: string[] = [];
  while (ready.length > 0) {
    const child = ready.shift();
    if (child === undefined) break;
    order.push(child);
    for (const parent of parentsByChild.get(child) ?? []) {
      const remaining = (childCountByParent.get(parent) ?? 0) - 1;
      childCountByParent.set(parent, remaining);
      if (remaining === 0) ready.push(parent);
    }
  }
  expect(order).toHaveLength(tables.length);
  expect(order.toSorted()).toEqual([...tables].toSorted());
  return order;
}

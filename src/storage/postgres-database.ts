import * as PgClient from "@effect/sql-pg/PgClient";
import {
  Effect,
  ManagedRuntime,
  Schema,
  type Redacted,
} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import type {SqlError} from "effect/unstable/sql/SqlError";

import {
  grantArtifactServerTenantObjectPrivileges,
  readPostgresMigrationStatus,
  ROW_SECURITY_TENANT_TABLES,
  runPostgresMigrations,
  type PostgresMigrationStatus,
} from "./postgres-migrations.js";

type PostgresRuntime = ManagedRuntime.ManagedRuntime<
  PgClient.PgClient | SqlClient,
  SqlError
>;

/** Configuration for one process-local Postgres pool. */
export interface PostgresDatabaseConfig {
  readonly applicationName?: string;
  readonly maxConnections?: number;
  readonly url: Redacted.Redacted;
}

/** Whether opening Postgres may mutate its schema. */
export type PostgresMigrationMode = "apply" | "validate";

/** The database schema cannot be served by this application build. */
export class PostgresSchemaIncompatibleError extends Schema.TaggedError<PostgresSchemaIncompatibleError>()(
  "PostgresSchemaIncompatibleError",
  {
    compatibility: Schema.Literals([
      "divergent",
      "missing",
      "newer",
      "pending",
    ]),
    currentVersion: Schema.Int,
    message: Schema.String,
    requiredVersion: Schema.Int,
  },
) {}

/** Postgres cannot safely serve because row-level security is unavailable. */
export class PostgresRowSecurityUnavailableError extends Schema.TaggedError<PostgresRowSecurityUnavailableError>()(
  "PostgresRowSecurityUnavailableError",
  {message: Schema.String},
) {}

/** Database handle permanently scoped to one trusted installation. */
export interface InstallationDatabase {
  readonly installationId: string;
  run<A, E>(
    program: Effect.Effect<A, E, SqlClient | PgClient.PgClient>,
  ): Promise<A>;
}

/** One owned Postgres pool and migration boundary shared by persistence adapters. */
export class PostgresDatabase {
  readonly #runtime: PostgresRuntime;
  readonly #privileged: boolean;

  private constructor(runtime: PostgresRuntime, privileged: boolean) {
    this.#runtime = runtime;
    this.#privileged = privileged;
  }

  /** Connect and apply or validate migrations before returning Postgres. */
  static async open(
    config: PostgresDatabaseConfig,
    migrationMode: PostgresMigrationMode,
  ): Promise<PostgresDatabase> {
    const database = await PostgresDatabase.inspect({
      ...config,
      applicationName: config.applicationName ?? "artifact-server",
      maxConnections: config.maxConnections ?? 10,
    });
    try {
      if (migrationMode === "apply") {
        await database.#runtime.runPromise(runPostgresMigrations);
      }
      const status = await database.migrationStatus();
      assertCompatibleMigrationStatus(status);
      if (database.#privileged) {
        await database.#runtime.runPromise(grantArtifactServerTenantObjectPrivileges);
      }
      await database.#probeRowSecurity();
      return database;
    } catch (cause) {
      await database.close();
      throw cause;
    }
  }

  /** Connect without applying or validating migrations for operator inspection. */
  static async inspect(
    config: PostgresDatabaseConfig,
  ): Promise<PostgresDatabase> {
    const runtime: PostgresRuntime = ManagedRuntime.make(PgClient.layer({
      applicationName: config.applicationName ?? "artifact-server-inspection",
      connectTimeout: "10 seconds",
      idleTimeout: "30 seconds",
      maxConnections: config.maxConnections ?? 1,
      url: config.url,
    }));
    try {
      await runtime.context();
      const privilegeRows = await runtime.runPromise(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql<{readonly privileged: boolean}>`
          SELECT rolsuper OR rolbypassrls AS privileged
          FROM pg_roles WHERE rolname = session_user
        `.withoutTransform;
      }));
      const privilegeRow = privilegeRows[0];
      if (privilegeRow === undefined) {
        throw new Error("Could not determine Postgres session role privileges.");
      }
      return new PostgresDatabase(runtime, privilegeRow.privileged);
    } catch (cause) {
      await runtime.dispose();
      throw cause;
    }
  }

  /** Read migration compatibility without applying schema changes. */
  migrationStatus(): Promise<PostgresMigrationStatus> {
    return this.#runtime.runPromise(readPostgresMigrationStatus);
  }

  /** Run an Effect SQL program in a transaction scoped to one installation. */
  runInInstallation<A, E>(
    installationId: string,
    program: Effect.Effect<A, E, SqlClient | PgClient.PgClient>,
  ): Promise<A> {
    if (installationId.trim() === "") {
      return Promise.reject(new TypeError("Installation id must not be empty or whitespace."));
    }
    const privileged = this.#privileged;
    return this.#runtime.runPromise(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        if (privileged) yield* sql`SET LOCAL ROLE artifact_server_tenant`;
        yield* sql`SELECT
          set_config('app.installation_id', ${installationId}, true),
          set_config('app.rls_mode', 'tenant', true)`;
        return yield* program;
      }));
    }));
  }

  /** Run an Effect SQL program with access to platform tables only. */
  runAsPlatform<A, E>(
    program: Effect.Effect<A, E, SqlClient | PgClient.PgClient>,
  ): Promise<A> {
    const privileged = this.#privileged;
    return this.#runtime.runPromise(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        if (privileged) yield* sql`SET LOCAL ROLE artifact_server_tenant`;
        yield* sql`SELECT
          set_config('app.installation_id', '', true),
          set_config('app.rls_mode', 'platform', true)`;
        return yield* program;
      }));
    }));
  }

  /** Bind a repository handle to one installation. */
  forInstallation(installationId: string): InstallationDatabase {
    if (installationId.trim() === "") {
      throw new TypeError("Installation id must not be empty or whitespace.");
    }
    return {
      installationId,
      run: (program) => this.runInInstallation(installationId, program),
    };
  }

  async #probeRowSecurity(): Promise<void> {
    try {
      await this.runInInstallation("artifact-server-rls-startup-probe", Effect.gen(function*() {
        const sql = yield* SqlClient;
        const roles = yield* sql<{
          readonly rolsuper: boolean;
          readonly rolbypassrls: boolean;
        }>`
          SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user
        `.withoutTransform;
        const role = roles[0];
        if (role === undefined || role.rolsuper || role.rolbypassrls) {
          return yield* Effect.die(new Error("Effective Postgres role bypasses row-level security."));
        }
        const tables = yield* sql<{
          readonly table_name: string;
          readonly relrowsecurity: boolean;
          readonly relforcerowsecurity: boolean;
          readonly policy_count: number;
          readonly expected_policy_count: number;
        }>`
          WITH protected_tables AS (
            SELECT cls.oid, cls.relname AS table_name, cls.relrowsecurity,
              cls.relforcerowsecurity,
              CASE WHEN cls.relname IN ('artifact_installations', 'artifact_platform_sessions')
                THEN 'platform_access' ELSE 'tenant_isolation' END AS expected_policy
            FROM pg_class cls
            JOIN pg_namespace ns ON ns.oid = cls.relnamespace
            WHERE ns.nspname = 'public' AND cls.relkind = 'r'
              AND (EXISTS (
                SELECT 1 FROM pg_attribute attr
                WHERE attr.attrelid = cls.oid AND attr.attname = 'installation_id'
                  AND NOT attr.attisdropped
              ) OR cls.relname IN ('artifact_installations', 'artifact_platform_sessions'))
          )
          SELECT protected_tables.table_name, relrowsecurity, relforcerowsecurity,
            count(policy.oid)::integer AS policy_count,
            count(policy.oid) FILTER (WHERE policy.polname = expected_policy)::integer
              AS expected_policy_count
          FROM protected_tables
          LEFT JOIN pg_policy policy ON policy.polrelid = protected_tables.oid
          GROUP BY protected_tables.oid, table_name, relrowsecurity,
            relforcerowsecurity, expected_policy
        `.withoutTransform;
        const expectedTables = new Set([
          ...ROW_SECURITY_TENANT_TABLES,
          "artifact_installations",
          "artifact_platform_sessions",
        ]);
        const observedTables = new Set(tables.map((table) => table.table_name));
        const missingTables = [...expectedTables].filter((table) => !observedTables.has(table));
        const unexpectedTables = [...observedTables].filter((table) => !expectedTables.has(table));
        const invalidTables = tables.filter((table) =>
          !table.relrowsecurity || !table.relforcerowsecurity ||
          table.policy_count !== 1 || table.expected_policy_count !== 1
        ).map((table) => table.table_name);
        if (missingTables.length > 0 || unexpectedTables.length > 0 || invalidTables.length > 0) {
          const detail = [
            ...missingTables.map((table) => `missing protected table ${table}`),
            ...unexpectedTables.map((table) => `unexpected protected table ${table}`),
            ...invalidTables.map((table) => `invalid RLS policy on ${table}`),
          ].join(", ");
          return yield* Effect.die(new Error(`RLS catalog probe failed: ${detail}.`));
        }
        return yield* Effect.void;
      }));
    } catch (cause) {
      const detail = String(cause);
      throw new PostgresRowSecurityUnavailableError({
        message: `Postgres row-level security startup probe failed${this.#privileged ? " for role artifact_server_tenant" : ""}: ${detail}`,
      });
    }
  }

  /** Verify that Postgres accepts a query before reporting ready. */
  health(): Promise<void> {
    return this.runAsPlatform(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`SELECT 1 AS healthy`;
    }).pipe(Effect.timeout("3 seconds")));
  }

  /** Close the process-local Postgres pool. */
  close(): Promise<void> {
    return this.#runtime.dispose();
  }
}

/** Narrow an active platform transaction to one installation's tenant rows. */
export const withInstallationScope = Effect.fnUntraced(function*(
  installationId: string,
) {
  if (installationId.trim() === "") {
    return yield* Effect.die(new TypeError("Installation id must not be empty or whitespace."));
  }
  const sql = yield* SqlClient;
  const modes = yield* sql<{readonly mode: string | null}>`
    SELECT current_setting('app.rls_mode', true) AS mode
  `.withoutTransform;
  if (modes[0]?.mode !== "platform") {
    return yield* Effect.die(new Error("Installation scope requires an active platform transaction."));
  }
  return yield* Effect.asVoid(sql`SELECT set_config('app.installation_id', ${installationId}, true)`);
});

function assertCompatibleMigrationStatus(status: PostgresMigrationStatus): void {
  if (status.compatibility === "current") return;
  throw new PostgresSchemaIncompatibleError({
    compatibility: status.compatibility,
    currentVersion: status.currentVersion,
    message: `Postgres schema ${status.currentVersion} is ${status.compatibility}; ` +
      `this build requires schema ${status.requiredVersion}.`,
    requiredVersion: status.requiredVersion,
  });
}

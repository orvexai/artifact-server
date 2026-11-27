import * as PgClient from "@effect/sql-pg/PgClient";
import {randomUUID} from "node:crypto";

import {Effect, ManagedRuntime, Redacted} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import type {SqlError} from "effect/unstable/sql/SqlError";

import {
  type PostgresDatabase,
  type PostgresDatabaseConfig,
} from "../../src/storage/postgres-database.js";
import {ROW_SECURITY_TENANT_TABLES} from "../../src/storage/postgres-migrations.js";

type PostgresRuntime = ManagedRuntime.ManagedRuntime<
  PgClient.PgClient | SqlClient,
  SqlError
>;

/** Run a fixture only with the Docker superuser URL, without tenant demotion. */
export async function withMigrationFixtureConnection<A, E>(
  program: Effect.Effect<A, E, SqlClient | PgClient.PgClient>,
  databaseUrl = process.env["ARTIFACT_SERVER_TEST_DATABASE_URL"],
): Promise<A> {
  if (databaseUrl === undefined || databaseUrl.trim() === "") {
    throw new Error("ARTIFACT_SERVER_TEST_DATABASE_URL is required for migration fixtures.");
  }
  const runtime: PostgresRuntime = ManagedRuntime.make(PgClient.layer({
    applicationName: "artifact-server-migration-fixture",
    connectTimeout: "10 seconds",
    idleTimeout: "30 seconds",
    maxConnections: 1,
    url: Redacted.make(databaseUrl),
  }));
  try {
    const roles = await runtime.runPromise(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql<{readonly privileged: boolean}>`
        SELECT rolsuper OR rolbypassrls AS privileged
        FROM pg_roles WHERE rolname = session_user
      `.withoutTransform;
    }));
    if (roles[0]?.privileged !== true) {
      throw new Error("Migration fixture URL must connect as a superuser or BYPASSRLS role.");
    }
    return await runtime.runPromise(program);
  } finally {
    await runtime.dispose();
  }
}

/** Raw SQL transaction scoped to one trusted test installation. */
export function withTenant<A, E>(
  database: PostgresDatabase,
  installationId: string,
  program: Effect.Effect<A, E, SqlClient | PgClient.PgClient>,
): Promise<A> {
  return database.runInInstallation(installationId, program);
}

/** Seed one valid, uniquely keyed row in every tenant table for isolation tests. */
export function seedTenantRows(
  database: PostgresDatabase,
  installationId: string,
  options: {readonly includeArtifactResponses?: boolean} = {},
): Promise<void> {
  return database.runInInstallation(installationId, Effect.gen(function*() {
    const sql = yield* SqlClient;
    const id = (suffix: string) => `${installationId}-${suffix}`;
    const now = "2026-01-01T00:00:00.000Z";

    yield* sql`INSERT INTO projects (installation_id, id, name, created_at)
      VALUES (${installationId}, 'prj_default', 'Default', ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO artifacts
      (installation_id, id, name, search_name, access_setting, created_at)
      VALUES (${installationId}, ${id("artifact")}, 'RLS fixture', 'rls fixture', 'account_required', ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO versions
      (installation_id, id, artifact_id, number, manifest_digest, entry_path,
       routing_mode, content_token, publisher_principal_id, created_at)
      VALUES (${installationId}, ${id("version")}, ${id("artifact")}, 1,
       'sha256:fixture', 'index.html', 'static', ${id("content")}, 'rls-fixture', ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`UPDATE artifacts SET current_version_id = ${id("version")}
      WHERE installation_id = ${installationId} AND id = ${id("artifact")}`;
    yield* sql`INSERT INTO installation_members
      (installation_id, id, email, display_name, role, status, created_at, updated_at)
      VALUES (${installationId}, ${id("member")}, ${id("member")} || '@example.test',
       'RLS fixture', 'owner', 'active', ${now}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO directory_groups (installation_id, id, name, path, synced_at)
      VALUES (${installationId}, ${id("group")}, 'RLS fixture', '/RLS fixture', ${now})
      ON CONFLICT DO NOTHING`;

    yield* sql`INSERT INTO actions
      (installation_id, id, artifact_id, version_id, action, principal_id, idempotency_key, created_at)
      VALUES (${installationId}, ${id("action")}, ${id("artifact")}, ${id("version")},
       'publish', 'rls-fixture', ${id("action-key")}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO agent_dispatches
      (installation_id, project_id, id, agent_id, agent_display_name, thread_ids_json,
       state, sender_principal_id, sender_principal_kind, sender_display_name,
       idempotency_key, created_at, updated_at)
      VALUES (${installationId}, 'prj_default', ${id("dispatch")}, ${id("agent")},
       'RLS fixture', '[]', 'queued', 'rls-fixture', 'human', 'RLS fixture',
       ${id("dispatch-key")}, ${now}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO application_sessions
      (installation_id, id, member_id, token_digest, csrf_digest, created_at, expires_at)
      VALUES (${installationId}, ${id("session")}, ${id("member")}, ${id("session-token")},
       ${id("csrf")}, ${now}, '2099-01-01T00:00:00.000Z') ON CONFLICT DO NOTHING`;
    if (options.includeArtifactResponses !== false) {
      yield* sql`INSERT INTO artifact_responses
        (installation_id, project_id, id, artifact_id, version_id, question_id, author_kind,
         author_subject, author_display_name, created_at)
        VALUES (${installationId}, 'prj_default', ${id("response")}, ${id("artifact")},
         ${id("version")}, 'question', 'member', ${id("member")}, 'RLS fixture', ${now})
        ON CONFLICT DO NOTHING`;
    }
    yield* sql`INSERT INTO artifact_state_entries
      (installation_id, project_id, artifact_id, key, value_json, updated_at,
       updated_by_display_name, updated_by_principal_id)
      VALUES (${installationId}, 'prj_default', ${id("artifact")}, 'state', '{}', ${now},
       'RLS fixture', 'rls-fixture') ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO artifact_tags (installation_id, artifact_id, tag)
      VALUES (${installationId}, ${id("artifact")}, ${id("tag")}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO comment_threads
      (installation_id, project_id, id, artifact_id, version_id, body, state,
       author_principal_id, author_principal_kind, author_display_name, idempotency_key,
       created_at, updated_at)
      VALUES (${installationId}, 'prj_default', ${id("thread")}, ${id("artifact")},
       ${id("version")}, 'RLS fixture', 'open', 'rls-fixture', 'human', 'RLS fixture',
       ${id("thread-key")}, ${now}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO comment_replies
      (installation_id, project_id, id, thread_id, body, author_principal_id,
       author_principal_kind, author_display_name, idempotency_key, created_at, updated_at)
      VALUES (${installationId}, 'prj_default', ${id("reply")}, ${id("thread")},
       'RLS fixture', 'rls-fixture', 'human', 'RLS fixture', ${id("reply-key")}, ${now}, ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO content_bootstraps
      (installation_id, token_digest, principal_id, artifact_id, version_id,
       content_token, created_at, expires_at)
      VALUES (${installationId}, ${id("bootstrap")}, 'rls-fixture', ${id("artifact")},
       ${id("version")}, ${id("content")}, ${now}, '2099-01-01T00:00:00.000Z')
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO content_sessions
      (installation_id, token_digest, principal_id, artifact_id, version_id,
       content_token, created_at, expires_at)
      VALUES (${installationId}, ${id("content-session")}, 'rls-fixture', ${id("artifact")},
       ${id("version")}, ${id("content")}, ${now}, '2099-01-01T00:00:00.000Z')
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO directory_group_members (installation_id, group_id, subject)
      VALUES (${installationId}, ${id("group")}, ${id("subject")}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO directory_group_role_rule_backfills (installation_id, backfilled_at)
      VALUES (${installationId}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO directory_group_role_seeds (installation_id, seeded_at)
      VALUES (${installationId}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO directory_group_roles
      (installation_id, group_id, role, assigned_at, assigned_by_principal_id)
      VALUES (${installationId}, ${id("group")}, 'owner', ${now}, 'rls-fixture')
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO external_identities
      (installation_id, provider, subject, member_id, email, bound_at)
      VALUES (${installationId}, 'rls-fixture', ${id("subject")}, ${id("member")},
       ${id("member")} || '@example.test', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_provider_identity
      (installation_id, provider, account_id, namespace, activated_at)
      VALUES (${installationId}, 'cloudflare-artifacts', ${id("account")}, ${id("namespace")}, ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_project_settings
      (installation_id, project_id, enabled, updated_by_principal_id, updated_at)
      VALUES (${installationId}, 'prj_default', false, 'rls-fixture', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_repositories
      (installation_id, project_id, artifact_id, provider, repository_name, remote_url,
       default_branch, status, created_at, updated_at)
      VALUES (${installationId}, 'prj_default', ${id("artifact")}, 'cloudflare-artifacts',
       ${id("repository")}, 'https://example.test/repository.git', 'main', 'provisioned', ${now}, ${now})
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_jobs
      (installation_id, id, project_id, artifact_id, kind, state, available_at, created_at, updated_at)
      VALUES (${installationId}, ${id("job")}, 'prj_default', ${id("artifact")},
       'delete-repository', 'queued', ${now}, ${now}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_mappings
      (installation_id, project_id, artifact_id, version_id, repository_name, commit_id,
       attempts, copied_bytes, status, created_at)
      VALUES (${installationId}, 'prj_default', ${id("artifact")}, ${id("version")},
       ${id("repository")}, ${id("commit")}, 1, 0, 'recorded', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO git_history_budget_reservations
      (installation_id, job_id, logical_bytes, state, updated_at)
      VALUES (${installationId}, ${id("job")}, 0, 'reserved', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO guest_review_invitations
      (installation_id, id, project_id, artifact_id, token_digest, created_by_principal_id, created_at)
      VALUES (${installationId}, ${id("invitation")}, 'prj_default', ${id("artifact")},
       ${id("invitation-token")}, 'rls-fixture', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO guest_review_sessions
      (installation_id, id, token_digest, csrf_digest, invitation_id, project_id,
       artifact_id, display_name, created_at, expires_at, absolute_expires_at, last_used_at)
      VALUES (${installationId}, ${id("guest-session")}, ${id("guest-token")}, ${id("guest-csrf")},
       ${id("invitation")}, 'prj_default', ${id("artifact")}, 'RLS fixture', ${now},
       '2099-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z', ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO idempotency_records
      (installation_id, idempotency_key, input_digest, artifact_id, version_id, created_at)
      VALUES (${installationId}, ${id("idempotency")}, 'sha256:fixture', ${id("artifact")},
       ${id("version")}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO installation_member_staff_audit
      (installation_id, member_id, member_email, actor, action, created_at)
      SELECT ${installationId}, ${id("member")}, ${id("member")} || '@example.test',
       'operator_cli', 'clear_staff', ${now}
      WHERE NOT EXISTS (SELECT 1 FROM installation_member_staff_audit
        WHERE installation_id = ${installationId} AND member_id = ${id("member")})`;
    yield* sql`INSERT INTO login_attempts
      (installation_id, state_digest, provider, code_verifier, return_to, created_at, expires_at)
      VALUES (${installationId}, ${id("login")}, 'rls-fixture', 'verifier', '/', ${now},
       '2099-01-01T00:00:00.000Z') ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO managed_api_keys
      (installation_id, id, name, prefix, secret_digest, principal_id, principal_kind,
       capabilities_json, authorized_by_principal_id, created_at, expires_at)
      VALUES (${installationId}, ${id("api-key")}, 'RLS fixture', ${id("key-prefix")},
       'sha256:fixture', 'rls-fixture', 'human', '[]', 'rls-fixture', ${now},
       '2099-01-01T00:00:00.000Z') ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO manifest_entries
      (installation_id, version_id, path, size, media_type, sha256, disposition)
      VALUES (${installationId}, ${id("version")}, 'index.html', 0, 'text/html',
       'sha256:fixture', 'inline') ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO project_archive_events
      (installation_id, project_id, action, principal_id, actor_display_name, created_at)
      SELECT ${installationId}, 'prj_default', 'archive', 'rls-fixture', 'RLS fixture', ${now}
      WHERE NOT EXISTS (SELECT 1 FROM project_archive_events
        WHERE installation_id = ${installationId} AND project_id = 'prj_default')`;
    yield* sql`INSERT INTO project_group_grants
      (installation_id, project_id, group_id, role, granted_at, granted_by_principal_id)
      VALUES (${installationId}, 'prj_default', ${id("group")}, 'manager', ${now}, 'rls-fixture')
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO project_provisioner_audit_events
      (installation_id, project_id, action, principal_id, client_id, actor_display_name, created_at)
      SELECT ${installationId}, 'prj_default', 'create', 'rls-fixture', 'rls-fixture',
       'RLS fixture', ${now}
      WHERE NOT EXISTS (SELECT 1 FROM project_provisioner_audit_events
        WHERE installation_id = ${installationId} AND project_id = 'prj_default')`;
    yield* sql`INSERT INTO registered_agents
      (installation_id, id, connection_key, display_name, kind, working_directory,
       principal_id, created_at, last_seen_at)
      VALUES (${installationId}, ${id("agent")}, ${id("connection")}, 'RLS fixture',
       'pi', '/', 'rls-fixture', ${now}, ${now}) ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO staged_uploads
      (installation_id, id, principal_id, status, manifest_digest, entry_path,
       routing_mode, created_at, expires_at)
      VALUES (${installationId}, ${id("upload")}, 'rls-fixture', 'open',
       'sha256:fixture', 'index.html', 'static', ${now}, '2099-01-01T00:00:00.000Z')
      ON CONFLICT DO NOTHING`;
    yield* sql`INSERT INTO staged_upload_files
      (installation_id, upload_id, storage_token, path, size, media_type, sha256, disposition)
      VALUES (${installationId}, ${id("upload")}, ${id("storage-token")}, 'index.html', 0,
       'text/html', 'sha256:fixture', 'inline') ON CONFLICT DO NOTHING`;
  }));
}

/** Create a disposable NOSUPERUSER owner database for the CNPG startup path. */
export async function createOwnerRole(options: {readonly bypassRls?: boolean} = {}): Promise<{
  readonly config: PostgresDatabaseConfig;
  readonly cleanup: () => Promise<void>;
  readonly roleName: string;
}> {
  const baseUrl = process.env["ARTIFACT_SERVER_TEST_DATABASE_URL"];
  if (baseUrl === undefined || baseUrl.trim() === "") {
    throw new Error("ARTIFACT_SERVER_TEST_DATABASE_URL is required to create the owner role.");
  }
  const role = `artifact_rls_owner_${randomUUID().replaceAll("-", "")}`;
  const databaseName = `artifact_rls_db_${randomUUID().replaceAll("-", "")}`;
  const password = randomUUID().replaceAll("-", "");
  const bypassRls = options.bypassRls === true;
  await withMigrationFixtureConnection(Effect.gen(function*() {
    const sql = yield* SqlClient;
    yield* sql.unsafe(`CREATE ROLE ${role} LOGIN NOSUPERUSER ${bypassRls ? "BYPASSRLS" : "NOBYPASSRLS"} PASSWORD '${password}'`);
    yield* sql.unsafe(`CREATE DATABASE ${databaseName} OWNER ${role}`);
  }));
  const ownerUrl = new URL(baseUrl);
  ownerUrl.username = role;
  ownerUrl.password = password;
  ownerUrl.pathname = `/${databaseName}`;
  const config: PostgresDatabaseConfig = {
    applicationName: "artifact-server-cnpg-rls-test",
    maxConnections: 2,
    url: Redacted.make(ownerUrl.toString()),
  };
  return {
    config,
    roleName: role,
    cleanup: () => withMigrationFixtureConnection(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = ${databaseName} AND pid <> pg_backend_pid()`;
      yield* sql.unsafe(`DROP DATABASE ${databaseName}`);
      yield* sql.unsafe(`DROP ROLE ${role}`);
    })),
  };
}

/** Tables protected by migration 0037. */
export {ROW_SECURITY_TENANT_TABLES};

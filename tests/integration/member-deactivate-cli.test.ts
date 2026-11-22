import {randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";

import {Effect, Redacted} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {afterAll, beforeAll, describe, expect, test} from "vitest";

import {principalKinds} from "../../src/core/identity.js";
import {OrganizationRegistry} from "../../src/external-storage/organization-registry.js";
import {PostgresDatabase} from "../../src/storage/postgres-database.js";
import {PostgresIdentityRepository} from "../../src/storage/postgres-identity-repository.js";

describe.sequential("P43 operator CLI member deactivate", () => {
  const databaseUrl = process.env["ARTIFACT_SERVER_TEST_DATABASE_URL"];
  const installationId = `p43-${randomUUID()}`;
  const tenantSlug = `p43-${randomUUID().slice(0, 8)}`;
  const editorId = randomUUID();
  const otherMemberId = randomUUID();
  const adminId = randomUUID();
  const sessionIds = [randomUUID(), randomUUID()];
  const otherSessionId = randomUUID();
  const adminSessionId = randomUUID();
  const keyId = `key_${randomUUID()}`;
  const otherKeyId = `key_${randomUUID()}`;
  let database: PostgresDatabase;
  let tenantInstallationId: string;

  const runCli = (...args: string[]) => spawnSync(process.execPath, [
    "--import", "tsx", "src/cli/main.ts", "member", "deactivate", ...args,
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ARTIFACT_SERVER_DATABASE_URL: databaseUrl,
      ARTIFACT_SERVER_INSTALLATION_ID: installationId,
    },
  });

  const readRows = () => database.run(Effect.gen(function*() {
    const sql = yield* SqlClient;
    const members = yield* sql`SELECT id, status, manual_deactivation AS "manualDeactivation"
      FROM installation_members WHERE installation_id = ${tenantInstallationId} ORDER BY id`;
    const sessions = yield* sql`SELECT id, revoked_at AS "revokedAt" FROM application_sessions
      WHERE installation_id = ${tenantInstallationId} ORDER BY id`;
    const keys = yield* sql`SELECT id, revoked_at AS "revokedAt" FROM managed_api_keys
      WHERE installation_id = ${tenantInstallationId} ORDER BY id`;
    return {keys, members, sessions};
  }));

  beforeAll(async () => {
    if (databaseUrl === undefined) {
      throw new Error("Run this test through scripts/with-external-storage-test-providers.sh.");
    }
    database = await PostgresDatabase.open({
      applicationName: "artifact-server-member-deactivate-cli-test",
      maxConnections: 8,
      url: Redacted.make(databaseUrl),
    }, "apply");
    const registry = new OrganizationRegistry(database);
    await registry.ensureOrvex(installationId);
    const tenant = await registry.create(tenantSlug, "P43 Tenant");
    tenantInstallationId = tenant.id;
    const now = new Date().toISOString();
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES
        (${editorId}, ${tenantInstallationId}, 'editor@p43.test', 'Editor', 'member', 'active', ${now}, ${now}),
        (${otherMemberId}, ${tenantInstallationId}, 'other@p43.test', 'Other', 'member', 'active', ${now}, ${now}),
        (${adminId}, ${tenantInstallationId}, 'admin@p43.test', 'Admin', 'administrator', 'active', ${now}, ${now})`;
    }));
    const repository = new PostgresIdentityRepository(database, tenantInstallationId);
    await Promise.all(sessionIds.map((sessionId, index) => repository.createApplicationSession({
        createdAt: now,
        csrfDigest: `csrf-${sessionId}`,
        expiresAt: "2099-01-01T00:00:00.000Z",
        id: sessionId,
        installationId: tenantInstallationId,
        memberId: editorId,
        tokenDigest: `token-${index}-${sessionId}`,
      })));
    await repository.createApplicationSession({
      createdAt: now,
      csrfDigest: `csrf-${otherSessionId}`,
      expiresAt: "2099-01-01T00:00:00.000Z",
      id: otherSessionId,
      installationId: tenantInstallationId,
      memberId: otherMemberId,
      tokenDigest: `token-${otherSessionId}`,
    });
    await repository.createApplicationSession({
      createdAt: now,
      csrfDigest: `csrf-${adminSessionId}`,
      expiresAt: "2099-01-01T00:00:00.000Z",
      id: adminSessionId,
      installationId: tenantInstallationId,
      memberId: adminId,
      tokenDigest: `token-${adminSessionId}`,
    });
    await Promise.all(([[keyId, editorId], [otherKeyId, otherMemberId]] as const).map(([id, memberId]) => repository.createApiKey({
        authorizedByPrincipalId: memberId,
        capabilities: [],
        createdAt: now,
        expiresAt: "2099-01-01T00:00:00.000Z",
        id,
        installationId: tenantInstallationId,
        name: "P43 test key",
        prefix: `prefix-${id}`,
        principalId: memberId,
        principalKind: principalKinds.human,
        revokedAt: null,
        rotatedFromId: null,
        secretDigest: `digest-${id}`,
      })));
  }, 60_000);

  afterAll(async () => {
    await database?.close();
  });

  test("P43-1 deactivates a member and revokes only their sessions and key", async () => {
    const result = runCli(tenantSlug, "EDITOR@p43.test", "--yes");
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      action: "deactivate",
      installationId: tenantInstallationId,
      memberEmail: "editor@p43.test",
      previousStatus: "active",
      status: "inactive",
      credentialsRevoked: true,
    });
    const {keys, members, sessions} = await readRows();
      expect(members.find(({id}) => id === editorId)).toMatchObject({
        manualDeactivation: true,
        status: "inactive",
      });
      const targetSessionIds = new Set<string>(sessionIds);
      expect(sessions.filter(({id}) => targetSessionIds.has(String(id))).every(({revokedAt}) => revokedAt !== null)).toBe(true);
      expect(keys.find(({id}) => id === keyId)?.["revokedAt"]).not.toBeNull();
      expect(sessions.find(({id}) => id === otherSessionId)?.["revokedAt"]).toBeNull();
      expect(keys.find(({id}) => id === otherKeyId)?.["revokedAt"]).toBeNull();
  });

  test("P43-2 is idempotent and preserves the original revocation times", async () => {
    const before = await readRows();
    const result = runCli(tenantSlug, "editor@p43.test", "--yes");
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({previousStatus: "inactive", status: "inactive"});
    const after = await readRows();
    const targetSessionIds = new Set<string>(sessionIds);
    expect(after.sessions.filter(({id}) => targetSessionIds.has(String(id)))).toEqual(
      before.sessions.filter(({id}) => targetSessionIds.has(String(id))),
    );
    expect(after.keys.find(({id}) => id === keyId)?.["revokedAt"]).toBe(
      before.keys.find(({id}) => id === keyId)?.["revokedAt"],
    );
  });

  test("P43-3 refuses to deactivate the last active administrator without changing rows", async () => {
    const before = await readRows();
    const result = runCli(tenantSlug, "admin@p43.test", "--yes");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("retain one active administrator");
    expect(await readRows()).toEqual(before);
  });

  test("P43-4 refuses missing confirmation, Orvex, unknown organizations, and unknown members", async () => {
    const before = await readRows();
    const missingConfirmation = runCli(tenantSlug, "editor@p43.test");
    expect(missingConfirmation.status).not.toBe(0);
    expect(await readRows()).toEqual(before);

    const orvex = runCli("orvex", "person@orvex.test", "--yes");
    expect(orvex.status).not.toBe(0);
    expect(orvex.stderr).toContain("Orvex members are governed by issuer groups");

    const unknownOrganization = runCli(`missing-${randomUUID().slice(0, 8)}`, "editor@p43.test", "--yes");
    expect(unknownOrganization.status).not.toBe(0);
    expect(unknownOrganization.stderr).toContain("Organization does not exist.");

    const unknownMember = runCli(tenantSlug, "missing@p43.test", "--yes");
    expect(unknownMember.status).not.toBe(0);
    expect(unknownMember.stderr).toContain("Member does not exist or email is ambiguous.");
    expect(await readRows()).toEqual(before);
  });

  test("P43-5 records manual deactivation for the tenant admission guard", async () => {
    expect(await new PostgresIdentityRepository(database, tenantInstallationId)
      .isMemberManuallyDeactivated(tenantInstallationId, "editor@p43.test")).toBe(true);
  });
});

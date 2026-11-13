import path from "node:path";
import {DatabaseSync} from "node:sqlite";

import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {createOidcIdentityProvider} from
  "../../src/identity/oidc-identity-provider.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import type {OidcGroupRoles} from "../../src/identity/oidc-groups-claim.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import {
  createTestInstallation,
  removeTestInstallation,
  reserveLoopbackPort,
  startTestServer,
  storeTestGroupRoles,
  storeTestKeeper,
  testKeeperEmail,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {
  startStubOidcLogin,
  startStubOidcProvider,
  type RunningStubOidcProvider,
} from "../support/stub-oidc-provider.js";

const bootstrapEmail = "administrator@example.test";
const groupRoles: OidcGroupRoles = {
  claim: "roles",
  seed: [
    {role: "administrator", selector: "artifact-admins"},
    {role: "member", selector: "artifact-users"},
  ],
};
const sessionResponseSchema = z.object({
  principal: z.object({
    id: z.string(),
    membershipRole: z.enum(["guest", "viewer", "member", "administrator", "owner"]),
  }),
});
const failureSchema = z.object({
  error: z.object({code: z.string(), message: z.string()}),
});
const memberRowSchema = z.object({
  email: z.string(),
  role: z.string(),
  status: z.string(),
});

describe("generic OIDC browser login with issuer group roles", () => {
  let installation: TestInstallation;
  let provider: RunningStubOidcProvider;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    provider = await startStubOidcProvider({
      clientId: "artifact-server-oidc-groups",
    });
    provider.claims.groupsClaim = groupRoles.claim;
    const port = await reserveLoopbackPort();
    const applicationOrigin = `http://127.0.0.1:${port}`;
    server = await startTestServer(installation, {
      applicationOrigin,
      bootstrapAdministratorEmail: bootstrapEmail,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      groupRolePolicy: {...groupRoles, guestGroupPrefixes: ["/Guests/"]},
      interactiveIdentityProvider: createOidcIdentityProvider({
        applicationOrigin,
        clientId: provider.clientId,
        clientSecret: null,
        groupRoles,
        issuer: provider.issuer,
        scopes: "openid email profile",
      }),
      port,
    });
  });

  afterEach(async () => {
    await server.stop();
    await provider.stop();
    await removeTestInstallation(installation);
  });

  test("until the directory sync stores roles, the configured roles apply to the reported groups", async () => {
    // No directory sync has run: the configured roles decide, exactly by name.
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-users", "artifact-admins"];
    expect(await sessionRole(await signIn())).toBe("administrator");

    provider.claims.email = "grace@example.test";
    provider.claims.subject = "subject-grace";
    provider.claims.groups = ["artifact-users", "sales"];
    expect(await sessionRole(await signIn())).toBe("member");

    provider.claims.email = "eve@example.test";
    provider.claims.subject = "subject-eve";
    provider.claims.groups = ["sales", "Artifact-Users"];
    const refused = await completeLogin();
    expect(refused.status).toBe(403);
    expect(failureSchema.parse(await refused.json()).error.message)
      .toBe("This person is not in a group admitted to the Artifact Server.");
  });

  test("a mirrored rule guest signs in again on a seeded installation; an unmirrored path is denied", async () => {
    await storeTestGroupRoles(server, installation, [
      {name: "artifact-admins", role: "administrator"},
      {name: "artifact-users", role: "member"},
    ]);
    provider.claims.email = "tenant@example.test";
    provider.claims.subject = "subject-tenant";
    provider.claims.groups = ["/Guests/acme"];
    expect((await completeLogin()).status).toBe(403);

    const databasePath = path.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    let installationId = "";
    let existingGroups: {id: string; name: string; path: string}[];
    try {
      installationId = z.object({installation_id: z.string()}).parse(database.prepare(
        "SELECT installation_id FROM directory_groups LIMIT 1",
      ).get()).installation_id;
      existingGroups = z.array(z.object({id: z.string(), name: z.string(), path: z.string()})).parse(database.prepare(
        "SELECT id, name, path FROM directory_groups",
      ).all());
    } finally {
      database.close();
    }
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      await repository.applyDirectoryGroups(installationId, {
        groups: [
          ...existingGroups.map((group) => Object.assign(group, {members: null})),
          {id: "group-tenant-acme", name: "acme", path: "/Guests/acme", members: [
            {email: "tenant@example.test", subject: "subject-tenant"},
          ]},
        ],
        guestGroupPrefixes: ["/Guests/"],
        provider: "test-oidc",
        syncedAt: new Date().toISOString(),
      });
      expect(await repository.listGroupRoles(installationId)).toContainEqual(expect.objectContaining({
        groupId: "group-tenant-acme", role: "guest", source: "rule",
      }));
    } finally {
      repository.close();
    }
    expect(await sessionRole(await signIn())).toBe("guest");
    expect(await sessionRole(await signIn())).toBe("guest");
  });

  test("once roles are stored they decide, and with none left sign-in is refused without changes", async () => {
    // The sync stored the starting roles, then every role was taken away.
    await storeTestGroupRoles(server, installation, []);
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-admins"];
    const refused = await completeLogin();
    expect(refused.status).toBe(403);
    expect(failureSchema.parse(await refused.json()).error).toEqual({
      code: "IDENTITY_ADMISSION_DENIED",
      message: "No group has been given a role in the Artifact Server yet.",
    });
    expect(members(installation)).toEqual([]);
  });

  test("the strongest stored group role wins, including Owner and Viewer, matched by name or full path", async () => {
    await storeTestGroupRoles(server, installation, [
      {name: "artifact-owners", role: "owner"},
      {name: "artifact-users", role: "member"},
      {name: "artifact-readers", role: "viewer"},
    ]);
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-readers", "artifact-owners", "artifact-users"];
    expect(await sessionRole(await signIn())).toBe("owner");

    provider.claims.email = "grace@example.test";
    provider.claims.subject = "subject-grace";
    provider.claims.groups = ["/artifact-readers"];
    expect(await sessionRole(await signIn())).toBe("viewer");
  });

  test("the last Admin or Owner keeps their role when their group loses it", async () => {
    await storeTestGroupRoles(server, installation, [
      {name: "artifact-owners", role: "owner"},
      {name: "artifact-users", role: "member"},
    ]);
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-owners"];
    expect(await sessionRole(await signIn())).toBe("owner");

    // Ada is the only Owner. Leaving the group, or every group, keeps her
    // role and access, so someone can still give the roles out again.
    await storeDirectoryMembership("ada@example.test", "subject-ada", "artifact-users");
    provider.claims.groups = ["artifact-users"];
    expect(await sessionRole(await signIn())).toBe("owner");
    provider.claims.groups = ["sales"];
    expect(await sessionRole(await signIn())).toBe("owner");
    expect(members(installation)).toEqual([
      {email: "ada@example.test", role: "owner", status: "active"},
    ]);

    // With another administrator in place, the same change applies.
    await storeTestKeeper(server, installation);
    provider.claims.groups = ["artifact-users"];
    expect(await sessionRole(await signIn())).toBe("member");
  });

  test("the configured claim admits people by group and every login re-applies their role", async () => {
    await storeTestGroupRoles(server, installation, [
      {name: "artifact-admins", role: "administrator"},
      {name: "artifact-users", role: "member"},
    ]);
    await storeTestKeeper(server, installation);
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-admins", "artifact-users"];
    const adaFirst = await signIn();
    expect(await sessionRole(adaFirst)).toBe("administrator");
    await storeDirectoryMembership("ada@example.test", "subject-ada", "artifact-admins");
    await storeDirectoryMembership("ada@example.test", "subject-ada", "artifact-users");

    provider.claims.email = "grace@example.test";
    provider.claims.subject = "subject-grace";
    provider.claims.groups = ["artifact-users", "sales"];
    expect(await sessionRole(await signIn())).toBe("member");
    await storeDirectoryMembership("grace@example.test", "subject-grace", "artifact-users");

    // Ada leaves the administrator group; her next login demotes her, and the
    // session she already holds follows the member it belongs to.
    provider.claims.email = "ada@example.test";
    provider.claims.subject = "subject-ada";
    provider.claims.groups = ["artifact-users"];
    await removeDirectoryMembership("subject-ada", "artifact-admins");
    expect(await sessionRole(await signIn())).toBe("member");
    expect(await sessionRole(adaFirst)).toBe("member");

    expect(members(installation)).toEqual([
      {email: "ada@example.test", role: "member", status: "active"},
      {email: "grace@example.test", role: "member", status: "active"},
    ]);
  });

  test("a person outside the groups is refused, deactivated, and signed out", async () => {
    await storeTestGroupRoles(server, installation, [
      {name: "artifact-users", role: "member"},
    ]);
    provider.claims.email = bootstrapEmail;
    provider.claims.groups = ["artifact-users"];
    const session = await signIn();
    expect(await sessionRole(session)).toBe("member");

    provider.claims.groups = ["sales"];
    const refused = await completeLogin();
    expect(refused.status).toBe(403);
    expect(refused.headers.getSetCookie()).toEqual([]);
    expect(failureSchema.parse(await refused.json()).error).toEqual({
      code: "IDENTITY_ADMISSION_DENIED",
      message: "This person is not in a group admitted to the Artifact Server.",
    });
    expect(members(installation)).toEqual([
      {email: bootstrapEmail, role: "member", status: "inactive"},
    ]);
    const revoked = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Cookie: session},
    });
    expect(revoked.status).toBe(401);

    // Without the claim at all, the bootstrap email admits no one either.
    provider.claims.groups = null;
    expect((await completeLogin()).status).toBe(403);
  });

  test("a groups claim that is not a list of strings fails as a provider failure", async () => {
    provider.claims.email = bootstrapEmail;
    provider.claims.groups = "artifact-admins";
    const refused = await completeLogin();
    expect(refused.status).toBe(502);
    expect(refused.headers.getSetCookie()).toEqual([]);
    expect(failureSchema.parse(await refused.json()).error.code)
      .toBe("IDENTITY_PROVIDER_FAILURE");
    expect(members(installation)).toEqual([]);
  });

  async function completeLogin(): Promise<Response> {
    const authorization = await startStubOidcLogin(server.baseUrl);
    return fetch(authorization.callbackUrl, {
      headers: {Cookie: authorization.handshakeCookie},
      redirect: "manual",
    });
  }

  async function storeDirectoryMembership(email: string, subject: string, group: string) {
    const database = new DatabaseSync(path.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const installationId = z.object({installation_id: z.string()}).parse(database.prepare(
        "SELECT installation_id FROM directory_groups LIMIT 1",
      ).get()).installation_id;
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`).run(
        installationId, `group-${group}`, subject, email, provider.issuer,
      );
    } finally {
      database.close();
    }
  }

  async function removeDirectoryMembership(subject: string, group: string) {
    const database = new DatabaseSync(path.join(installation.dataDirectory, "artifact-server.db"));
    try {
      database.prepare(`DELETE FROM directory_group_members WHERE group_id = ? AND subject = ?`)
        .run(`group-${group}`, subject);
    } finally {
      database.close();
    }
  }

  /** Complete one login and return the application cookie header it issued. */
  async function signIn(): Promise<string> {
    const completed = await completeLogin();
    expect(completed.status).toBe(303);
    const pairs = completed.headers.getSetCookie()
      .filter((value) =>
        value.startsWith("artifact_session=") || value.startsWith("artifact_csrf=")
      )
      .map((value) => value.split(";", 1)[0]);
    expect(pairs).toHaveLength(2);
    return pairs.join("; ");
  }

  async function sessionRole(cookieHeader: string): Promise<string> {
    const session = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Cookie: cookieHeader},
    });
    expect(session.status).toBe(200);
    return sessionResponseSchema.parse(await session.json())
      .principal.membershipRole;
  }
});

function members(
  installation: TestInstallation,
): readonly z.infer<typeof memberRowSchema>[] {
  const database = new DatabaseSync(
    path.join(installation.dataDirectory, "artifact-server.db"),
    {readOnly: true},
  );
  try {
    return database
      .prepare("SELECT email, role, status FROM installation_members ORDER BY email")
      .all()
      .map((row) => memberRowSchema.parse(row))
      .filter((row) => row.email !== testKeeperEmail);
  } finally {
    database.close();
  }
}

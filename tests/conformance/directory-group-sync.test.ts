import path from "node:path";
import {randomUUID} from "node:crypto";
import {DatabaseSync} from "node:sqlite";

import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {DirectoryGroupSyncReport} from
  "../../src/application/directory-sync.js";
import type {DirectoryGroupScope} from "../../src/core/directory-group-scope.js";
import type {ExternalMcpBearerVerifier} from "../../src/application/authentication.js";
import type {InteractiveIdentityProvider} from "../../src/application/interactive-login.js";
import type {ExternalIdentity} from "../../src/core/installation-identity.js";
import {AuthenticationRequired, IdentityProviderFailure} from "../../src/core/errors.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import type {OidcGroupRoles} from "../../src/identity/oidc-groups-claim.js";
import {
  KeycloakDirectory,
  keycloakAdminBaseUrl,
} from "../../src/identity/keycloak-directory.js";
import {createLocalRuntime} from "../../src/local/create-local-runtime.js";
import {oidcIdentityProviderName} from "../../src/core/project-access.js";
import {
  createTestInstallation,
  removeTestInstallation,
  type TestInstallation,
  loginHandshakeCookie,
} from "../support/runtime-harness.js";
import {
  keycloakUser,
  startStubKeycloak,
  type RunningStubKeycloak,
} from "../support/stub-keycloak-directory.js";

const groupRoles: OidcGroupRoles = {
  claim: "groups",
  seed: [
    {role: "administrator", selector: "artifact-admins"},
    {role: "member", selector: "artifact-users"},
  ],
};
const groupRowSchema = z.object({id: z.string(), name: z.string(), path: z.string()});
const memberRowSchema = z.object({
  email: z.string().nullable(),
  path: z.string(),
  subject: z.string(),
});

describe("Keycloak directory group sync", () => {
  let installation: TestInstallation;
  let keycloak: RunningStubKeycloak;

  beforeEach(async () => {
    installation = await createTestInstallation();
    keycloak = await startStubKeycloak();
    keycloak.groups.set("artifact-admins", [keycloakUser("ada")]);
    keycloak.groups.set("artifact-users", [keycloakUser("bob")]);
  });

  afterEach(async () => {
    await keycloak.stop();
    await removeTestInstallation(installation);
  });

  test("copies every group, nested ones by full path, with direct members only", async () => {
    keycloak.groups.set("Engineering", [keycloakUser("eve")]);
    keycloak.groups.set("Platform Team", [
      // Never-admitted and unverified people are members; a disabled one is not.
      keycloakUser("pat"),
      keycloakUser("uma", {emailVerified: false}),
      keycloakUser("dan", {enabled: false}),
    ]);
    keycloak.nestGroup("Platform Team", "Engineering");

    await expect(syncGroups()).resolves.toEqual(report({
      groups: 4,
      created: 4,
      membershipsReplaced: 4,
    }));
    expect(groups().map((group) => group.path)).toEqual([
      "/Engineering",
      "/Engineering/Platform Team",
      "/artifact-admins",
      "/artifact-users",
    ]);
    expect(groupMembers().filter((row) => row.path.startsWith("/Engineering")))
      .toEqual([
        {email: "eve@example.test", path: "/Engineering", subject: "user-eve"},
        {email: "pat@example.test", path: "/Engineering/Platform Team", subject: "user-pat"},
        {email: null, path: "/Engineering/Platform Team", subject: "user-uma"},
      ]);

    // A second pass with nothing new changes nothing but the membership copy.
    await expect(syncGroups()).resolves.toEqual(report({
      groups: 4,
      membershipsReplaced: 4,
    }));
  });

  test("AUTH-032-B, directory group sync keeps only in-scope groups", async () => {
    keycloak.groups.set("Engineering", [keycloakUser("ada")]);
    keycloak.groups.set("Guests", []);
    keycloak.groups.set("acme", [keycloakUser("legacy-guest")]);
    keycloak.nestGroup("acme", "Guests");

    // Seed a stored legacy tenant group with its actual Keycloak id, then add
    // an unstored tenant group that must not have its members read.
    await syncGroups();
    const database = new DatabaseSync(path.join(installation.dataDirectory, "artifact-server.db"));
    const now = new Date().toISOString();
    const installationId = "local";
    let legacyGroupId = "";
    try {
      legacyGroupId = z.object({id: z.string()}).parse(database.prepare(
        "SELECT id FROM directory_groups WHERE path = ?",
      ).get("/Guests/acme")).id;
      database.prepare(`INSERT INTO directory_group_roles (
        installation_id, group_id, role, assigned_at, assigned_by_principal_id
      ) VALUES (?, ?, 'guest', ?, 'test')`)
        .run(installationId, legacyGroupId, now);
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'guest', 'active', ?, ?)`)
        .run("legacy-acme-guest-member", installationId, "legacy-guest@example.test", "Legacy guest", now, now);
    } finally {
      database.close();
    }

    keycloak.groups.set("TenantWorkspaces", []);
    keycloak.groups.set("workspace", []);
    keycloak.groups.set("workspace-staff", [keycloakUser("staff")]);
    keycloak.nestGroup("workspace", "TenantWorkspaces");
    keycloak.nestGroup("workspace-staff", "workspace");
    await syncGroups();
    const staffDatabase = new DatabaseSync(path.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const staffId = z.object({id: z.string()}).parse(staffDatabase.prepare(
        "SELECT id FROM directory_groups WHERE path = ?",
      ).get("/TenantWorkspaces/workspace/workspace-staff")).id;
      staffDatabase.prepare(`INSERT INTO directory_group_roles (
        installation_id, group_id, role, assigned_at, assigned_by_principal_id
      ) VALUES (?, ?, 'member', ?, 'test')`)
        .run(installationId, staffId, now);
    } finally {
      staffDatabase.close();
    }
    keycloak.groups.set("other", [keycloakUser("blocked")]);
    keycloak.nestGroup("other", "workspace");
    keycloak.failGroupMembers("other");
    const storedGroupIdsBeforeSync = groups().map(({id}) => id);
    const requestStart = keycloak.adminRequests().length;

    await expect(syncGroups("2026-10-24T00:00:00.000Z", {
      kind: "orvex",
      excludeTenantPaths: true,
      organizationStaffGroups: ["/TenantWorkspaces/{slug}/{slug}-staff"],
    })).resolves.toMatchObject({groups: storedGroupIdsBeforeSync.length, deleted: 4});
    expect(groups().map((group) => group.path)).toEqual([
      "/Engineering",
      "/TenantWorkspaces/workspace/workspace-staff",
      "/artifact-admins",
      "/artifact-users",
    ]);
    expect(groupMembers().map((member) => member.path)).toEqual([
      "/Engineering",
      "/TenantWorkspaces/workspace/workspace-staff",
      "/artifact-admins",
      "/artifact-users",
    ]);
    const staffGroupId = groups().find(({path: groupPath}) =>
      groupPath === "/TenantWorkspaces/workspace/workspace-staff"
    )?.id;
    if (staffGroupId === undefined) throw new Error("The configured Orvex staff group was not retained.");
    const memberRequestIds = keycloak.adminRequests().slice(requestStart)
      .filter(({path: requestPath}) => requestPath.endsWith("/members"))
      .map(({path: requestPath}) => /^\/groups\/([^/]+)\/members$/u.exec(requestPath)?.[1])
      .filter((id) => id !== undefined);
    expect(memberRequestIds.toSorted()).toEqual(storedGroupIdsBeforeSync.toSorted());
    expect(memberRequestIds.filter((id) => id === legacyGroupId)).toHaveLength(1);
    expect(groups().some(({path: groupPath}) => groupPath.startsWith("/Guests") ||
      groupPath === "/TenantWorkspaces" || groupPath === "/TenantWorkspaces/workspace" ||
      groupPath === "/TenantWorkspaces/workspace/other")).toBe(false);
    const afterSync = new DatabaseSync(path.join(installation.dataDirectory, "artifact-server.db"), {
      readOnly: true,
    });
    try {
      expect(afterSync.prepare(`SELECT status FROM installation_members WHERE id = ?`)
        .get("legacy-acme-guest-member")).toEqual({status: "inactive"});
      expect(afterSync.prepare(`SELECT role FROM directory_group_roles WHERE group_id = ?`)
        .get(staffGroupId)).toEqual({role: "member"});
    } finally {
      afterSync.close();
    }

    const authInstallation = await createTestInstallation();
    const guestPath = "/TenantWorkspaces/acme/acme-guest";
    const staffPath = "/TenantWorkspaces/acme/acme-staff";
    const authPolicy: OidcGroupRoles = {
      claim: "groups",
      seed: [
        {role: "member", selector: guestPath},
        {role: "member", selector: staffPath},
      ],
    };
    const authScope: DirectoryGroupScope = {
      kind: "orvex",
      excludeTenantPaths: true,
      organizationStaffGroups: ["/TenantWorkspaces/{slug}/{slug}-staff"],
    };
    const loginStatus = async (identity: ExternalIdentity, scope: DirectoryGroupScope) => {
      const state = randomUUID();
      const code = randomUUID();
      const provider: InteractiveIdentityProvider = {
        name: identity.provider,
        start: () => Effect.succeed({
          authorizationUrl: "https://identity.example/authorize",
          codeVerifier: randomUUID(),
          nonce: null,
          state,
        }),
        complete: (receivedCode) => receivedCode === code
          ? Effect.succeed(identity)
          : Effect.fail(new IdentityProviderFailure({message: "Invalid test code."})),
      };
      const runtime = await createLocalRuntime({
        apiToken: authInstallation.apiToken,
        browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
        contentDomain: "localhost",
        dataDirectory: authInstallation.dataDirectory,
        directoryGroupScope: scope,
        groupRolePolicy: authPolicy,
        interactiveIdentityProvider: provider,
        orvexTenantGroupProtection: false,
      });
      try {
        const login = await runtime.app.request("http://localhost/auth/login");
        const callback = new URL("http://localhost/auth/callback");
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", state);
        const response = await runtime.app.request(callback, {
          headers: {Cookie: loginHandshakeCookie(login)},
        });
        return response.status;
      } finally {
        await runtime.close();
      }
    };
    const serviceStatus = async (scope: DirectoryGroupScope) => {
      const verifier: ExternalMcpBearerVerifier = {
        verify: (credential) => Redacted.value(credential) === "directory-scope-service"
          ? Effect.succeed({
            clientId: "directory-scope-service",
            expiresAt: Math.floor(Date.now() / 1_000) + 60,
            provider: "directory-scope-test",
            scopes: ["api"],
            subject: "directory-scope-service",
          })
          : Effect.fail(new AuthenticationRequired({message: "Invalid test credential."})),
        resolveIdentity: () => Effect.succeed({
          displayName: "Directory scope service",
          email: null,
          emailVerified: false,
          groups: [guestPath],
          provider: "directory-scope-test",
          serviceAccount: true,
          serviceAccountClientId: "directory-scope-service",
          subject: "directory-scope-service",
        }),
      };
      const runtime = await createLocalRuntime({
        apiToken: authInstallation.apiToken,
        browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
        contentDomain: "localhost",
        dataDirectory: authInstallation.dataDirectory,
        directoryGroupScope: scope,
        externalApiOAuthVerifier: verifier,
        groupRolePolicy: authPolicy,
        orvexTenantGroupProtection: false,
      });
      try {
        const response = await runtime.app.request("http://localhost/api/v1/artifacts/missing/responses", {
          headers: {Authorization: "Bearer directory-scope-service"},
        });
        return response.status;
      } finally {
        await runtime.close();
      }
    };
    const guestIdentity = (subject: string): ExternalIdentity => ({
      displayName: subject,
      email: `${subject}@example.test`,
      emailVerified: true,
      groups: [guestPath],
      provider: "directory-scope-test",
      subject,
    });
    const staffIdentity: ExternalIdentity = {
      displayName: "Staff principal",
      email: "staff@example.test",
      emailVerified: true,
      groups: [staffPath],
      provider: "directory-scope-test",
      subject: "directory-scope-staff",
    };
    try {
      expect(await loginStatus(guestIdentity("configured-guest"), authScope)).toBe(403);
      expect(await serviceStatus(authScope)).toBe(403);
      expect(await loginStatus(staffIdentity, authScope)).toBe(303);

      const authDatabase = new DatabaseSync(path.join(authInstallation.dataDirectory, "artifact-server.db"));
      try {
        const authNow = new Date().toISOString();
        const authGroups: Array<[string, string]> = [
          ["auth-acme-guest", guestPath],
          ["auth-acme-staff", staffPath],
        ];
        for (const [id, pathValue] of authGroups) {
          authDatabase.prepare(`INSERT INTO directory_groups
            (installation_id, id, name, path, first_path, synced_at)
            VALUES ('local', ?, ?, ?, ?, ?)`)
            .run(id, pathValue.slice(pathValue.lastIndexOf("/") + 1), pathValue, pathValue, authNow);
          authDatabase.prepare(`INSERT INTO directory_group_roles
            (installation_id, group_id, role, assigned_at, assigned_by_principal_id)
            VALUES ('local', ?, 'member', ?, 'test')`).run(id, authNow);
        }
        authDatabase.prepare(`INSERT INTO directory_group_role_seeds (installation_id, seeded_at)
          VALUES ('local', ?)`)
          .run(authNow);
      } finally {
        authDatabase.close();
      }

      expect(await loginStatus(guestIdentity("stored-guest"), authScope)).toBe(403);
      expect(await serviceStatus(authScope)).toBe(403);
      expect(await loginStatus(guestIdentity("all-scope-guest"), {kind: "all"})).toBe(303);
      expect(await serviceStatus({kind: "all"})).toBe(404);
    } finally {
      await removeTestInstallation(authInstallation);
    }
  });

  test("Keycloak-managed tenant sync refuses before directory access", async () => {
    keycloak.groups.set("Control", [keycloakUser("control")]);
    keycloak.groups.set("Included", [keycloakUser("included")]);
    keycloak.nestGroup("Included", "Control");
    await expect(syncGroups("2026-10-24T00:00:00.000Z", {kind: "none"})).rejects.toThrow(
      "Directory groups are not synced for an organization whose membership is managed by Keycloak Organizations; nothing was changed.",
    );
    expect(keycloak.tokenRequests()).toBe(0);
    expect(groups()).toEqual([]);

    const successfulControl = await syncGroups("2026-10-24T00:00:00.000Z", {
      kind: "roots",
      roots: ["/Control"],
    });
    expect(successfulControl.groups).toBe(1);
    expect(keycloak.tokenRequests()).toBe(1);
  });

  test("a rename keeps the group id, and a group gone from Keycloak is deleted", async () => {
    keycloak.groups.set("Ops", [keycloakUser("olga")]);
    keycloak.groups.set("Design", [keycloakUser("dee")]);
    await syncGroups();
    const before = new Map(groups().map((group) => [group.name, group.id]));

    keycloak.renameGroup("Ops", "Operations");
    keycloak.groups.delete("Design");
    await expect(syncGroups()).resolves.toEqual(report({
      groups: 3,
      renamed: 1,
      deleted: 1,
      membershipsReplaced: 3,
    }));
    const after = groups();
    expect(after.find((group) => group.name === "Operations")?.id).toBe(before.get("Ops"));
    expect(after.some((group) => group.name === "Design")).toBe(false);
    expect(groupMembers().some((row) => row.subject === "user-dee")).toBe(false);
  });

  test("two groups swapping paths in one pass do not collide", async () => {
    keycloak.groups.set("Red", [keycloakUser("rae")]);
    keycloak.groups.set("Blue", [keycloakUser("bo")]);
    await syncGroups();
    keycloak.renameGroup("Red", "Swap");
    keycloak.renameGroup("Blue", "Red");
    keycloak.renameGroup("Swap", "Blue");
    await expect(syncGroups()).resolves.toMatchObject({renamed: 2, deleted: 0});
    const byName = new Map(groupMembers().map((row) => [row.subject, row.path]));
    expect(byName.get("user-rae")).toBe("/Blue");
    expect(byName.get("user-bo")).toBe("/Red");
  });

  test("an unreadable group fails the whole pass and changes nothing", async () => {
    keycloak.groups.set("Platform Team", [keycloakUser("pat")]);
    keycloak.groups.set("Engineering", [keycloakUser("eve")]);
    await syncGroups();

    keycloak.groups.set("Platform Team", [keycloakUser("pat"), keycloakUser("quinn")]);
    keycloak.groups.set("Engineering", [keycloakUser("eve"), keycloakUser("ezra")]);
    const before = {
      groups: rowsOf("SELECT id, name, path, synced_at FROM directory_groups ORDER BY path"),
      members: groupMembers(),
      memberRolesAndStatuses: rowsOf(
        "SELECT id, role, status FROM installation_members ORDER BY id",
      ),
    };
    keycloak.failGroupMembers("Platform Team");
    await expect(syncGroups("2026-10-24T01:00:00.000Z")).rejects.toThrow(
      "The Keycloak members of /Platform Team returned HTTP 500.",
    );
    expect({
      groups: rowsOf("SELECT id, name, path, synced_at FROM directory_groups ORDER BY path"),
      members: groupMembers(),
      memberRolesAndStatuses: rowsOf(
        "SELECT id, role, status FROM installation_members ORDER BY id",
      ),
    }).toEqual(before);
  });

  test("more than one page of groups and members is read completely", async () => {
    for (let index = 0; index < 130; index += 1) {
      keycloak.groups.set(`team-${String(index).padStart(3, "0")}`, [keycloakUser(`u${index}`)]);
    }
    keycloak.groups.set("crowd", Array.from({length: 150}, (_, index) => keycloakUser(`c${index}`)));
    await expect(syncGroups()).resolves.toMatchObject({groups: 133, created: 133});
    expect(groups()).toHaveLength(133);
    expect(groupMembers().filter((row) => row.path === "/crowd")).toHaveLength(150);
    // One admin token serves the whole pass, not one per group.
    expect(keycloak.tokenRequests()).toBe(1);
  });

  test("the groups API lists copied groups by path with member counts", async () => {
    keycloak.groups.set("Platform Team", [keycloakUser("pat"), keycloakUser("quinn")]);
    await syncGroups();
    const runtime = await openRuntime();
    try {
      const response = await runtime.app.request("http://localhost/api/v1/groups", {
        headers: {Authorization: `Bearer ${installation.apiToken}`},
      });
      expect(response.status).toBe(200);
      const body = z.object({groups: z.array(z.object({
        memberCount: z.number(),
        path: z.string(),
      }).loose())}).parse(await response.json());
      expect(body.groups.map(({memberCount, path: groupPath}) => [groupPath, memberCount]))
        .toEqual([
          ["/Platform Team", 2],
          ["/artifact-admins", 1],
          ["/artifact-users", 1],
        ]);
    } finally {
      await runtime.close();
    }
  });

  test("a failed group listing changes and deletes nothing", async () => {
    keycloak.groups.set("Platform Team", [keycloakUser("pat")]);
    await syncGroups();
    const before = {groups: groups(), members: groupMembers()};

    keycloak.groups.delete("Platform Team");
    keycloak.setTokenStatus(503);
    await expect(syncGroups()).rejects.toThrow("The Keycloak token request returned HTTP 503.");
    expect({groups: groups(), members: groupMembers()}).toEqual(before);
  });

  function openRuntime(directoryGroupScope: DirectoryGroupScope = {kind: "all"}) {
    return createLocalRuntime({
      apiToken: installation.apiToken,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "localhost",
      dataDirectory: installation.dataDirectory,
      directoryGroupScope,
      groupRolePolicy: groupRoles,
    });
  }

  async function syncGroups(
    syncedAt = "2026-10-24T00:00:00.000Z",
    directoryGroupScope: DirectoryGroupScope = {kind: "all"},
  ): Promise<DirectoryGroupSyncReport> {
    const runtime = await openRuntime(directoryGroupScope);
    try {
      const adminBaseUrl = keycloakAdminBaseUrl(keycloak.issuer);
      if (adminBaseUrl === null) throw new Error("The stub issuer is not a realm.");
      return await runtime.syncDirectoryGroups(new KeycloakDirectory({
        adminBaseUrl,
        clientId: keycloak.clientId,
        clientSecret: Redacted.make(keycloak.clientSecret),
        issuer: keycloak.issuer,
        retryBaseDelayMilliseconds: 0,
      }), syncedAt, oidcIdentityProviderName(keycloak.issuer));
    } finally {
      await runtime.close();
    }
  }

  function groups(): readonly z.infer<typeof groupRowSchema>[] {
    return rowsOf("SELECT id, name, path FROM directory_groups ORDER BY path")
      .map((row) => groupRowSchema.parse(row));
  }

  function groupMembers(): readonly z.infer<typeof memberRowSchema>[] {
    return rowsOf(`SELECT g.path, m.subject, m.email
      FROM directory_group_members m
      JOIN directory_groups g ON g.installation_id = m.installation_id AND g.id = m.group_id
      ORDER BY g.path, m.subject`).map((row) => memberRowSchema.parse(row));
  }

  function rowsOf(sql: string) {
    const database = new DatabaseSync(
      path.join(installation.dataDirectory, "artifact-server.db"),
      {readOnly: true},
    );
    try {
      return database.prepare(sql).all();
    } finally {
      database.close();
    }
  }
});

function report(changes: Partial<DirectoryGroupSyncReport>): DirectoryGroupSyncReport {
  return {
    groups: 0,
    created: 0,
    renamed: 0,
    deleted: 0,
    membershipsReplaced: 0,
    groupsFailed: 0,
    ...changes,
  };
}

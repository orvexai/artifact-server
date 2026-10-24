import path from "node:path";
import {DatabaseSync} from "node:sqlite";

import {Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {DirectoryGroupSyncReport} from
  "../../src/application/directory-sync.js";
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
import {
  createTestInstallation,
  removeTestInstallation,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {
  keycloakUser,
  startStubKeycloak,
  type RunningStubKeycloak,
} from "../support/stub-keycloak-directory.js";

const groupRoles: OidcGroupRoles = {
  administratorGroups: ["artifact-admins"],
  claim: "groups",
  memberGroups: ["artifact-users"],
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

  test("an unreadable group keeps its stored members; the rest still sync", async () => {
    keycloak.groups.set("Platform Team", [keycloakUser("pat")]);
    keycloak.groups.set("Engineering", [keycloakUser("eve")]);
    await syncGroups();

    keycloak.groups.set("Platform Team", [keycloakUser("pat"), keycloakUser("quinn")]);
    keycloak.groups.set("Engineering", [keycloakUser("eve"), keycloakUser("ezra")]);
    keycloak.failGroupMembers("Platform Team");
    await expect(syncGroups("2026-10-24T01:00:00.000Z")).resolves.toEqual(report({
      groups: 4,
      membershipsReplaced: 3,
      groupsFailed: 1,
    }));
    const subjects = (groupPath: string) => groupMembers()
      .filter((row) => row.path === groupPath)
      .map((row) => row.subject);
    expect(subjects("/Platform Team")).toEqual(["user-pat"]);
    expect(subjects("/Engineering")).toEqual(["user-eve", "user-ezra"]);
    // The kept group still says when its members were last actually read.
    const syncedAt = new Map(rowsOf("SELECT path, synced_at FROM directory_groups")
      .map((row) => [String(row["path"]), String(row["synced_at"])]));
    expect(syncedAt.get("/Platform Team")).toBe("2026-10-24T00:00:00.000Z");
    expect(syncedAt.get("/Engineering")).toBe("2026-10-24T01:00:00.000Z");
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

  function openRuntime() {
    return createLocalRuntime({
      apiToken: installation.apiToken,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "localhost",
      dataDirectory: installation.dataDirectory,
      groupRolePolicy: groupRoles,
    });
  }

  async function syncGroups(
    syncedAt = "2026-10-24T00:00:00.000Z",
  ): Promise<DirectoryGroupSyncReport> {
    const runtime = await openRuntime();
    try {
      const adminBaseUrl = keycloakAdminBaseUrl(keycloak.issuer);
      if (adminBaseUrl === null) throw new Error("The stub issuer is not a realm.");
      return await runtime.syncDirectoryGroups(new KeycloakDirectory({
        adminBaseUrl,
        clientId: keycloak.clientId,
        clientSecret: Redacted.make(keycloak.clientSecret),
        issuer: keycloak.issuer,
        retryBaseDelayMilliseconds: 0,
      }), syncedAt);
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

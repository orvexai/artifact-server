import path from "node:path";
import {DatabaseSync} from "node:sqlite";

import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import type {DirectoryGroupObservation} from "../../src/core/directory-groups.js";
import {createLocalRuntime} from "../../src/local/create-local-runtime.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {
  createTestInstallation,
  removeTestInstallation,
  type TestInstallation,
} from "../support/runtime-harness.js";

const keycloak = "oidc:https://idp.example.test/realms/main";
const otherProvider = "oidc:https://other.example.test";
const defaultProject = "prj_default";

describe("project access storage (SQLite)", () => {
  let installation: TestInstallation;
  let databasePath: string;
  let installationId: string;
  let repository: SqliteIdentityRepository;

  beforeEach(async () => {
    installation = await createTestInstallation();
    databasePath = path.join(installation.dataDirectory, "artifact-server.db");
    // Let the runtime create and migrate the database as production does.
    await (await openRuntime()).close();
    installationId = z.object({installation_id: z.string()}).parse(
      readOnly((database) =>
        database.prepare("SELECT installation_id FROM projects WHERE id = ?").get(defaultProject)
      ),
    ).installation_id;
    repository = new SqliteIdentityRepository(databasePath);
  });

  afterEach(async () => {
    repository.close();
    await removeTestInstallation(installation);
  });

  test("an existing project stays open to every member", async () => {
    expect(await repository.findProjectAccess(installationId, defaultProject, "nobody"))
      .toEqual({accessMode: "installation", grantRoles: [], member: null});
    expect(await repository.findProjectAccess(installationId, "prj_missing", "nobody"))
      .toBeNull();
  });

  test("grants reach a member by external identity, or by verified email only when unbound", async () => {
    // ada: bound to Keycloak as user-ada. bob: never signed in. cat: bound to
    // Keycloak as user-cat, while a different Keycloak user carries her
    // address. dee: bound only to another provider.
    await Promise.all(["ada", "bob", "cat", "dee"].map(admit));
    await bind("ada", keycloak, "user-ada");
    await bind("cat", keycloak, "user-cat");
    await bind("dee", otherProvider, "other-dee");
    await groups([
      group("g-view", [["user-ada", "ada"], ["user-bob", "bob"], ["user-imposter", "cat"], ["user-dee", "dee"]]),
      group("g-edit", [["user-ada", "ada"]]),
    ]);
    await repository.setProjectAccessMode(installationId, defaultProject, "restricted");
    await grant("g-view", "viewer");
    await grant("g-edit", "editor");

    const rolesOf = async (name: string) =>
      [...(await repository.findProjectAccess(installationId, defaultProject, `mem_${name}`))
        ?.grantRoles ?? []].toSorted();
    expect(await rolesOf("ada")).toEqual(["editor", "viewer"]);
    expect(await rolesOf("bob")).toEqual(["viewer"]);
    expect(await rolesOf("cat")).toEqual([]);
    expect(await rolesOf("dee")).toEqual(["viewer"]);
    expect(await repository.findProjectAccess(installationId, defaultProject, "mem_ada"))
      .toMatchObject({accessMode: "restricted", member: {role: "member", status: "active"}});
  });

  test("a group row from before providers were recorded matches nobody", async () => {
    await Promise.all(["ada", "cat"].map(admit));
    await bind("cat", keycloak, "user-cat");
    await groups([group("g-old", [["user-ada", "ada"], ["user-imposter", "cat"]])]);
    await repository.setProjectAccessMode(installationId, defaultProject, "restricted");
    await grant("g-old", "manager");
    readWrite((database) => database.exec("UPDATE directory_group_members SET provider = NULL"));
    for (const name of ["ada", "cat"]) {
      expect((await repository.findProjectAccess(installationId, defaultProject, `mem_${name}`))
        ?.grantRoles).toEqual([]);
    }
    // The next sync records the provider and the unbound member matches again.
    await groups([group("g-old", [["user-ada", "ada"], ["user-imposter", "cat"]])]);
    expect((await repository.findProjectAccess(installationId, defaultProject, "mem_ada"))
      ?.grantRoles).toEqual(["manager"]);
    expect((await repository.findProjectAccess(installationId, defaultProject, "mem_cat"))
      ?.grantRoles).toEqual([]);
  });

  test("grants list, replace and remove; a deleted group takes its grants with it", async () => {
    await admit("ada");
    await groups([group("g-a", [["user-ada", "ada"]]), group("g-b", [])]);
    await grant("g-a", "viewer");
    await grant("g-b", "editor");
    await grant("g-a", "manager");
    expect((await repository.listProjectGroupGrants(installationId, defaultProject))
      .map(({groupId, role}) => [groupId, role])).toEqual([["g-a", "manager"], ["g-b", "editor"]]);

    expect(await repository.removeProjectGroupGrant(installationId, defaultProject, "g-b")).toBe(true);
    expect(await repository.removeProjectGroupGrant(installationId, defaultProject, "g-b")).toBe(false);

    await groups([group("g-b", [])]);
    expect(await repository.listProjectGroupGrants(installationId, defaultProject)).toEqual([]);
  });

  test("an unknown group or project is refused", async () => {
    await expect(repository.putProjectGroupGrant(installationId, {
      grantedAt: "t",
      grantedByPrincipalId: "mem_admin",
      groupId: "g-missing",
      projectId: defaultProject,
      role: "viewer",
    })).rejects.toThrow("The project or group does not exist.");
    await expect(repository.setProjectAccessMode(installationId, "prj_missing", "restricted"))
      .rejects.toThrow("The project does not exist.");
  });

  test("a schema 14 database upgrades in place with every project still open", async () => {
    repository.close();
    readWrite((database) => database.exec(`
      DROP TABLE project_group_grants;
      ALTER TABLE directory_group_members DROP COLUMN provider;
      ALTER TABLE projects DROP COLUMN access_mode;
      PRAGMA user_version = 14;
    `));
    await (await openRuntime()).close();
    repository = new SqliteIdentityRepository(databasePath);
    expect(readOnly((database) =>
      database.prepare("PRAGMA user_version").get()
    )).toEqual({user_version: 15});
    expect(await repository.findProjectAccess(installationId, defaultProject, "nobody"))
      .toMatchObject({accessMode: "installation"});
    await groups([group("g-a", [])]);
    await grant("g-a", "viewer");
    expect(await repository.listProjectGroupGrants(installationId, defaultProject)).toHaveLength(1);
  });

  function openRuntime() {
    return createLocalRuntime({
      apiToken: installation.apiToken,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "localhost",
      dataDirectory: installation.dataDirectory,
      groupRolePolicy: {administratorGroups: ["admins"], memberGroups: ["users"]},
    });
  }

  async function admit(name: string): Promise<void> {
    await repository.admitMember({
      createdAt: "2026-10-24T00:00:00.000Z",
      displayName: name,
      email: `${name}@example.test`,
      id: `mem_${name}`,
      installationId,
      role: "member",
    });
  }

  async function bind(name: string, provider: string, subject: string): Promise<void> {
    await repository.bindExternalIdentity({
      boundAt: "2026-10-24T00:00:00.000Z",
      email: `${name}@example.test`,
      memberId: `mem_${name}`,
      provider,
      subject,
    });
  }

  async function groups(observed: readonly DirectoryGroupObservation[]): Promise<void> {
    await repository.applyDirectoryGroups(installationId, {
      groups: observed,
      provider: keycloak,
      syncedAt: "2026-10-24T00:00:00.000Z",
    });
  }

  async function grant(groupId: string, role: "viewer" | "editor" | "manager"): Promise<void> {
    await repository.putProjectGroupGrant(installationId, {
      grantedAt: "2026-10-24T00:00:00.000Z",
      grantedByPrincipalId: "mem_admin",
      groupId,
      projectId: defaultProject,
      role,
    });
  }

  function readOnly<T>(run: (database: DatabaseSync) => T): T {
    const database = new DatabaseSync(databasePath, {readOnly: true});
    try {
      return run(database);
    } finally {
      database.close();
    }
  }

  function readWrite(run: (database: DatabaseSync) => void): void {
    const database = new DatabaseSync(databasePath);
    try {
      run(database);
    } finally {
      database.close();
    }
  }
});

function group(
  id: string,
  members: readonly (readonly [subject: string, name: string])[],
): DirectoryGroupObservation {
  return {
    id,
    members: members.map(([subject, name]) => ({email: `${name}@example.test`, subject})),
    name: id,
    path: `/${id}`,
  };
}

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
      .toEqual({accessMode: "installation", grantRoles: [], isCreator: false, member: null});
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
    const before = await Promise.all(["ada", "cat"].map((name) =>
      repository.findProjectAccess(installationId, defaultProject, `mem_${name}`)
    ));
    expect(before.map((access) => access?.grantRoles)).toEqual([[], []]);
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

  test("the member recorded as creator is reported as the creator", async () => {
    await Promise.all(["ada", "bob"].map(admit));
    await repository.setProjectAccessMode(installationId, defaultProject, "restricted");
    readWrite((database) => database.prepare(
      "UPDATE projects SET created_by_member_id = ? WHERE id = ?",
    ).run("mem_ada", defaultProject));
    expect(await repository.findProjectAccess(installationId, defaultProject, "mem_ada"))
      .toMatchObject({grantRoles: [], isCreator: true});
    expect(await repository.findProjectAccess(installationId, defaultProject, "mem_bob"))
      .toMatchObject({grantRoles: [], isCreator: false});
  });

  test("a project created with a service key has no managing creator", async () => {
    repository.close();
    const runtime = await openRuntime();
    let projectId: string;
    try {
      const response = await runtime.app.request("http://localhost/api/v1/projects", {
        body: JSON.stringify({name: "Service project"}),
        headers: {
          Authorization: `Bearer ${installation.apiToken}`,
          "Content-Type": "application/json",
          "Idempotency-Key": "create-service-project",
        },
        method: "POST",
      });
      expect(response.status).toBe(201);
      projectId = z.object({project: z.object({id: z.string()})}).parse(await response.json())
        .project.id;
    } finally {
      await runtime.close();
    }
    repository = new SqliteIdentityRepository(databasePath);
    expect(readOnly((database) => database.prepare(
      "SELECT access_mode, created_by_member_id FROM projects WHERE id = ?",
    ).get(projectId))).toEqual({access_mode: "restricted", created_by_member_id: null});
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
      ALTER TABLE projects DROP COLUMN created_by_member_id;
      PRAGMA user_version = 14;
    `));
    await (await openRuntime()).close();
    repository = new SqliteIdentityRepository(databasePath);
    expect(readOnly((database) =>
      database.prepare("PRAGMA user_version").get()
    )).toEqual({user_version: 17});
    expect(await repository.findProjectAccess(installationId, defaultProject, "nobody"))
      .toMatchObject({accessMode: "installation"});
    await groups([group("g-a", [])]);
    await grant("g-a", "viewer");
    expect(await repository.listProjectGroupGrants(installationId, defaultProject)).toHaveLength(1);
  });

  test("a schema 16 database widens member roles and keeps every member and its identity", async () => {
    await admit("ada");
    await repository.bindExternalIdentity({
      boundAt: "2026-10-24T00:00:00.000Z",
      email: "ada@example.test",
      memberId: "mem_ada",
      provider: "oidc:test",
      subject: "subject-ada",
    });
    repository.close();
    // Rebuild the members table as schema 16 had it: two roles only.
    readWrite((database) => database.exec(`
      PRAGMA foreign_keys = OFF;
      CREATE TABLE installation_members_old (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        email TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('administrator', 'member')),
        status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (installation_id, email)
      );
      INSERT INTO installation_members_old SELECT * FROM installation_members;
      DROP TABLE installation_members;
      ALTER TABLE installation_members_old RENAME TO installation_members;
      DROP TABLE directory_group_roles;
      DROP TABLE directory_group_role_seeds;
      PRAGMA foreign_keys = ON;
      PRAGMA user_version = 16;
    `));
    repository = new SqliteIdentityRepository(databasePath);
    expect(readOnly((database) =>
      database.prepare("PRAGMA user_version").get()
    )).toEqual({user_version: 17});
    expect(readOnly((database) => database.prepare("PRAGMA foreign_key_check").all()))
      .toEqual([]);
    expect(await repository.findActiveMemberByExternalIdentity(
      installationId,
      "oidc:test",
      "subject-ada",
    )).toMatchObject({id: "mem_ada", role: "member"});
    await repository.setMemberRole(installationId, "mem_ada", "owner", "2026-10-26T00:00:00.000Z");
    expect(await repository.findMember(installationId, "mem_ada"))
      .toMatchObject({role: "owner"});
    expect(await repository.listGroupRoles(installationId)).toEqual([]);
  });

  test("starting roles are stored once, and later changes and removals stay", async () => {
    await groups([group("g-a", []), group("g-b", [])]);
    expect(await repository.isGroupRoleSeedApplied(installationId)).toBe(false);
    expect(await repository.seedGroupRoles(
      installationId,
      [{groupId: "g-a", role: "owner"}, {groupId: "g-b", role: "member"}],
      "2026-10-26T00:00:00.000Z",
    )).toBe(true);
    expect(await repository.isGroupRoleSeedApplied(installationId)).toBe(true);
    await repository.setGroupRole(installationId, "g-a", "viewer", "2026-10-26T01:00:00.000Z", "mem_ada");
    await repository.setGroupRole(installationId, "g-b", null, "2026-10-26T01:00:00.000Z", "mem_ada");
    expect(await repository.seedGroupRoles(
      installationId,
      [{groupId: "g-a", role: "owner"}, {groupId: "g-b", role: "member"}],
      "2026-10-26T02:00:00.000Z",
    )).toBe(false);
    expect((await repository.listGroupRoles(installationId))
      .map(({groupId, role}) => ({groupId, role}))).toEqual([{groupId: "g-a", role: "viewer"}]);
    await expect(repository.setGroupRole(installationId, "missing", "member", "2026-10-26T03:00:00.000Z", "mem_ada"))
      .rejects.toMatchObject({_tag: "IdentityNotFound"});
    // A group the directory deletes takes its role with it.
    await groups([group("g-b", [])]);
    expect(await repository.listGroupRoles(installationId)).toEqual([]);
  });

  test("a stored role reports whether its group's name is shared by another group", async () => {
    await repository.applyDirectoryGroups(installationId, {
      groups: [
        {id: "g-temporal", members: [], name: "default:admin", path: "/temporal/default:admin"},
        {id: "g-other", members: [], name: "default:admin", path: "/other/default:admin"},
        {id: "g-dev", members: [], name: "Developers", path: "/Developers"},
      ],
      provider: keycloak,
      syncedAt: "2026-10-26T00:00:00.000Z",
    });
    await repository.setGroupRole(installationId, "g-temporal", "owner", "2026-10-26T00:00:00.000Z", "mem_ada");
    await repository.setGroupRole(installationId, "g-dev", "member", "2026-10-26T00:00:00.000Z", "mem_ada");
    expect((await repository.listGroupRoles(installationId))
      .map(({groupId, nameUnique}) => ({groupId, nameUnique}))).toEqual([
      {groupId: "g-dev", nameUnique: true},
      {groupId: "g-temporal", nameUnique: false},
    ]);
  });

  function openRuntime() {
    return createLocalRuntime({
      apiToken: installation.apiToken,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "localhost",
      dataDirectory: installation.dataDirectory,
      groupRolePolicy: {
        seed: [
          {role: "administrator", selector: "admins"},
          {role: "member", selector: "users"},
        ],
      },
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

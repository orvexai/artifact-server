import {describe, expect, test} from "vitest";

import type {Principal} from "../../src/core/identity.js";
import {
  type ProjectAccessRecord,
  type ProjectGrantRole,
  projectRoleAtLeast,
  resolveProjectAccess,
} from "../../src/core/project-access.js";

function principal(overrides: Partial<Principal> = {}): Principal {
  return {
    authorizedByPrincipalId: null,
    capabilities: [],
    displayName: "Pat",
    id: "mem_pat",
    installationId: "inst",
    kind: "human",
    membershipRole: "member",
    ...overrides,
  };
}

function restricted(
  grantRoles: readonly ProjectGrantRole[],
  member: ProjectAccessRecord["member"] = {role: "member", status: "active"},
  isCreator = false,
): ProjectAccessRecord {
  return {accessMode: "restricted", grantRoles, isCreator, member};
}

describe("project access rules", () => {
  test("an installation project keeps today's rules for every principal", () => {
    const record: ProjectAccessRecord = {
      accessMode: "installation",
      grantRoles: [],
      isCreator: false,
      member: null,
    };
    for (const who of [
      principal(),
      principal({kind: "service", id: "service:ci"}),
      principal({authorizedByPrincipalId: "mem_admin"}),
    ]) {
      expect(resolveProjectAccess(who, record)).toEqual({mode: "installation"});
    }
  });

  test.each<[string, Principal, ProjectAccessRecord, string | null]>([
    ["a service key keeps full reach", principal({kind: "service", id: "service:ci"}), restricted([], null), "administrator"],
    ["an administrator sees every project", principal(), restricted([], {role: "administrator", status: "active"}), "administrator"],
    ["a viewer grant", principal(), restricted(["viewer"]), "viewer"],
    ["an editor grant", principal(), restricted(["editor"]), "editor"],
    ["a manager grant", principal(), restricted(["manager"]), "manager"],
    ["the strongest of several grants wins", principal(), restricted(["viewer", "manager", "editor"]), "manager"],
    ["an ungranted member sees nothing", principal(), restricted([]), null],
    ["a deactivated member sees nothing, even with a grant", principal(), restricted(["manager"], {role: "member", status: "inactive"}), null],
    ["a human principal that is not a stored member sees nothing", principal(), restricted(["viewer"], null), null],
    // An API key issued for a member is a human principal with that member's id.
    ["a member's key reaches only what the member can", principal({authorizedByPrincipalId: "mem_admin"}), restricted(["viewer"]), "viewer"],
    ["stored administrator role wins over a key's member role", principal({authorizedByPrincipalId: "mem_admin"}), restricted([], {role: "administrator", status: "active"}), "administrator"],
    ["a principal claiming administrator is judged by its stored role", principal({membershipRole: "administrator"}), restricted([]), null],
    ["an MCP client acts as its member", principal({actorClientId: "client-1"}), restricted(["editor"]), "editor"],
    ["the creator manages its project with no grant", principal(), restricted([], undefined, true), "manager"],
    ["a creator's weaker grant does not lower it", principal(), restricted(["viewer"], undefined, true), "manager"],
    ["a deactivated creator sees nothing", principal(), restricted([], {role: "member", status: "inactive"}, true), null],
  ])("%s", (_name, who, record, role) => {
    expect(resolveProjectAccess(who, record)).toEqual({mode: "restricted", role});
  });

  test("roles are ordered viewer < editor < manager < administrator", () => {
    expect(projectRoleAtLeast("editor", "viewer")).toBe(true);
    expect(projectRoleAtLeast("viewer", "editor")).toBe(false);
    expect(projectRoleAtLeast("manager", "manager")).toBe(true);
    expect(projectRoleAtLeast("administrator", "manager")).toBe(true);
    expect(projectRoleAtLeast("manager", "administrator")).toBe(false);
  });
});

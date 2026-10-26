import {describe, expect, test} from "vitest";

import {
  type GroupRoleAssignment,
  groupMembershipRole,
} from "../../src/core/group-role-policy.js";
import type {MembershipRole} from "../../src/core/identity.js";

function assignment(
  path: string,
  role: MembershipRole,
  nameUnique = true,
): GroupRoleAssignment {
  return {
    assignedAt: "2026-10-26T00:00:00.000Z",
    groupId: `id-${path}`,
    name: path.slice(path.lastIndexOf("/") + 1),
    nameUnique,
    path,
    role,
  };
}

const assignments = [
  assignment("/Administrators", "owner"),
  assignment("/Platform Team", "administrator"),
  assignment("/Developers", "member"),
  assignment("/temporal/default:read", "viewer"),
];

describe("stored group roles", () => {
  test("the strongest role among a person's groups wins", () => {
    expect(groupMembershipRole(assignments, ["Developers", "Administrators"]))
      .toBe("owner");
    expect(groupMembershipRole(assignments, ["Developers", "Platform Team"]))
      .toBe("administrator");
    expect(groupMembershipRole(assignments, ["default:read", "Developers"]))
      .toBe("member");
    expect(groupMembershipRole(assignments, ["default:read"])).toBe("viewer");
  });

  test("a reported group matches by its name or its full path", () => {
    expect(groupMembershipRole(assignments, ["/temporal/default:read"]))
      .toBe("viewer");
    expect(groupMembershipRole(assignments, ["/Administrators"])).toBe("owner");
  });

  test("a name another group shares never stands for the group that has the role", () => {
    // /temporal/default:admin is Owner; /other/default:admin has no role.
    const shared = [assignment("/temporal/default:admin", "owner", false)];
    expect(groupMembershipRole(shared, ["default:admin"])).toBeNull();
    expect(groupMembershipRole(shared, ["/temporal/default:admin"])).toBe("owner");
  });

  test("no group with a role, no reported groups, or a near miss admits no one", () => {
    expect(groupMembershipRole(assignments, [])).toBeNull();
    expect(groupMembershipRole(assignments, null)).toBeNull();
    expect(groupMembershipRole(assignments, ["sales"])).toBeNull();
    expect(groupMembershipRole([], ["Administrators"])).toBeNull();
    // Names compare exactly: case, a wrong path and padding are other groups.
    expect(groupMembershipRole(assignments, [
      "administrators",
      "/Developers/extra",
      " Developers",
    ])).toBeNull();
  });
});

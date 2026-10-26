import {membershipRoleAtLeast, type MembershipRole} from "./identity.js";

/** One configured starting role: a directory group name or full path, and its role. */
export interface GroupRoleSeedEntry {
  readonly role: MembershipRole;
  /** A group's exact name, or its full path when it starts with "/". */
  readonly selector: string;
}

/**
 * Issuer groups decide who may sign in and with which installation role. The
 * roles themselves are stored per group and edited in the application; the
 * seed only fills them in the first time, so later edits are never undone.
 */
export interface GroupRolePolicy {
  readonly seed: readonly GroupRoleSeedEntry[];
}

/** Who stored a role that came from the configured seed rather than a person. */
export const groupRoleSeedPrincipalId = "configuration:group-role-seed";

/** One directory group's stored installation role. */
export interface GroupRoleAssignment {
  readonly assignedAt: string;
  readonly groupId: string;
  readonly name: string;
  /**
   * True when no other directory group has this name. Group names repeat
   * under different parents, so a reported name may stand for this group only
   * when it is unique.
   */
  readonly nameUnique: boolean;
  readonly path: string;
  readonly role: MembershipRole;
}

/**
 * Return the strongest role a person's issuer groups grant, or null when no
 * group with a role admits them. A reported group matches a stored group by
 * its full path, or by its name only when no other directory group shares
 * that name; a provider that reported no groups admits no one.
 */
export function groupMembershipRole(
  assignments: readonly GroupRoleAssignment[],
  groups: readonly string[] | null,
): MembershipRole | null {
  if (groups === null) return null;
  const reported = new Set(groups);
  let best: MembershipRole | null = null;
  for (const assignment of assignments) {
    const matches = reported.has(assignment.path) ||
      (assignment.nameUnique && reported.has(assignment.name));
    if (!matches) continue;
    if (best === null || !membershipRoleAtLeast(best, assignment.role)) {
      best = assignment.role;
    }
  }
  return best;
}

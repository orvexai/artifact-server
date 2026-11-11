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
  /** Full-path prefixes whose matching directory groups receive guest. */
  readonly guestGroupPrefixes?: readonly string[];
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
  /** Present for a role supplied by configuration rather than a stored row. */
  readonly source?: "rule";
}

/** A configured prefix matches only descendant full paths, never a group name. */
export function guestGroupPathMatches(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => path.startsWith(prefix) && path.length > prefix.length);
}

/** Add rule assignments for matching groups that have no explicit role row. */
export function withGuestGroupRuleAssignments(
  assignments: readonly GroupRoleAssignment[],
  groups: readonly {readonly id: string; readonly name: string; readonly path: string}[],
  prefixes: readonly string[],
): readonly GroupRoleAssignment[] {
  const explicit = new Set(assignments.map(({groupId}) => groupId));
  const counts = new Map<string, number>();
  for (const group of groups) counts.set(group.name, (counts.get(group.name) ?? 0) + 1);
  return [...assignments, ...groups.filter((group) =>
    !explicit.has(group.id) && guestGroupPathMatches(group.path, prefixes)
  ).map((group) => ({
    assignedAt: "",
    groupId: group.id,
    name: group.name,
    nameUnique: counts.get(group.name) === 1,
    path: group.path,
    role: "guest" as const,
    source: "rule" as const,
  }))];
}

/**
 * The configured starting roles as assignments matched exactly against the
 * group names or paths a sign-in reports. They decide access until the
 * directory sync has stored them, and always on an installation that runs no
 * directory sync, so group roles work with the claim alone.
 */
export function configuredGroupRoleAssignments(
  seed: readonly GroupRoleSeedEntry[],
): readonly GroupRoleAssignment[] {
  return seed.map(({role, selector}) => ({
    assignedAt: "",
    groupId: selector,
    name: selector,
    nameUnique: true,
    path: selector,
    role,
  }));
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
  let bestPrivileged: MembershipRole | null = null;
  let bestNonGuest: MembershipRole | null = null;
  let hasGuestRole = false;
  for (const assignment of assignments) {
    const matches = reported.has(assignment.path) ||
      (assignment.nameUnique && reported.has(assignment.name));
    if (!matches) continue;
    if (assignment.role === "owner" || assignment.role === "administrator") {
      if (bestPrivileged === null || !membershipRoleAtLeast(bestPrivileged, assignment.role)) {
        bestPrivileged = assignment.role;
      }
    } else if (assignment.role === "guest") {
      hasGuestRole = true;
    } else if (bestNonGuest === null || !membershipRoleAtLeast(bestNonGuest, assignment.role)) {
      bestNonGuest = assignment.role;
    }
  }
  return bestPrivileged ?? (hasGuestRole ? "guest" : bestNonGuest);
}

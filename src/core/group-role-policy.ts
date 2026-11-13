import type {MembershipRole} from "./identity.js";

/** One configured starting role: a directory group name or full path, and its role. */
export interface GroupRoleSeedEntry {
  readonly role: MembershipRole;
  /** A group's exact name, or its full path when it starts with "/". */
  readonly selector: string;
  /** Marks this admission group as Orvex staff for tenant-facing masking. */
  readonly staff?: boolean;
}

/**
 * Issuer groups decide who may sign in and with which installation role. The
 * roles themselves are stored per group and edited in the application; the
 * seed only fills them in the first time, so later edits are never undone.
 */
export interface GroupRolePolicy {
  readonly seed: readonly GroupRoleSeedEntry[];
  /** Full-path roots that constrain which reported directory groups can admit an org member. */
  readonly groupRoots?: readonly string[];
  /** Full-path prefixes whose newly mirrored directory groups receive guest. */
  readonly guestGroupPrefixes?: readonly string[];
}

/** Staff selectors are exact names or exact full paths, matching admission semantics. */
export function groupRoleSeedMarksStaff(
  group: {readonly name: string; readonly path: string},
  seed: readonly GroupRoleSeedEntry[],
): boolean {
  return seed.some((entry) => entry.staff === true &&
    (entry.selector.startsWith("/") ? entry.selector === group.path : entry.selector === group.name));
}

/** Group-role edits stay with direct installation owners. */
export function groupRoleEditAllowed(
  role: MembershipRole,
  directHuman: boolean,
): boolean {
  return directHuman && role === "owner";
}

/** Who stored a role that came from the configured seed rather than a person. */
export const groupRoleSeedPrincipalId = "configuration:group-role-seed";
/** Marker stored on a role row created from the guest path rule. */
export const guestGroupRulePrincipalId = "configuration:guest-group-rule";
/** Strict absolute path prefix syntax shared with the Helm values schema. */
export const guestGroupPrefixPattern = new RegExp("^(/[^/\\s]+)+/$");

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
  /** Set by the application adapter from the configured staff selector. */
  readonly staff?: boolean;
  /** Present for a guest role row created from the configured path rule. */
  readonly source?: "rule";
}

/** A configured prefix matches only descendant full paths, never a group name. */
export function guestGroupPathMatches(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => path.startsWith(prefix) && path.length > prefix.length);
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
  groupRoots?: readonly string[],
): MembershipRole | null {
  if (groups === null) return null;
  const reported = new Set(groupRoots === undefined
    ? groups
    : groups.filter((group) => groupRoots.some((root) =>
      group.startsWith(root) && group.length > root.length
    )));
  let bestPrivileged: MembershipRole | null = null;
  let bestNonGuest: MembershipRole | null = null;
  let hasGuestRole = false;
  for (const assignment of assignments) {
    const matches = reported.has(assignment.path) ||
      (assignment.nameUnique && reported.has(assignment.name));
    if (!matches) continue;
    if (assignment.role === "owner" || assignment.role === "administrator") {
      if (bestPrivileged === null || membershipRolePrecedence(assignment.role) > membershipRolePrecedence(bestPrivileged)) {
        bestPrivileged = assignment.role;
      }
    } else if (assignment.role === "guest") {
      hasGuestRole = true;
    } else if (bestNonGuest === null || membershipRolePrecedence(assignment.role) > membershipRolePrecedence(bestNonGuest)) {
      bestNonGuest = assignment.role;
    }
  }
  return bestPrivileged ?? (hasGuestRole ? "guest" : bestNonGuest);
}

/** The precedence used by groupMembershipRole and directory member sync. */
export function membershipRolePrecedence(role: MembershipRole): number {
  switch (role) {
    case "owner": return 5;
    case "administrator": return 4;
    case "guest": return 3;
    case "member": return 2;
    case "viewer": return 1;
    default: return 0;
  }
}

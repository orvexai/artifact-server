import {Effect, Schema} from "effect";

import type {
  DirectoryGroupObservation,
  DirectoryGroupRecord,
} from "../core/directory-groups.js";
import {membershipRolePrecedence} from "../core/group-role-policy.js";
import type {MembershipRole} from "../core/identity.js";
import type {DirectoryOrganization} from "../identity/keycloak-directory.js";
import type {OrganizationDirectory} from "../identity/keycloak-directory.js";
import {
  type DirectoryMemberEntry,
  InstallationAccessService,
  normalizeMemberEmail,
} from "./installation-access.js";

/** One person a member directory lists in a group. */
export interface DirectoryUser {
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly enabled: boolean;
  readonly firstName: string | null;
  readonly id: string;
  readonly lastName: string | null;
  readonly username: string;
}

/** The complete membership of one named directory group. */
export interface DirectoryGroup {
  readonly name: string;
  readonly users: readonly DirectoryUser[];
}

/** The directory could not be read completely, so nothing may change. */
export class DirectoryUnavailable extends Schema.TaggedError<DirectoryUnavailable>()(
  "DirectoryUnavailable",
  {message: Schema.String},
) {}

/**
 * A member directory that reports the complete membership of named groups.
 * It must fail rather than answer with a partial group.
 */
export interface MemberDirectory {
  readonly listGroups: (
    names: readonly string[],
  ) => Effect.Effect<readonly DirectoryGroup[], DirectoryUnavailable>;
}

/**
 * A directory that lists every group it holds and each group's members, for
 * group sync. Both must fail rather than answer partially.
 */
export interface GroupDirectory {
  readonly listAllGroups: () => Effect.Effect<
    readonly DirectoryGroupRecord[],
    DirectoryUnavailable
  >;
  readonly listGroupMembers: (
    group: DirectoryGroupRecord,
  ) => Effect.Effect<readonly DirectoryUser[], DirectoryUnavailable>;
}

/** The one-line outcome of one directory sync pass. */
export interface DirectorySyncReport {
  readonly admitted: number;
  readonly deactivated: number;
  readonly directoryUsers: number;
  readonly groups: number;
  readonly reactivated: number;
  readonly roleChanged: number;
  readonly skipped: number;
  readonly unchanged: number;
}

export type OrganizationDirectorySyncResult = DirectorySyncReport | {
  readonly kind: "emptied";
  readonly reason: string;
};

/**
 * Read the members of every group that holds an installation role, then make
 * the installation's human members match: each person gets the strongest role
 * among their groups, and anyone in none of them is deactivated. The directory
 * is read completely before the first write; with no group holding a role, or
 * no eligible user, nothing changes.
 */
export const syncDirectoryMembers = Effect.fn("syncDirectoryMembers")(function*(
  directory: GroupDirectory,
) {
  const assignments = yield* InstallationAccessService.use((access) =>
    access.listGroupRoles()
  );
  if (assignments.length === 0) {
    return yield* new DirectoryUnavailable({
      message: "No directory group has an installation role yet; nothing was changed.",
    });
  }
  const rolesByUser = new Map<string, {
    role: MembershipRole;
    staffSelector: boolean;
    readonly user: DirectoryUser;
  }>();
  for (const assignment of assignments) {
    const users = yield* directory.listGroupMembers({
      id: assignment.groupId,
      name: assignment.name,
      path: assignment.path,
    });
    for (const user of users) {
      const seen = rolesByUser.get(user.id);
      if (seen === undefined) {
        rolesByUser.set(user.id, {
          role: assignment.role,
          staffSelector: assignment.staff === true,
          user,
        });
      } else if (membershipRolePrecedence(assignment.role) > membershipRolePrecedence(seen.role)) {
        seen.role = assignment.role;
      }
      if (seen !== undefined) {
        if (assignment.staff === true) seen.staffSelector = true;
      }
    }
  }
  const desired = new Map<string, DirectoryMemberEntry>();
  let skipped = 0;
  for (const {role, staffSelector, user} of rolesByUser.values()) {
    const staff = staffSelector;
    const email = user.enabled && user.emailVerified && user.email !== null
      ? normalizeMemberEmail(user.email)
      : null;
    if (email === null) {
      skipped += 1;
      continue;
    }
    const previous = desired.get(email);
    // Two directory users sharing one address are one member; the stronger
    // role wins, as one person in both groups would.
    if (previous === undefined) {
      desired.set(email, {displayName: displayName(user, email), email, role, staff});
    } else {
      const strongest = membershipRolePrecedence(role) > membershipRolePrecedence(previous.role)
        ? {displayName: displayName(user, email), role}
        : {displayName: previous.displayName, role: previous.role};
      desired.set(email, {...previous, ...strongest, staff: previous.staff === true || staff});
    }
  }
  if (desired.size === 0) {
    return yield* new DirectoryUnavailable({
      message:
        "The directory reported no enabled user with a verified email in the groups that hold a role; nothing was changed.",
    });
  }
  const reconciliation = yield* InstallationAccessService.use((access) =>
    access.reconcileDirectoryMembers([...desired.values()])
  );
  // Field order is the order operators read the one-line summary in.
  const report: DirectorySyncReport = {
    groups: assignments.length,
    directoryUsers: rolesByUser.size,
    admitted: reconciliation.admitted,
    reactivated: reconciliation.reactivated,
    roleChanged: reconciliation.roleChanged,
    deactivated: reconciliation.deactivated,
    unchanged: reconciliation.unchanged,
    skipped,
  };
  return report;
});

/** One Keycloak organization's desired member entries, before reconciliation. */
export interface OrganizationDirectorySnapshot {
  readonly desired: readonly DirectoryMemberEntry[];
  readonly directoryUsers: number;
  readonly skipped: number;
}

/**
 * Read one Keycloak organization's members into desired entries. Staff are
 * marked from the org's admission-policy staff selectors, exactly as
 * interactive login marks them, so a synced staff member is masked from
 * tenant member lists before they ever sign in.
 */
export const readOrganizationDirectorySnapshot = Effect.fn(
  "readOrganizationDirectorySnapshot",
)(function*(
  directory: OrganizationDirectory,
  organization: DirectoryOrganization,
  staffSelectors: readonly string[] = [],
) {
  const members = yield* directory.listOrganizationMembers(organization);
  if (members.length === 0) {
    return {
      kind: "emptied",
      reason: "Keycloak organization has no enabled members.",
    } as const;
  }
  const staffUserIds = new Set<string>();
  if (staffSelectors.length > 0) {
    if (directory.listGroupMemberIdsByPath === undefined) {
      return yield* new DirectoryUnavailable({
        message: `Keycloak organization ${organization.alias} has staff selectors but the directory cannot read group members; nothing was changed.`,
      });
    }
    for (const selector of staffSelectors) {
      for (const id of yield* directory.listGroupMemberIdsByPath(selector)) staffUserIds.add(id);
    }
  }
  const desired = new Map<string, DirectoryMemberEntry>();
  let skipped = 0;
  for (const user of members) {
    const email = user.enabled && user.emailVerified && user.email !== null
      ? normalizeMemberEmail(user.email)
      : null;
    if (email === null || user.role === null) {
      skipped += 1;
      continue;
    }
    const role: MembershipRole = user.role === "owner"
      ? "owner"
      : user.role === "editor"
      ? "member"
      : "viewer";
    const previous = desired.get(email);
    const staff = staffUserIds.has(user.id) || previous?.staff === true;
    const entry: DirectoryMemberEntry = staff
      ? {displayName: displayName(user, email), email, role, staff: true}
      : {displayName: displayName(user, email), email, role};
    if (previous === undefined || membershipRolePrecedence(role) > membershipRolePrecedence(previous.role)) {
      desired.set(email, entry);
    } else if (staff && previous.staff !== true) {
      desired.set(email, {...previous, staff: true});
    }
  }
  if (desired.size === 0) {
    return yield* new DirectoryUnavailable({
      message: `Keycloak organization ${organization.alias} has no eligible members; nothing was changed.`,
    });
  }
  return {
    desired: [...desired.values()],
    directoryUsers: members.length,
    skipped,
  } satisfies OrganizationDirectorySnapshot;
});

/** Sync one Keycloak Organization into only the current installation. */
export const syncOrganizationDirectoryMembers = Effect.fn(
  "syncOrganizationDirectoryMembers",
)(function*(
  directory: OrganizationDirectory,
  organization: DirectoryOrganization,
  maximumDeactivations: number,
  staffSelectors: readonly string[] = [],
) {
  const snapshot = yield* readOrganizationDirectorySnapshot(directory, organization, staffSelectors);
  if (snapshot.kind === "emptied") return {kind: snapshot.kind, reason: snapshot.reason} as const;
  const reconciliation = yield* InstallationAccessService.use((access) =>
    access.reconcileDirectoryMembers(snapshot.desired, maximumDeactivations)
  );
  return {
    groups: 1,
    directoryUsers: snapshot.directoryUsers,
    admitted: reconciliation.admitted,
    reactivated: reconciliation.reactivated,
    roleChanged: reconciliation.roleChanged,
    deactivated: reconciliation.deactivated,
    unchanged: reconciliation.unchanged,
    skipped: snapshot.skipped,
  } satisfies DirectorySyncReport;
});

const displayNameLimit = 200;

function displayName(user: DirectoryUser, email: string): string {
  return preferredName(user, email).slice(0, displayNameLimit);
}

function preferredName(user: DirectoryUser, email: string): string {
  const name = [user.firstName, user.lastName]
    .map((part) => part?.trim() ?? "")
    .filter((part) => part !== "")
    .join(" ");
  if (name !== "") return name;
  const username = user.username.trim();
  return username === "" ? email : username;
}

/** The one-line outcome of one directory group sync pass. */
export interface DirectoryGroupSyncReport {
  readonly groups: number;
  readonly created: number;
  readonly renamed: number;
  readonly deleted: number;
  readonly membershipsReplaced: number;
  readonly roleChanged?: number;
  /** Groups whose members could not be read; they keep their stored members. */
  readonly groupsFailed: number;
}

/**
 * Copy every directory group and its direct members, keyed by directory id.
 * The listing must be complete or nothing changes; a group whose members
 * cannot be read keeps its stored membership and the pass continues.
 */
export const syncDirectoryGroups = Effect.fn("syncDirectoryGroups")(function*(
  directory: GroupDirectory,
  syncedAt: string,
  provider: string,
  maxDeactivations = 5,
  recomputeRoles = true,
) {
  const listed = yield* directory.listAllGroups();
  if (listed.length === 0) {
    return yield* Effect.fail(new DirectoryUnavailable({message: "Refusing an empty directory group snapshot."}));
  }
  const groups: DirectoryGroupObservation[] = [];
  for (const group of listed) {
    const users = yield* directory.listGroupMembers(group);
    groups.push({
      ...group,
      // A disabled directory user belongs to no group here.
      members: users.filter((user) => user.enabled).map((user) => ({
        email: user.emailVerified && user.email !== null
          ? normalizeMemberEmail(user.email)
          : null,
        subject: user.id,
      })),
    });
  }
  const roleGroups = yield* InstallationAccessService.use((access) => access.listGroupRoles());
  const rolesSeeded = yield* InstallationAccessService.use((access) => access.isGroupRoleSeedApplied());
  const nonGuestRoleGroupIds = new Set(roleGroups.filter(({role}) => role !== "guest").map(({groupId}) => groupId));
  if (nonGuestRoleGroupIds.size > 0 && !groups.some((group) => nonGuestRoleGroupIds.has(group.id) && (group.members?.length ?? 0) > 0)) {
    return yield* Effect.fail(new DirectoryUnavailable({message: "Refusing a directory snapshot with no members in any role-bearing group."}));
  }
  const applied = yield* InstallationAccessService.use((access) =>
    access.applyDirectoryGroups({
      groups, provider, syncedAt, maxDeactivations,
      recomputeRoles: recomputeRoles && (rolesSeeded || roleGroups.length > 0),
    })
  );
  // Field order is the order operators read the one-line summary in.
  const reportBase = {
    groups: groups.length,
    created: applied.created,
    renamed: applied.renamed,
    deleted: applied.deleted,
    membershipsReplaced: applied.membershipsReplaced,
    groupsFailed: 0,
  };
  const report: DirectoryGroupSyncReport = applied.roleChanged === undefined
    ? reportBase
    : {...reportBase, roleChanged: applied.roleChanged};
  return report;
});

import {Effect, Schema} from "effect";

import type {
  DirectoryGroupObservation,
  DirectoryGroupRecord,
} from "../core/directory-groups.js";
import {membershipRoleAtLeast, type MembershipRole} from "../core/identity.js";
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
        rolesByUser.set(user.id, {role: assignment.role, user});
      } else if (!membershipRoleAtLeast(seen.role, assignment.role)) {
        seen.role = assignment.role;
      }
    }
  }
  const desired = new Map<string, DirectoryMemberEntry>();
  let skipped = 0;
  for (const {role, user} of rolesByUser.values()) {
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
    if (previous === undefined || !membershipRoleAtLeast(previous.role, role)) {
      desired.set(email, {displayName: displayName(user, email), email, role});
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
  const roleGroupIds = new Set(roleGroups.map(({groupId}) => groupId));
  for (const group of listed) {
    const matchesGuestRule = yield* InstallationAccessService.use((access) =>
      Effect.succeed(access.isGuestGroupPath(group.path))
    );
    if (matchesGuestRule) roleGroupIds.add(group.id);
  }
  if (roleGroupIds.size > 0 && !groups.some((group) => roleGroupIds.has(group.id) && (group.members?.length ?? 0) > 0)) {
    return yield* Effect.fail(new DirectoryUnavailable({message: "Refusing a directory snapshot with no members in any role-bearing group."}));
  }
  const applied = yield* InstallationAccessService.use((access) =>
    access.applyDirectoryGroups({
      groups, provider, syncedAt, maxDeactivations,
      recomputeRoles: recomputeRoles && (rolesSeeded || roleGroupIds.size > 0),
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

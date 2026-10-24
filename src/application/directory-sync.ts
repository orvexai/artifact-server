import {Effect, Schema} from "effect";

import {
  type GroupRolePolicy,
  groupMembershipRole,
} from "../core/group-role-policy.js";
import type {
  DirectoryGroupObservation,
  DirectoryGroupRecord,
} from "../core/directory-groups.js";
import {membershipRoles} from "../core/identity.js";
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
 * Read every configured group from the directory, then make the installation's
 * human members match it. The directory is read completely before the first
 * write, and a directory with no eligible user changes nothing.
 */
export const syncDirectoryMembers = Effect.fn("syncDirectoryMembers")(function*(
  directory: MemberDirectory,
  policy: GroupRolePolicy,
) {
  const names = [...new Set([
    ...policy.administratorGroups,
    ...policy.memberGroups,
  ])];
  const groups = yield* directory.listGroups(names);
  const groupsByUser = new Map<string, {
    readonly groups: string[];
    readonly user: DirectoryUser;
  }>();
  for (const group of groups) {
    for (const user of group.users) {
      const seen = groupsByUser.get(user.id);
      if (seen === undefined) {
        groupsByUser.set(user.id, {groups: [group.name], user});
      } else {
        seen.groups.push(group.name);
      }
    }
  }
  const desired = new Map<string, DirectoryMemberEntry>();
  let skipped = 0;
  for (const {groups: userGroups, user} of groupsByUser.values()) {
    const email = user.enabled && user.emailVerified && user.email !== null
      ? normalizeMemberEmail(user.email)
      : null;
    const role = groupMembershipRole(policy, userGroups);
    if (email === null || role === null) {
      skipped += 1;
      continue;
    }
    const previous = desired.get(email);
    // Two directory users sharing one address are one member; the stronger
    // role wins, as one person in both groups would.
    if (previous === undefined || role === membershipRoles.administrator) {
      desired.set(email, {displayName: displayName(user, email), email, role});
    }
  }
  if (desired.size === 0) {
    return yield* new DirectoryUnavailable({
      message:
        "The directory reported no enabled user with a verified email in the configured groups; nothing was changed.",
    });
  }
  const reconciliation = yield* InstallationAccessService.use((access) =>
    access.reconcileDirectoryMembers([...desired.values()])
  );
  // Field order is the order operators read the one-line summary in.
  const report: DirectorySyncReport = {
    groups: groups.length,
    directoryUsers: groupsByUser.size,
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
) {
  const listed = yield* directory.listAllGroups();
  const groups: DirectoryGroupObservation[] = [];
  let groupsFailed = 0;
  for (const group of listed) {
    const users = yield* directory.listGroupMembers(group).pipe(
      Effect.map((read): readonly DirectoryUser[] | null => read),
      Effect.catchTag("DirectoryUnavailable", (failure) =>
        Effect.logWarning(
          `Keeping the stored members of ${group.path}: ${failure.message}`,
        ).pipe(Effect.as(null))
      ),
    );
    if (users === null) groupsFailed += 1;
    groups.push({
      ...group,
      members: users === null ? null : users.map((user) => ({
        email: user.enabled && user.emailVerified && user.email !== null
          ? normalizeMemberEmail(user.email)
          : null,
        subject: user.id,
      })),
    });
  }
  const applied = yield* InstallationAccessService.use((access) =>
    access.applyDirectoryGroups({groups, syncedAt})
  );
  // Field order is the order operators read the one-line summary in.
  const report: DirectoryGroupSyncReport = {
    groups: groups.length,
    created: applied.created,
    renamed: applied.renamed,
    deleted: applied.deleted,
    membershipsReplaced: applied.membershipsReplaced,
    groupsFailed,
  };
  return report;
});

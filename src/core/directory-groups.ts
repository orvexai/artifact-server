/** One group as the member directory lists it, keyed by its directory id. */
export interface DirectoryGroupRecord {
  readonly id: string;
  readonly name: string;
  /** Full path such as `/Engineering/Platform`, unique in the directory. */
  readonly path: string;
}

/** One enabled person in a directory group, whether or not they are admitted. */
export interface DirectoryGroupMember {
  /** Normalized address, present only for an enabled user with a verified email. */
  readonly email: string | null;
  /** The directory's user id, the same value as the OIDC `sub` claim. */
  readonly subject: string;
}

/** One listed group and, when it could be read, its complete membership. */
export interface DirectoryGroupObservation extends DirectoryGroupRecord {
  /** Null keeps the stored membership: this group's members could not be read. */
  readonly members: readonly DirectoryGroupMember[] | null;
}

/**
 * Every group the directory listed in one pass. A stored group missing from
 * it is deleted, so it must come from a complete listing.
 */
export interface DirectoryGroupSnapshot {
  readonly groups: readonly DirectoryGroupObservation[];
  /** The identity provider whose user ids the member subjects are. */
  readonly provider: string;
  readonly syncedAt: string;
}

/** A stored directory group with its current member count. */
export interface StoredDirectoryGroup extends DirectoryGroupRecord {
  readonly memberCount: number;
  readonly syncedAt: string;
}

/** What applying one snapshot changed. */
export interface DirectoryGroupApplyResult {
  readonly created: number;
  readonly deleted: number;
  readonly membershipsKept: number;
  readonly membershipsReplaced: number;
  readonly renamed: number;
}

/** The row changes one snapshot needs against the stored groups. */
export interface DirectoryGroupChangePlan {
  /** Stored groups missing from the snapshot. */
  readonly deletedIds: readonly string[];
  /** Kept groups whose path changes; move these aside before writing paths. */
  readonly movedIds: readonly string[];
  readonly result: DirectoryGroupApplyResult;
}

/**
 * Compare one snapshot with the stored groups. Refuses a snapshot that names
 * one id or one path twice, which no complete directory listing can.
 */
export function planDirectoryGroupChanges(
  stored: ReadonlyMap<string, DirectoryGroupRecord>,
  snapshot: DirectoryGroupSnapshot,
): DirectoryGroupChangePlan {
  const ids = new Set<string>();
  const paths = new Set<string>();
  for (const group of snapshot.groups) {
    if (ids.has(group.id) || paths.has(group.path)) {
      throw new Error("A directory group snapshot must name each group once.");
    }
    ids.add(group.id);
    paths.add(group.path);
  }
  let created = 0;
  let renamed = 0;
  let membershipsKept = 0;
  let membershipsReplaced = 0;
  const movedIds: string[] = [];
  for (const group of snapshot.groups) {
    const previous = stored.get(group.id);
    if (previous === undefined) {
      created += 1;
    } else if (previous.path !== group.path || previous.name !== group.name) {
      renamed += 1;
      if (previous.path !== group.path) movedIds.push(group.id);
    }
    if (group.members === null) {
      membershipsKept += 1;
    } else {
      membershipsReplaced += 1;
    }
  }
  const deletedIds = [...stored.keys()].filter((id) => !ids.has(id));
  return {
    deletedIds,
    movedIds,
    result: {
      created,
      deleted: deletedIds.length,
      membershipsKept,
      membershipsReplaced,
      renamed,
    },
  };
}

/**
 * A placeholder path no directory group can have, for one transaction only:
 * every real path starts with `/`.
 */
export function parkedDirectoryGroupPath(id: string): string {
  return `parked:${id}`;
}

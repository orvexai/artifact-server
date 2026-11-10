import {Effect} from "effect";

import type {ApplicationRuntime} from
  "../application/application-runtime.js";
import {
  type DirectoryGroupSyncReport,
  type DirectorySyncReport,
  type GroupDirectory,
  syncDirectoryGroups,
  syncDirectoryMembers,
} from "../application/directory-sync.js";
import type {GroupRoleSeedEntry} from "../core/group-role-policy.js";
import {
  type GroupRoleSeedResult,
  InstallationAccessService,
} from "../application/installation-access.js";

/** Run one complete directory sync pass and reject with a stable message. */
export function runDirectorySyncPass(
  runtime: ApplicationRuntime,
  directory: GroupDirectory,
): Promise<DirectorySyncReport> {
  return runtime.runPromise(syncDirectoryMembers(directory).pipe(
    Effect.mapError((error) => new Error(`${error._tag}: ${error.message}`)),
  ));
}

/** Copy every directory group and its members, rejecting with a stable message. */
export function runDirectoryGroupSyncPass(
  runtime: ApplicationRuntime,
  directory: GroupDirectory,
  syncedAt: string,
  provider: string,
): Promise<DirectoryGroupSyncReport> {
  const configured = process.env["ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS"];
  const maxDeactivations = configured === undefined ? 5 : Number(configured);
  if (!Number.isSafeInteger(maxDeactivations) || maxDeactivations < 0) {
    return Promise.reject(new Error("ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS must be a non-negative integer."));
  }
  return runtime.runPromise(syncDirectoryGroups(directory, syncedAt, provider, maxDeactivations).pipe(
    Effect.mapError((error) => new Error(`${error._tag}: ${error.message}`)),
  ));
}

/** Store the configured starting group roles once, rejecting with a stable message. */
export function runGroupRoleSeed(
  runtime: ApplicationRuntime,
  seed: readonly GroupRoleSeedEntry[],
): Promise<GroupRoleSeedResult> {
  return runtime.runPromise(
    InstallationAccessService.use((access) => access.seedGroupRoles(seed)).pipe(
      Effect.mapError((error) => new Error(`${error._tag}: ${error.message}`)),
    ),
  );
}

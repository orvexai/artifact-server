import {Effect} from "effect";

import type {ApplicationRuntime} from
  "../application/application-runtime.js";
import {
  type DirectoryGroupSyncReport,
  type DirectorySyncReport,
  type OrganizationDirectorySyncResult,
  type GroupDirectory,
  syncDirectoryGroups,
  syncDirectoryMembers,
  syncOrganizationDirectoryMembers,
} from "../application/directory-sync.js";
import type {DirectoryOrganization, OrganizationDirectory} from
  "../identity/keycloak-directory.js";
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

/** Sync one Keycloak organization's members with the configured safety cap. */
export function runOrganizationDirectorySyncPass(
  runtime: ApplicationRuntime,
  directory: OrganizationDirectory,
  organization: DirectoryOrganization,
  staffSelectors: readonly string[] = [],
): Promise<OrganizationDirectorySyncResult> {
  const configured = process.env["ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS"];
  if (configured !== undefined && !/^[0-9]+$/u.test(configured)) {
    return Promise.reject(new Error("ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS must contain only decimal digits."));
  }
  const maximumDeactivations = configured === undefined ? 5 : Number(configured);
  if (!Number.isSafeInteger(maximumDeactivations) || maximumDeactivations < 0) {
    return Promise.reject(new Error("ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS must be a non-negative integer."));
  }
  return runtime.runPromise(syncOrganizationDirectoryMembers(
    directory,
    organization,
    maximumDeactivations,
    staffSelectors,
  ).pipe(Effect.mapError((error) => new Error(`${error._tag}: ${error.message}`))));
}

/** Copy every directory group and its members, rejecting with a stable message. */
export function runDirectoryGroupSyncPass(
  runtime: ApplicationRuntime,
  directory: GroupDirectory,
  syncedAt: string,
  provider: string,
  recomputeRoles = true,
): Promise<DirectoryGroupSyncReport> {
  const configured = process.env["ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS"];
  if (configured !== undefined && !/^[0-9]+$/u.test(configured)) {
    return Promise.reject(new Error("ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS must contain only decimal digits."));
  }
  const maxDeactivations = configured === undefined ? 5 : Number(configured);
  if (!Number.isSafeInteger(maxDeactivations) || maxDeactivations < 0) {
    return Promise.reject(new Error("ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS must be a non-negative integer."));
  }
  return runtime.runPromise(syncDirectoryGroups(
    directory, syncedAt, provider, maxDeactivations, recomputeRoles,
  ).pipe(
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

/** Check whether a starting group-role seed exists after a seed attempt. */
export function runIsGroupRoleSeedApplied(
  runtime: ApplicationRuntime,
): Promise<boolean> {
  return runtime.runPromise(
    InstallationAccessService.use((access) => access.isGroupRoleSeedApplied()).pipe(
      Effect.mapError((error) => new Error(`${error._tag}: ${error.message}`)),
    ),
  );
}

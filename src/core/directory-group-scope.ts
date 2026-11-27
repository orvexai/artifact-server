import type {DirectoryGroupRecord} from "./directory-groups.js";
import {isOrvexTenantGroupPath, organizationStaffPathMatches} from "./group-role-policy.js";

export type DirectoryGroupScope =
  | {readonly kind: "none"}
  | {readonly kind: "roots"; readonly roots: readonly string[]}
  | {
    readonly kind: "orvex";
    readonly excludeTenantPaths: boolean;
    readonly organizationStaffGroups?: readonly string[];
  }
  | {readonly kind: "all"};

export function directoryGroupInScope(scope: DirectoryGroupScope, path: string): boolean {
  switch (scope.kind) {
    case "none":
      return false;
    case "roots":
      return scope.roots.some((root) => path.startsWith(root.endsWith("/") ? root : `${root}/`));
    case "orvex":
      return !scope.excludeTenantPaths || (
        !isOrvexTenantGroupPath(path) && path !== "/Guests" && path !== "/TenantWorkspaces"
      ) || organizationStaffPathMatches(path, scope.organizationStaffGroups ?? []);
    case "all":
      return true;
  }
  return false;
}

export function filterDirectoryGroups<T extends DirectoryGroupRecord>(
  scope: DirectoryGroupScope,
  groups: readonly T[],
): T[] {
  return groups.filter((group) => directoryGroupInScope(scope, group.path));
}

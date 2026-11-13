import type {GroupRoleSeedEntry} from "./group-role-policy.js";

/** A staff group path covers itself and every subgroup beneath it. */
export function staffPathCovers(staffPath: string, group: string): boolean {
  return group === staffPath || group.startsWith(`${staffPath}/`);
}

/**
 * One tenant's staff definition, shared by login and org sync: exact staff
 * group paths (each covering its subgroups), and the {slug}-expanded paths
 * that may not exist in Keycloak yet. Staff come only from staff groups.
 */
export interface TenantStaffDefinition {
  readonly groups: readonly string[];
  readonly groupsMayBeMissing: readonly string[];
}

export const emptyTenantStaffDefinition: TenantStaffDefinition = {groups: [], groupsMayBeMissing: []};

/** Inputs to the tenant login staff decision. */
export interface TenantLoginStaffInput {
  /** Groups the provider reported; only full paths can match. */
  readonly groups: readonly string[] | null;
  readonly seed: readonly GroupRoleSeedEntry[];
  readonly staffGroups: readonly string[];
}

/**
 * Whether a tenant login is Orvex staff: membership of a staff group or one
 * of its subgroups (the platform staff groups and the org's own full-path
 * staff selectors).
 */
export function tenantLoginIsStaff(input: TenantLoginStaffInput): boolean {
  const fullPathGroups = (input.groups ?? []).filter((group) => group.startsWith("/"));
  const staffPaths = [
    ...input.staffGroups,
    ...input.seed.flatMap(({selector, staff}) => staff === true && selector.startsWith("/") ? [selector] : []),
  ];
  return fullPathGroups.some((group) => staffPaths.some((path) => staffPathCovers(path, group)));
}

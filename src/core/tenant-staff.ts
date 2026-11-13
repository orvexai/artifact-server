import type {GroupRoleSeedEntry} from "./group-role-policy.js";

/**
 * True when a verified email's domain is exactly one of the configured Orvex
 * staff domains (case-insensitive). Subdomains never match, and an
 * unverified email never counts.
 */
export function emailHasStaffDomain(
  email: string | null,
  emailVerified: boolean,
  domains: readonly string[],
): boolean {
  if (!emailVerified || email === null || domains.length === 0) return false;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return false;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domains.includes(domain);
}

/** A staff group path covers itself and every subgroup beneath it. */
export function staffPathCovers(staffPath: string, group: string): boolean {
  return group === staffPath || group.startsWith(`${staffPath}/`);
}

/** Inputs to the tenant login staff decision. */
export interface TenantLoginStaffInput {
  readonly email: string | null;
  readonly emailVerified: boolean;
  /** Groups the provider reported; only full paths can match. */
  readonly groups: readonly string[] | null;
  readonly seed: readonly GroupRoleSeedEntry[];
  readonly staffEmailDomains: readonly string[];
  readonly staffGroups: readonly string[];
}

/**
 * Whether a tenant login is Orvex staff: a verified email on a staff domain,
 * or membership of a staff group or one of its subgroups (the platform staff
 * groups and the org's own full-path staff selectors).
 */
export function tenantLoginIsStaff(input: TenantLoginStaffInput): boolean {
  if (emailHasStaffDomain(input.email, input.emailVerified, input.staffEmailDomains)) return true;
  const fullPathGroups = (input.groups ?? []).filter((group) => group.startsWith("/"));
  const staffPaths = [
    ...input.staffGroups,
    ...input.seed.flatMap(({selector, staff}) => staff === true && selector.startsWith("/") ? [selector] : []),
  ];
  return fullPathGroups.some((group) => staffPaths.some((path) => staffPathCovers(path, group)));
}

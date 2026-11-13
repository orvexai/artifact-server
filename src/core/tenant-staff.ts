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

/**
 * One tenant's staff definition, shared by login and org sync: exact staff
 * group paths (each covering its subgroups), the paths that may be missing
 * in Keycloak ({slug}-expanded ones), verified-email domains, and the
 * identity providers trusted to assert those emails.
 */
export interface TenantStaffDefinition {
  readonly emailDomains: readonly string[];
  readonly emailTrustedIdps: readonly string[];
  readonly groups: readonly string[];
  readonly groupsMissingIsEmpty: readonly string[];
}

export const emptyTenantStaffDefinition: TenantStaffDefinition = {
  emailDomains: [], emailTrustedIdps: [], groups: [], groupsMissingIsEmpty: [],
};

/**
 * Whether an email-domain match may count for an account linked to these
 * identity providers: a native account (none), or only trusted providers.
 */
export function staffEmailIdentityProvidersTrusted(
  identityProviders: readonly string[],
  trustedIdps: readonly string[],
): boolean {
  return identityProviders.every((provider) => trustedIdps.includes(provider));
}

/** Inputs to the tenant login staff decision. */
export interface TenantLoginStaffInput {
  readonly email: string | null;
  readonly emailVerified: boolean;
  /** The verified `identity_provider` claim; absent or null for a native account. */
  readonly identityProvider?: string | null | undefined;
  readonly staffEmailTrustedIdps?: readonly string[] | undefined;
  /** Groups the provider reported; only full paths can match. */
  readonly groups: readonly string[] | null;
  readonly seed: readonly GroupRoleSeedEntry[];
  readonly staffEmailDomains: readonly string[];
  readonly staffGroups: readonly string[];
}

/**
 * Whether a tenant login is Orvex staff: a verified email on a staff domain
 * asserted by a native account or a trusted identity provider, or membership of a staff group or one of its subgroups (the platform staff
 * groups and the org's own full-path staff selectors).
 */
export function tenantLoginIsStaff(input: TenantLoginStaffInput): boolean {
  const identityProviders = input.identityProvider === undefined || input.identityProvider === null
    ? []
    : [input.identityProvider];
  if (emailHasStaffDomain(input.email, input.emailVerified, input.staffEmailDomains) &&
    staffEmailIdentityProvidersTrusted(identityProviders, input.staffEmailTrustedIdps ?? [])) return true;
  const fullPathGroups = (input.groups ?? []).filter((group) => group.startsWith("/"));
  const staffPaths = [
    ...input.staffGroups,
    ...input.seed.flatMap(({selector, staff}) => staff === true && selector.startsWith("/") ? [selector] : []),
  ];
  return fullPathGroups.some((group) => staffPaths.some((path) => staffPathCovers(path, group)));
}

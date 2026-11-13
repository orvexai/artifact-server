/** Environment variable naming the platform-wide Orvex staff groups. */
export const organizationStaffGroupsVariable = "ARTIFACT_SERVER_ORG_STAFF_GROUPS";

/** Placeholder expanded to each organization's slug. */
export const organizationSlugPlaceholder = "{slug}";

const staffGroupPathPattern = /^(?:\/[^/\s,{}]+)+$/u;

/**
 * Parse the platform-wide staff definition: comma-separated exact Keycloak
 * group paths such as `/Administrators,/Developers`. Members of these groups
 * are Orvex staff in every non-Orvex organization, at login and at sync.
 */
export function parseOrganizationStaffGroups(value: string | undefined): readonly string[] {
  if (value === undefined) return [];
  const groups = value.split(",").map((group) => group.trim()).filter((group) => group !== "");
  for (const group of groups) {
    // `{slug}` is the only placeholder; it must still form an exact path.
    if (!staffGroupPathPattern.test(group.replaceAll(organizationSlugPlaceholder, "slug"))) {
      throw new Error(`${organizationStaffGroupsVariable} entries must be exact group paths such as /Developers; got ${JSON.stringify(group)}.`);
    }
  }
  return [...new Set(groups)];
}

/**
 * Refuse to run organization tenancy without a staff definition, so a staff
 * member can never be admitted to a tenant unmasked.
 */
export function requireOrganizationStaffGroups(groups: readonly string[] | undefined): readonly string[] {
  if (groups === undefined || groups.length === 0) {
    throw new Error(`Organization tenancy requires ${organizationStaffGroupsVariable}: set it to the comma-separated Keycloak group paths of Orvex staff, for example /Administrators,/Developers.`);
  }
  return groups;
}

/**
 * Expand `{slug}` in the platform staff groups for one organization and check
 * that every expanded path is still an exact group path.
 */
export function expandOrganizationStaffGroups(groups: readonly string[], slug: string): readonly string[] {
  return [...new Set(groups.map((group) => {
    const expanded = group.replaceAll(organizationSlugPlaceholder, slug);
    if (!staffGroupPathPattern.test(expanded)) {
      throw new Error(`${organizationStaffGroupsVariable} entry ${JSON.stringify(group)} is not an exact group path for organization ${JSON.stringify(slug)}.`);
    }
    return expanded;
  }))];
}

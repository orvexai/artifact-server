/** Environment variable naming the platform-wide Orvex staff groups. */
export const organizationStaffGroupsVariable = "ARTIFACT_SERVER_ORG_STAFF_GROUPS";

const staffGroupPathPattern = /^(?:\/[^/\s,]+)+$/u;

/**
 * Parse the platform-wide staff definition: comma-separated exact Keycloak
 * group paths such as `/Administrators,/Developers`. Members of these groups
 * are Orvex staff in every non-Orvex organization, at login and at sync.
 */
export function parseOrganizationStaffGroups(value: string | undefined): readonly string[] {
  if (value === undefined) return [];
  const groups = value.split(",").map((group) => group.trim()).filter((group) => group !== "");
  for (const group of groups) {
    if (!staffGroupPathPattern.test(group)) {
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

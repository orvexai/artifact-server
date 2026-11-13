import type {ExternalIdentity} from "../core/installation-identity.js";
import {membershipRolePrecedence} from "../core/group-role-policy.js";
import {membershipRoles} from "../core/identity.js";
import type {OrganizationRecord} from "./organization-registry.js";

/** One verified Keycloak organization membership returned after sign-in. */
export interface OrganizationMembership {
  readonly displayName: string;
  readonly role: string;
  readonly slug: string;
}

/** Slice 2 adapter: resolve memberships from the verified identity/token. */
export interface OrganizationMembershipResolver {
  readonly forIdentity: (
    identity: ExternalIdentity,
  ) => Promise<readonly OrganizationMembership[]>;
}

/** Test seam used before the Keycloak Organizations adapter is composed. */
export const emptyOrganizationMembershipResolver: OrganizationMembershipResolver = {
  forIdentity: async () => [],
};

/** Named composition seam for the verified-identity organization claim adapter. */
export function createOrganizationMembershipsAdapter(
  resolver?: OrganizationMembershipResolver,
): OrganizationMembershipResolver {
  return resolver ?? emptyOrganizationMembershipResolver;
}

/** Adapter point for verified Keycloak `organization` claims without directory synchronization. */
export function createKeycloakOrganizationMembershipResolver(
  findOrganization: (slug: string) => Promise<OrganizationRecord | null>,
): OrganizationMembershipResolver {
  return {
    forIdentity: async (identity) => {
      const claim = identity.organizations ?? {};
      const results = await Promise.all(Object.entries(claim).map(async ([slug, membership]) => {
        const organization = await findOrganization(slug);
        if (organization === null || organization.status !== "active" || organization.admissionPolicy === null) return null;
        const groups = new Set(membership.groups);
        const roles = organization.admissionPolicy.seed
          .filter(({selector}) => selector.startsWith("/") && groups.has(selector))
          .map(({role}) => role)
          .filter((role) => role !== membershipRoles.guest);
        const role = roles.toSorted((left, right) => membershipRolePrecedence(right) - membershipRolePrecedence(left))[0];
        return role === undefined ? null : {displayName: organization.displayName, role: String(role), slug} satisfies OrganizationMembership;
      }));
      return results.filter((value): value is OrganizationMembership => value !== null);
    },
  };
}

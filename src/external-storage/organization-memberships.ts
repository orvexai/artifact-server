import type {ExternalIdentity} from "../core/installation-identity.js";

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

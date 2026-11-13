import type {ExternalIdentity} from "../core/installation-identity.js";
import {
  configuredGroupRoleAssignments,
  groupMembershipRole,
  type GroupRoleAssignment,
  type GroupRolePolicy,
} from "../core/group-role-policy.js";
import {
  isAdministratorRole,
  membershipRoles,
  type MembershipRole,
} from "../core/identity.js";
import type {InstallationMember} from "../core/installation-identity.js";
import {normalizeMemberEmail} from "../application/installation-access.js";
import {mapKeycloakOrganizationGroups} from "../identity/oidc-organization-claim.js";
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

/** Orvex keeps its own issuer-group admission; the router supplies that check. */
export type OrvexAdmissionRole = (identity: ExternalIdentity) => Promise<MembershipRole | null>;

/** The installation role a Keycloak organization claim admits, matching tenant login. */
export function keycloakClaimMembershipRole(groups: readonly string[]): MembershipRole | null {
  const role = mapKeycloakOrganizationGroups(groups);
  return role === "owner"
    ? membershipRoles.owner
    : role === "editor"
    ? membershipRoles.member
    : role === "viewer"
    ? membershipRoles.viewer
    : null;
}

/**
 * Resolve the root chooser's organizations from the verified identity. A
 * Keycloak-linked organization is listed when the token's `organization`
 * claim carries its registered Keycloak id and its /viewer, /editor or /owner
 * groups admit a role, exactly as tenant login admits. Orvex is listed when
 * its normal issuer-group admission admits the identity.
 */
export function createKeycloakOrganizationMembershipResolver(
  findOrganization: (slug: string) => Promise<OrganizationRecord | null>,
  isManuallyDeactivated?: (organization: OrganizationRecord, identity: ExternalIdentity) => Promise<boolean>,
  orvexAdmissionRole?: OrvexAdmissionRole,
): OrganizationMembershipResolver {
  return {
    forIdentity: async (identity) => {
      const claim = identity.organizations ?? {};
      const results = await Promise.all(Object.entries(claim).map(async ([slug, membership]) => {
        if (slug === "orvex") return null;
        const organization = await findOrganization(slug);
        if (organization === null || organization.status !== "active" || organization.slug !== slug) return null;
        if (organization.keycloakId === null || organization.keycloakId !== membership.id) return null;
        const role = keycloakClaimMembershipRole(membership.groups);
        if (role === null) return null;
        if (isManuallyDeactivated !== undefined && await isManuallyDeactivated(organization, identity)) return null;
        const listed: OrganizationMembership = {displayName: organization.displayName, role, slug};
        return listed;
      }));
      const memberships = results.filter((value): value is OrganizationMembership => value !== null);
      if (orvexAdmissionRole !== undefined) {
        const orvex = await findOrganization("orvex");
        if (orvex !== null && orvex.status === "active") {
          const role = await orvexAdmissionRole(identity).catch(() => null);
          if (role !== null) {
            memberships.unshift({displayName: orvex.displayName, role, slug: "orvex"});
          }
        }
      }
      return memberships;
    },
  };
}

/** Inputs to the side-effect-free Orvex admission check behind the chooser. */
export interface OrvexAdmissionReader {
  readonly bootstrapAdministratorEmail: string | null;
  readonly findActiveMemberByEmail: (email: string) => Promise<InstallationMember | null>;
  readonly findActiveMemberByExternalIdentity: (provider: string, subject: string) => Promise<InstallationMember | null>;
  readonly groupRolePolicy: GroupRolePolicy | null;
  readonly hasMembers: () => Promise<boolean>;
  readonly isGroupRoleSeedApplied: () => Promise<boolean>;
  readonly listGroupRoles: () => Promise<readonly GroupRoleAssignment[]>;
}

/**
 * Preview Orvex's interactive admission without admitting, binding or
 * deactivating anyone: the role Orvex sign-in would grant, or null.
 */
export function createOrvexAdmissionRole(reader: OrvexAdmissionReader): OrvexAdmissionRole {
  return async (identity) => {
    if (identity.serviceAccount === true || identity.email === null || !identity.emailVerified) return null;
    const email = normalizeMemberEmail(identity.email);
    if (email === null) return null;
    const member = await reader.findActiveMemberByExternalIdentity(identity.provider, identity.subject) ??
      await reader.findActiveMemberByEmail(email);
    const policy = reader.groupRolePolicy;
    if (policy === null) {
      if (member !== null) return member.role;
      const bootstrap = reader.bootstrapAdministratorEmail === null
        ? null
        : normalizeMemberEmail(reader.bootstrapAdministratorEmail);
      return bootstrap !== null && bootstrap === email && !(await reader.hasMembers())
        ? membershipRoles.administrator
        : null;
    }
    const assignments = await reader.isGroupRoleSeedApplied()
      ? await reader.listGroupRoles()
      : configuredGroupRoleAssignments(policy.seed);
    if (assignments.length === 0) return null;
    const role = policy.groupRoots === undefined
      ? groupMembershipRole(assignments, identity.groups)
      : groupMembershipRole(assignments, identity.groups, policy.groupRoots);
    if (role === null && member !== null && isAdministratorRole(member.role)) return member.role;
    return role;
  };
}

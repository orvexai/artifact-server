import {detectConfusables, skeleton} from "@verifyhash/unicode-inspector";

/** Principal kinds recognized by Artifact Server policy. */
export const principalKinds = {
  human: "human",
  service: "service",
} as const;

/** One provider-neutral principal kind. */
export type PrincipalKind =
  (typeof principalKinds)[keyof typeof principalKinds];

/**
 * Standalone installation membership roles, weakest first. The application
 * labels them Viewer, Operator, Admin and Owner; the stored values keep the
 * original names so existing members, sessions and clients are unchanged.
 */
export const membershipRoles = {
  guest: "guest",
  viewer: "viewer",
  member: "member",
  administrator: "administrator",
  owner: "owner",
} as const;

/** One standalone installation membership role. */
export type MembershipRole =
  (typeof membershipRoles)[keyof typeof membershipRoles];

const membershipRoleRank = {
  guest: 0,
  viewer: 1,
  member: 2,
  administrator: 3,
  owner: 4,
} as const satisfies Readonly<Record<MembershipRole, number>>;

/** True when `role` is at least `minimum`. */
export function membershipRoleAtLeast(
  role: MembershipRole,
  minimum: MembershipRole,
): boolean {
  return membershipRoleRank[role] >= membershipRoleRank[minimum];
}

/** True for the roles that administer the installation: Admin and Owner. */
export function isAdministratorRole(role: MembershipRole): boolean {
  return membershipRoleAtLeast(role, membershipRoles.administrator);
}

/** Explicit capabilities assignable to API keys and service principals. */
export const principalCapabilities = {
  connectAgents: "agent:connect",
  createArtifact: "artifact:create",
  issueContentSession: "content-session:issue",
  manageAnyArtifact: "artifact:manage:any",
  publishAnyArtifact: "artifact:publish:any",
  readArtifacts: "artifact:read",
  readArtifactResponses: "artifact:responses:read",
  bindArtifactEmbed: "artifact:embed:bind",
  manageProjects: "project:manage",
  provisionProjects: "project:provision",
  writeComments: "comment:write",
} as const;

/** One explicit capability granted to a principal. */
export type PrincipalCapability =
  (typeof principalCapabilities)[keyof typeof principalCapabilities];

/** A credential-independent identity used by every application operation. */
export interface Principal {
  readonly authorizedByPrincipalId: string | null;
  /** OAuth client ID verified by the MCP bearer boundary, when applicable. */
  readonly actorClientId?: string | null;
  /** Verified OIDC client-credentials client ID for a service principal. */
  readonly serviceAccountClientId?: string | undefined;
  readonly capabilities: readonly PrincipalCapability[];
  /** Name captured with every write this principal makes; never re-read later. */
  readonly displayName: string;
  /** Verified OIDC email claim, when the identity provider supplied one. */
  readonly email?: string | null | undefined;
  readonly id: string;
  readonly installationId: string;
  readonly kind: PrincipalKind;
  readonly membershipRole: MembershipRole;
  /** Internal request context used to project tenant-visible identities by id. */
  readonly tenantStaffPrincipalIds?: readonly string[] | undefined;
  /** Persisted tenant privacy marker; once true it means this identity has ever been staff. */
  readonly staff?: boolean | undefined;
  /** Directory group IDs carried by a constrained OIDC service identity. */
  readonly directoryGroupIds?: readonly string[] | undefined;
  /** Full path prefixes eligible for this configured project provisioner. */
  readonly provisionerGroupPrefixes?: readonly string[] | undefined;
  /** Marks an OIDC client-credentials principal with group-bound access. */
  readonly serviceAccountSource?: "oidc" | undefined;
}

/** Resolve staff status strictly by identity id, never by display text. */
export function isTenantStaffIdentity(principal: Principal, principalId: string): boolean {
  return principal.staff === true && principal.id === principalId ||
    principal.tenantStaffPrincipalIds?.includes(principalId) === true;
}

/** Hide tenant staff IDs wherever a typed public projection exposes attribution. */
export function tenantVisiblePrincipalId(principal: Principal | undefined, principalId: string | null): string | null {
  if (principalId === null || principal?.tenantStaffPrincipalIds === undefined) return principalId;
  return isTenantStaffIdentity(principal, principalId) ? null : principalId;
}

/** Compare reserved tenant identity labels after compatibility and confusable folding. */
export function isReservedTenantIdentityName(value: string): boolean {
  // U+028B is an official UTS #39 confusable of "u", while tenant users
  // commonly use it visually for the "v" in this reserved label.
  const normalized = value.normalize("NFKC").replace(/\u028b/gu, "v");
  const canonicalSkeleton = skeleton(normalized).toLowerCase()
    .replace(/[\p{M}\p{P}\p{S}\p{Z}\p{Default_Ignorable_Code_Point}]/gu, "");
  return detectConfusables(normalized).mixedScripts.length > 0 ||
    canonicalSkeleton.includes("orvexsupport");
}

/** Apply the tenant author projection to a version at the application boundary. */
export function tenantVersionRecord<T extends {readonly publisherPrincipalId: string | null}>(
  principal: Principal | undefined,
  version: T,
): Omit<T, "publisherPrincipalId"> & {readonly publisherPrincipalId: string | null} {
  return {...version, publisherPrincipalId: principal === undefined ? null : tenantVisiblePrincipalId(principal, version.publisherPrincipalId)};
}

/** Stable public presentation for an identity in a tenant organization. */
export function tenantIdentityPresentation(
  principal: Principal | undefined,
  identity: {readonly principalId: string; readonly displayName: string; readonly email?: string | null; readonly staff?: boolean},
) {
  const isStaff = identity.staff === true || principal !== undefined && isTenantStaffIdentity(principal, identity.principalId);
  return {
    displayName: isStaff ? "Orvex Support" : isReservedTenantIdentityName(identity.displayName) ? "Orvex Support (member)" : identity.displayName,
    email: isStaff || identity.email === undefined ? null : identity.email,
    isStaff,
    subject: isStaff ? null : identity.principalId,
  };
}

/** Determine whether a principal has an explicit capability. */
export function hasCapability(
  principal: Principal,
  capability: PrincipalCapability,
): boolean {
  return principal.capabilities.includes(capability);
}

/** Determine whether a human principal administers the standalone installation. */
export function isHumanAdministrator(principal: Principal): boolean {
  return isDirectHumanPrincipal(principal) &&
    isAdministratorRole(principal.membershipRole);
}

/** Determine whether a principal came from a person's interactive session. */
export function isDirectHumanPrincipal(principal: Principal): boolean {
  return principal.kind === principalKinds.human &&
    principal.authorizedByPrincipalId === null;
}

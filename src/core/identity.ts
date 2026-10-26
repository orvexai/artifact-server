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
  viewer: "viewer",
  member: "member",
  administrator: "administrator",
  owner: "owner",
} as const;

/** One standalone installation membership role. */
export type MembershipRole =
  (typeof membershipRoles)[keyof typeof membershipRoles];

const membershipRoleRank = {
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
  manageProjects: "project:manage",
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
  readonly capabilities: readonly PrincipalCapability[];
  /** Name captured with every write this principal makes; never re-read later. */
  readonly displayName: string;
  readonly id: string;
  readonly installationId: string;
  readonly kind: PrincipalKind;
  readonly membershipRole: MembershipRole;
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

import type {MemberStatus} from "./installation-identity.js";
import {
  isAdministratorRole,
  principalKinds,
  type MembershipRole,
  type Principal,
} from "./identity.js";

/** Who may see a project: every member, or only administrators and granted groups. */
export const projectAccessModes = {
  installation: "installation",
  restricted: "restricted",
} as const;

/** One project access mode. */
export type ProjectAccessMode =
  (typeof projectAccessModes)[keyof typeof projectAccessModes];

/** A role a group can be granted on a restricted project, weakest first. */
export const projectGrantRoles = {
  viewer: "viewer",
  editor: "editor",
  manager: "manager",
} as const;

/** One project grant role. */
export type ProjectGrantRole =
  (typeof projectGrantRoles)[keyof typeof projectGrantRoles];

/** The effective role on a restricted project, including installation administrators. */
export type ProjectRole = ProjectGrantRole | "administrator";

const roleRank = {
  viewer: 1,
  editor: 2,
  manager: 3,
  administrator: 4,
} as const satisfies Readonly<Record<ProjectRole, number>>;

/** True when `role` is at least `minimum`. */
export function projectRoleAtLeast(role: ProjectRole, minimum: ProjectRole): boolean {
  return roleRank[role] >= roleRank[minimum];
}

/** What storage knows about one member's access to one project. */
export interface ProjectAccessRecord {
  readonly accessMode: ProjectAccessMode;
  /** The grant roles reaching this member through its directory groups. */
  readonly grantRoles: readonly ProjectGrantRole[];
  /** True when this member created the project, which makes it a manager. */
  readonly isCreator: boolean;
  /** Null when the principal is not a stored member. */
  readonly member: {
    readonly role: MembershipRole;
    readonly status: MemberStatus;
  } | null;
}

/**
 * The access one principal has to one project. An `installation` project
 * keeps today's capability rules unchanged; a `restricted` one also needs a
 * role, and a null role means the project must look absent.
 */
export type ProjectAccess =
  | {
    readonly mode: "installation";
    /** The principal who created it may still manage it once opened. */
    readonly isCreator: boolean;
  }
  | {readonly mode: "restricted"; readonly isCreator?: boolean; readonly role: ProjectRole | null};

/**
 * Decide one principal's access from storage. Service principals use only
 * their matching project grants. Every human principal, whether a
 * browser session, an MCP client, or an API key issued for that member, is
 * judged as the member in `principal.id`, by its current stored role and
 * status rather than by what the credential carries. The member who created
 * a project manages it.
 */
export function resolveProjectAccess(
  principal: Principal,
  record: ProjectAccessRecord,
): ProjectAccess {
  if (
    principal.kind === principalKinds.service &&
    principal.serviceAccountSource === "oidc" &&
    principal.directoryGroupIds === undefined
  ) {
    return {mode: "restricted", role: null};
  }
  if (
    principal.kind === principalKinds.human &&
    (principal.membershipRole === "guest" || record.member?.role === "guest")
  ) {
    if (record.member?.status !== "active") return {mode: "restricted", role: null};
    if (record.accessMode === projectAccessModes.installation) {
      return {mode: "restricted", role: null};
    }
    return {
      mode: "restricted",
      role: record.grantRoles.length > 0 ? "viewer" : null,
    };
  }
  if (record.accessMode === projectAccessModes.installation) {
    return {
      isCreator: record.isCreator && (principal.kind === principalKinds.service ||
        record.member?.status === "active"),
      mode: "installation",
    };
  }
  if (principal.kind === principalKinds.service) {
    if (principal.serviceAccountSource !== "oidc") {
      return {mode: "restricted", role: "administrator"};
    }
    return {
      mode: "restricted",
      isCreator: record.isCreator,
      role: record.isCreator ? "manager" : record.grantRoles.reduce<ProjectRole | null>(
        (best, role) => best === null || roleRank[role] > roleRank[best]
          ? role
          : best,
        null,
      ),
    };
  }
  const member = record.member;
  if (member === null || member.status !== "active") {
    return {mode: "restricted", role: null};
  }
  if (isAdministratorRole(member.role)) {
    return {mode: "restricted", role: "administrator"};
  }
  let best: ProjectRole | null = record.isCreator ? "manager" : null;
  for (const role of record.grantRoles) {
    if (best === null || roleRank[role] > roleRank[best]) best = role;
  }
  return {mode: "restricted", role: best};
}

/** One group's grant on one project. */
export interface ProjectGroupGrant {
  readonly grantedAt: string;
  readonly grantedByPrincipalId: string;
  readonly groupId: string;
  readonly projectId: string;
  readonly role: ProjectGrantRole;
}

/** The provider name an OIDC issuer's external identities are stored under. */
export function oidcIdentityProviderName(issuer: string): string {
  return `oidc:${issuer}`;
}

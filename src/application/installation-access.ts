import { createHash, timingSafeEqual } from "node:crypto";

import {
  type ProjectAccess,
  type ProjectAccessMode,
  type ProjectAccessRecord,
  type ProjectGroupGrant,
  resolveProjectAccess,
} from "../core/project-access.js";
import type {
  DirectoryGroupApplyResult,
  DirectoryGroupSnapshot,
  StoredDirectoryGroup,
} from "../core/directory-groups.js";
import { Context, Effect, Layer, Redacted } from "effect";

import type { AuthenticatedApplicationSession } from "./authentication.js";
import {
  AuthenticationCache,
  type AuthenticationCachePolicy,
  defaultAuthenticationCachePolicy,
} from "./authentication-cache.js";
import {
  AuthenticationRequired,
  AuthorizationDenied,
  IdentityAdmissionDenied,
  IdentityConflict,
  IdentityNotFound,
} from "../core/errors.js";
import type {
  IdentityRepositoryFailure,
  LoginAttemptRejected,
} from "../core/errors.js";
import {
  type ApplicationSession,
  type ExternalIdentity,
  type InstallationMember,
  type IssuedApplicationSession,
  type IssuedManagedApiKey,
  type LoginAttempt,
  managedApiKeyCredentialPattern,
  type ManagedApiKey,
  memberStatuses,
  type StoredManagedApiKey,
} from "../core/installation-identity.js";
import {
  configuredGroupRoleAssignments,
  type GroupRoleAssignment,
  type GroupRolePolicy,
  type GroupRoleSeedEntry,
  groupMembershipRole,
} from "../core/group-role-policy.js";
import {
  isAdministratorRole,
  isHumanAdministrator,
  membershipRoles,
  membershipRoleAtLeast,
  principalCapabilities,
  principalKinds,
  type MembershipRole,
  type Principal,
  type PrincipalCapability,
} from "../core/identity.js";

const allCapabilities = new Set<PrincipalCapability>(
  Object.values(principalCapabilities).filter((capability) =>
    capability !== principalCapabilities.provisionProjects
  ),
);
const localBrowserLoginProvider = "artifact-server-local";

export interface InstallationIdentityRepository {
  readonly applyDirectoryGroups: (
    installationId: string,
    snapshot: DirectoryGroupSnapshot,
  ) => Effect.Effect<DirectoryGroupApplyResult, IdentityRepositoryFailure>;
  /** Apply one Keycloak organization snapshot under one directory lock/transaction. */
  readonly applyOrganizationMemberSnapshot?: (
    installationId: string,
    entries: readonly (DirectoryMemberEntry & {readonly id: string})[],
    updatedAt: string,
    maximumDeactivations: number,
  ) => Effect.Effect<DirectoryReconciliation, IdentityConflict | IdentityRepositoryFailure>;
  readonly setOrganizationMemberRole?: (
    installationId: string,
    memberId: string,
    role: MembershipRole,
    updatedAt: string,
  ) => Effect.Effect<InstallationMember | null, IdentityConflict | IdentityRepositoryFailure>;
  readonly listDirectoryGroups: (
    installationId: string,
  ) => Effect.Effect<readonly StoredDirectoryGroup[], IdentityRepositoryFailure>;
  readonly listGroupRoles: (
    installationId: string,
  ) => Effect.Effect<readonly GroupRoleAssignment[], IdentityRepositoryFailure>;
  readonly setGroupRole: (
    installationId: string,
    groupId: string,
    role: MembershipRole | null,
    assignedAt: string,
    assignedByPrincipalId: string,
  ) => Effect.Effect<void, IdentityConflict | IdentityNotFound | IdentityRepositoryFailure>;
  readonly isGroupRoleSeedApplied: (
    installationId: string,
  ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly seedGroupRoles: (
    installationId: string,
    roles: readonly {readonly groupId: string; readonly role: MembershipRole}[],
    seededAt: string,
  ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly findProjectAccess: (
    installationId: string,
    projectId: string,
    memberId: string,
  ) => Effect.Effect<ProjectAccessRecord | null, IdentityRepositoryFailure>;
  readonly listProjectGroupGrants: (
    installationId: string,
    projectId: string,
  ) => Effect.Effect<readonly ProjectGroupGrant[], IdentityRepositoryFailure>;
  readonly putProjectGroupGrant: (
    installationId: string,
    grant: ProjectGroupGrant,
  ) => Effect.Effect<void, IdentityRepositoryFailure>;
  readonly removeProjectGroupGrant: (
    installationId: string,
    projectId: string,
    groupId: string,
  ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly setProjectAccessMode: (
    installationId: string,
    projectId: string,
    accessMode: ProjectAccessMode,
  ) => Effect.Effect<void, IdentityRepositoryFailure>;
  readonly admitMember: (
    command: {
      readonly createdAt: string;
      readonly displayName: string;
      readonly email: string;
      readonly id: string;
      readonly installationId: string;
      readonly role: MembershipRole;
    },
  ) => Effect.Effect<InstallationMember, IdentityConflict | IdentityRepositoryFailure>;
  readonly bindExternalIdentity: (
    command: {
      readonly boundAt: string;
      readonly email: string;
      readonly memberId: string;
      readonly provider: string;
      readonly subject: string;
    },
  ) => Effect.Effect<void, IdentityConflict | IdentityRepositoryFailure>;
  readonly createApiKey: (
    key: StoredManagedApiKey,
  ) => Effect.Effect<ManagedApiKey, IdentityRepositoryFailure>;
  readonly createApplicationSession: (
    command: {
      readonly createdAt: string;
      readonly csrfDigest: string;
      readonly expiresAt: string;
      readonly id: string;
      readonly installationId: string;
      readonly memberId: string;
      readonly tokenDigest: string;
    },
  ) => Effect.Effect<ApplicationSession, IdentityRepositoryFailure>;
  readonly consumeLoginAttempt: (
    stateDigest: string,
    provider: string,
    consumedAt: string,
  ) => Effect.Effect<
    LoginAttempt,
    LoginAttemptRejected | IdentityRepositoryFailure
  >;
  readonly createLoginAttempt: (
    attempt: LoginAttempt,
  ) => Effect.Effect<void, IdentityRepositoryFailure>;
  readonly deactivateMember: (
    installationId: string,
    memberId: string,
    updatedAt: string,
    manuallyDeactivated?: boolean,
  ) => Effect.Effect<
    InstallationMember,
    IdentityConflict | IdentityNotFound | IdentityRepositoryFailure
  >;
  readonly reactivateMember?: (
    installationId: string,
    memberId: string,
  ) => Effect.Effect<InstallationMember,
    IdentityConflict | IdentityNotFound | IdentityRepositoryFailure>;
  readonly findActiveMemberByEmail: (
    installationId: string,
    email: string,
  ) => Effect.Effect<InstallationMember | null, IdentityRepositoryFailure>;
  readonly findActiveMemberByExternalIdentity: (
    installationId: string,
    provider: string,
    subject: string,
  ) => Effect.Effect<InstallationMember | null, IdentityRepositoryFailure>;
  readonly findMember: (
    installationId: string,
    memberId: string,
  ) => Effect.Effect<InstallationMember | null, IdentityRepositoryFailure>;
  readonly findApiKey: (
    installationId: string,
    keyId: string,
  ) => Effect.Effect<StoredManagedApiKey | null, IdentityRepositoryFailure>;
  readonly findApplicationSession: (
    installationId: string,
    tokenDigest: string,
    requestTime: string,
  ) => Effect.Effect<ApplicationSession | null, IdentityRepositoryFailure>;
  readonly hasMembers: (
    installationId: string,
  ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly listApiKeys: (
    installationId: string,
  ) => Effect.Effect<readonly ManagedApiKey[], IdentityRepositoryFailure>;
  readonly listMembers: (
    installationId: string,
  ) => Effect.Effect<readonly InstallationMember[], IdentityRepositoryFailure>;
  readonly revokeApiKey: (
    installationId: string,
    keyId: string,
    revokedAt: string,
  ) => Effect.Effect<ManagedApiKey, IdentityNotFound | IdentityRepositoryFailure>;
  readonly revokeApplicationSession: (
    installationId: string,
    tokenDigest: string,
    revokedAt: string,
  ) => Effect.Effect<void, IdentityRepositoryFailure>;
  readonly rotateApiKey: (
    installationId: string,
    previousKeyId: string,
    replacement: StoredManagedApiKey,
    revokedAt: string,
  ) => Effect.Effect<
    ManagedApiKey,
    IdentityConflict | IdentityNotFound | IdentityRepositoryFailure
  >;
  readonly setMemberRole: (
    installationId: string,
    memberId: string,
    role: MembershipRole,
    updatedAt: string,
    recomputeFromCurrentGroups?: boolean,
  ) => Effect.Effect<
    InstallationMember | null,
    IdentityNotFound | IdentityRepositoryFailure
  >;
}

export interface IdentitySecretProvider {
  readonly digest: (value: string) => string;
  readonly issue: () => string;
}

export interface IdentityIdProvider {
  readonly apiKeyId: () => string;
  readonly memberId: () => string;
  readonly sessionId: () => string;
}

export interface InstallationAccessDependencies {
  /**
   * Bounded-staleness cache policy for successful session and managed-key
   * authentication, keyed by installation and credential digest. Omit it to
   * apply {@link defaultAuthenticationCachePolicy}; pass `null` to disable
   * caching. Only successes are cached, entries never outlive the credential's
   * own expiry, and local revocation paths evict, so a credential revoked in
   * another process may authenticate here for at most the TTL.
   */
  readonly authenticationCache?: AuthenticationCachePolicy | null;
  readonly bootstrapAdministratorEmail: string | null;
  readonly clock: {readonly now: () => Date};
  /**
   * Issuer groups that admit external identities and set their role. When
   * present it replaces manual admission and the bootstrap-email rule for
   * external identities; omit it or pass `null` to keep both.
   */
  readonly groupRolePolicy?: GroupRolePolicy | null;
  readonly organizationAdmission?: {readonly alias: string; readonly id: string};
  readonly ids: IdentityIdProvider;
  readonly installationId: string;
  /** Let non-guest tenant members read their org-scoped directory. */
  readonly organizationDirectoryVisibility?: boolean | undefined;
  readonly localBootstrapCredential: Redacted.Redacted | null;
  readonly localLoginAttemptLifetimeMilliseconds: number;
  /** Keep the installation's local-owner member permanently active. */
  readonly protectBootstrapAdministrator: boolean;
  readonly repository: InstallationIdentityRepository;
  readonly secrets: IdentitySecretProvider;
  readonly sessionLifetimeMilliseconds: number;
}

export interface AdmitMemberCommand {
  readonly displayName: string;
  readonly email: string;
  readonly principal: Principal;
  readonly role: MembershipRole;
}

/** One person a member directory says should be an active member. */
/** The outcome of applying the configured starting group roles. */
export interface GroupRoleSeedResult {
  /** True only on the run that stored the roles. */
  readonly seeded: boolean;
  /** Seed entries that named no group, or more than one. */
  readonly unresolved: readonly string[];
}

export interface DirectoryMemberEntry {
  readonly displayName: string;
  /** Already normalized with {@link normalizeMemberEmail}. */
  readonly email: string;
  readonly role: MembershipRole;
}

/** What one directory reconciliation changed. */
export interface DirectoryReconciliation {
  readonly admitted: number;
  readonly deactivated: number;
  readonly reactivated: number;
  readonly roleChanged: number;
  readonly unchanged: number;
}

export interface IssueApiKeyCommand {
  readonly capabilities: readonly PrincipalCapability[];
  readonly expiresAt: string;
  readonly memberId?: string;
  readonly name: string;
  readonly principal: Principal;
}

/** One short-lived credential intended for a single local browser navigation. */
export interface IssuedLocalBrowserLogin {
  readonly expiresAt: string;
  readonly token: Redacted.Redacted;
}

export interface InstallationAccessOperations {
  readonly findActiveHumanPrincipal: (
    memberId: string,
  ) => Effect.Effect<Principal | null, IdentityRepositoryFailure>;
  readonly admitMember: (
    command: AdmitMemberCommand,
  ) => Effect.Effect<
    InstallationMember,
    AuthorizationDenied | IdentityConflict | IdentityRepositoryFailure
  >;
  readonly authenticateManagedApiKey: (
    credential: Redacted.Redacted,
  ) => Effect.Effect<Principal, AuthenticationRequired | IdentityRepositoryFailure>;
  readonly authenticateExternalIdentity: (
    identity: ExternalIdentity,
  ) => Effect.Effect<
    Principal,
    IdentityAdmissionDenied | IdentityConflict | IdentityRepositoryFailure
  >;
  /**
   * Recognize an already-bound external subject without its profile. Answers
   * null under an issuer group policy, whose groups must be read every time.
   */
  readonly authenticateExternalSubject: (
    provider: string,
    subject: string,
  ) => Effect.Effect<Principal | null, IdentityRepositoryFailure>;
  readonly authenticateSession: (
    credential: Redacted.Redacted,
  ) => Effect.Effect<
    AuthenticatedApplicationSession,
    AuthenticationRequired | IdentityRepositoryFailure
  >;
  readonly completeExternalIdentity: (
    identity: ExternalIdentity,
  ) => Effect.Effect<
    IssuedApplicationSession,
    | IdentityAdmissionDenied
    | IdentityConflict
    | IdentityRepositoryFailure
  >;
  readonly deactivateMember: (
    principal: Principal,
    memberId: string,
  ) => Effect.Effect<
    InstallationMember,
    AuthorizationDenied | IdentityConflict | IdentityNotFound | IdentityRepositoryFailure
  >;
  readonly reactivateMember?: (
    principal: Principal,
    memberId: string,
  ) => Effect.Effect<InstallationMember,
    AuthorizationDenied | IdentityConflict | IdentityNotFound | IdentityRepositoryFailure>;
  readonly issueApiKey: (
    command: IssueApiKeyCommand,
  ) => Effect.Effect<
    IssuedManagedApiKey,
    | AuthorizationDenied
    | IdentityConflict
    | IdentityNotFound
    | IdentityRepositoryFailure
  >;
  readonly listApiKeys: (
    principal: Principal,
  ) => Effect.Effect<readonly ManagedApiKey[], AuthorizationDenied | IdentityRepositoryFailure>;
  readonly listMembers: (
    principal: Principal,
  ) => Effect.Effect<
    readonly InstallationMember[],
    AuthorizationDenied | IdentityRepositoryFailure
  >;
  readonly issueLocalBrowserLogin: (
    credential: Redacted.Redacted,
  ) => Effect.Effect<
    IssuedLocalBrowserLogin,
    AuthenticationRequired | IdentityRepositoryFailure
  >;
  readonly loginWithLocalBrowserToken: (
    token: Redacted.Redacted,
  ) => Effect.Effect<
    IssuedApplicationSession,
    IdentityConflict | IdentityRepositoryFailure | LoginAttemptRejected
  >;
  /** Issue a session for the stable administrator of a local-owner process. */
  readonly loginAsLocalOwner: () => Effect.Effect<
    IssuedApplicationSession,
    IdentityConflict | IdentityRepositoryFailure
  >;
  /**
   * Make the installation's human members exactly the given directory entries:
   * admit, restore, or re-role each entry, and deactivate every other active
   * member. Only an installation with issuer group roles may do this, and an
   * empty entry list is refused so a failed read can never empty it.
   */
  readonly reconcileDirectoryMembers: (
    entries: readonly DirectoryMemberEntry[],
    maximumDeactivations?: number,
  ) => Effect.Effect<
    DirectoryReconciliation,
    IdentityConflict | IdentityRepositoryFailure
  >;
  /**
   * Make the stored directory groups match one complete listing. A group
   * whose members could not be read keeps its stored membership.
   */
  readonly applyDirectoryGroups: (
    snapshot: DirectoryGroupSnapshot,
  ) => Effect.Effect<DirectoryGroupApplyResult, IdentityRepositoryFailure>;
  /** Every stored directory group, ordered by path. */
  readonly listDirectoryGroups: () => Effect.Effect<
    readonly StoredDirectoryGroup[],
    IdentityRepositoryFailure
  >;
  /** Every directory group's installation role, ordered by path. */
  readonly listGroupRoles: () => Effect.Effect<
    readonly GroupRoleAssignment[],
    IdentityRepositoryFailure
  >;
  readonly isGroupRoleSeedApplied: () => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly setGroupRole: (
    principal: Principal,
    groupId: string,
    role: MembershipRole | null,
  ) => Effect.Effect<void, AuthorizationDenied | IdentityConflict | IdentityNotFound | IdentityRepositoryFailure>;
  /**
   * Store the configured starting roles once. Every seed entry must name
   * exactly one stored directory group; otherwise nothing is stored and the
   * entries that matched no single group are reported.
   */
  readonly seedGroupRoles: (
    seed: readonly GroupRoleSeedEntry[],
  ) => Effect.Effect<GroupRoleSeedResult, IdentityRepositoryFailure>;
  /**
   * The access one principal has to one project, read fresh on every call,
   * or null when the project does not exist in this installation.
   */
  readonly projectAccess: (
    principal: Principal,
    projectId: string,
  ) => Effect.Effect<ProjectAccess | null, IdentityRepositoryFailure>;
  /**
   * The access the principal that owns something (an agent) has to one
   * project, known only by its id: a stored member is judged as that member,
   * anything else is a service principal. Null when the project is absent.
   */
  readonly ownerProjectAccess: (
    ownerPrincipalId: string,
    projectId: string,
  ) => Effect.Effect<ProjectAccess | null, IdentityRepositoryFailure>;
  /**
   * Storage for project sharing. These do no authorization of their own:
   * ProjectManagementService decides who may share before calling them.
   */
  readonly projectSharing: {
    readonly list: (
      projectId: string,
    ) => Effect.Effect<readonly ProjectGroupGrant[], IdentityRepositoryFailure>;
    readonly put: (
      grant: ProjectGroupGrant,
    ) => Effect.Effect<void, IdentityRepositoryFailure>;
    readonly remove: (
      projectId: string,
      groupId: string,
    ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
    readonly setAccessMode: (
      projectId: string,
      accessMode: ProjectAccessMode,
    ) => Effect.Effect<void, IdentityRepositoryFailure>;
  };
  readonly revokeApiKey: (
    principal: Principal,
    keyId: string,
  ) => Effect.Effect<
    ManagedApiKey,
    AuthorizationDenied | IdentityNotFound | IdentityRepositoryFailure
  >;
  readonly revokeSession: (
    credential: Redacted.Redacted,
  ) => Effect.Effect<void, IdentityRepositoryFailure>;
  readonly rotateApiKey: (
    principal: Principal,
    keyId: string,
  ) => Effect.Effect<
    IssuedManagedApiKey,
    AuthorizationDenied | IdentityConflict | IdentityNotFound | IdentityRepositoryFailure
  >;
}

/** Installation membership, browser-session, and managed-key lifecycle. */
export class InstallationAccessService extends Context.Service<
  InstallationAccessService,
  InstallationAccessOperations
>()("artifact-server/application/InstallationAccessService") {
  static readonly layer = (
    dependencies: InstallationAccessDependencies,
  ): Layer.Layer<InstallationAccessService> =>
    Layer.succeed(
      InstallationAccessService,
      makeInstallationAccessService(dependencies),
    );
}

function makeInstallationAccessService(
  dependencies: InstallationAccessDependencies,
): InstallationAccessOperations {
  const cachePolicy = dependencies.authenticationCache === undefined
    ? defaultAuthenticationCachePolicy
    : dependencies.authenticationCache;
  const sessionCache = cachePolicy === null
    ? null
    : new AuthenticationCache<AuthenticatedApplicationSession>(cachePolicy);
  const apiKeyCache = cachePolicy === null
    ? null
    : new AuthenticationCache<Principal>(cachePolicy);
  const cacheKey = (digest: string): string =>
    `${dependencies.installationId}:${digest}`;
  // Session entries are keyed by token digest, not member, so the rare
  // membership mutations clear the whole cache instead of indexing it.
  const clearAuthenticationCaches = (): void => {
    sessionCache?.clear();
    apiKeyCache?.clear();
  };
  const groupRolePolicy = dependencies.groupRolePolicy ?? null;

  const issueSession = Effect.fn(
    "InstallationAccessService.issueSession",
  )(function*(member: InstallationMember) {
    const now = dependencies.clock.now();
    const token = dependencies.secrets.issue();
    const csrfToken = dependencies.secrets.issue();
    const session = yield* dependencies.repository.createApplicationSession({
      createdAt: now.toISOString(),
      csrfDigest: dependencies.secrets.digest(csrfToken),
      expiresAt: new Date(
        now.getTime() + dependencies.sessionLifetimeMilliseconds,
      ).toISOString(),
      id: dependencies.ids.sessionId(),
      installationId: dependencies.installationId,
      memberId: member.id,
      tokenDigest: dependencies.secrets.digest(token),
    });
    return {csrfToken, session, token};
  });

  const requireLocalBootstrap = Effect.fn(
    "InstallationAccessService.requireLocalBootstrap",
  )(function*(credential: Redacted.Redacted) {
    const configuredCredential = dependencies.localBootstrapCredential;
    if (
      configuredCredential === null ||
      !identitySecretsEqual(
        Redacted.value(credential),
        Redacted.value(configuredCredential),
      )
    ) {
      return yield* Effect.fail(new AuthenticationRequired({
        message: "The local browser-login credential is invalid.",
      }));
    }
    return yield* Effect.void;
  });

  const issueLocalBrowserLogin = Effect.fn(
    "InstallationAccessService.issueLocalBrowserLogin",
  )(function*(credential: Redacted.Redacted) {
    yield* requireLocalBootstrap(credential);
    const now = dependencies.clock.now();
    const expiresAt = new Date(
      now.getTime() + dependencies.localLoginAttemptLifetimeMilliseconds,
    ).toISOString();
    const token = dependencies.secrets.issue();
    yield* dependencies.repository.createLoginAttempt({
      codeVerifier: "not-applicable",
      createdAt: now.toISOString(),
      expiresAt,
      nonce: null,
      provider: localBrowserLoginProvider,
      returnTo: "/",
      stateDigest: dependencies.secrets.digest(token),
    });
    return {
      expiresAt,
      token: Redacted.make(token, {label: "local-browser-login"}),
    };
  });

  const loginAsLocalOwner = Effect.fn(
    "InstallationAccessService.loginAsLocalOwner",
  )(function*() {
    if (dependencies.bootstrapAdministratorEmail === null) {
      return yield* Effect.fail(new IdentityConflict({
        message: "No bootstrap administrator is configured for this installation.",
      }));
    }
    const email = yield* normalizeEmail(dependencies.bootstrapAdministratorEmail);
    let member = yield* dependencies.repository.findActiveMemberByEmail(
      dependencies.installationId,
      email,
    );
    if (member === null) {
      if (yield* dependencies.repository.hasMembers(dependencies.installationId)) {
        return yield* Effect.fail(new IdentityConflict({
          message: "The configured local administrator is not an active member.",
        }));
      }
      member = yield* dependencies.repository.admitMember({
        createdAt: dependencies.clock.now().toISOString(),
        displayName: "Local administrator",
        email,
        id: dependencies.ids.memberId(),
        installationId: dependencies.installationId,
        role: membershipRoles.administrator,
      });
    }
    if (!isAdministratorRole(member.role)) {
      return yield* Effect.fail(new IdentityConflict({
        message: "The configured local administrator is not an administrator.",
      }));
    }
    return yield* issueSession(member);
  });

  const loginWithLocalBrowserToken = Effect.fn(
    "InstallationAccessService.loginWithLocalBrowserToken",
  )(function*(token: Redacted.Redacted) {
    yield* dependencies.repository.consumeLoginAttempt(
      dependencies.secrets.digest(Redacted.value(token)),
      localBrowserLoginProvider,
      dependencies.clock.now().toISOString(),
    );
    return yield* loginAsLocalOwner();
  });

  const completeExternalIdentity = Effect.fn(
    "InstallationAccessService.completeExternalIdentity",
  )(function*(identity: ExternalIdentity) {
    const member = yield* resolveExternalMember(identity);
    return yield* issueSession(member);
  });

  /**
   * Deactivate one member the issuer no longer admits. Deactivation keeps a
   * last administrator in place; the issuer has already taken that role away,
   * so demote an Admin or Owner before deactivating. Callers keep the last
   * Admin or Owner out of here themselves.
   */
  const deactivateRemovedMember = Effect.fn(
    "InstallationAccessService.deactivateRemovedMember",
  )(function*(member: InstallationMember, now: string) {
    if (isAdministratorRole(member.role)) {
      yield* dependencies.repository.setMemberRole(
        dependencies.installationId,
        member.id,
        membershipRoles.member,
        now,
      );
    }
    yield* dependencies.repository.deactivateMember(
      dependencies.installationId,
      member.id,
      now,
    );
  });

  const applyDirectoryGroups = Effect.fn(
    "InstallationAccessService.applyDirectoryGroups",
  )(function*(snapshot: DirectoryGroupSnapshot) {
    const result = yield* dependencies.repository.applyDirectoryGroups(
      dependencies.installationId,
      {...snapshot, guestGroupPrefixes: dependencies.groupRolePolicy?.guestGroupPrefixes ?? []},
    );
    // Group membership will decide project access; never serve a stale grant.
    if (
      result.deleted + result.membershipsReplaced + result.renamed > 0
    ) {
      clearAuthenticationCaches();
    }
    return result;
  });

  const listDirectoryGroups = Effect.fn(
    "InstallationAccessService.listDirectoryGroups",
  )(function*() {
    const groups = yield* dependencies.repository.listDirectoryGroups(
      dependencies.installationId,
    );
    if (dependencies.organizationDirectoryVisibility !== true || groupRolePolicy === null) return groups;
    const staffSelectors = groupRolePolicy.seed.filter(({staff}) => staff === true)
      .map(({selector}) => selector);
    return groups.filter((group) => !staffSelectors.some((selector) =>
      selector.startsWith("/") ? group.path === selector : group.name === selector
    ));
  });

  const listGroupRoles = Effect.fn(
    "InstallationAccessService.listGroupRoles",
  )(function*() {
    return yield* dependencies.repository.listGroupRoles(dependencies.installationId);
  });

  const isGroupRoleSeedApplied = Effect.fn(
    "InstallationAccessService.isGroupRoleSeedApplied",
  )(function*() {
    return yield* dependencies.repository.isGroupRoleSeedApplied(dependencies.installationId);
  });

  const seedGroupRoles = Effect.fn(
    "InstallationAccessService.seedGroupRoles",
  )(function*(seed: readonly GroupRoleSeedEntry[]) {
    const groups = yield* dependencies.repository.listDirectoryGroups(
      dependencies.installationId,
    );
    const roles: {groupId: string; role: MembershipRole}[] = [];
    const unresolved: string[] = [];
    for (const entry of seed) {
      const matches = groups.filter((group) =>
        entry.selector.startsWith("/")
          ? group.path === entry.selector
          : group.name === entry.selector
      );
      const match = matches.length === 1 ? matches[0] : undefined;
      if (match === undefined) {
        unresolved.push(entry.selector);
      } else {
        roles.push({groupId: match.id, role: entry.role});
      }
    }
    // A partial seed would be stored for good, so store all of it or none.
    if (unresolved.length > 0) {
      const result: GroupRoleSeedResult = {seeded: false, unresolved};
      return result;
    }
    const seeded = yield* dependencies.repository.seedGroupRoles(
      dependencies.installationId,
      roles,
      dependencies.clock.now().toISOString(),
    );
    if (seeded) clearAuthenticationCaches();
    const result: GroupRoleSeedResult = {seeded, unresolved: []};
    return result;
  });

  const setGroupRole = Effect.fn("InstallationAccessService.setGroupRole")(
    function*(principal: Principal, groupId: string, role: MembershipRole | null) {
      if (
        principal.kind !== "human" || principal.authorizedByPrincipalId !== null ||
        principal.membershipRole !== membershipRoles.owner &&
        !(dependencies.organizationDirectoryVisibility === true && isAdministratorRole(principal.membershipRole))
      ) return yield* new AuthorizationDenied({message: "Only installation owners may edit group roles."});
      yield* dependencies.repository.setGroupRole(
        dependencies.installationId,
        groupId,
        role,
        dependencies.clock.now().toISOString(),
        principal.id,
      );
      // Local authentication caches clear immediately; other replicas observe
      // the changed role after their cache entries expire (30 seconds).
      clearAuthenticationCaches();
      return undefined;
    },
  );

  const projectAccess = Effect.fn(
    "InstallationAccessService.projectAccess",
  )(function*(principal: Principal, projectId: string) {
    if (principal.installationId !== dependencies.installationId) return null;
    const record = yield* dependencies.repository.findProjectAccess(
      dependencies.installationId,
      projectId,
      principal.id,
    );
    if (record === null) return null;
    if (
      principal.kind === principalKinds.service &&
      principal.serviceAccountSource === "oidc" &&
      principal.directoryGroupIds !== undefined
    ) {
      const groupIds = new Set(principal.directoryGroupIds);
      const grants = yield* dependencies.repository.listProjectGroupGrants(
        dependencies.installationId,
        projectId,
      );
      return resolveProjectAccess(principal, {
        ...record,
        grantRoles: grants.filter((grant) => groupIds.has(grant.groupId)).map((grant) => grant.role),
      });
    }
    return resolveProjectAccess(principal, record);
  });

  const ownerProjectAccess = Effect.fn(
    "InstallationAccessService.ownerProjectAccess",
  )(function*(ownerPrincipalId: string, projectId: string) {
    const record = yield* dependencies.repository.findProjectAccess(
      dependencies.installationId,
      projectId,
      ownerPrincipalId,
    );
    if (record === null) return null;
    // Members are deactivated, never deleted, so no member row means a
    // service principal rather than a former member.
    return resolveProjectAccess({
      authorizedByPrincipalId: null,
      capabilities: [],
      displayName: ownerPrincipalId,
      id: ownerPrincipalId,
      installationId: dependencies.installationId,
      kind: record.member === null ? principalKinds.service : principalKinds.human,
      membershipRole: record.member?.role ?? membershipRoles.member,
    }, record);
  });

  const reconcileDirectoryMembers = Effect.fn(
    "InstallationAccessService.reconcileDirectoryMembers",
  )(function*(entries: readonly DirectoryMemberEntry[], maximumDeactivations?: number) {
    if (groupRolePolicy === null && dependencies.organizationAdmission === undefined) {
      return yield* Effect.fail(new IdentityConflict({
        message: "Directory sync requires issuer group roles.",
      }));
    }
    if (entries.length === 0) {
      return yield* Effect.fail(new IdentityConflict({
        message: "Directory sync refuses an empty directory.",
      }));
    }
    const desired = new Map<string, DirectoryMemberEntry>();
    for (const entry of entries) {
      if (normalizeMemberEmail(entry.email) !== entry.email) {
        return yield* Effect.fail(new IdentityConflict({
          message: "Directory entries must carry normalized email addresses.",
        }));
      }
      desired.set(entry.email, entry);
    }
    const now = dependencies.clock.now().toISOString();
    if (dependencies.organizationAdmission !== undefined &&
      dependencies.repository.applyOrganizationMemberSnapshot !== undefined) {
      const snapshot = [...desired.values()].map((entry) =>
        Object.assign({id: dependencies.ids.memberId()}, entry)
      );
      const result = yield* dependencies.repository.applyOrganizationMemberSnapshot(
        dependencies.installationId,
        snapshot,
        now,
        maximumDeactivations ?? Number.MAX_SAFE_INTEGER,
      );
      if (result.deactivated + result.reactivated + result.roleChanged > 0) {
        clearAuthenticationCaches();
      }
      return result;
    }
    const members = yield* dependencies.repository.listMembers(
      dependencies.installationId,
    );
    const byEmail = new Map(members.map((member) => [member.email, member]));
    // A deleted or emptied group can take every Admin and Owner role with it,
    // and then nobody could give a role again. When the directory leaves no
    // one able to administer, the current Admins and Owners keep their role.
    const keptAdministrators = new Set(
      [...desired.values()].some((entry) => isAdministratorRole(entry.role))
        ? []
        : members
          .filter((member) =>
            member.status === memberStatuses.active && isAdministratorRole(member.role)
          )
          .map((member) => member.email),
    );
    const removals = members.filter((member) =>
      member.status === memberStatuses.active && !desired.has(member.email) &&
      !keptAdministrators.has(member.email)
    );
    if (maximumDeactivations !== undefined && removals.length > maximumDeactivations) {
      return yield* Effect.fail(new IdentityConflict({
        message: `Directory sync would deactivate ${removals.length} members, above the configured maximum of ${maximumDeactivations}; nothing was changed.`,
      }));
    }
    let admitted = 0;
    let reactivated = 0;
    let roleChanged = 0;
    let unchanged = 0;
    // Apply promotions before demotions so the repository's last-admin guard
    // evaluates against the complete directory snapshot, not an intermediate
    // state where the incoming administrator has not yet been promoted.
    for (const entry of [...desired.values()].toSorted((left, right) =>
      Number(isAdministratorRole(right.role)) - Number(isAdministratorRole(left.role)) ||
      left.email.localeCompare(right.email)
    )) {
      const member = byEmail.get(entry.email);
      if (member === undefined) {
        yield* dependencies.repository.admitMember({
          createdAt: now,
          displayName: entry.displayName,
          email: entry.email,
          id: dependencies.ids.memberId(),
          installationId: dependencies.installationId,
          role: entry.role,
        });
        admitted += 1;
      } else if (member.status !== memberStatuses.active) {
        yield* dependencies.repository.setMemberRole(
          dependencies.installationId,
          member.id,
          entry.role,
          now,
        );
        reactivated += 1;
      } else if (member.role !== entry.role && !keptAdministrators.has(member.email)) {
        yield* dependencies.repository.setMemberRole(
          dependencies.installationId,
          member.id,
          entry.role,
          now,
        );
        roleChanged += 1;
      } else {
        unchanged += 1;
      }
    }
    let deactivated = 0;
    for (const member of members) {
      if (
        member.status !== memberStatuses.active || desired.has(member.email) ||
        keptAdministrators.has(member.email)
      ) {
        continue;
      }
      yield* deactivateRemovedMember(member, now);
      deactivated += 1;
    }
    if (roleChanged + deactivated > 0) clearAuthenticationCaches();
    const reconciliation: DirectoryReconciliation = {
      admitted,
      deactivated,
      reactivated,
      roleChanged,
      unchanged,
    };
    return reconciliation;
  }, Effect.catchTag("IdentityNotFound", () =>
    Effect.fail(new IdentityConflict({
      message: "A member changed while the directory was applied.",
    }))));

  /**
   * Make the member's state match the role its issuer groups grant: admit or
   * restore it, change its role, or deactivate it and refuse admission.
   */
  const isSoleActiveAdministrator = Effect.fn(
    "InstallationAccessService.isSoleActiveAdministrator",
  )(function*(member: InstallationMember) {
    if (
      member.status !== memberStatuses.active ||
      !isAdministratorRole(member.role)
    ) return false;
    const members = yield* dependencies.repository.listMembers(
      dependencies.installationId,
    );
    return !members.some((candidate) =>
      candidate.id !== member.id &&
      candidate.status === memberStatuses.active &&
      isAdministratorRole(candidate.role)
    );
  });

  const applyGroupRole = Effect.fn(
    "InstallationAccessService.applyGroupRole",
  )(function*(
    policy: GroupRolePolicy,
    identity: ExternalIdentity,
    email: string,
    member: InstallationMember | null,
  ) {
    // The configured roles decide until the directory sync has stored them,
    // and always without a directory sync; after that the stored roles do.
    const seeded = yield* dependencies.repository.isGroupRoleSeedApplied(dependencies.installationId);
    const baseAssignments = seeded
      ? yield* dependencies.repository.listGroupRoles(dependencies.installationId)
      : configuredGroupRoleAssignments(policy.seed);
    const assignments = baseAssignments;
    const now = dependencies.clock.now().toISOString();
    // With every stored role removed nobody is turned away for good: the
    // roles are simply not set up.
    if (assignments.length === 0) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "No group has been given a role in the Artifact Server yet.",
      }));
    }
    const role = policy.groupRoots === undefined
      ? groupMembershipRole(assignments, identity.groups)
      : groupMembershipRole(assignments, identity.groups, policy.groupRoots);
    // The last active Admin or Owner keeps their role, so someone can always
    // give the roles out again after a group that held them is lost.
    if (
      member !== null && isAdministratorRole(member.role) &&
      (role === null || !isAdministratorRole(role))
    ) {
      const members = yield* dependencies.repository.listMembers(
        dependencies.installationId,
      );
      const otherAdministrators = members.filter((candidate) =>
        candidate.id !== member.id &&
        candidate.status === memberStatuses.active &&
        isAdministratorRole(candidate.role)
      );
      if (otherAdministrators.length === 0) return member;
    }
    if (role === null) {
      if (member !== null) {
        yield* deactivateRemovedMember(member, now);
        clearAuthenticationCaches();
      }
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "This person is not in a group admitted to the Artifact Server.",
      }));
    }
    if (member !== null) {
      const changed = yield* dependencies.repository.setMemberRole(
        dependencies.installationId,
        member.id,
        role,
        now,
        true,
      );
      if (changed === null) {
        if (yield* isSoleActiveAdministrator(member)) return member;
        return yield* Effect.fail(new IdentityAdmissionDenied({
          message: "This person's current group memberships are not in the stored directory mirror.",
        }));
      }
      clearAuthenticationCaches();
      if (changed.status !== memberStatuses.active) {
        return yield* Effect.fail(new IdentityAdmissionDenied({
          message: "This person is no longer in an admitted group.",
        }));
      }
      return changed;
    }
    // A member deactivated earlier keeps its email, so restore that member
    // rather than admitting a second one under the same address.
    const members = yield* dependencies.repository.listMembers(
      dependencies.installationId,
    );
    const previous = members.find((candidate) => candidate.email === email);
    if (previous !== undefined) {
      const restored = yield* dependencies.repository.setMemberRole(
        dependencies.installationId,
        previous.id,
        role,
        now,
        true,
      );
      if (restored === null) {
        if (yield* isSoleActiveAdministrator(previous)) return previous;
        return yield* Effect.fail(new IdentityAdmissionDenied({
          message: "This person's current group memberships are not in the stored directory mirror.",
        }));
      }
      if (restored.status !== memberStatuses.active) {
        return yield* Effect.fail(new IdentityAdmissionDenied({
          message: "This person is no longer in an admitted group.",
        }));
      }
      return restored;
    }
    const admitted = yield* dependencies.repository.admitMember({
      createdAt: now,
      displayName: identity.displayName,
      email,
      id: dependencies.ids.memberId(),
      installationId: dependencies.installationId,
      role,
    });
    // `role` was resolved from the complete group assignment set above, before
    // admitting the row. Do not create an active member and then discover a
    // missing role during a second lookup.
    return admitted;
  }, Effect.catchTag("IdentityNotFound", () =>
    Effect.fail(new IdentityConflict({
      message: "The member changed while its groups were applied.",
    }))));

  const applyOrganizationAdmission = Effect.fn(
    "InstallationAccessService.applyOrganizationAdmission",
  )(function*(
    identity: ExternalIdentity,
    email: string,
    existingMember: InstallationMember | null,
  ): Effect.fn.Return<
    InstallationMember,
    IdentityAdmissionDenied | IdentityConflict | IdentityNotFound | IdentityRepositoryFailure
  > {
    const expected = dependencies.organizationAdmission;
    if (expected === undefined) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "Organization admission is not configured for this installation.",
      }));
    }
    const organization = identity.organizationMembership;
    if (organization === null || organization === undefined ||
      organization.alias !== expected.alias || organization.id !== expected.id ||
      organization.role === null) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "This person is not a member of the requested organization.",
      }));
    }
    let member = existingMember;
    let previousRole = member?.role;
    let previousStatus = member?.status;
    if (member === null) {
      const previousMembers = yield* dependencies.repository.listMembers(
        dependencies.installationId,
      );
      const previous = previousMembers.find((candidate) => candidate.email === email);
      if (previous !== undefined) {
        previousRole = previous.role;
        previousStatus = previous.status;
        const updateRole = dependencies.repository.setOrganizationMemberRole ??
          dependencies.repository.setMemberRole;
        member = yield* updateRole(
          dependencies.installationId,
          previous.id,
          organization.role,
          dependencies.clock.now().toISOString(),
        );
      } else {
        member = yield* dependencies.repository.admitMember({
          createdAt: dependencies.clock.now().toISOString(),
          displayName: identity.displayName,
          email,
          id: dependencies.ids.memberId(),
          installationId: dependencies.installationId,
          role: organization.role,
        });
      }
    } else {
      const updateRole = dependencies.repository.setOrganizationMemberRole ??
        dependencies.repository.setMemberRole;
      member = yield* updateRole(
        dependencies.installationId,
        member.id,
        organization.role,
        dependencies.clock.now().toISOString(),
      );
    }
    if (member !== null && (member.role !== previousRole || member.status !== previousStatus)) {
      clearAuthenticationCaches();
    }
    if (member === null || member.status !== memberStatuses.active) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "This organization member was manually deactivated or changed during login.",
      }));
    }
    return member;
  }, Effect.catchTag("IdentityNotFound", () =>
    Effect.fail(new IdentityConflict({
      message: "The member changed while organization admission was applied.",
    }))));

  const resolveExternalMember = Effect.fn(
    "InstallationAccessService.resolveExternalMember",
  )(function*(identity: ExternalIdentity) {
    if (identity.serviceAccount === true) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "Service accounts cannot authenticate as members.",
      }));
    }
    if (identity.email === null) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "The login provider did not supply an email address.",
      }));
    }
    if (!identity.emailVerified) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "The login provider did not verify the email address.",
      }));
    }
    const email = yield* normalizeEmail(identity.email);
    let member = yield* dependencies.repository.findActiveMemberByExternalIdentity(
      dependencies.installationId,
      identity.provider,
      identity.subject,
    );
    if (member === null) {
      member = yield* dependencies.repository.findActiveMemberByEmail(
        dependencies.installationId,
        email,
      );
    }
    if (dependencies.organizationAdmission !== undefined) {
      member = yield* applyOrganizationAdmission(identity, email, member);
    } else if (groupRolePolicy !== null) {
      member = yield* applyGroupRole(
        groupRolePolicy,
        identity,
        email,
        member,
      );
    } else if (member === null) {
      const hasMembers = yield* dependencies.repository.hasMembers(
        dependencies.installationId,
      );
      const bootstrapAdministratorEmail = dependencies.bootstrapAdministratorEmail === null
        ? null
        : yield* normalizeEmail(dependencies.bootstrapAdministratorEmail);
      if (
        hasMembers ||
        bootstrapAdministratorEmail === null ||
        email !== bootstrapAdministratorEmail
      ) {
        return yield* Effect.fail(new IdentityAdmissionDenied({
          message: "This person has not been admitted to the Artifact Server.",
        }));
      }
      member = yield* dependencies.repository.admitMember({
        createdAt: dependencies.clock.now().toISOString(),
        displayName: identity.displayName,
        email,
        id: dependencies.ids.memberId(),
        installationId: dependencies.installationId,
        role: membershipRoles.administrator,
      });
    }
    if (member === null) {
      return yield* Effect.fail(new IdentityAdmissionDenied({
        message: "This person has not been admitted to the Artifact Server.",
      }));
    }
    const binding = {
      boundAt: dependencies.clock.now().toISOString(),
      email,
      memberId: member.id,
      provider: identity.provider,
      subject: identity.subject,
    };
    if (identity.identityProvider !== undefined) {
      Object.assign(binding, {identityProvider: identity.identityProvider});
    }
    yield* dependencies.repository.bindExternalIdentity(binding);
    return member;
  });

  const authenticateExternalIdentity = Effect.fn(
    "InstallationAccessService.authenticateExternalIdentity",
  )(function*(identity: ExternalIdentity) {
    if (identity.serviceAccount === true) {
      if (groupRolePolicy === null) {
        return yield* new IdentityAdmissionDenied({
          message: "Service accounts require an installation group role.",
        });
      }
      const baseAssignments = (yield* dependencies.repository.isGroupRoleSeedApplied(
          dependencies.installationId,
        ))
        ? yield* dependencies.repository.listGroupRoles(dependencies.installationId)
        : configuredGroupRoleAssignments(groupRolePolicy.seed);
      const assignments = baseAssignments;
      const role = groupRolePolicy.groupRoots === undefined
        ? groupMembershipRole(assignments, identity.groups)
        : groupMembershipRole(assignments, identity.groups, groupRolePolicy.groupRoots);
      if (role === null) {
        return yield* new IdentityAdmissionDenied({
          message: "This service account is not in a group admitted to the Artifact Server.",
        });
      }
      const storedGroups = yield* dependencies.repository.listDirectoryGroups(
        dependencies.installationId,
      );
      const reported = new Set((identity.groups ?? []).filter((group) =>
        groupRolePolicy.groupRoots === undefined ||
        groupRolePolicy.groupRoots.some((root) =>
          group.startsWith(root) && group.length > root.length
        )
      ));
      const nameCounts = new Map<string, number>();
      for (const group of storedGroups) {
        nameCounts.set(group.name, (nameCounts.get(group.name) ?? 0) + 1);
      }
      const directoryGroupIds = storedGroups.filter((group) =>
        reported.has(group.path) ||
        (nameCounts.get(group.name) === 1 && reported.has(group.name))
      ).map((group) => group.id);
      return {
        authorizedByPrincipalId: null,
        capabilities: [
          ...(identity.provisionProjectsServiceAccount !== true ||
              identity.embedBindingServiceAccount === true
            ? [principalCapabilities.readArtifactResponses]
            : []),
          ...(identity.embedBindingServiceAccount === true
            ? [principalCapabilities.bindArtifactEmbed]
            : []),
          ...(identity.provisionProjectsServiceAccount === true &&
              membershipRoleAtLeast(role, membershipRoles.member)
            ? [principalCapabilities.provisionProjects]
            : []),
        ],
        directoryGroupIds,
        displayName: identity.displayName,
        email: null,
        id: `oidc-service:${identity.provider}:${identity.subject}`,
        installationId: dependencies.installationId,
        kind: principalKinds.service,
        membershipRole: role,
        provisionerGroupPrefixes: identity.provisionerGroupPrefixes ?? [],
        serviceAccountClientId: identity.serviceAccountClientId,
        serviceAccountSource: "oidc" as const,
      };
    }
    return humanPrincipal(yield* resolveExternalMember(identity));
  });

  const authenticateExternalSubject = Effect.fn(
    "InstallationAccessService.authenticateExternalSubject",
  )(function*(provider: string, subject: string) {
    if (groupRolePolicy !== null || dependencies.organizationAdmission !== undefined) return null;
    const member = yield* dependencies.repository.findActiveMemberByExternalIdentity(
      dependencies.installationId,
      provider,
      subject,
    );
    return member === null ? null : humanPrincipal(member);
  });

  const findActiveHumanPrincipal = Effect.fn(
    "InstallationAccessService.findActiveHumanPrincipal",
  )(function*(memberId: string) {
    const member = yield* dependencies.repository.findMember(
      dependencies.installationId,
      memberId,
    );
    return member?.status === memberStatuses.active ? humanPrincipal(member) : null;
  });

  const authenticateSession = Effect.fn(
    "InstallationAccessService.authenticateSession",
  )(function*(credential: Redacted.Redacted) {
    const now = dependencies.clock.now();
    const tokenDigest = dependencies.secrets.digest(Redacted.value(credential));
    const cached = sessionCache?.get(cacheKey(tokenDigest), now.getTime());
    if (cached !== undefined) return cached;
    const session = yield* dependencies.repository.findApplicationSession(
      dependencies.installationId,
      tokenDigest,
      now.toISOString(),
    );
    if (session === null) {
      return yield* Effect.fail(new AuthenticationRequired({
        message: "A valid application session is required.",
      }));
    }
    const authenticated: AuthenticatedApplicationSession = {
      csrfDigest: session.csrfDigest,
      expiresAt: session.expiresAt,
      principal: humanPrincipal(session.member),
    };
    sessionCache?.set(
      cacheKey(tokenDigest),
      authenticated,
      now.getTime(),
      new Date(session.expiresAt).getTime(),
    );
    return authenticated;
  });

  const authenticateManagedApiKey = Effect.fn(
    "InstallationAccessService.authenticateManagedApiKey",
  )(function*(credential: Redacted.Redacted) {
    const raw = Redacted.value(credential);
    const parsed = managedApiKeyCredentialPattern.exec(raw);
    if (parsed === null || parsed[1] === undefined) {
      return yield* invalidApiKey();
    }
    const presentedDigest = dependencies.secrets.digest(raw);
    const requestTime = dependencies.clock.now();
    const cached = apiKeyCache?.get(
      cacheKey(presentedDigest),
      requestTime.getTime(),
    );
    if (cached !== undefined && cached.kind !== principalKinds.human) return cached;
    const key = yield* dependencies.repository.findApiKey(
      dependencies.installationId,
      parsed[1],
    );
    const now = requestTime.toISOString();
    if (
      key === null || key.revokedAt !== null || key.expiresAt <= now ||
      !identitySecretsEqual(presentedDigest, key.secretDigest)
    ) {
      return yield* invalidApiKey();
    }
    const boundMember = key.principalKind === principalKinds.human
      ? yield* dependencies.repository.findMember(
        dependencies.installationId,
        key.principalId,
      )
      : null;
    if (
      key.principalKind === principalKinds.human &&
      (boundMember === null || boundMember.status !== memberStatuses.active)
    ) {
      return yield* invalidApiKey();
    }
    const principal: Principal = {
      authorizedByPrincipalId: key.authorizedByPrincipalId,
      capabilities: key.capabilities,
      displayName: key.name,
      id: key.principalId,
      installationId: key.installationId,
      kind: key.principalKind,
      membershipRole: boundMember?.role ?? membershipRoles.member,
    };
    // Human API keys are reloaded on every request so role changes take effect
    // immediately. Service key entries still use the short local cache.
    if (key.principalKind !== principalKinds.human) apiKeyCache?.set(
      cacheKey(presentedDigest), principal, requestTime.getTime(), new Date(key.expiresAt).getTime(),
    );
    return principal;
  });

  const admitMember = Effect.fn(
    "InstallationAccessService.admitMember",
  )(function*(command: AdmitMemberCommand) {
    yield* requireAdministrator(command.principal, dependencies.installationId);
    const displayName = yield* requireText(command.displayName, "display name");
    const email = yield* normalizeEmail(command.email);
    return yield* dependencies.repository.admitMember({
      createdAt: dependencies.clock.now().toISOString(),
      displayName,
      email,
      id: dependencies.ids.memberId(),
      installationId: dependencies.installationId,
      role: command.role,
    });
  });

  const listMembers = Effect.fn(
    "InstallationAccessService.listMembers",
  )(function*(principal: Principal) {
    if (dependencies.organizationDirectoryVisibility === true) {
      if (principal.installationId !== dependencies.installationId || principal.kind !== "human" || principal.membershipRole === membershipRoles.guest) {
        return yield* new AuthorizationDenied({message: "This organization directory is not available to this principal."});
      }
    } else {
      yield* requireAdministrator(principal, dependencies.installationId);
    }
    return yield* dependencies.repository.listMembers(dependencies.installationId);
  });

  const deactivateMember = Effect.fn(
    "InstallationAccessService.deactivateMember",
  )(function*(principal: Principal, memberId: string) {
    yield* requireAdministrator(principal, dependencies.installationId);
    if (principal.id === memberId) {
      return yield* Effect.fail(new IdentityConflict({
        message: "An administrator cannot deactivate their current member.",
      }));
    }
    if (dependencies.protectBootstrapAdministrator) {
      const member = yield* dependencies.repository.findMember(
        dependencies.installationId,
        memberId,
      );
      const bootstrapAdministratorEmail = dependencies.bootstrapAdministratorEmail === null
        ? null
        : yield* normalizeEmail(dependencies.bootstrapAdministratorEmail);
      if (member?.email === bootstrapAdministratorEmail) {
        return yield* Effect.fail(new IdentityConflict({
          message: "The local-owner administrator cannot be deactivated.",
        }));
      }
    }
    const member = yield* dependencies.repository.deactivateMember(
      dependencies.installationId,
      memberId,
      dependencies.clock.now().toISOString(),
      dependencies.organizationAdmission !== undefined,
    );
    clearAuthenticationCaches();
    return member;
  });

  const reactivateMember = Effect.fn(
    "InstallationAccessService.reactivateMember",
  )(function*(principal: Principal, memberId: string) {
    yield* requireAdministrator(principal, dependencies.installationId);
    if (dependencies.organizationAdmission === undefined ||
      dependencies.repository.reactivateMember === undefined) {
      return yield* Effect.fail(new AuthorizationDenied({
        message: "Member reactivation is available only for organization installations.",
      }));
    }
    const member = yield* dependencies.repository.reactivateMember(
      dependencies.installationId,
      memberId,
    );
    clearAuthenticationCaches();
    return member;
  });

  const issueApiKey = Effect.fn(
    "InstallationAccessService.issueApiKey",
  )(function*(command: IssueApiKeyCommand) {
    yield* requireAdministrator(command.principal, dependencies.installationId);
    const capabilities = yield* normalizeCapabilities(command.capabilities);
    const expiresAt = yield* requireFutureDate(
      command.expiresAt,
      dependencies.clock.now(),
    );
    const name = yield* requireText(command.name, "API key name");
    const id = dependencies.ids.apiKeyId();
    const secret = dependencies.secrets.issue();
    const token = `as_key_${id}_${secret}`;
    const member = command.memberId === undefined
      ? null
      : yield* dependencies.repository.findMember(
        dependencies.installationId,
        command.memberId,
      );
    if (command.memberId !== undefined && member?.status !== memberStatuses.active) {
      return yield* Effect.fail(new IdentityNotFound({
        message: "The active member for this API key does not exist.",
      }));
    }
    if (member?.role === membershipRoles.guest) {
      return yield* Effect.fail(new AuthorizationDenied({
        message: "API keys cannot be issued for guest members.",
      }));
    }
    const key: StoredManagedApiKey = {
      authorizedByPrincipalId: command.principal.id,
      capabilities,
      createdAt: dependencies.clock.now().toISOString(),
      expiresAt,
      id,
      installationId: dependencies.installationId,
      name,
      prefix: token.slice(0, Math.min(token.length, 32)),
      principalId: member?.id ?? `service:${id}`,
      principalKind: member === null ? principalKinds.service : principalKinds.human,
      revokedAt: null,
      rotatedFromId: null,
      secretDigest: dependencies.secrets.digest(token),
    };
    const apiKey = yield* dependencies.repository.createApiKey(key);
    return {apiKey, token};
  });

  const listApiKeys = Effect.fn(
    "InstallationAccessService.listApiKeys",
  )(function*(principal: Principal) {
    yield* requireAdministrator(principal, dependencies.installationId);
    return yield* dependencies.repository.listApiKeys(dependencies.installationId);
  });

  const revokeApiKey = Effect.fn(
    "InstallationAccessService.revokeApiKey",
  )(function*(principal: Principal, keyId: string) {
    yield* requireAdministrator(principal, dependencies.installationId);
    const revoked = yield* dependencies.repository.revokeApiKey(
      dependencies.installationId,
      keyId,
      dependencies.clock.now().toISOString(),
    );
    // Key entries are keyed by presented-credential digest, not key id, so
    // this rare administrative mutation clears the cache instead of indexing.
    apiKeyCache?.clear();
    return revoked;
  });

  const rotateApiKey = Effect.fn(
    "InstallationAccessService.rotateApiKey",
  )(function*(principal: Principal, keyId: string) {
    yield* requireAdministrator(principal, dependencies.installationId);
    const now = dependencies.clock.now();
    const previous = yield* dependencies.repository.findApiKey(
      dependencies.installationId,
      keyId,
    );
    if (previous === null) {
      return yield* Effect.fail(new IdentityNotFound({
        message: "The API key does not exist.",
      }));
    }
    if (previous.principalKind === principalKinds.human) {
      const member = yield* dependencies.repository.findMember(dependencies.installationId, previous.principalId);
      if (member?.role === membershipRoles.guest) {
        return yield* Effect.fail(new AuthorizationDenied({message: "Guest member API keys cannot be rotated."}));
      }
    }
    if (previous.revokedAt !== null || previous.expiresAt <= now.toISOString()) {
      return yield* Effect.fail(new IdentityConflict({
        message: "A revoked or expired API key cannot be rotated.",
      }));
    }
    const replacementId = dependencies.ids.apiKeyId();
    const secret = dependencies.secrets.issue();
    const token = `as_key_${replacementId}_${secret}`;
    const replacement: StoredManagedApiKey = {
      ...previous,
      createdAt: now.toISOString(),
      id: replacementId,
      prefix: token.slice(0, Math.min(token.length, 32)),
      revokedAt: null,
      rotatedFromId: previous.id,
      secretDigest: dependencies.secrets.digest(token),
    };
    const apiKey = yield* dependencies.repository.rotateApiKey(
      dependencies.installationId,
      previous.id,
      replacement,
      now.toISOString(),
    );
    apiKeyCache?.clear();
    return {apiKey, token};
  });

  const revokeSession = Effect.fn(
    "InstallationAccessService.revokeSession",
  )(function*(credential: Redacted.Redacted) {
    const tokenDigest = dependencies.secrets.digest(Redacted.value(credential));
    yield* dependencies.repository.revokeApplicationSession(
      dependencies.installationId,
      tokenDigest,
      dependencies.clock.now().toISOString(),
    );
    sessionCache?.evict(cacheKey(tokenDigest));
  });

  return InstallationAccessService.of({
    admitMember,
    authenticateExternalIdentity,
    authenticateExternalSubject,
    authenticateManagedApiKey,
    authenticateSession,
    completeExternalIdentity,
    deactivateMember,
    reactivateMember,
    findActiveHumanPrincipal,
    issueApiKey,
    issueLocalBrowserLogin,
    loginAsLocalOwner,
    listApiKeys,
    listMembers,
    loginWithLocalBrowserToken,
    reconcileDirectoryMembers,
    applyDirectoryGroups,
    listDirectoryGroups,
    listGroupRoles,
    isGroupRoleSeedApplied,
    setGroupRole,
    seedGroupRoles,
    projectAccess,
    ownerProjectAccess,
    projectSharing: {
      list: (projectId: string) =>
        dependencies.repository.listProjectGroupGrants(dependencies.installationId, projectId),
      put: (grant: ProjectGroupGrant) =>
        dependencies.repository.putProjectGroupGrant(dependencies.installationId, grant),
      remove: (projectId: string, groupId: string) =>
        dependencies.repository.removeProjectGroupGrant(
          dependencies.installationId,
          projectId,
          groupId,
        ),
      setAccessMode: (projectId: string, accessMode: ProjectAccessMode) =>
        dependencies.repository.setProjectAccessMode(
          dependencies.installationId,
          projectId,
          accessMode,
        ),
    },
    revokeApiKey,
    revokeSession,
    rotateApiKey,
  });
}

function humanPrincipal(member: InstallationMember): Principal {
  return {
    authorizedByPrincipalId: null,
    capabilities: [],
    displayName: member.displayName,
    email: member.email,
    id: member.id,
    installationId: member.installationId,
    kind: principalKinds.human,
    membershipRole: member.role,
  };
}

function requireAdministrator(
  principal: Principal,
  installationId: string,
): Effect.Effect<void, AuthorizationDenied> {
  return principal.installationId === installationId &&
      isHumanAdministrator(principal)
    ? Effect.void
    : Effect.fail(new AuthorizationDenied({
      message: "An Artifact Server administrator is required.",
    }));
}

function invalidApiKey(): Effect.Effect<never, AuthenticationRequired> {
  return Effect.fail(new AuthenticationRequired({
    message: "A valid Artifact Server API key is required.",
  }));
}

/** The stored form of one member email, or null when it is not an address. */
export function normalizeMemberEmail(value: string): string | null {
  const normalized = value.trim().toLocaleLowerCase("en-US");
  return normalized.length < 3 || normalized.length > 320 ||
      !normalized.includes("@")
    ? null
    : normalized;
}

const normalizeEmail = Effect.fn("InstallationAccessService.normalizeEmail")(
  function*(value: string): Effect.fn.Return<string, IdentityConflict> {
    const normalized = normalizeMemberEmail(value);
    if (normalized === null) {
      return yield* new IdentityConflict({
        message: "A valid email address is required.",
      });
    }
    return normalized;
  },
);

const requireText = Effect.fn("InstallationAccessService.requireText")(
  function*(value: string, label: string): Effect.fn.Return<string, IdentityConflict> {
    const normalized = value.trim();
    if (normalized.length < 1 || normalized.length > 200) {
      return yield* new IdentityConflict({
        message: `A valid ${label} is required.`,
      });
    }
    return normalized;
  },
);

const requireFutureDate = Effect.fn("InstallationAccessService.requireFutureDate")(
  function*(value: string, now: Date): Effect.fn.Return<string, IdentityConflict> {
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= now.getTime()) {
      return yield* new IdentityConflict({
        message: "The API key expiration must be a future date and time.",
      });
    }
    return parsed.toISOString();
  },
);

const normalizeCapabilities = Effect.fn(
  "InstallationAccessService.normalizeCapabilities",
)(function*(
  capabilities: readonly PrincipalCapability[],
): Effect.fn.Return<readonly PrincipalCapability[], IdentityConflict> {
  const unique = [...new Set(capabilities)];
  if (
    unique.length === 0 ||
    unique.some((capability) => !allCapabilities.has(capability))
  ) {
    return yield* new IdentityConflict({
      message: "At least one recognized API key capability is required.",
    });
  }
  return unique.toSorted();
});

/** Constant-time comparison for identity secrets presented by a caller. */
export function identitySecretsEqual(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  return actualBytes.byteLength === expectedBytes.byteLength &&
    timingSafeEqual(actualBytes, expectedBytes);
}

/** SHA-256 secret digests used by local installation adapters. */
export function digestIdentitySecret(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

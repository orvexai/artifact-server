import type {
  DirectoryGroupApplyResult,
  DirectoryGroupSnapshot,
  StoredDirectoryGroup,
} from "./directory-groups.js";
import type {
  ProjectAccessMode,
  ProjectAccessRecord,
  ProjectGroupGrant,
} from "./project-access.js";
import type {
  ApplicationSession,
  InstallationMember,
  LoginAttempt,
  ManagedApiKey,
  StoredManagedApiKey,
} from "./installation-identity.js";

/** Values persisted when admitting one installation member. */
export interface AdmitMemberRecord {
  readonly createdAt: string;
  readonly displayName: string;
  readonly email: string;
  readonly id: string;
  readonly installationId: string;
  readonly role: InstallationMember["role"];
}

/** Values persisted when binding one external identity to a member. */
export interface BindExternalIdentityRecord {
  readonly boundAt: string;
  readonly email: string;
  readonly memberId: string;
  readonly provider: string;
  readonly subject: string;
}

/** Values persisted when creating one browser application session. */
export interface CreateApplicationSessionRecord {
  readonly createdAt: string;
  readonly csrfDigest: string;
  readonly expiresAt: string;
  readonly id: string;
  readonly installationId: string;
  readonly memberId: string;
  readonly tokenDigest: string;
}

/** Persistent identity operations required by the Node application composition. */
export interface IdentityRepository {
  admitMember(command: AdmitMemberRecord): Promise<InstallationMember>;
  /**
   * Make the stored directory groups match one complete listing in a single
   * transaction: create, rename, or delete groups, and replace the membership
   * of every group whose members were read.
   */
  applyDirectoryGroups(
    installationId: string,
    snapshot: DirectoryGroupSnapshot,
  ): Promise<DirectoryGroupApplyResult>;
  bindExternalIdentity(command: BindExternalIdentityRecord): Promise<void>;
  consumeLoginAttempt(
    stateDigest: string,
    provider: string,
    consumedAt: string,
  ): Promise<LoginAttempt>;
  createApiKey(key: StoredManagedApiKey): Promise<ManagedApiKey>;
  createApplicationSession(
    command: CreateApplicationSessionRecord,
  ): Promise<ApplicationSession>;
  createLoginAttempt(attempt: LoginAttempt): Promise<void>;
  deactivateMember(
    installationId: string,
    memberId: string,
    updatedAt: string,
  ): Promise<InstallationMember>;
  findActiveMemberByEmail(
    installationId: string,
    email: string,
  ): Promise<InstallationMember | null>;
  findActiveMemberByExternalIdentity(
    installationId: string,
    provider: string,
    subject: string,
  ): Promise<InstallationMember | null>;
  findApiKey(
    installationId: string,
    keyId: string,
  ): Promise<StoredManagedApiKey | null>;
  findApplicationSession(
    installationId: string,
    tokenDigest: string,
    requestTime: string,
  ): Promise<ApplicationSession | null>;
  findMember(
    installationId: string,
    memberId: string,
  ): Promise<InstallationMember | null>;
  hasMembers(installationId: string): Promise<boolean>;
  listApiKeys(installationId: string): Promise<readonly ManagedApiKey[]>;
  /** Every stored directory group, ordered by path. */
  listDirectoryGroups(
    installationId: string,
  ): Promise<readonly StoredDirectoryGroup[]>;
  /**
   * Read one project's access mode and the grant roles that reach one member
   * through directory groups, or null when the project does not exist. A
   * group member matches through the member's external identity for the
   * member row's provider, or by verified email only when the member has no
   * identity for that provider.
   */
  findProjectAccess(
    installationId: string,
    projectId: string,
    memberId: string,
  ): Promise<ProjectAccessRecord | null>;
  /** Every group grant on one project, ordered by group id. */
  listProjectGroupGrants(
    installationId: string,
    projectId: string,
  ): Promise<readonly ProjectGroupGrant[]>;
  /** Create or replace one group's grant on one project. */
  putProjectGroupGrant(
    installationId: string,
    grant: ProjectGroupGrant,
  ): Promise<void>;
  /** Remove one group's grant on one project; false when there was none. */
  removeProjectGroupGrant(
    installationId: string,
    projectId: string,
    groupId: string,
  ): Promise<boolean>;
  /** Set one project's access mode; IdentityNotFound when it does not exist. */
  setProjectAccessMode(
    installationId: string,
    projectId: string,
    accessMode: ProjectAccessMode,
  ): Promise<void>;
  listMembers(installationId: string): Promise<readonly InstallationMember[]>;
  revokeApiKey(
    installationId: string,
    keyId: string,
    revokedAt: string,
  ): Promise<ManagedApiKey>;
  revokeApplicationSession(
    installationId: string,
    tokenDigest: string,
    revokedAt: string,
  ): Promise<void>;
  rotateApiKey(
    installationId: string,
    previousKeyId: string,
    replacement: StoredManagedApiKey,
    revokedAt: string,
  ): Promise<ManagedApiKey>;
  /**
   * Give one existing member a role and make it active. Issuer group policy is
   * authoritative here, so this does not keep a last administrator in place.
   */
  setMemberRole(
    installationId: string,
    memberId: string,
    role: InstallationMember["role"],
    updatedAt: string,
  ): Promise<InstallationMember>;
}

/** Atomic first-key operation required by private-team composition roots. */
export interface BootstrapManagedApiKeyRepository extends IdentityRepository {
  /** Return the same key, or create it only while the installation has no identity state. */
  initializeBootstrapApiKey(
    key: StoredManagedApiKey,
  ): Promise<StoredManagedApiKey>;
}

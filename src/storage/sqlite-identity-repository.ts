import { DatabaseSync, type SQLOutputValue } from "node:sqlite";

import { z } from "zod";

import {
  IdentityConflict,
  IdentityNotFound,
  LoginAttemptRejected,
} from "../core/errors.js";
import {
  type ApplicationSession,
  type InstallationMember,
  type LoginAttempt,
  type ManagedApiKey,
  memberStatuses,
  type StoredManagedApiKey,
} from "../core/installation-identity.js";
import {
  isAdministratorRole,
  type MembershipRole,
  membershipRoles,
  principalCapabilities,
  principalKinds,
} from "../core/identity.js";
import {requiredSqliteSchemaVersion} from "./sqlite-schema.js";
import {
  type GroupRoleAssignment,
  groupRoleSeedPrincipalId,
} from "../core/group-role-policy.js";
import {
  type DirectoryGroupApplyResult,
  type DirectoryGroupSnapshot,
  parkedDirectoryGroupPath,
  planDirectoryGroupChanges,
  type StoredDirectoryGroup,
} from "../core/directory-groups.js";
import type {
  ProjectAccessMode,
  ProjectAccessRecord,
  ProjectGroupGrant,
} from "../core/project-access.js";
import type {
  AdmitMemberRecord,
  BindExternalIdentityRecord,
  BootstrapManagedApiKeyRepository,
  CreateApplicationSessionRecord,
} from "../core/identity-ports.js";

const directoryGroupRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  path: z.string(),
});
const projectAccessModeSchema = z.enum(["installation", "restricted"]);
const projectGrantRoleSchema = z.enum(["viewer", "editor", "manager"]);
const projectAccessRowSchema = z.object({
  access_mode: projectAccessModeSchema,
  created_by_member_id: z.string().nullable(),
});
const projectGroupGrantRowSchema = z.object({
  grantedAt: z.string(),
  grantedByPrincipalId: z.string(),
  groupId: z.string(),
  projectId: z.string(),
  role: projectGrantRoleSchema,
});
const accessMemberRowSchema = z.object({
  email: z.string(),
  role: z.enum(Object.values(membershipRoles)),
  status: z.enum(["active", "inactive"]),
});
const storedDirectoryGroupRowSchema = z.object({
  id: z.string(),
  memberCount: z.number().int().nonnegative(),
  name: z.string(),
  path: z.string(),
  syncedAt: z.string(),
});
const membershipRoleSchema = z.enum(Object.values(membershipRoles));
const groupRoleRowSchema = z.object({
  assignedAt: z.string(),
  groupId: z.string(),
  name: z.string(),
  nameUnique: z.coerce.boolean(),
  path: z.string(),
  role: membershipRoleSchema,
});
const memberStatusSchema = z.enum([
  memberStatuses.active,
  memberStatuses.inactive,
]);
const principalKindSchema = z.enum([
  principalKinds.human,
  principalKinds.service,
]);
const principalCapabilitySchema = z.enum([
  principalCapabilities.connectAgents,
  principalCapabilities.createArtifact,
  principalCapabilities.issueContentSession,
  principalCapabilities.manageAnyArtifact,
  principalCapabilities.manageProjects,
  principalCapabilities.publishAnyArtifact,
  principalCapabilities.readArtifacts,
  principalCapabilities.writeComments,
]);
const memberRowSchema = z.object({
  createdAt: z.string(),
  displayName: z.string(),
  email: z.string(),
  id: z.string(),
  installationId: z.string(),
  role: membershipRoleSchema,
  status: memberStatusSchema,
  updatedAt: z.string(),
});
const sessionRowSchema = z.object({
  createdAt: z.string(),
  csrfDigest: z.string(),
  expiresAt: z.string(),
  id: z.string(),
  installationId: z.string(),
  memberCreatedAt: z.string(),
  memberDisplayName: z.string(),
  memberEmail: z.string(),
  memberId: z.string(),
  memberRole: membershipRoleSchema,
  memberStatus: memberStatusSchema,
  memberUpdatedAt: z.string(),
  revokedAt: z.string().nullable(),
  tokenDigest: z.string(),
});
const apiKeyRowSchema = z.object({
  authorizedByPrincipalId: z.string(),
  capabilitiesJson: z.string(),
  createdAt: z.string(),
  expiresAt: z.string(),
  id: z.string(),
  installationId: z.string(),
  name: z.string(),
  prefix: z.string(),
  principalId: z.string(),
  principalKind: principalKindSchema,
  revokedAt: z.string().nullable(),
  rotatedFromId: z.string().nullable(),
  secretDigest: z.string(),
});
const loginAttemptRowSchema = z.object({
  codeVerifier: z.string(),
  createdAt: z.string(),
  expiresAt: z.string(),
  nonce: z.string().nullable(),
  provider: z.string(),
  returnTo: z.string(),
  stateDigest: z.string(),
});
const presenceRowSchema = z.object({present: z.union([z.literal(0), z.literal(1)])});
const countRowSchema = z.object({count: z.number().int().nonnegative()});

/** SQLite persistence for installation membership, sessions, and API keys. */
export class SqliteIdentityRepository implements BootstrapManagedApiKeyRepository {
  readonly #database: DatabaseSync;

  constructor(databasePath: string) {
    this.#database = new DatabaseSync(databasePath, {
      allowExtension: false,
      enableForeignKeyConstraints: true,
      timeout: 5_000,
    });
    this.#database.enableDefensive(true);
    this.#database.exec("PRAGMA journal_mode = WAL;");
    this.#database.exec("PRAGMA synchronous = FULL;");
    this.#migrate();
  }

  close(): void {
    this.#database.close();
  }

  async hasMembers(installationId: string): Promise<boolean> {
    const row = this.#database.prepare(`
      SELECT EXISTS(
        SELECT 1 FROM installation_members WHERE installation_id = ?
      ) AS present
    `).get(installationId);
    return presenceRowSchema.parse(row).present === 1;
  }

  async applyDirectoryGroups(
    installationId: string,
    snapshot: DirectoryGroupSnapshot,
  ): Promise<DirectoryGroupApplyResult> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const rows = this.#database.prepare(
        "SELECT id, name, path FROM directory_groups WHERE installation_id = ?",
      ).all(installationId);
      const stored = new Map(
        z.array(directoryGroupRowSchema).parse(rows).map((row) => [row.id, row]),
      );
      const plan = planDirectoryGroupChanges(stored, snapshot);
      const deleteMembers = this.#database.prepare(
        "DELETE FROM directory_group_members WHERE installation_id = ? AND group_id = ?",
      );
      const deleteGroup = this.#database.prepare(
        "DELETE FROM directory_groups WHERE installation_id = ? AND id = ?",
      );
      for (const id of plan.deletedIds) {
        deleteMembers.run(installationId, id);
        deleteGroup.run(installationId, id);
      }
      // Park moved groups first, so two groups swapping paths never collide.
      const park = this.#database.prepare(
        "UPDATE directory_groups SET path = ? WHERE installation_id = ? AND id = ?",
      );
      for (const id of plan.movedIds) {
        park.run(parkedDirectoryGroupPath(id), installationId, id);
      }
      // synced_at records when the members were last read, so a group whose
      // members could not be read keeps its old time.
      const upsertGroup = this.#database.prepare(`
        INSERT INTO directory_groups (installation_id, id, name, path, synced_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (installation_id, id) DO UPDATE SET
          name = excluded.name, path = excluded.path,
          synced_at = CASE WHEN ? THEN directory_groups.synced_at
            ELSE excluded.synced_at END
      `);
      const insertMember = this.#database.prepare(`
        INSERT INTO directory_group_members (
          installation_id, group_id, subject, email, provider
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
      `);
      for (const group of snapshot.groups) {
        upsertGroup.run(
          installationId,
          group.id,
          group.name,
          group.path,
          snapshot.syncedAt,
          group.members === null ? 1 : 0,
        );
        if (group.members === null) continue;
        deleteMembers.run(installationId, group.id);
        for (const member of group.members) {
          insertMember.run(
            installationId,
            group.id,
            member.subject,
            member.email,
            snapshot.provider,
          );
        }
      }
      this.#database.exec("COMMIT;");
      return plan.result;
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  async listGroupRoles(
    installationId: string,
  ): Promise<readonly GroupRoleAssignment[]> {
    const rows = this.#database.prepare(`
      SELECT r.group_id AS groupId, g.name, g.path, r.role,
        r.assigned_at AS assignedAt,
        (SELECT COUNT(*) FROM directory_groups same
          WHERE same.installation_id = g.installation_id AND same.name = g.name
        ) = 1 AS nameUnique
      FROM directory_group_roles r
      JOIN directory_groups g
        ON g.installation_id = r.installation_id AND g.id = r.group_id
      WHERE r.installation_id = ?
      ORDER BY g.path ASC
    `).all(installationId);
    return z.array(groupRoleRowSchema).parse(rows);
  }

  async setGroupRole(
    installationId: string,
    groupId: string,
    role: MembershipRole | null,
    assignedAt: string,
    assignedByPrincipalId: string,
  ): Promise<void> {
    const exists = this.#database.prepare(`
      SELECT EXISTS(
        SELECT 1 FROM directory_groups WHERE installation_id = ? AND id = ?
      ) AS present
    `).get(installationId, groupId);
    if (presenceRowSchema.parse(exists).present !== 1) {
      throw new IdentityNotFound({message: "The group does not exist."});
    }
    if (role === null) {
      this.#database.prepare(
        "DELETE FROM directory_group_roles WHERE installation_id = ? AND group_id = ?",
      ).run(installationId, groupId);
      return;
    }
    this.#database.prepare(`
      INSERT INTO directory_group_roles (
        installation_id, group_id, role, assigned_at, assigned_by_principal_id
      ) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (installation_id, group_id) DO UPDATE SET
        role = excluded.role, assigned_at = excluded.assigned_at,
        assigned_by_principal_id = excluded.assigned_by_principal_id
    `).run(installationId, groupId, role, assignedAt, assignedByPrincipalId);
  }

  async seedGroupRoles(
    installationId: string,
    roles: readonly {readonly groupId: string; readonly role: MembershipRole}[],
    seededAt: string,
  ): Promise<boolean> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const seeded = this.#database.prepare(`
        INSERT INTO directory_group_role_seeds (installation_id, seeded_at)
        VALUES (?, ?) ON CONFLICT (installation_id) DO NOTHING
      `).run(installationId, seededAt);
      if (seeded.changes === 0) {
        this.#database.exec("COMMIT;");
        return false;
      }
      const insert = this.#database.prepare(`
        INSERT INTO directory_group_roles (
          installation_id, group_id, role, assigned_at, assigned_by_principal_id
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (installation_id, group_id) DO NOTHING
      `);
      for (const {groupId, role} of roles) {
        insert.run(installationId, groupId, role, seededAt, groupRoleSeedPrincipalId);
      }
      this.#database.exec("COMMIT;");
      return true;
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  async listDirectoryGroups(
    installationId: string,
  ): Promise<readonly StoredDirectoryGroup[]> {
    const rows = this.#database.prepare(`
      SELECT g.id, g.name, g.path, g.synced_at AS syncedAt,
        COUNT(m.subject) AS memberCount
      FROM directory_groups g
      LEFT JOIN directory_group_members m
        ON m.installation_id = g.installation_id AND m.group_id = g.id
      WHERE g.installation_id = ?
      GROUP BY g.installation_id, g.id
      ORDER BY g.path ASC
    `).all(installationId);
    return z.array(storedDirectoryGroupRowSchema).parse(rows);
  }

  async findProjectAccess(
    installationId: string,
    projectId: string,
    memberId: string,
  ): Promise<ProjectAccessRecord | null> {
    // One SQLite file is one installation and project ids are its primary
    // key; the artifact repository owns the row's installation label.
    const project = this.#database.prepare(
      "SELECT access_mode, created_by_member_id FROM projects WHERE id = ?",
    ).get(projectId);
    if (project === undefined) return null;
    const projectRow = projectAccessRowSchema.parse(project);
    const accessMode = projectRow.access_mode;
    const isCreator = projectRow.created_by_member_id === memberId;
    const row = this.#database.prepare(
      "SELECT email, role, status FROM installation_members WHERE installation_id = ? AND id = ?",
    ).get(installationId, memberId);
    const member = row === undefined ? null : accessMemberRowSchema.parse(row);
    if (accessMode === "installation" || member === null) {
      return {
        accessMode,
        grantRoles: [],
        isCreator,
        member: member === null ? null : {role: member.role, status: member.status},
      };
    }
    // A group member is this member through its external identity for the
    // row's provider, or by verified email only when the member has none.
    // A row written before providers were recorded matches nobody until the
    // next sync rewrites it.
    const grants = this.#database.prepare(`
      SELECT DISTINCT g.role FROM project_group_grants g
      JOIN directory_group_members d
        ON d.installation_id = g.installation_id AND d.group_id = g.group_id
      WHERE g.installation_id = ? AND g.project_id = ?
        AND d.provider IS NOT NULL AND (
        EXISTS (
          SELECT 1 FROM external_identities e
          WHERE e.member_id = ? AND e.provider = d.provider AND e.subject = d.subject
        ) OR (
          d.email = ? AND NOT EXISTS (
            SELECT 1 FROM external_identities e
            WHERE e.member_id = ? AND e.provider = d.provider
          )
        )
      )
    `).all(installationId, projectId, memberId, member.email, memberId);
    return {
      accessMode,
      grantRoles: z.array(z.object({role: projectGrantRoleSchema})).parse(grants)
        .map((grant) => grant.role),
      isCreator,
      member: {role: member.role, status: member.status},
    };
  }

  async listProjectGroupGrants(
    installationId: string,
    projectId: string,
  ): Promise<readonly ProjectGroupGrant[]> {
    const rows = this.#database.prepare(`
      SELECT project_id AS projectId, group_id AS groupId, role,
        granted_at AS grantedAt, granted_by_principal_id AS grantedByPrincipalId
      FROM project_group_grants
      WHERE installation_id = ? AND project_id = ?
      ORDER BY group_id ASC
    `).all(installationId, projectId);
    return z.array(projectGroupGrantRowSchema).parse(rows);
  }

  async putProjectGroupGrant(
    installationId: string,
    grant: ProjectGroupGrant,
  ): Promise<void> {
    try {
      this.#database.prepare(`
        INSERT INTO project_group_grants (
          installation_id, project_id, group_id, role, granted_at,
          granted_by_principal_id
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (installation_id, project_id, group_id) DO UPDATE SET
          role = excluded.role, granted_at = excluded.granted_at,
          granted_by_principal_id = excluded.granted_by_principal_id
      `).run(
        installationId,
        grant.projectId,
        grant.groupId,
        grant.role,
        grant.grantedAt,
        grant.grantedByPrincipalId,
      );
    } catch (cause) {
      if (isSqliteConstraint(cause)) {
        throw new IdentityNotFound({message: "The project or group does not exist."});
      }
      throw cause;
    }
  }

  async removeProjectGroupGrant(
    installationId: string,
    projectId: string,
    groupId: string,
  ): Promise<boolean> {
    const result = this.#database.prepare(`
      DELETE FROM project_group_grants
      WHERE installation_id = ? AND project_id = ? AND group_id = ?
    `).run(installationId, projectId, groupId);
    return Number(result.changes) > 0;
  }

  async setProjectAccessMode(
    installationId: string,
    projectId: string,
    accessMode: ProjectAccessMode,
  ): Promise<void> {
    const result = this.#database.prepare(
      "UPDATE projects SET access_mode = ? WHERE id = ?",
    ).run(accessMode, projectId);
    if (Number(result.changes) === 0) {
      throw new IdentityNotFound({message: "The project does not exist."});
    }
  }

  async admitMember(command: AdmitMemberRecord): Promise<InstallationMember> {
    try {
      this.#database.prepare(`
        INSERT INTO installation_members (
          id, installation_id, email, display_name, role, status,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        command.id,
        command.installationId,
        command.email,
        command.displayName,
        command.role,
        memberStatuses.active,
        command.createdAt,
        command.createdAt,
      );
    } catch (cause) {
      if (isSqliteConstraint(cause)) {
        throw new IdentityConflict({
          message: "That email is already admitted to this installation.",
        });
      }
      throw cause;
    }
    const member = await this.findMember(command.installationId, command.id);
    if (member === null) throw new Error("The admitted member was not persisted.");
    return member;
  }

  async listMembers(installationId: string): Promise<readonly InstallationMember[]> {
    const rows = this.#database.prepare(`
      SELECT
        id,
        installation_id AS installationId,
        email,
        display_name AS displayName,
        role,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM installation_members
      WHERE installation_id = ?
      ORDER BY created_at ASC, id ASC
    `).all(installationId);
    return rows.map((row) => memberRowSchema.parse(row));
  }

  async findMember(
    installationId: string,
    memberId: string,
  ): Promise<InstallationMember | null> {
    return this.#findMember(installationId, memberId);
  }

  #findMember(
    installationId: string,
    memberId: string,
  ): InstallationMember | null {
    const row = this.#database.prepare(`
      SELECT
        id,
        installation_id AS installationId,
        email,
        display_name AS displayName,
        role,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM installation_members
      WHERE installation_id = ? AND id = ?
    `).get(installationId, memberId);
    return row === undefined ? null : memberRowSchema.parse(row);
  }

  async findActiveMemberByEmail(
    installationId: string,
    email: string,
  ): Promise<InstallationMember | null> {
    const row = this.#database.prepare(`
      SELECT
        id,
        installation_id AS installationId,
        email,
        display_name AS displayName,
        role,
        status,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM installation_members
      WHERE installation_id = ? AND email = ? AND status = ?
    `).get(installationId, email, memberStatuses.active);
    return row === undefined ? null : memberRowSchema.parse(row);
  }

  async findActiveMemberByExternalIdentity(
    installationId: string,
    provider: string,
    subject: string,
  ): Promise<InstallationMember | null> {
    const row = this.#database.prepare(`
      SELECT
        member.id,
        member.installation_id AS installationId,
        member.email,
        member.display_name AS displayName,
        member.role,
        member.status,
        member.created_at AS createdAt,
        member.updated_at AS updatedAt
      FROM external_identities AS external
      JOIN installation_members AS member ON member.id = external.member_id
      WHERE
        member.installation_id = ? AND external.provider = ? AND
        external.subject = ? AND member.status = ?
    `).get(installationId, provider, subject, memberStatuses.active);
    return row === undefined ? null : memberRowSchema.parse(row);
  }

  async bindExternalIdentity(command: BindExternalIdentityRecord): Promise<void> {
    try {
      const result = this.#database.prepare(`
        INSERT INTO external_identities (
          provider, subject, member_id, email, bound_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(provider, subject) DO UPDATE SET
          email = excluded.email,
          bound_at = excluded.bound_at
        WHERE external_identities.member_id = excluded.member_id
      `).run(
        command.provider,
        command.subject,
        command.memberId,
        command.email,
        command.boundAt,
      );
      if (result.changes !== 1) {
        throw new IdentityConflict({
          message: "That external identity is already bound to another member.",
        });
      }
    } catch (cause) {
      if (isSqliteConstraint(cause)) {
        throw new IdentityConflict({
          message: "That external identity is already bound to another member.",
        });
      }
      throw cause;
    }
  }

  async deactivateMember(
    installationId: string,
    memberId: string,
    updatedAt: string,
  ): Promise<InstallationMember> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const existing = this.#findMember(installationId, memberId);
      if (existing === null) {
        throw new IdentityNotFound({message: "The member does not exist."});
      }
      if (
        existing.status === memberStatuses.active &&
        isAdministratorRole(existing.role)
      ) {
        const activeAdministratorCount = countRowSchema.parse(
          this.#database.prepare(`
          SELECT COUNT(*) AS count
          FROM installation_members
          WHERE installation_id = ? AND role IN (?, ?) AND status = ?
          `).get(
            installationId,
            membershipRoles.administrator,
            membershipRoles.owner,
            memberStatuses.active,
          ),
        );
        if (activeAdministratorCount.count <= 1) {
          throw new IdentityConflict({
            message: "The installation must retain one active administrator.",
          });
        }
      }
      this.#database.prepare(`
        UPDATE installation_members
        SET status = ?, updated_at = ?
        WHERE installation_id = ? AND id = ?
      `).run(memberStatuses.inactive, updatedAt, installationId, memberId);
      this.#database.prepare(`
        UPDATE application_sessions
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE installation_id = ? AND member_id = ?
      `).run(updatedAt, installationId, memberId);
      this.#database.prepare(`
        UPDATE managed_api_keys
        SET revoked_at = COALESCE(revoked_at, ?)
        WHERE
          installation_id = ? AND principal_kind = ? AND principal_id = ?
      `).run(updatedAt, installationId, principalKinds.human, memberId);
      this.#database.exec("COMMIT;");
      return {...existing, status: memberStatuses.inactive, updatedAt};
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  async setMemberRole(
    installationId: string,
    memberId: string,
    role: InstallationMember["role"],
    updatedAt: string,
  ): Promise<InstallationMember> {
    const result = this.#database.prepare(`
      UPDATE installation_members
      SET role = ?, status = ?, updated_at = ?
      WHERE installation_id = ? AND id = ?
    `).run(role, memberStatuses.active, updatedAt, installationId, memberId);
    const member = result.changes === 1
      ? this.#findMember(installationId, memberId)
      : null;
    if (member === null) {
      throw new IdentityNotFound({message: "The member does not exist."});
    }
    return member;
  }

  async createApplicationSession(
    command: CreateApplicationSessionRecord,
  ): Promise<ApplicationSession> {
    this.#database.prepare(`
      INSERT INTO application_sessions (
        id, installation_id, member_id, token_digest, csrf_digest,
        created_at, expires_at, revoked_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    `).run(
      command.id,
      command.installationId,
      command.memberId,
      command.tokenDigest,
      command.csrfDigest,
      command.createdAt,
      command.expiresAt,
    );
    const session = await this.findApplicationSession(
      command.installationId,
      command.tokenDigest,
      command.createdAt,
    );
    if (session === null) throw new Error("The application session was not persisted.");
    return session;
  }

  async findApplicationSession(
    installationId: string,
    tokenDigest: string,
    requestTime: string,
  ): Promise<ApplicationSession | null> {
    const row = this.#database.prepare(`
      SELECT
        session.id,
        session.installation_id AS installationId,
        session.token_digest AS tokenDigest,
        session.csrf_digest AS csrfDigest,
        session.created_at AS createdAt,
        session.expires_at AS expiresAt,
        session.revoked_at AS revokedAt,
        member.id AS memberId,
        member.email AS memberEmail,
        member.display_name AS memberDisplayName,
        member.role AS memberRole,
        member.status AS memberStatus,
        member.created_at AS memberCreatedAt,
        member.updated_at AS memberUpdatedAt
      FROM application_sessions AS session
      JOIN installation_members AS member ON member.id = session.member_id
      WHERE
        session.installation_id = ? AND session.token_digest = ? AND
        session.revoked_at IS NULL AND session.expires_at > ? AND
        member.status = ?
    `).get(
      installationId,
      tokenDigest,
      requestTime,
      memberStatuses.active,
    );
    if (row === undefined) return null;
    const parsed = sessionRowSchema.parse(row);
    return {
      createdAt: parsed.createdAt,
      csrfDigest: parsed.csrfDigest,
      expiresAt: parsed.expiresAt,
      id: parsed.id,
      installationId: parsed.installationId,
      member: {
        createdAt: parsed.memberCreatedAt,
        displayName: parsed.memberDisplayName,
        email: parsed.memberEmail,
        id: parsed.memberId,
        installationId: parsed.installationId,
        role: parsed.memberRole,
        status: parsed.memberStatus,
        updatedAt: parsed.memberUpdatedAt,
      },
      revokedAt: parsed.revokedAt,
      tokenDigest: parsed.tokenDigest,
    };
  }

  async revokeApplicationSession(
    installationId: string,
    tokenDigest: string,
    revokedAt: string,
  ): Promise<void> {
    this.#database.prepare(`
      UPDATE application_sessions
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE installation_id = ? AND token_digest = ?
    `).run(revokedAt, installationId, tokenDigest);
  }

  async createApiKey(key: StoredManagedApiKey): Promise<ManagedApiKey> {
    this.#insertApiKey(key);
    return withoutSecretDigest(key);
  }

  async initializeBootstrapApiKey(
    key: StoredManagedApiKey,
  ): Promise<StoredManagedApiKey> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const existing = this.#findApiKey(key.installationId, key.id);
      if (existing !== null) {
        this.#database.exec("COMMIT;");
        return existing;
      }
      const state = countRowSchema.parse(this.#database.prepare(`
        SELECT (
          (SELECT COUNT(*) FROM installation_members WHERE installation_id = ?)
          + (SELECT COUNT(*) FROM managed_api_keys WHERE installation_id = ?)
        ) AS count
      `).get(key.installationId, key.installationId));
      if (state.count > 0) {
        throw new IdentityConflict({
          message:
            "The private-team bootstrap key id cannot change after installation identity exists.",
        });
      }
      this.#insertApiKey(key);
      this.#database.exec("COMMIT;");
      return key;
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  async findApiKey(
    installationId: string,
    keyId: string,
  ): Promise<StoredManagedApiKey | null> {
    return this.#findApiKey(installationId, keyId);
  }

  #findApiKey(
    installationId: string,
    keyId: string,
  ): StoredManagedApiKey | null {
    const row = this.#database.prepare(`
      SELECT
        id,
        installation_id AS installationId,
        name,
        prefix,
        secret_digest AS secretDigest,
        principal_id AS principalId,
        principal_kind AS principalKind,
        capabilities_json AS capabilitiesJson,
        authorized_by_principal_id AS authorizedByPrincipalId,
        created_at AS createdAt,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        rotated_from_id AS rotatedFromId
      FROM managed_api_keys
      WHERE installation_id = ? AND id = ?
    `).get(installationId, keyId);
    return row === undefined ? null : parseApiKey(row);
  }

  async listApiKeys(installationId: string): Promise<readonly ManagedApiKey[]> {
    const rows = this.#database.prepare(`
      SELECT
        id,
        installation_id AS installationId,
        name,
        prefix,
        secret_digest AS secretDigest,
        principal_id AS principalId,
        principal_kind AS principalKind,
        capabilities_json AS capabilitiesJson,
        authorized_by_principal_id AS authorizedByPrincipalId,
        created_at AS createdAt,
        expires_at AS expiresAt,
        revoked_at AS revokedAt,
        rotated_from_id AS rotatedFromId
      FROM managed_api_keys
      WHERE installation_id = ?
      ORDER BY created_at DESC, id DESC
    `).all(installationId);
    return rows.map((row) => withoutSecretDigest(parseApiKey(row)));
  }

  async revokeApiKey(
    installationId: string,
    keyId: string,
    revokedAt: string,
  ): Promise<ManagedApiKey> {
    const result = this.#database.prepare(`
      UPDATE managed_api_keys
      SET revoked_at = COALESCE(revoked_at, ?)
      WHERE installation_id = ? AND id = ?
    `).run(revokedAt, installationId, keyId);
    if (result.changes !== 1) {
      throw new IdentityNotFound({message: "The API key does not exist."});
    }
    const key = await this.findApiKey(installationId, keyId);
    if (key === null) throw new Error("The revoked API key disappeared.");
    return withoutSecretDigest(key);
  }

  async rotateApiKey(
    installationId: string,
    previousKeyId: string,
    replacement: StoredManagedApiKey,
    revokedAt: string,
  ): Promise<ManagedApiKey> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const result = this.#database.prepare(`
        UPDATE managed_api_keys
        SET revoked_at = ?
        WHERE installation_id = ? AND id = ? AND revoked_at IS NULL
      `).run(revokedAt, installationId, previousKeyId);
      if (result.changes !== 1) {
        const existing = this.#findApiKey(installationId, previousKeyId);
        if (existing === null) {
          throw new IdentityNotFound({message: "The API key does not exist."});
        }
        throw new IdentityConflict({
          message: "A revoked API key cannot be rotated.",
        });
      }
      this.#insertApiKey(replacement);
      this.#database.exec("COMMIT;");
      return withoutSecretDigest(replacement);
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  async createLoginAttempt(attempt: LoginAttempt): Promise<void> {
    // `/auth/login` is unauthenticated, so every insert clears the attempts that
    // can no longer be consumed instead of letting the table grow forever.
    this.#database.prepare(`
      DELETE FROM login_attempts WHERE expires_at <= ?
    `).run(attempt.createdAt);
    this.#database.prepare(`
      INSERT INTO login_attempts (
        state_digest, provider, code_verifier, nonce, return_to, created_at,
        expires_at, consumed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    `).run(
      attempt.stateDigest,
      attempt.provider,
      attempt.codeVerifier,
      attempt.nonce,
      attempt.returnTo,
      attempt.createdAt,
      attempt.expiresAt,
    );
  }

  async consumeLoginAttempt(
    stateDigest: string,
    provider: string,
    consumedAt: string,
  ): Promise<LoginAttempt> {
    this.#database.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.#database.prepare(`
        SELECT
          state_digest AS stateDigest,
          provider,
          code_verifier AS codeVerifier,
          nonce,
          return_to AS returnTo,
          created_at AS createdAt,
          expires_at AS expiresAt
        FROM login_attempts
        WHERE
          state_digest = ? AND provider = ? AND consumed_at IS NULL AND
          expires_at > ?
      `).get(stateDigest, provider, consumedAt);
      if (row === undefined) {
        throw new LoginAttemptRejected({
          message: "The browser login attempt is invalid or no longer active.",
        });
      }
      const result = this.#database.prepare(`
        UPDATE login_attempts SET consumed_at = ?
        WHERE state_digest = ? AND consumed_at IS NULL
      `).run(consumedAt, stateDigest);
      if (result.changes !== 1) {
        throw new LoginAttemptRejected({
          message: "The browser login attempt was already used.",
        });
      }
      this.#database.exec("COMMIT;");
      return loginAttemptRowSchema.parse(row);
    } catch (cause) {
      this.#database.exec("ROLLBACK;");
      throw cause;
    }
  }

  #insertApiKey(key: StoredManagedApiKey): void {
    this.#database.prepare(`
      INSERT INTO managed_api_keys (
        id, installation_id, name, prefix, secret_digest, principal_id,
        principal_kind, capabilities_json, authorized_by_principal_id,
        created_at, expires_at, revoked_at, rotated_from_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      key.id,
      key.installationId,
      key.name,
      key.prefix,
      key.secretDigest,
      key.principalId,
      key.principalKind,
      JSON.stringify(key.capabilities),
      key.authorizedByPrincipalId,
      key.createdAt,
      key.expiresAt,
      key.revokedAt,
      key.rotatedFromId,
    );
  }

  #migrate(): void {
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS installation_members (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        email TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL
          CHECK (role IN ('viewer', 'member', 'administrator', 'owner')),
        status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (installation_id, email)
      );

      CREATE TABLE IF NOT EXISTS external_identities (
        provider TEXT NOT NULL,
        subject TEXT NOT NULL,
        member_id TEXT NOT NULL REFERENCES installation_members(id),
        email TEXT NOT NULL,
        bound_at TEXT NOT NULL,
        PRIMARY KEY (provider, subject),
        UNIQUE (provider, member_id)
      );

      CREATE TABLE IF NOT EXISTS application_sessions (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        member_id TEXT NOT NULL REFERENCES installation_members(id),
        token_digest TEXT NOT NULL UNIQUE,
        csrf_digest TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS application_sessions_member_idx
        ON application_sessions(installation_id, member_id);

      CREATE TABLE IF NOT EXISTS managed_api_keys (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        name TEXT NOT NULL,
        prefix TEXT NOT NULL,
        secret_digest TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human', 'service')),
        capabilities_json TEXT NOT NULL,
        authorized_by_principal_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        rotated_from_id TEXT REFERENCES managed_api_keys(id),
        UNIQUE (installation_id, prefix)
      );

      CREATE TABLE IF NOT EXISTS login_attempts (
        state_digest TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        code_verifier TEXT NOT NULL,
        nonce TEXT,
        return_to TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT
      );

      CREATE TABLE IF NOT EXISTS git_history_provider_identity (
        installation_id TEXT PRIMARY KEY,
        provider TEXT NOT NULL CHECK (provider = 'cloudflare-artifacts'),
        account_id TEXT NOT NULL,
        namespace TEXT NOT NULL,
        activated_at TEXT NOT NULL,
        UNIQUE (provider, account_id, namespace)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS directory_groups (
        installation_id TEXT NOT NULL,
        id TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT NOT NULL,
        synced_at TEXT NOT NULL,
        PRIMARY KEY (installation_id, id),
        UNIQUE (installation_id, path)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS directory_group_members (
        installation_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        email TEXT,
        provider TEXT,
        PRIMARY KEY (installation_id, group_id, subject),
        FOREIGN KEY (installation_id, group_id)
          REFERENCES directory_groups(installation_id, id) ON DELETE CASCADE
      ) STRICT;

      CREATE INDEX IF NOT EXISTS directory_group_members_by_subject
        ON directory_group_members (installation_id, subject);

      CREATE TABLE IF NOT EXISTS project_group_grants (
        installation_id TEXT NOT NULL,
        project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        group_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'manager')),
        granted_at TEXT NOT NULL,
        granted_by_principal_id TEXT NOT NULL,
        PRIMARY KEY (installation_id, project_id, group_id),
        FOREIGN KEY (installation_id, group_id)
          REFERENCES directory_groups(installation_id, id) ON DELETE CASCADE
      ) STRICT;

      CREATE TABLE IF NOT EXISTS directory_group_roles (
        installation_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        role TEXT NOT NULL
          CHECK (role IN ('viewer', 'member', 'administrator', 'owner')),
        assigned_at TEXT NOT NULL,
        assigned_by_principal_id TEXT NOT NULL,
        PRIMARY KEY (installation_id, group_id),
        FOREIGN KEY (installation_id, group_id)
          REFERENCES directory_groups(installation_id, id) ON DELETE CASCADE
      ) STRICT;

      CREATE TABLE IF NOT EXISTS directory_group_role_seeds (
        installation_id TEXT PRIMARY KEY,
        seeded_at TEXT NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS project_group_grants_by_group
        ON project_group_grants (installation_id, group_id);

      CREATE TABLE IF NOT EXISTS git_history_project_settings (
        project_id TEXT PRIMARY KEY REFERENCES projects(id),
        installation_id TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
        updated_by_principal_id TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;
    `);
    this.#addLoginAttemptNonceIfMissing();
    this.#addDirectoryGroupMemberProviderIfMissing();
    this.#widenMemberRolesIfNeeded();
    this.#database.exec(`PRAGMA user_version = ${requiredSqliteSchemaVersion};`);
  }

  #addLoginAttemptNonceIfMissing(): void {
    if (this.#tableColumns("login_attempts").includes("nonce")) return;
    this.#database.exec("ALTER TABLE login_attempts ADD COLUMN nonce TEXT");
  }

  #addDirectoryGroupMemberProviderIfMissing(): void {
    if (this.#tableColumns("directory_group_members").includes("provider")) return;
    this.#database.exec("ALTER TABLE directory_group_members ADD COLUMN provider TEXT");
  }

  /**
   * Older files allow only the Admin and Operator roles. SQLite cannot change
   * a CHECK constraint, so copy the members into a table that allows all four,
   * with foreign keys paused so the sessions and identities that point at
   * members keep pointing at the same rows.
   */
  #widenMemberRolesIfNeeded(): void {
    const row = z.object({sql: z.string()}).parse(this.#database.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'installation_members'",
    ).get());
    if (row.sql.includes("'owner'")) return;
    this.#database.exec("PRAGMA foreign_keys = OFF;");
    try {
      this.#database.exec("BEGIN IMMEDIATE;");
      try {
        this.#database.exec(`
          CREATE TABLE installation_members_widened (
            id TEXT PRIMARY KEY,
            installation_id TEXT NOT NULL,
            email TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL
              CHECK (role IN ('viewer', 'member', 'administrator', 'owner')),
            status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (installation_id, email)
          );
          INSERT INTO installation_members_widened (
            id, installation_id, email, display_name, role, status,
            created_at, updated_at
          )
          SELECT id, installation_id, email, display_name, role, status,
            created_at, updated_at
          FROM installation_members;
          DROP TABLE installation_members;
          ALTER TABLE installation_members_widened RENAME TO installation_members;
        `);
        if (this.#database.prepare("PRAGMA foreign_key_check").all().length > 0) {
          throw new Error("Widening member roles broke a member reference.");
        }
        this.#database.exec("COMMIT;");
      } catch (cause) {
        this.#database.exec("ROLLBACK;");
        throw cause;
      }
    } finally {
      this.#database.exec("PRAGMA foreign_keys = ON;");
    }
  }

  #tableColumns(table: "directory_group_members" | "login_attempts"): readonly string[] {
    const rows = this.#database.prepare(`PRAGMA table_info(${table})`).all();
    const columns = z.array(z.object({name: z.string()})).parse(rows);
    return columns.map((column) => column.name);
  }
}

function parseApiKey(
  input: Readonly<Record<string, SQLOutputValue>>,
): StoredManagedApiKey {
  const row = apiKeyRowSchema.parse(input);
  const capabilities = z.array(principalCapabilitySchema).parse(
    JSON.parse(row.capabilitiesJson),
  );
  return {
    authorizedByPrincipalId: row.authorizedByPrincipalId,
    capabilities,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    id: row.id,
    installationId: row.installationId,
    name: row.name,
    prefix: row.prefix,
    principalId: row.principalId,
    principalKind: row.principalKind,
    revokedAt: row.revokedAt,
    rotatedFromId: row.rotatedFromId,
    secretDigest: row.secretDigest,
  };
}

function withoutSecretDigest(key: StoredManagedApiKey): ManagedApiKey {
  const {secretDigest: _secretDigest, ...metadata} = key;
  return metadata;
}

function isSqliteConstraint(cause: unknown): boolean {
  return cause instanceof Error && cause.message.includes("constraint failed");
}

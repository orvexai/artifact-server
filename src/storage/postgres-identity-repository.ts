import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {isSqlError} from "effect/unstable/sql/SqlError";
import {z} from "zod";

import {
  type DirectoryGroupApplyResult,
  type DirectoryGroupSnapshot,
  parkedDirectoryGroupPath,
  planDirectoryGroupChanges,
  type StoredDirectoryGroup,
} from "../core/directory-groups.js";
import {
  IdentityConflict,
  IdentityNotFound,
  LoginAttemptRejected,
} from "../core/errors.js";
import {
  type ProjectAccessMode,
  type ProjectAccessRecord,
  type ProjectGroupGrant,
} from "../core/project-access.js";
import type {
  AdmitMemberRecord,
  BindExternalIdentityRecord,
  BootstrapManagedApiKeyRepository,
  CreateApplicationSessionRecord,
} from "../core/identity-ports.js";
import {
  type ApplicationSession,
  type InstallationMember,
  type LoginAttempt,
  type ManagedApiKey,
  memberStatuses,
  type StoredManagedApiKey,
} from "../core/installation-identity.js";
import {
  membershipRoleAtLeast,
  isAdministratorRole,
  type MembershipRole,
  membershipRoles,
  principalCapabilities,
  principalKinds,
} from "../core/identity.js";
import {
  type GroupRoleAssignment,
  guestGroupPathMatches,
  guestGroupRulePrincipalId,
  groupRoleSeedPrincipalId,
} from "../core/group-role-policy.js";
import type {PostgresDatabase} from "./postgres-database.js";

const membershipRoleSchema = z.enum(Object.values(membershipRoles));
const groupRoleRowSchema = z.object({
  assignedAt: z.string(),
  groupId: z.string(),
  name: z.string(),
  nameUnique: z.coerce.boolean(),
  path: z.string(),
  role: membershipRoleSchema,
  source: z.literal("rule").nullable().optional(),
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
  principalCapabilities.readArtifactResponses,
  principalCapabilities.bindArtifactEmbed,
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
const organizationMemberRowSchema = memberRowSchema.extend({
  manualDeactivation: z.boolean(),
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
const countRowSchema = z.object({count: z.coerce.number().int().nonnegative()});
const directoryGroupRowSchema = z.object({
  firstPath: z.string(),
  id: z.string(),
  name: z.string(),
  path: z.string(),
});
const projectAccessModeSchema = z.enum(["installation", "restricted"]);
const projectGrantRoleSchema = z.enum(["viewer", "editor", "manager"]);
const projectAccessRowSchema = z.object({
  access_mode: projectAccessModeSchema,
  created_by_member_id: z.string().nullable(),
  created_by_principal_id: z.string().nullable(),
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
  role: membershipRoleSchema,
  status: z.enum(["active", "inactive"]),
});
const storedDirectoryGroupRowSchema = z.object({
  hasHigherRoleOverlap: z.boolean(),
  id: z.string(),
  memberCount: z.coerce.number().int().nonnegative(),
  name: z.string(),
  path: z.string(),
  syncedAt: z.string(),
});

/** Installation-scoped Postgres persistence for membership and credentials. */
export class PostgresIdentityRepository implements BootstrapManagedApiKeyRepository {
  readonly #database: PostgresDatabase;
  readonly #installationId: string;

  constructor(database: PostgresDatabase, installationId: string) {
    this.#database = database;
    this.#installationId = installationId;
  }

  async hasMembers(installationId: string): Promise<boolean> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<{present: boolean}>(
        `SELECT EXISTS(
          SELECT 1 FROM installation_members WHERE installation_id = $1
        ) AS present`,
        [installationId],
      );
      return z.object({present: z.boolean()}).parse(rows[0]).present;
    }));
  }

  async applyDirectoryGroups(
    installationId: string,
    snapshot: DirectoryGroupSnapshot,
  ): Promise<DirectoryGroupApplyResult> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        if (snapshot.groups.length === 0 || !snapshot.groups.some((group) =>
          group.members !== null && group.members.length > 0
        )) {
          return yield* Effect.fail(new IdentityConflict({message: "Refusing an empty or memberless directory snapshot."}));
        }
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:directory-groups:${installationId}`}, 0)
        )`;
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        const beforeRoleRows = yield* sql.unsafe<object>(
          `SELECT COUNT(*) FILTER (WHERE status = 'active')::integer AS active,
             COUNT(*) FILTER (WHERE status = 'active' AND role = 'owner')::integer AS owners,
             COUNT(*) FILTER (WHERE status = 'active' AND role IN ('administrator','owner'))::integer AS administrators
           FROM installation_members WHERE installation_id = $1`, [installationId]);
        const beforeRoles = z.object({active: z.number(), owners: z.number(), administrators: z.number()}).parse(beforeRoleRows[0]);
        const beforeMemberRoleRows = yield* sql.unsafe<object>(
          `SELECT id, role FROM installation_members WHERE installation_id = $1`,
          [installationId],
        );
        const beforeMemberRoles = z.array(z.object({id: z.string(), role: membershipRoleSchema}))
          .parse(beforeMemberRoleRows);
        const rows = yield* sql.unsafe<object>(
          "SELECT id, name, path, COALESCE(NULLIF(first_path, ''), path) AS \"firstPath\" FROM directory_groups WHERE installation_id = $1",
          [installationId],
        );
        const stored = new Map(
          z.array(directoryGroupRowSchema).parse(rows).map((row) => [row.id, row]),
        );
        const plan = planDirectoryGroupChanges(stored, snapshot);
        let backfillGuestRoles = false;
        if ((snapshot.guestGroupPrefixes ?? []).length > 0) {
          const backfillRows = yield* sql.unsafe<object>(
            `INSERT INTO directory_group_role_rule_backfills (installation_id, backfilled_at)
             VALUES ($1, $2) ON CONFLICT (installation_id) DO NOTHING
             RETURNING installation_id`,
            [installationId, snapshot.syncedAt],
          );
          backfillGuestRoles = backfillRows.length > 0;
        }
        for (const id of plan.deletedIds) {
          yield* sql`DELETE FROM directory_group_members
            WHERE installation_id = ${installationId} AND group_id = ${id}`;
          yield* sql`DELETE FROM directory_groups
            WHERE installation_id = ${installationId} AND id = ${id}`;
        }
        // Park moved groups first, so two groups swapping paths never collide.
        for (const id of plan.movedIds) {
          yield* sql`UPDATE directory_groups SET path = ${parkedDirectoryGroupPath(id)}
            WHERE installation_id = ${installationId} AND id = ${id}`;
        }
        for (const group of snapshot.groups) {
          // synced_at records when the members were last read, so a group
          // whose members could not be read keeps its old time.
          yield* sql`INSERT INTO directory_groups (
            installation_id, id, name, path, first_path, synced_at
          ) VALUES (
            ${installationId}, ${group.id}, ${group.name}, ${group.path}, ${group.path},
            ${snapshot.syncedAt}
          ) ON CONFLICT (installation_id, id) DO UPDATE SET
            name = EXCLUDED.name, path = EXCLUDED.path,
            synced_at = CASE WHEN ${group.members === null}
              THEN directory_groups.synced_at ELSE EXCLUDED.synced_at END`;
          if (group.members === null) continue;
          yield* sql`DELETE FROM directory_group_members
            WHERE installation_id = ${installationId} AND group_id = ${group.id}`;
          for (const member of group.members) {
            yield* sql`INSERT INTO directory_group_members (
              installation_id, group_id, subject, email, provider
            ) VALUES (
              ${installationId}, ${group.id}, ${member.subject}, ${member.email},
              ${snapshot.provider}
            ) ON CONFLICT DO NOTHING`;
          }
        }
        for (const group of snapshot.groups) {
          if (
            guestGroupPathMatches(stored.get(group.id)?.firstPath || group.path, snapshot.guestGroupPrefixes ?? []) &&
            (backfillGuestRoles || !stored.has(group.id))
          ) {
            yield* sql.unsafe(
              `INSERT INTO directory_group_roles (
                 installation_id, group_id, role, assigned_at, assigned_by_principal_id
               ) VALUES ($1, $2, 'guest', $3, $4)
               ON CONFLICT (installation_id, group_id) DO NOTHING`,
              [installationId, group.id, snapshot.syncedAt, guestGroupRulePrincipalId],
            );
          }
        }
        if (snapshot.recomputeRoles !== false) {
        yield* sql.unsafe(
          `WITH resolved AS (
             SELECT member.id, member.role AS old_role,
               (SELECT assigned.role
                FROM directory_group_members gm
                LEFT JOIN directory_group_roles assigned ON assigned.installation_id = gm.installation_id AND assigned.group_id = gm.group_id
                WHERE gm.installation_id = member.installation_id AND assigned.group_id IS NOT NULL AND (
                  EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
                  OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider))
                ) ORDER BY CASE assigned.role WHEN 'owner' THEN 5 WHEN 'administrator' THEN 4 WHEN 'guest' THEN 3 WHEN 'member' THEN 2 ELSE 1 END DESC LIMIT 1) AS desired_role
             FROM installation_members member WHERE member.installation_id = $1 AND (
               EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id)
               OR EXISTS (SELECT 1 FROM directory_group_members gm WHERE gm.installation_id = member.installation_id AND (
                 EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
                 OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider))
               ))
             )
           ), policy AS (
             SELECT resolved.id,
               CASE WHEN resolved.old_role = 'owner' AND (resolved.desired_role IS NULL OR resolved.desired_role <> 'owner')
                 AND NOT EXISTS (SELECT 1 FROM installation_members other
                   LEFT JOIN resolved projected ON projected.id = other.id
                   WHERE other.installation_id = $1 AND other.status = 'active'
                     AND other.id <> resolved.id
                     AND ((projected.id IS NULL AND other.role = 'owner') OR projected.desired_role = 'owner')) THEN 'owner'
               WHEN resolved.old_role IN ('administrator','owner') AND (resolved.desired_role IS NULL OR resolved.desired_role NOT IN ('administrator','owner'))
                 AND NOT EXISTS (SELECT 1 FROM installation_members other
                   LEFT JOIN resolved projected ON projected.id = other.id
                   WHERE other.installation_id = $1 AND other.status = 'active'
                     AND other.id <> resolved.id
                     AND ((projected.id IS NULL AND other.role IN ('administrator','owner'))
                       OR projected.desired_role IN ('administrator','owner'))) THEN resolved.old_role
               ELSE resolved.desired_role END AS next_role FROM resolved
           )
           UPDATE installation_members member SET role = COALESCE(policy.next_role, member.role),
             status = CASE WHEN policy.next_role IS NULL THEN 'inactive' ELSE member.status END,
             updated_at = $2 FROM policy WHERE member.installation_id = $1 AND member.id = policy.id`,
          [installationId, snapshot.syncedAt],
        );
        yield* sql.unsafe(
          `UPDATE application_sessions SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND member_id IN (SELECT id FROM installation_members WHERE installation_id = $2 AND status = 'inactive')`,
          [snapshot.syncedAt, installationId],
        );
        yield* sql.unsafe(
          `UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND principal_kind = 'human' AND principal_id IN
             (SELECT id FROM installation_members WHERE installation_id = $2 AND status = 'inactive')`,
          [snapshot.syncedAt, installationId],
        );
        yield* sql.unsafe(
          `UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND principal_kind = 'human' AND principal_id IN
             (SELECT id FROM installation_members WHERE installation_id = $2 AND status = 'active' AND role = 'guest')`,
          [snapshot.syncedAt, installationId],
        );
        }
        const afterRoleRows = yield* sql.unsafe<object>(
          `SELECT COUNT(*) FILTER (WHERE status = 'active')::integer AS active,
             COUNT(*) FILTER (WHERE status = 'active' AND role = 'owner')::integer AS owners,
             COUNT(*) FILTER (WHERE status = 'active' AND role IN ('administrator','owner'))::integer AS administrators
           FROM installation_members WHERE installation_id = $1`, [installationId]);
        const afterRoles = z.object({active: z.number(), owners: z.number(), administrators: z.number()}).parse(afterRoleRows[0]);
        if (beforeRoles.owners > 0 && afterRoles.owners === 0) {
          return yield* Effect.fail(new IdentityConflict({message: "Directory sync cannot remove the last active owner."}));
        }
        if (beforeRoles.administrators > 0 && afterRoles.administrators === 0) {
          return yield* Effect.fail(new IdentityConflict({message: "Directory sync cannot remove the last active administrator."}));
        }
        const deactivated = beforeRoles.active - afterRoles.active;
        const threshold = Math.max(snapshot.maxDeactivations ?? 5, Math.ceil(beforeRoles.active * 0.2));
        if (deactivated > threshold) {
          return yield* Effect.fail(new IdentityConflict({message: `Directory sync would deactivate ${deactivated} members, exceeding the configured safety threshold of ${threshold}.`}));
        }
        const afterMemberRoleRows = yield* sql.unsafe<object>(
          `SELECT id, role FROM installation_members WHERE installation_id = $1`,
          [installationId],
        );
        const afterMemberRoles = z.array(z.object({id: z.string(), role: membershipRoleSchema}))
          .parse(afterMemberRoleRows);
        const previousRoles = new Map(beforeMemberRoles.map((member) => [member.id, member.role]));
        const roleChanged = afterMemberRoles.filter((member) =>
          previousRoles.has(member.id) && previousRoles.get(member.id) !== member.role
        ).length;
        return roleChanged === 0 ? plan.result : {...plan.result, roleChanged};
      }));
    }));
  }

  async applyOrganizationMemberSnapshot(
    installationId: string,
    entries: readonly {
      readonly displayName: string;
      readonly email: string;
      readonly id: string;
      readonly role: MembershipRole;
    }[],
    updatedAt: string,
    maximumDeactivations: number,
  ): Promise<{
    readonly admitted: number;
    readonly deactivated: number;
    readonly directoryUsers: number;
    readonly groups: number;
    readonly reactivated: number;
    readonly roleChanged: number;
    readonly skipped: number;
    readonly unchanged: number;
  }> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        if (entries.length === 0) {
          return yield* Effect.fail(new IdentityConflict({
            message: "Directory sync refuses an empty organization snapshot.",
          }));
        }
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:directory-groups:${installationId}`}, 0)
        )`;
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        const installationRows = yield* sql.unsafe<{status: string}>(
          `SELECT status FROM artifact_installations WHERE id = $1 FOR UPDATE`,
          [installationId],
        );
        if (installationRows[0]?.status !== "active") {
          return yield* Effect.fail(new IdentityConflict({
            message: "Directory sync cannot update a suspended organization installation.",
          }));
        }
        const rows = yield* sql.unsafe<object>(
          `SELECT id, installation_id AS "installationId", email,
             display_name AS "displayName", role, status,
             created_at AS "createdAt", updated_at AS "updatedAt",
             manual_deactivation AS "manualDeactivation"
           FROM installation_members WHERE installation_id = $1 FOR UPDATE`,
          [installationId],
        );
        const existing = z.array(organizationMemberRowSchema).parse(rows);
        const byEmail = new Map(existing.map((member) => [member.email, member]));
        const desired = new Map(entries.map((entry) => [entry.email, entry]));
        const willBeActive = (entry: typeof entries[number]) => {
          const current = byEmail.get(entry.email);
          return current === undefined || current.status === memberStatuses.active ||
            !current.manualDeactivation;
        };
        const hasDesiredAdministrator = entries.some((entry) =>
          willBeActive(entry) && isAdministratorRole(entry.role)
        );
        const hasDesiredOwner = entries.some((entry) =>
          willBeActive(entry) && entry.role === membershipRoles.owner
        );
        const protectedIds = new Set(existing.filter((member) =>
          member.status === memberStatuses.active && (
            (!hasDesiredAdministrator && isAdministratorRole(member.role)) ||
            (!hasDesiredOwner && member.role === membershipRoles.owner)
          )
        ).map((member) => member.id));
        const removals = existing.filter((member) =>
          member.status === memberStatuses.active && !desired.has(member.email) &&
          !protectedIds.has(member.id)
        );
        if (removals.length > maximumDeactivations) {
          return yield* Effect.fail(new IdentityConflict({
            message: `Directory sync would deactivate ${removals.length} members, above the configured maximum of ${maximumDeactivations}; nothing was changed.`,
          }));
        }
        let admitted = 0;
        let reactivated = 0;
        let roleChanged = 0;
        let unchanged = 0;
        for (const entry of [...entries].toSorted((left, right) =>
          Number(isAdministratorRole(right.role)) - Number(isAdministratorRole(left.role)) ||
          left.email.localeCompare(right.email)
        )) {
          const member = byEmail.get(entry.email);
          if (member === undefined) {
            yield* sql`INSERT INTO installation_members (
              id, installation_id, email, display_name, role, status, created_at, updated_at
            ) VALUES (
              ${entry.id}, ${installationId}, ${entry.email}, ${entry.displayName},
              ${entry.role}, ${memberStatuses.active}, ${updatedAt}, ${updatedAt}
            )`;
            admitted += 1;
          } else if (member.status !== memberStatuses.active && member.manualDeactivation) {
            unchanged += 1;
          } else if (member.status !== memberStatuses.active) {
            yield* sql`UPDATE installation_members SET display_name = ${entry.displayName},
              role = ${entry.role}, status = ${memberStatuses.active}, updated_at = ${updatedAt}
              WHERE installation_id = ${installationId} AND id = ${member.id}`;
            reactivated += 1;
          } else if (member.role !== entry.role && !protectedIds.has(member.id)) {
            yield* sql`UPDATE installation_members SET display_name = ${entry.displayName},
              role = ${entry.role}, updated_at = ${updatedAt}
              WHERE installation_id = ${installationId} AND id = ${member.id}`;
            roleChanged += 1;
          } else {
            unchanged += 1;
          }
        }
        for (const member of removals) {
          yield* sql`UPDATE installation_members SET status = ${memberStatuses.inactive},
            updated_at = ${updatedAt}
            WHERE installation_id = ${installationId} AND id = ${member.id}`;
          yield* sql`UPDATE application_sessions SET revoked_at = COALESCE(revoked_at, ${updatedAt})
            WHERE installation_id = ${installationId} AND member_id = ${member.id}`;
          yield* sql`UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, ${updatedAt})
            WHERE installation_id = ${installationId} AND principal_kind = ${principalKinds.human}
              AND principal_id = ${member.id}`;
        }
        return {
          admitted,
          deactivated: removals.length,
          directoryUsers: entries.length,
          groups: 0,
          reactivated,
          roleChanged,
          skipped: 0,
          unchanged,
        };
      }));
    }));
  }

  async setOrganizationMemberRole(
    installationId: string,
    memberId: string,
    role: InstallationMember["role"],
    updatedAt: string,
  ): Promise<InstallationMember | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        const rows = yield* sql.unsafe<object>(
          `SELECT id, installation_id AS "installationId", email,
             display_name AS "displayName", role, status,
             created_at AS "createdAt", updated_at AS "updatedAt",
             manual_deactivation AS "manualDeactivation"
           FROM installation_members WHERE installation_id = $1 AND id = $2 FOR UPDATE`,
          [installationId, memberId],
        );
        const row = rows[0];
        if (row === undefined) {
          return yield* new IdentityNotFound({message: "The member does not exist."});
        }
        const {manualDeactivation, ...existing} = organizationMemberRowSchema.parse(row);
        if (manualDeactivation) return null;
        let effectiveRole = role;
        if (isAdministratorRole(existing.role) && !isAdministratorRole(role)) {
          const otherRows = yield* sql.unsafe<object>(
            `SELECT COUNT(*)::integer AS count FROM installation_members
             WHERE installation_id = $1 AND id <> $2 AND status = $3
               AND role IN ($4, $5)`,
            [installationId, memberId, memberStatuses.active,
              membershipRoles.administrator, membershipRoles.owner],
          );
          if (countRowSchema.parse(otherRows[0]).count === 0) effectiveRole = existing.role;
        }
        if (existing.role === membershipRoles.owner && role !== membershipRoles.owner) {
          const otherOwnerRows = yield* sql.unsafe<object>(
            `SELECT COUNT(*)::integer AS count FROM installation_members
             WHERE installation_id = $1 AND id <> $2 AND status = $3 AND role = $4`,
            [installationId, memberId, memberStatuses.active, membershipRoles.owner],
          );
          if (countRowSchema.parse(otherOwnerRows[0]).count === 0) {
            effectiveRole = membershipRoles.owner;
          }
        }
        yield* sql`UPDATE installation_members SET role = ${effectiveRole},
          status = ${memberStatuses.active}, updated_at = ${updatedAt}
          WHERE installation_id = ${installationId} AND id = ${memberId}`;
        return {...existing, role: effectiveRole, status: memberStatuses.active, updatedAt};
      }));
    }));
  }

  async listDirectoryGroups(
    installationId: string,
  ): Promise<readonly StoredDirectoryGroup[]> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `SELECT g.id, g.name, g.path, g.synced_at AS "syncedAt",
          COUNT(m.subject) AS "memberCount",
          EXISTS (
            SELECT 1 FROM directory_group_roles guest_role
            JOIN directory_group_members guest_member
              ON guest_member.installation_id = guest_role.installation_id
              AND guest_member.group_id = guest_role.group_id
            JOIN directory_group_members other_member
              ON other_member.installation_id = guest_member.installation_id
              AND other_member.provider = guest_member.provider
              AND other_member.subject = guest_member.subject
              AND other_member.group_id <> guest_member.group_id
            JOIN directory_group_roles other_role
              ON other_role.installation_id = other_member.installation_id
              AND other_role.group_id = other_member.group_id
            WHERE guest_role.installation_id = g.installation_id
              AND guest_role.group_id = g.id AND guest_role.role = 'guest'
              AND other_role.role IN ('viewer', 'member', 'administrator', 'owner')
          ) AS "hasHigherRoleOverlap"
         FROM directory_groups g
         LEFT JOIN directory_group_members m
           ON m.installation_id = g.installation_id AND m.group_id = g.id
         WHERE g.installation_id = $1
         GROUP BY g.installation_id, g.id
         ORDER BY g.path ASC`,
        [installationId],
      );
      return z.array(storedDirectoryGroupRowSchema).parse(rows);
    }));
  }

  async findProjectAccess(
    installationId: string,
    projectId: string,
    memberId: string,
  ): Promise<ProjectAccessRecord | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const projects = yield* sql.unsafe<object>(
        "SELECT access_mode, created_by_member_id, created_by_principal_id FROM projects WHERE installation_id = $1 AND id = $2",
        [installationId, projectId],
      );
      if (projects.length === 0) return null;
      const project = projectAccessRowSchema.parse(projects[0]);
      const accessMode = project.access_mode;
      const isCreator = project.created_by_member_id === memberId ||
        project.created_by_principal_id === memberId;
      const members = yield* sql.unsafe<object>(
        `SELECT email, role, status FROM installation_members
         WHERE installation_id = $1 AND id = $2`,
        [installationId, memberId],
      );
      const member = members.length === 0
        ? null
        : accessMemberRowSchema.parse(members[0]);
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
      // A row written before providers were recorded matches nobody until
      // the next sync rewrites it.
      const grants = yield* sql.unsafe<object>(
        `SELECT DISTINCT g.role FROM project_group_grants g
         JOIN directory_group_members d
           ON d.installation_id = g.installation_id AND d.group_id = g.group_id
         WHERE g.installation_id = $1 AND g.project_id = $2
           AND d.provider IS NOT NULL AND (
           EXISTS (
             SELECT 1 FROM external_identities e
             WHERE e.installation_id = d.installation_id AND e.member_id = $3
               AND e.provider = d.provider AND e.subject = d.subject
           ) OR (
             d.email = $4 AND NOT EXISTS (
               SELECT 1 FROM external_identities e
               WHERE e.installation_id = d.installation_id AND e.member_id = $3
                 AND e.provider = d.provider
             )
           )
         )`,
        [installationId, projectId, memberId, member.email],
      );
      return {
        accessMode,
        grantRoles: z.array(z.object({role: projectGrantRoleSchema})).parse(grants)
          .map((row) => row.role),
        isCreator,
        member: {role: member.role, status: member.status},
      };
    }));
  }

  async listProjectGroupGrants(
    installationId: string,
    projectId: string,
  ): Promise<readonly ProjectGroupGrant[]> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `SELECT project_id AS "projectId", group_id AS "groupId", role,
          granted_at AS "grantedAt", granted_by_principal_id AS "grantedByPrincipalId"
         FROM project_group_grants
         WHERE installation_id = $1 AND project_id = $2
         ORDER BY group_id ASC`,
        [installationId, projectId],
      );
      return z.array(projectGroupGrantRowSchema).parse(rows);
    }));
  }

  async putProjectGroupGrant(
    installationId: string,
    grant: ProjectGroupGrant,
  ): Promise<void> {
    this.#assertInstallationScope(installationId);
    try {
      await this.#database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`INSERT INTO project_group_grants (
          installation_id, project_id, group_id, role, granted_at,
          granted_by_principal_id
        ) VALUES (
          ${installationId}, ${grant.projectId}, ${grant.groupId}, ${grant.role},
          ${grant.grantedAt}, ${grant.grantedByPrincipalId}
        ) ON CONFLICT (installation_id, project_id, group_id) DO UPDATE SET
          role = EXCLUDED.role, granted_at = EXCLUDED.granted_at,
          granted_by_principal_id = EXCLUDED.granted_by_principal_id`;
      }));
    } catch (cause) {
      if (isConstraintFailure(cause)) {
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
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `DELETE FROM project_group_grants
         WHERE installation_id = $1 AND project_id = $2 AND group_id = $3
         RETURNING group_id`,
        [installationId, projectId, groupId],
      );
      return rows.length > 0;
    }));
  }

  async listGroupRoles(
    installationId: string,
  ): Promise<readonly GroupRoleAssignment[]> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `SELECT r.group_id AS "groupId", g.name, g.path, r.role,
          r.assigned_at AS "assignedAt",
          CASE WHEN r.assigned_by_principal_id = $2 THEN 'rule' ELSE NULL END AS source,
          (SELECT COUNT(*) FROM directory_groups same
            WHERE same.installation_id = g.installation_id AND same.name = g.name
          ) = 1 AS "nameUnique"
         FROM directory_group_roles r
         JOIN directory_groups g
           ON g.installation_id = r.installation_id AND g.id = r.group_id
         WHERE r.installation_id = $1
         ORDER BY g.path ASC`,
        [installationId, guestGroupRulePrincipalId],
      );
      return z.array(groupRoleRowSchema).parse(rows).map(({source, ...assignment}) => {
        if (source === "rule") Object.assign(assignment, {source});
        return assignment;
      });
    }));
  }

  async setGroupRole(
    installationId: string,
    groupId: string,
    role: MembershipRole | null,
    assignedAt: string,
    assignedByPrincipalId: string,
  ): Promise<void> {
    this.#assertInstallationScope(installationId);
    const found = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        yield* sql.unsafe(
          `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
          [`artifact-server:directory-groups:${installationId}`],
        );
        yield* sql.unsafe(
          `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
          [`artifact-server:member-policy:${installationId}`],
        );
        const groups = yield* sql.unsafe<object>(
          `SELECT id FROM directory_groups
           WHERE installation_id = $1 AND id = $2 FOR SHARE`,
          [installationId, groupId],
        );
        if (groups.length === 0) return false;
        const currentRows = yield* sql.unsafe<object>(
          `SELECT role FROM directory_group_roles WHERE installation_id = $1 AND group_id = $2 FOR UPDATE`,
          [installationId, groupId],
        );
        const currentRole = currentRows[0] === undefined ? null
          : z.object({role: membershipRoleSchema}).parse(currentRows[0]).role;
        if (currentRole === membershipRoles.owner && role !== membershipRoles.owner) {
          const ownerRows = yield* sql.unsafe<object>(
            `SELECT COUNT(*)::integer AS count FROM installation_members member
             WHERE member.installation_id = $1 AND member.status = 'active' AND member.role = 'owner'
               AND EXISTS (SELECT 1 FROM directory_group_members gm WHERE gm.installation_id = member.installation_id
                 AND gm.group_id = $2 AND (EXISTS (SELECT 1 FROM external_identities identity
                   WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
                   OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity
                     WHERE identity.member_id = member.id AND identity.provider = gm.provider))))
               AND NOT EXISTS (SELECT 1 FROM directory_group_members gm JOIN directory_group_roles other_role
                 ON other_role.installation_id = gm.installation_id AND other_role.group_id = gm.group_id
                 WHERE gm.installation_id = member.installation_id AND gm.group_id <> $2 AND other_role.role = 'owner'
                   AND (EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id
                     AND identity.provider = gm.provider AND identity.subject = gm.subject)
                     OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity
                       WHERE identity.member_id = member.id AND identity.provider = gm.provider))))`,
            [installationId, groupId],
          );
          if (z.object({count: z.number()}).parse(ownerRows[0]).count > 0) {
            return yield* Effect.fail(new IdentityConflict({message: "The last active owner cannot be removed."}));
          }
        }
        if (role === null) {
          yield* sql.unsafe(
            `DELETE FROM directory_group_roles
             WHERE installation_id = $1 AND group_id = $2`,
            [installationId, groupId],
          );
        } else {
          yield* sql.unsafe(
            `INSERT INTO directory_group_roles (
               installation_id, group_id, role, assigned_at, assigned_by_principal_id
             ) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (installation_id, group_id) DO UPDATE SET
               role = EXCLUDED.role, assigned_at = EXCLUDED.assigned_at,
               assigned_by_principal_id = EXCLUDED.assigned_by_principal_id`,
            [installationId, groupId, role, assignedAt, assignedByPrincipalId],
          );
        }
        const beforeRows = yield* sql.unsafe<object>(
          `SELECT COUNT(*) FILTER (WHERE status = 'active')::integer AS active,
             COUNT(*) FILTER (WHERE status = 'active' AND role = 'owner')::integer AS owners,
             COUNT(*) FILTER (WHERE status = 'active' AND role IN ('administrator','owner'))::integer AS administrators
           FROM installation_members WHERE installation_id = $1`, [installationId]);
        const before = z.object({active: z.number(), owners: z.number(), administrators: z.number()}).parse(beforeRows[0]);
        const result = yield* sql.unsafe<object>(
          `WITH resolved AS (
             SELECT member.id, member.role AS old_role,
               (SELECT assigned.role FROM directory_group_members gm
                JOIN directory_group_roles assigned ON assigned.installation_id = gm.installation_id AND assigned.group_id = gm.group_id
                WHERE gm.installation_id = member.installation_id AND (
                  EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
                  OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider))
                ) ORDER BY CASE assigned.role WHEN 'owner' THEN 5 WHEN 'administrator' THEN 4 WHEN 'guest' THEN 3 WHEN 'member' THEN 2 ELSE 1 END DESC LIMIT 1) AS desired_role
             FROM installation_members member WHERE member.installation_id = $1 AND EXISTS (
               SELECT 1 FROM directory_group_members gm WHERE gm.installation_id = member.installation_id AND gm.group_id = $2 AND (
                 EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
                 OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider))
               )
             )
           ), policy AS (
             SELECT resolved.id, resolved.desired_role,
               CASE WHEN resolved.old_role = 'owner' AND (resolved.desired_role IS NULL OR resolved.desired_role <> 'owner')
                 AND NOT EXISTS (SELECT 1 FROM installation_members other WHERE other.installation_id = $1 AND other.status = 'active' AND other.role = 'owner' AND other.id <> resolved.id) THEN 'owner'
               WHEN resolved.old_role IN ('administrator','owner') AND (resolved.desired_role IS NULL OR resolved.desired_role NOT IN ('administrator','owner'))
                 AND NOT EXISTS (SELECT 1 FROM installation_members other WHERE other.installation_id = $1 AND other.status = 'active' AND other.role IN ('administrator','owner') AND other.id <> resolved.id) THEN resolved.old_role
               ELSE resolved.desired_role END AS next_role FROM resolved
           )
           UPDATE installation_members member SET role = COALESCE(policy.next_role, member.role),
             status = CASE WHEN policy.next_role IS NULL THEN 'inactive' ELSE member.status END,
             updated_at = $3 FROM policy WHERE member.installation_id = $1 AND member.id = policy.id`,
          [installationId, groupId, assignedAt]);
        void result;
        yield* sql.unsafe(
          `UPDATE application_sessions SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND member_id IN (SELECT id FROM installation_members WHERE installation_id = $2 AND status = 'inactive')`, [assignedAt, installationId]);
        yield* sql.unsafe(
          `UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND principal_kind = 'human' AND principal_id IN
             (SELECT id FROM installation_members WHERE installation_id = $2 AND status = 'inactive')`, [assignedAt, installationId]);
        yield* sql.unsafe(
          `UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND principal_kind = 'human' AND principal_id IN (
             SELECT member.id FROM installation_members member JOIN directory_group_members gm ON gm.installation_id = member.installation_id
             WHERE member.installation_id = $2 AND member.status = 'active' AND member.role = 'guest' AND gm.group_id = $3 AND (
               EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider AND identity.subject = gm.subject)
               OR (gm.email = member.email AND NOT EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = member.id AND identity.provider = gm.provider)))
           )`, [assignedAt, installationId, groupId]);
        const afterRows = yield* sql.unsafe<object>(
          `SELECT COUNT(*) FILTER (WHERE status = 'active' AND role = 'owner')::integer AS owners,
             COUNT(*) FILTER (WHERE status = 'active' AND role IN ('administrator','owner'))::integer AS administrators
           FROM installation_members WHERE installation_id = $1`, [installationId]);
        const after = z.object({owners: z.number(), administrators: z.number()}).parse(afterRows[0]);
        if (before.owners > 0 && after.owners === 0) {
          return yield* Effect.fail(new IdentityConflict({message: "The last active owner cannot be removed by this group role change."}));
        }
        if (before.administrators > 0 && after.administrators === 0) {
          return yield* Effect.fail(new IdentityConflict({message: "The last active administrator cannot be demoted by this group role change."}));
        }
        return true;
      }));
    }));
    if (!found) throw new IdentityNotFound({message: "The group does not exist."});
  }

  async isGroupRoleSeedApplied(installationId: string): Promise<boolean> {
    this.#assertInstallationScope(installationId);
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.unsafe<object>(
        `SELECT installation_id FROM directory_group_role_seeds
         WHERE installation_id = $1`,
        [installationId],
      );
    }));
    return rows.length > 0;
  }

  async seedGroupRoles(
    installationId: string,
    roles: readonly {readonly groupId: string; readonly role: MembershipRole}[],
    seededAt: string,
  ): Promise<boolean> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        const seeded = yield* sql.unsafe<object>(
          `INSERT INTO directory_group_role_seeds (installation_id, seeded_at)
           VALUES ($1, $2) ON CONFLICT (installation_id) DO NOTHING
           RETURNING installation_id`,
          [installationId, seededAt],
        );
        if (seeded.length === 0) return false;
        for (const {groupId, role} of roles) {
          yield* sql.unsafe(
            `INSERT INTO directory_group_roles (
               installation_id, group_id, role, assigned_at, assigned_by_principal_id
             ) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (installation_id, group_id) DO UPDATE SET
               role = EXCLUDED.role, assigned_at = EXCLUDED.assigned_at,
               assigned_by_principal_id = EXCLUDED.assigned_by_principal_id
             WHERE directory_group_roles.assigned_by_principal_id = $6`,
            [installationId, groupId, role, seededAt, groupRoleSeedPrincipalId, guestGroupRulePrincipalId],
          );
        }
        return true;
      }));
    }));
  }

  async setProjectAccessMode(
    installationId: string,
    projectId: string,
    accessMode: ProjectAccessMode,
  ): Promise<void> {
    this.#assertInstallationScope(installationId);
    const updated = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.unsafe<object>(
        `UPDATE projects SET access_mode = $3
         WHERE installation_id = $1 AND id = $2 RETURNING id`,
        [installationId, projectId, accessMode],
      );
    }));
    if (updated.length === 0) {
      throw new IdentityNotFound({message: "The project does not exist."});
    }
  }

  async admitMember(command: AdmitMemberRecord): Promise<InstallationMember> {
    this.#assertInstallationScope(command.installationId);
    try {
      await this.#database.run(Effect.gen({self: this}, function*() {
        const sql = yield* SqlClient;
        yield* sql`INSERT INTO installation_members (
          installation_id, id, email, display_name, role, status,
          created_at, updated_at
        ) VALUES (
          ${command.installationId}, ${command.id}, ${command.email},
          ${command.displayName}, ${command.role}, ${memberStatuses.active},
          ${command.createdAt}, ${command.createdAt}
        )`;
      }));
    } catch (cause) {
      if (isConstraintFailure(cause)) {
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
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(memberSelect(
        "WHERE installation_id = $1 ORDER BY created_at ASC, id ASC",
      ), [installationId]);
      return z.array(memberRowSchema).parse(rows);
    }));
  }

  async findMember(
    installationId: string,
    memberId: string,
  ): Promise<InstallationMember | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(this.#findMember(installationId, memberId, false));
  }

  async findActiveMemberByEmail(
    installationId: string,
    email: string,
  ): Promise<InstallationMember | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(memberSelect(
        "WHERE installation_id = $1 AND email = $2 AND status = $3",
      ), [installationId, email, memberStatuses.active]);
      return memberRowSchema.nullable().parse(rows[0] ?? null);
    }));
  }

  async findActiveMemberByExternalIdentity(
    installationId: string,
    provider: string,
    subject: string,
  ): Promise<InstallationMember | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `SELECT member.id, member.installation_id AS "installationId",
          member.email, member.display_name AS "displayName", member.role,
          member.status, member.created_at AS "createdAt",
          member.updated_at AS "updatedAt"
         FROM external_identities AS external
         JOIN installation_members AS member
           ON member.installation_id = external.installation_id
          AND member.id = external.member_id
         WHERE member.installation_id = $1 AND external.provider = $2
           AND external.subject = $3 AND member.status = $4`,
        [installationId, provider, subject, memberStatuses.active],
      );
      return memberRowSchema.nullable().parse(rows[0] ?? null);
    }));
  }

  async bindExternalIdentity(command: BindExternalIdentityRecord): Promise<void> {
    const installationId = this.#installationId;
    const existingMember = await this.findMember(
      installationId,
      command.memberId,
    );
    if (existingMember === null) {
      throw new IdentityConflict({message: "The member does not exist."});
    }
    try {
      const changed = await this.#database.run(Effect.gen({self: this}, function*() {
        const sql = yield* SqlClient;
        return yield* sql`INSERT INTO external_identities (
          installation_id, provider, subject, member_id, email, bound_at,
          identity_provider
        ) VALUES (
          ${installationId}, ${command.provider}, ${command.subject},
          ${command.memberId}, ${command.email}, ${command.boundAt},
          ${command.identityProvider ?? null}
        )
        ON CONFLICT (installation_id, provider, subject) DO UPDATE SET
          email = EXCLUDED.email,
          bound_at = EXCLUDED.bound_at,
          identity_provider = COALESCE(EXCLUDED.identity_provider, external_identities.identity_provider)
        WHERE external_identities.member_id = EXCLUDED.member_id
        RETURNING member_id`;
      }));
      if (changed.length !== 1) throw identityBindingConflict();
    } catch (cause) {
      if (cause instanceof IdentityConflict) throw cause;
      if (isConstraintFailure(cause)) throw identityBindingConflict();
      throw cause;
    }
  }

  async deactivateMember(
    installationId: string,
    memberId: string,
    updatedAt: string,
    manualDeactivation = false,
  ): Promise<InstallationMember> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        const existing = yield* this.#findMember(installationId, memberId, true);
        if (existing === null) {
          return yield* new IdentityNotFound({message: "The member does not exist."});
        }
        if (
          existing.status === memberStatuses.active &&
          isAdministratorRole(existing.role)
        ) {
          const rows = yield* sql.unsafe<object>(
            `SELECT COUNT(*) AS count FROM installation_members
             WHERE installation_id = $1 AND role IN ($2, $3) AND status = $4`,
            [
              installationId,
              membershipRoles.administrator,
              membershipRoles.owner,
              memberStatuses.active,
            ],
          );
          if (countRowSchema.parse(rows[0]).count <= 1) {
            return yield* new IdentityConflict({
              message: "The installation must retain one active administrator.",
            });
          }
        }
        if (manualDeactivation) {
          yield* sql`UPDATE installation_members
            SET status = ${memberStatuses.inactive}, manual_deactivation = TRUE,
              updated_at = ${updatedAt}
            WHERE installation_id = ${installationId} AND id = ${memberId}`;
        } else {
          // Keep the Orvex/flag-off path compatible with databases that have
          // not applied the optional org-tenancy migration.
          yield* sql`UPDATE installation_members
            SET status = ${memberStatuses.inactive}, updated_at = ${updatedAt}
            WHERE installation_id = ${installationId} AND id = ${memberId}`;
        }
        yield* sql`UPDATE application_sessions
          SET revoked_at = COALESCE(revoked_at, ${updatedAt})
          WHERE installation_id = ${installationId} AND member_id = ${memberId}`;
        yield* sql`UPDATE managed_api_keys
          SET revoked_at = COALESCE(revoked_at, ${updatedAt})
          WHERE installation_id = ${installationId}
            AND principal_kind = ${principalKinds.human}
            AND principal_id = ${memberId}`;
        return {...existing, status: memberStatuses.inactive, updatedAt};
      }));
    }));
  }

  async reactivateMember(
    installationId: string,
    memberId: string,
    updatedAt: string,
  ): Promise<InstallationMember> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        const rows = yield* sql.unsafe<object>(
          `UPDATE installation_members SET status = 'active', manual_deactivation = FALSE,
             updated_at = $3
           WHERE installation_id = $1 AND id = $2 AND suspended_by_org_at IS NULL
           RETURNING id, installation_id AS "installationId", email,
             display_name AS "displayName", role, status,
             created_at AS "createdAt", updated_at AS "updatedAt"`,
          [installationId, memberId, updatedAt],
        );
        if (rows[0] !== undefined) return memberRowSchema.parse(rows[0]);
        const existing = yield* sql.unsafe<{id: string}>(
          `SELECT id FROM installation_members WHERE installation_id = $1 AND id = $2`,
          [installationId, memberId],
        );
        if (existing.length === 0) return yield* new IdentityNotFound({message: "The member does not exist."});
        return yield* new IdentityConflict({message: "A member suspended with the organization can only be restored by org resume."});
      }));
    }));
  }

  async setMemberRole(
    installationId: string,
    memberId: string,
    role: InstallationMember["role"],
    updatedAt: string,
    recomputeFromCurrentGroups = false,
  ): Promise<InstallationMember | null> {
    this.#assertInstallationScope(installationId);
    const member = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        // Serialize sign-in role resolution with group sync and group-role edits.
        if (recomputeFromCurrentGroups) yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:directory-groups:${installationId}`}, 0)
        )`;
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${installationId}`}, 0)
        )`;
        let effectiveRole = role;
        let priorAdministratorCount: number | null = null;
        let originalMember: InstallationMember | null = null;
        if (recomputeFromCurrentGroups) {
          const members = yield* sql.unsafe<object>(
            `SELECT id, installation_id AS "installationId", email, display_name AS "displayName",
               role, status, created_at AS "createdAt", updated_at AS "updatedAt"
             FROM installation_members WHERE installation_id = $1 AND id = $2`, [installationId, memberId]);
          if (members[0] === undefined) {
            return yield* new IdentityNotFound({message: "The member does not exist."});
          }
          const current = memberRowSchema.parse(members[0]);
          originalMember = current;
          if (current.status === memberStatuses.active && isAdministratorRole(current.role)) {
            const priorCounts = yield* sql.unsafe<object>(
              `SELECT COUNT(*)::integer AS count FROM installation_members
               WHERE installation_id = $1 AND status = 'active' AND role IN ('administrator','owner')`, [installationId]);
            priorAdministratorCount = z.object({count: z.number()}).parse(priorCounts[0]).count;
          }
          const email = current.email;
          const roleRows = yield* sql.unsafe<object>(
            `SELECT DISTINCT assigned.role FROM directory_group_members gm JOIN directory_group_roles assigned
              ON assigned.installation_id = gm.installation_id AND assigned.group_id = gm.group_id
             WHERE gm.installation_id = $1 AND (
               EXISTS (SELECT 1 FROM external_identities identity WHERE identity.member_id = $2
                 AND identity.provider = gm.provider AND identity.subject = gm.subject)
               OR (gm.email = $3 AND NOT EXISTS (SELECT 1 FROM external_identities identity
                 WHERE identity.member_id = $2 AND identity.provider = gm.provider))
             )`, [installationId, memberId, email]);
          const assigned = z.array(z.object({role: membershipRoleSchema})).parse(roleRows).map(({role: value}) => value);
          const seedRows = yield* sql.unsafe<object>(`SELECT installation_id FROM directory_group_role_seeds WHERE installation_id = $1`, [installationId]);
          if (seedRows.length > 0 && assigned.length === 0) {
            return null;
          }
          effectiveRole = assigned.includes(membershipRoles.owner) ? membershipRoles.owner
            : assigned.includes(membershipRoles.administrator) ? membershipRoles.administrator
            : assigned.includes(membershipRoles.guest) ? membershipRoles.guest
            : assigned.reduce<MembershipRole | null>((best, value) =>
              best === null || !membershipRoleAtLeast(best, value) ? value : best, null) ?? role;
          if (current.status === memberStatuses.active && isAdministratorRole(current.role) && !isAdministratorRole(effectiveRole)) {
            const counts = yield* sql.unsafe<object>(
              `SELECT COUNT(*)::integer AS count FROM installation_members
               WHERE installation_id = $1 AND status = 'active' AND role IN ('administrator','owner')`, [installationId]);
            if (z.object({count: z.number()}).parse(counts[0]).count <= 1) effectiveRole = current.role;
          }
        }
        let rows = yield* sql.unsafe<object>(
          `UPDATE installation_members
           SET role = $1, status = $2, updated_at = $3
           WHERE installation_id = $4 AND id = $5
           RETURNING id, installation_id AS "installationId", email,
             display_name AS "displayName", role, status,
             created_at AS "createdAt", updated_at AS "updatedAt"`,
          [effectiveRole, memberStatuses.active, updatedAt, installationId, memberId],
        );
        if (rows.length > 0 && priorAdministratorCount !== null && priorAdministratorCount > 0 && !isAdministratorRole(effectiveRole)) {
          const afterCounts = yield* sql.unsafe<object>(
            `SELECT COUNT(*)::integer AS count FROM installation_members
             WHERE installation_id = $1 AND status = 'active' AND role IN ('administrator','owner')`, [installationId]);
          if (z.object({count: z.number()}).parse(afterCounts[0]).count === 0) {
            rows = yield* sql.unsafe<object>(
              `UPDATE installation_members SET role = $1, status = $2, updated_at = $3
               WHERE installation_id = $4 AND id = $5
               RETURNING id, installation_id AS "installationId", email,
                 display_name AS "displayName", role, status,
                 created_at AS "createdAt", updated_at AS "updatedAt"`,
              [originalMember?.role, originalMember?.status, updatedAt, installationId, memberId]);
          }
        }
        if (rows.length > 0 && effectiveRole === membershipRoles.guest) yield* sql.unsafe(
          `UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, $1)
           WHERE installation_id = $2 AND principal_kind = 'human' AND principal_id = $3`,
          [updatedAt, installationId, memberId],
        );
        return memberRowSchema.nullable().parse(rows[0] ?? null);
      }));
    }));
    if (member === null && !recomputeFromCurrentGroups) {
      throw new IdentityNotFound({message: "The member does not exist."});
    }
    return member;
  }

  async createApplicationSession(
    command: CreateApplicationSessionRecord,
  ): Promise<ApplicationSession> {
    this.#assertInstallationScope(command.installationId);
    await this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      yield* sql`INSERT INTO application_sessions (
        installation_id, id, member_id, token_digest, csrf_digest,
        created_at, expires_at, revoked_at
      ) VALUES (
        ${command.installationId}, ${command.id}, ${command.memberId},
        ${command.tokenDigest}, ${command.csrfDigest}, ${command.createdAt},
        ${command.expiresAt}, NULL
      )`;
    }));
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
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(
        `SELECT session.id, session.installation_id AS "installationId",
          session.token_digest AS "tokenDigest",
          session.csrf_digest AS "csrfDigest",
          session.created_at AS "createdAt", session.expires_at AS "expiresAt",
          session.revoked_at AS "revokedAt", member.id AS "memberId",
          member.email AS "memberEmail",
          member.display_name AS "memberDisplayName",
          member.role AS "memberRole", member.status AS "memberStatus",
          member.created_at AS "memberCreatedAt",
          member.updated_at AS "memberUpdatedAt"
         FROM application_sessions AS session
         JOIN installation_members AS member
           ON member.installation_id = session.installation_id
          AND member.id = session.member_id
         WHERE session.installation_id = $1 AND session.token_digest = $2
           AND session.revoked_at IS NULL AND session.expires_at > $3
           AND member.status = $4`,
        [installationId, tokenDigest, requestTime, memberStatuses.active],
      );
      const parsed = sessionRowSchema.nullable().parse(rows[0] ?? null);
      if (parsed === null) return null;
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
    }));
  }

  async revokeApplicationSession(
    installationId: string,
    tokenDigest: string,
    revokedAt: string,
  ): Promise<void> {
    this.#assertInstallationScope(installationId);
    await this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      yield* sql`UPDATE application_sessions
        SET revoked_at = COALESCE(revoked_at, ${revokedAt})
        WHERE installation_id = ${installationId}
          AND token_digest = ${tokenDigest}`;
    }));
  }

  async createApiKey(key: StoredManagedApiKey): Promise<ManagedApiKey> {
    this.#assertInstallationScope(key.installationId);
    await this.#database.run(this.#insertApiKey(key));
    return withoutSecretDigest(key);
  }

  async initializeBootstrapApiKey(
    key: StoredManagedApiKey,
  ): Promise<StoredManagedApiKey> {
    this.#assertInstallationScope(key.installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        yield* sql.unsafe(
          "SELECT pg_advisory_xact_lock(hashtext($1))",
          [`artifact-server-bootstrap:${key.installationId}`],
        );
        const existing = yield* this.#findApiKey(
          key.installationId,
          key.id,
          false,
        );
        if (existing !== null) return existing;
        const rows = yield* sql.unsafe<{count: number}>(`
          SELECT (
            (SELECT COUNT(*) FROM installation_members WHERE installation_id = $1)
            + (SELECT COUNT(*) FROM managed_api_keys WHERE installation_id = $1)
          ) AS count
        `, [key.installationId]);
        if (countRowSchema.parse(rows[0]).count > 0) {
          return yield* new IdentityConflict({
            message:
              "The private-team bootstrap key id cannot change after installation identity exists.",
          });
        }
        yield* this.#insertApiKey(key);
        return key;
      }));
    }));
  }

  async findApiKey(
    installationId: string,
    keyId: string,
  ): Promise<StoredManagedApiKey | null> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(this.#findApiKey(installationId, keyId, false));
  }

  async listApiKeys(installationId: string): Promise<readonly ManagedApiKey[]> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(apiKeySelect(
        "WHERE installation_id = $1 ORDER BY created_at DESC, id DESC",
      ), [installationId]);
      return z.array(apiKeyRowSchema).parse(rows).map((row) =>
        withoutSecretDigest(parseApiKey(row))
      );
    }));
  }

  async revokeApiKey(
    installationId: string,
    keyId: string,
    revokedAt: string,
  ): Promise<ManagedApiKey> {
    this.#assertInstallationScope(installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        const updated = yield* sql`UPDATE managed_api_keys
          SET revoked_at = COALESCE(revoked_at, ${revokedAt})
          WHERE installation_id = ${installationId} AND id = ${keyId}
          RETURNING id`;
        if (updated.length !== 1) {
          return yield* new IdentityNotFound({
            message: "The API key does not exist.",
          });
        }
        const key = yield* this.#findApiKey(installationId, keyId, false);
        if (key === null) throw new Error("The revoked API key disappeared.");
        return withoutSecretDigest(key);
      }));
    }));
  }

  async rotateApiKey(
    installationId: string,
    previousKeyId: string,
    replacement: StoredManagedApiKey,
    revokedAt: string,
  ): Promise<ManagedApiKey> {
    this.#assertInstallationScope(installationId);
    this.#assertInstallationScope(replacement.installationId);
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        const existing = yield* this.#findApiKey(
          installationId,
          previousKeyId,
          true,
        );
        if (existing === null) {
          return yield* new IdentityNotFound({
            message: "The API key does not exist.",
          });
        }
        if (existing.revokedAt !== null) {
          return yield* new IdentityConflict({
            message: "A revoked API key cannot be rotated.",
          });
        }
        yield* sql`UPDATE managed_api_keys SET revoked_at = ${revokedAt}
          WHERE installation_id = ${installationId} AND id = ${previousKeyId}`;
        yield* this.#insertApiKey(replacement);
        return withoutSecretDigest(replacement);
      }));
    }));
  }

  async createLoginAttempt(attempt: LoginAttempt): Promise<void> {
    const installationId = this.#installationId;
    await this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      // `/auth/login` is unauthenticated, so every insert clears the attempts
      // that can no longer be consumed instead of growing the table forever.
      yield* sql`DELETE FROM login_attempts
        WHERE installation_id = ${installationId}
          AND expires_at <= ${attempt.createdAt}`;
      yield* sql`INSERT INTO login_attempts (
        installation_id, state_digest, provider, code_verifier, nonce, return_to,
        created_at, expires_at, consumed_at
      ) VALUES (
        ${installationId}, ${attempt.stateDigest}, ${attempt.provider},
        ${attempt.codeVerifier}, ${attempt.nonce}, ${attempt.returnTo},
        ${attempt.createdAt}, ${attempt.expiresAt}, NULL
      )`;
    }));
  }

  async consumeLoginAttempt(
    stateDigest: string,
    provider: string,
    consumedAt: string,
  ): Promise<LoginAttempt> {
    const installationId = this.#installationId;
    return this.#database.run(Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen({self: this}, function*() {
        const rows = yield* sql.unsafe<object>(
          `SELECT state_digest AS "stateDigest", provider,
            code_verifier AS "codeVerifier", nonce, return_to AS "returnTo",
            created_at AS "createdAt", expires_at AS "expiresAt"
           FROM login_attempts
           WHERE installation_id = $1 AND state_digest = $2 AND provider = $3
             AND consumed_at IS NULL AND expires_at > $4
           FOR UPDATE`,
          [installationId, stateDigest, provider, consumedAt],
        );
        const attempt = loginAttemptRowSchema.nullable().parse(rows[0] ?? null);
        if (attempt === null) {
          return yield* new LoginAttemptRejected({
            message: "The browser login attempt is invalid or no longer active.",
          });
        }
        const updated = yield* sql`UPDATE login_attempts
          SET consumed_at = ${consumedAt}
          WHERE installation_id = ${installationId}
            AND state_digest = ${stateDigest}
            AND consumed_at IS NULL
          RETURNING state_digest`;
        if (updated.length !== 1) {
          return yield* new LoginAttemptRejected({
            message: "The browser login attempt was already used.",
          });
        }
        return attempt;
      }));
    }));
  }

  #assertInstallationScope(installationId: string): void {
    if (installationId !== this.#installationId) {
      throw new IdentityNotFound({
        message: "The installation identity does not exist in this repository.",
      });
    }
  }

  #findMember(
    installationId: string,
    memberId: string,
    lock: boolean,
  ): Effect.Effect<InstallationMember | null, unknown, SqlClient> {
    return Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(memberSelect(
        `WHERE installation_id = $1 AND id = $2 ${lock ? "FOR UPDATE" : ""}`,
      ), [installationId, memberId]);
      return memberRowSchema.nullable().parse(rows[0] ?? null);
    });
  }

  #findApiKey(
    installationId: string,
    keyId: string,
    lock: boolean,
  ): Effect.Effect<StoredManagedApiKey | null, unknown, SqlClient> {
    return Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql.unsafe<object>(apiKeySelect(
        `WHERE installation_id = $1 AND id = $2 ${lock ? "FOR UPDATE" : ""}`,
      ), [installationId, keyId]);
      const row = apiKeyRowSchema.nullable().parse(rows[0] ?? null);
      return row === null ? null : parseApiKey(row);
    });
  }

  #insertApiKey(
    key: StoredManagedApiKey,
  ): Effect.Effect<void, unknown, SqlClient> {
    return Effect.gen({self: this}, function*() {
      const sql = yield* SqlClient;
      yield* sql`INSERT INTO managed_api_keys (
        installation_id, id, name, prefix, secret_digest, principal_id,
        principal_kind, capabilities_json, authorized_by_principal_id,
        created_at, expires_at, revoked_at, rotated_from_id
      ) VALUES (
        ${key.installationId}, ${key.id}, ${key.name}, ${key.prefix},
        ${key.secretDigest}, ${key.principalId}, ${key.principalKind},
        ${JSON.stringify(key.capabilities)}, ${key.authorizedByPrincipalId},
        ${key.createdAt}, ${key.expiresAt}, ${key.revokedAt},
        ${key.rotatedFromId}
      )`;
    });
  }
}

function memberSelect(suffix: string): string {
  return `SELECT id, installation_id AS "installationId", email,
    display_name AS "displayName", role, status,
    created_at AS "createdAt", updated_at AS "updatedAt"
    FROM installation_members ${suffix}`;
}

function apiKeySelect(suffix: string): string {
  return `SELECT id, installation_id AS "installationId", name, prefix,
    secret_digest AS "secretDigest", principal_id AS "principalId",
    principal_kind AS "principalKind",
    capabilities_json AS "capabilitiesJson",
    authorized_by_principal_id AS "authorizedByPrincipalId",
    created_at AS "createdAt", expires_at AS "expiresAt",
    revoked_at AS "revokedAt", rotated_from_id AS "rotatedFromId"
    FROM managed_api_keys ${suffix}`;
}

function parseApiKey(
  row: z.infer<typeof apiKeyRowSchema>,
): StoredManagedApiKey {
  const decoded: unknown = JSON.parse(row.capabilitiesJson);
  const capabilities = z.array(principalCapabilitySchema).parse(decoded);
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

function identityBindingConflict(): IdentityConflict {
  return new IdentityConflict({
    message: "That external identity is already bound to another member.",
  });
}

function isConstraintFailure(cause: unknown): boolean {
  if (isSqlError(cause)) {
    return cause.reason._tag === "ConstraintError" ||
      cause.reason._tag === "UniqueViolation";
  }
  return false;
}

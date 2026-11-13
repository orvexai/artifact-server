import {randomBytes, randomUUID} from "node:crypto";

import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {z} from "zod";

import type {PostgresDatabase} from "../storage/postgres-database.js";

const organizationGroupRootSchema = z.string().regex(/^\/(?:[^/\s]+\/)+$/u);
const admissionPolicySchema = z.object({
  groupRoots: z.array(organizationGroupRootSchema).default([]),
  guestGroupPrefixes: z.array(z.string().min(1)).optional(),
  seed: z.array(z.object({
    role: z.enum(["administrator", "guest", "member", "owner", "viewer"]),
    selector: z.string().min(1),
  }).strict()),
}).strict().superRefine((policy, context) => {
  for (const [index, entry] of policy.seed.entries()) {
    if (!entry.selector.startsWith("/") || !policy.groupRoots.some((root) =>
      entry.selector.startsWith(root) && entry.selector.length > root.length
    )) {
      context.addIssue({
        code: "custom",
        message: "Admission selectors must be full group paths beneath one of the organization's groupRoots.",
        path: ["seed", index, "selector"],
      });
    }
  }
});
export type OrganizationAdmissionPolicy = z.infer<typeof admissionPolicySchema>;

export function parseOrganizationAdmissionPolicyJson(
  input: string,
): OrganizationAdmissionPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new Error("Organization admission policy must be valid JSON.");
  }
  return admissionPolicySchema.parse(parsed);
}

const organizationSlugSchema = z.string().regex(
  /^[a-z0-9][a-z0-9-]{1,38}$/u,
  "Organization slugs must match ^[a-z0-9][a-z0-9-]{1,38}$.",
);
const organizationNameSchema = z.string().trim().min(1).max(160);
const keycloakOrganizationIdSchema = z.string().uuid();
const reservedOrganizationSlugs = new Set(["orvex"]);
const organizationSchema = z.object({
  displayName: z.string(),
  id: z.string(),
  keycloakId: z.string().nullable(),
  admissionPolicy: admissionPolicySchema.nullable(),
  routeId: z.string().regex(/^[a-z0-9]{8}$/u),
  slug: organizationSlugSchema,
  status: z.enum(["active", "suspended"]),
}).strict();

/** An installation's configured organization route and display metadata. */
export interface OrganizationRecord {
  readonly admissionPolicy: z.infer<typeof admissionPolicySchema> | null;
  readonly displayName: string;
  readonly id: string;
  readonly keycloakId: string | null;
  readonly routeId: string;
  readonly slug: string;
  readonly status: "active" | "suspended";
}

export type KeycloakOrganizationSyncResult =
  | {readonly kind: "synced"; readonly organization: OrganizationRecord}
  | {readonly kind: "conflict"; readonly alias: string; readonly reason: string};

export function isReservedOrganizationSlug(slug: string): boolean {
  return reservedOrganizationSlugs.has(slug);
}

/** Report active registrations absent from the latest complete Keycloak list. */
export function findDisappearedOrganizations(
  registered: readonly OrganizationRecord[],
  observed: readonly {readonly id: string}[],
): readonly {readonly alias: string; readonly id: string}[] {
  const observedIds = new Set(observed.map(({id}) => id));
  return registered.flatMap((organization) =>
    organization.slug !== "orvex" && organization.status === "active" &&
      organization.keycloakId !== null && !observedIds.has(organization.keycloakId)
      ? [{alias: organization.slug, id: organization.keycloakId}]
      : [],
  );
}

/** Registry operations over the shared Postgres pool. */
export class OrganizationRegistry {
  readonly #database: PostgresDatabase;

  constructor(database: PostgresDatabase) {
    this.#database = database;
  }

  async find(slug: string): Promise<OrganizationRecord | null> {
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`SELECT id, slug, display_name AS "displayName",
        route_id AS "routeId", status, admission_policy AS "admissionPolicy",
        keycloak_organization_id AS "keycloakId"
        FROM artifact_installations
        WHERE slug = ${slug}`;
      return rows[0] ?? null;
    }));
    return row === null ? null : organizationSchema.parse(row);
  }

  async findByKeycloakId(keycloakId: string): Promise<OrganizationRecord | null> {
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`SELECT id, slug, display_name AS "displayName",
        route_id AS "routeId", status, admission_policy AS "admissionPolicy",
        keycloak_organization_id AS "keycloakId"
        FROM artifact_installations
        WHERE keycloak_organization_id = ${keycloakId}`;
      return rows[0] ?? null;
    }));
    return row === null ? null : organizationSchema.parse(row);
  }

  async list(): Promise<readonly OrganizationRecord[]> {
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`SELECT id, slug, display_name AS "displayName",
        route_id AS "routeId", status, admission_policy AS "admissionPolicy",
        keycloak_organization_id AS "keycloakId"
        FROM artifact_installations
        WHERE slug IS NOT NULL ORDER BY slug`;
    }));
    const organizations: OrganizationRecord[] = [];
    for (const [index, row] of rows.entries()) {
      const parsed = organizationSchema.safeParse(row);
      if (parsed.success) {
        organizations.push(parsed.data);
      } else {
        // A corrupt registry entry must not take unrelated organizations
        // offline, while retaining an operator-visible diagnostic.
        console.error("Skipping invalid organization registry row", {
          index,
          issues: parsed.error.issues.map(({path, code}) => ({code, path})),
        });
      }
    }
    return organizations;
  }

  async ensureOrvex(installationId: string): Promise<OrganizationRecord> {
    const existing = await this.find("orvex");
    if (existing !== null) {
      if (existing.id !== installationId) {
        throw new Error("The configured installation does not match org slug 'orvex'.");
      }
      return existing;
    }
    const routeId = randomRouteId();
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id
      ) VALUES (
        ${installationId}, ${new Date().toISOString()}, 'orvex', 'Orvex', 'active', ${routeId}
      ) ON CONFLICT (id) DO UPDATE SET slug = 'orvex', display_name = 'Orvex',
        status = 'active', route_id = COALESCE(artifact_installations.route_id, EXCLUDED.route_id)
      WHERE artifact_installations.slug IS NULL OR artifact_installations.slug = 'orvex'
        RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
        status, admission_policy AS "admissionPolicy", NULL::TEXT AS "keycloakId"`;
      return rows[0] ?? null;
    }));
    if (row === null) {
      throw new Error("The configured installation cannot be registered as org slug 'orvex'.");
    }
    const organization = organizationSchema.parse(row);
    if (organization.id !== installationId) {
      throw new Error("The configured installation does not match org slug 'orvex'.");
    }
    return organization;
  }

  async create(
    slugInput: string,
    nameInput: string,
    admissionPolicyInput: OrganizationAdmissionPolicy | null = null,
    keycloakId: string | null = null,
  ): Promise<OrganizationRecord> {
    const slug = organizationSlugSchema.parse(slugInput);
    const displayName = organizationNameSchema.parse(nameInput);
    const admissionPolicy = admissionPolicyInput === null
      ? null
      : admissionPolicySchema.parse(admissionPolicyInput);
    const id = randomUUID();
    const routeId = randomRouteId();
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id, admission_policy,
        keycloak_organization_id
      ) VALUES (
        ${id}, ${new Date().toISOString()}, ${slug}, ${displayName}, 'active',
        ${routeId}, ${admissionPolicy === null ? null : JSON.stringify(admissionPolicy)}::jsonb,
        ${keycloakId}
      ) RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
        status, admission_policy AS "admissionPolicy",
        keycloak_organization_id AS "keycloakId"`;
      return rows[0];
    }));
    return organizationSchema.parse(row);
  }

  async syncKeycloakOrganization(
    alias: string,
    name: string,
    keycloakId: string,
  ): Promise<KeycloakOrganizationSyncResult> {
    const slug = organizationSlugSchema.parse(alias);
    const id = keycloakOrganizationIdSchema.parse(keycloakId);
    if (isReservedOrganizationSlug(slug)) {
      return {kind: "conflict", alias, reason: `Organization alias '${alias}' is reserved.`};
    }
    const existing = await this.find(slug);
    if (existing !== null) {
      if (existing.keycloakId === null) {
        return {
          kind: "conflict",
          alias,
          reason: `Organization '${alias}' is registered but not linked to Keycloak; run org link deliberately.`,
        };
      }
      if (existing.keycloakId !== id) {
        return {kind: "conflict", alias, reason: `Organization '${alias}' is linked to a different Keycloak id.`};
      }
      const rows = await this.#database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`UPDATE artifact_installations
          SET display_name = ${organizationNameSchema.parse(name)},
            keycloak_organization_id = ${id}
          WHERE id = ${existing.id}
          RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
            status, admission_policy AS "admissionPolicy",
            keycloak_organization_id AS "keycloakId"`;
      }));
      return {kind: "synced", organization: organizationSchema.parse(rows[0])};
    }
    const oldAlias = await this.findByKeycloakId(id);
    if (oldAlias !== null) {
      return {
        kind: "conflict",
        alias,
        reason: `Keycloak organization ${id} is already registered as '${oldAlias.slug}'.`,
      };
    }
    return {
      kind: "synced",
      organization: await this.create(slug, name, null, id),
    };
  }

  async linkKeycloakOrganization(
    slugInput: string,
    keycloakIdInput: string,
  ): Promise<OrganizationRecord> {
    const slug = organizationSlugSchema.parse(slugInput);
    if (isReservedOrganizationSlug(slug)) {
      throw new Error(`Organization alias '${slug}' is reserved.`);
    }
    const keycloakId = keycloakOrganizationIdSchema.parse(keycloakIdInput);
    const existing = await this.find(slug);
    if (existing === null) throw new Error(`No organization '${slug}' is registered.`);
    if (existing.keycloakId !== null && existing.keycloakId !== keycloakId) {
      throw new Error(`Organization '${slug}' is already linked to another Keycloak id.`);
    }
    const byId = await this.findByKeycloakId(keycloakId);
    if (byId !== null && byId.id !== existing.id) {
      throw new Error(`Keycloak organization ${keycloakId} is already linked to '${byId.slug}'.`);
    }
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`UPDATE artifact_installations
        SET keycloak_organization_id = ${keycloakId}
        WHERE id = ${existing.id} AND (keycloak_organization_id IS NULL OR keycloak_organization_id = ${keycloakId})
        RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
          status, admission_policy AS "admissionPolicy", keycloak_organization_id AS "keycloakId"`;
    }));
    return organizationSchema.parse(rows[0]);
  }

  async suspend(slug: string): Promise<OrganizationRecord> {
    const organization = await this.find(slug);
    if (organization === null) throw new Error(`No organization '${slug}' is registered.`);
    if (organization.slug === "orvex") throw new Error("The Orvex installation cannot be suspended with this command.");
    const updatedAt = new Date().toISOString();
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:directory-groups:${organization.id}`}, 0)
        )`;
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${organization.id}`}, 0)
        )`;
        const members = yield* sql`UPDATE installation_members SET
          suspended_by_org_at = COALESCE(suspended_by_org_at, ${updatedAt}),
          pre_suspend_status = COALESCE(pre_suspend_status, status),
          pre_suspend_manual_deactivation = COALESCE(pre_suspend_manual_deactivation, manual_deactivation),
          status = 'inactive', manual_deactivation = TRUE, updated_at = ${updatedAt}
          WHERE installation_id = ${organization.id}
          RETURNING id`;
        const memberIds = members.map((member) => member["id"]);
        if (memberIds.length > 0) {
          yield* sql`UPDATE application_sessions SET revoked_at = COALESCE(revoked_at, ${updatedAt})
            WHERE installation_id = ${organization.id} AND member_id = ANY(${memberIds}::text[])`;
          yield* sql`UPDATE managed_api_keys SET revoked_at = COALESCE(revoked_at, ${updatedAt})
            WHERE installation_id = ${organization.id} AND principal_kind = 'human'
              AND principal_id = ANY(${memberIds}::text[])`;
        }
        return yield* sql`UPDATE artifact_installations SET status = 'suspended'
          WHERE id = ${organization.id}
          RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
            status, admission_policy AS "admissionPolicy",
            keycloak_organization_id AS "keycloakId"`;
      }));
    }));
    if (rows[0] === undefined) throw new Error(`Organization '${slug}' disappeared while being suspended.`);
    return organizationSchema.parse(rows[0]);
  }

  async resume(slug: string): Promise<OrganizationRecord> {
    const organization = await this.find(slug);
    if (organization === null) throw new Error(`No organization '${slug}' is registered.`);
    if (organization.slug === "orvex") throw new Error("The Orvex installation cannot be resumed with this command.");
    const updatedAt = new Date().toISOString();
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql.withTransaction(Effect.gen(function*() {
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:directory-groups:${organization.id}`}, 0)
        )`;
        yield* sql`SELECT pg_advisory_xact_lock(
          hashtextextended(${`artifact-server:member-policy:${organization.id}`}, 0)
        )`;
        yield* sql`UPDATE installation_members SET
          status = COALESCE(pre_suspend_status, 'inactive'),
          manual_deactivation = COALESCE(pre_suspend_manual_deactivation, FALSE),
          suspended_by_org_at = NULL, pre_suspend_status = NULL,
          pre_suspend_manual_deactivation = NULL, updated_at = ${updatedAt}
          WHERE installation_id = ${organization.id} AND suspended_by_org_at IS NOT NULL`;
        return yield* sql`UPDATE artifact_installations SET status = 'active'
          WHERE id = ${organization.id}
          RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
            status, admission_policy AS "admissionPolicy",
            keycloak_organization_id AS "keycloakId"`;
      }));
    }));
    if (rows[0] === undefined) throw new Error(`Organization '${slug}' disappeared while being resumed.`);
    return organizationSchema.parse(rows[0]);
  }
}

function randomRouteId(): string {
  return randomBytes(4).toString("hex");
}

import {randomBytes, randomUUID} from "node:crypto";

import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {z} from "zod";

import type {PostgresDatabase} from "../storage/postgres-database.js";

const admissionPolicySchema = z.object({
  groupRoots: z.array(z.string().min(1)).default([]),
  guestGroupPrefixes: z.array(z.string().min(1)).optional(),
  seed: z.array(z.object({
    role: z.enum(["administrator", "guest", "member", "owner", "viewer"]),
    selector: z.string().min(1),
  }).strict()),
}).strict();
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
const organizationSchema = z.object({
  displayName: z.string(),
  id: z.string(),
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
  readonly routeId: string;
  readonly slug: string;
  readonly status: "active" | "suspended";
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
        route_id AS "routeId", status, admission_policy AS "admissionPolicy"
        FROM artifact_installations
        WHERE slug = ${slug}`;
      return rows[0] ?? null;
    }));
    return row === null ? null : organizationSchema.parse(row);
  }

  async list(): Promise<readonly OrganizationRecord[]> {
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`SELECT id, slug, display_name AS "displayName",
        route_id AS "routeId", status, admission_policy AS "admissionPolicy"
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
        status, admission_policy AS "admissionPolicy"`;
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
  ): Promise<OrganizationRecord> {
    const slug = organizationSlugSchema.parse(slugInput);
    const displayName = organizationNameSchema.parse(nameInput);
    const admissionPolicy = admissionPolicyInput;
    const id = randomUUID();
    const routeId = randomRouteId();
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id, admission_policy
      ) VALUES (
        ${id}, ${new Date().toISOString()}, ${slug}, ${displayName}, 'active',
        ${routeId}, ${admissionPolicy === null ? null : JSON.stringify(admissionPolicy)}::jsonb
      ) RETURNING id, slug, display_name AS "displayName", route_id AS "routeId",
        status, admission_policy AS "admissionPolicy"`;
      return rows[0];
    }));
    return organizationSchema.parse(row);
  }
}

function randomRouteId(): string {
  return randomBytes(4).toString("hex");
}

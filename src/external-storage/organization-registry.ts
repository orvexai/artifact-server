import {randomBytes, randomUUID} from "node:crypto";

import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {z} from "zod";

import type {PostgresDatabase} from "../storage/postgres-database.js";

const organizationSlugSchema = z.string().regex(
  /^[a-z0-9][a-z0-9-]{1,38}$/u,
  "Organization slugs must match ^[a-z0-9][a-z0-9-]{1,38}$.",
);
const organizationNameSchema = z.string().trim().min(1).max(160);
const organizationSchema = z.object({
  displayName: z.string(),
  id: z.string(),
  routeId: z.string().regex(/^[a-z0-9]{8}$/u),
  slug: organizationSlugSchema,
  status: z.enum(["active", "suspended"]),
}).strict();

/** An installation's configured organization route and display metadata. */
export interface OrganizationRecord {
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
        route_id AS "routeId", status FROM artifact_installations
        WHERE slug = ${slug}`;
      return rows[0] ?? null;
    }));
    return row === null ? null : organizationSchema.parse(row);
  }

  async list(): Promise<readonly OrganizationRecord[]> {
    const rows = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`SELECT id, slug, display_name AS "displayName",
        route_id AS "routeId", status FROM artifact_installations
        WHERE slug IS NOT NULL ORDER BY slug`;
    }));
    return z.array(organizationSchema).parse(rows);
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
      RETURNING id, slug, display_name AS "displayName", route_id AS "routeId", status`;
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

  async create(slugInput: string, nameInput: string): Promise<OrganizationRecord> {
    const slug = organizationSlugSchema.parse(slugInput);
    const displayName = organizationNameSchema.parse(nameInput);
    const id = randomUUID();
    const routeId = randomRouteId();
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id
      ) VALUES (
        ${id}, ${new Date().toISOString()}, ${slug}, ${displayName}, 'active', ${routeId}
      ) RETURNING id, slug, display_name AS "displayName", route_id AS "routeId", status`;
      return rows[0];
    }));
    return organizationSchema.parse(row);
  }
}

function randomRouteId(): string {
  return randomBytes(4).toString("hex");
}

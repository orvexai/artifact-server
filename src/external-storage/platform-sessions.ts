import {createHash, randomBytes} from "node:crypto";

import {Effect} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {z} from "zod";

import type {ExternalIdentity} from "../core/installation-identity.js";
import type {PostgresDatabase} from "../storage/postgres-database.js";
import type {OrganizationMembership, OrganizationMembershipResolver} from "./organization-memberships.js";

const membershipsSchema = z.array(z.object({
  displayName: z.string().min(1).max(160),
  role: z.string().min(1).max(80),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,38}$/u),
}).strict());

/** Shared, opaque browser sessions for the root platform surface. */
export class PlatformSessions {
  readonly #database: PostgresDatabase;
  readonly #memberships: OrganizationMembershipResolver;

  constructor(database: PostgresDatabase, memberships: OrganizationMembershipResolver) {
    this.#database = database;
    this.#memberships = memberships;
  }

  async issue(identity: ExternalIdentity): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    const now = new Date();
    const memberships = membershipsSchema.parse(await this.#memberships.forIdentity(identity))
      .filter(({role}) => role.trim().length > 0);
    await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`INSERT INTO artifact_platform_sessions
        (token_digest, organizations_json, last_org, created_at, expires_at)
        VALUES (${digest(token)}, ${JSON.stringify(memberships)}::jsonb,
          NULL, ${now.toISOString()}, ${new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()})
        ON CONFLICT (token_digest) DO NOTHING`;
    }));
    return token;
  }

  async find(token: string): Promise<PlatformSession | null> {
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`SELECT organizations_json::text AS "organizations", last_org AS "lastOrg",
        expires_at AS "expiresAt" FROM artifact_platform_sessions
        WHERE token_digest = ${digest(token)} AND expires_at > ${new Date().toISOString()}`;
      return rows[0] ?? null;
    }));
    if (row === null) return null;
    const parsed = z.object({
      organizations: z.string().transform((value) => JSON.parse(value)).pipe(membershipsSchema),
      lastOrg: z.string().nullable(),
      expiresAt: z.string(),
    }).safeParse(row);
    if (!parsed.success) return null;
    return {organizations: parsed.data.organizations, lastOrg: parsed.data.lastOrg};
  }

  async setLastOrg(token: string, slug: string): Promise<boolean> {
    const session = await this.find(token);
    if (session === null || !session.organizations.some((org) => org.slug === slug)) return false;
    await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`UPDATE artifact_platform_sessions SET last_org = ${slug}
        WHERE token_digest = ${digest(token)} AND expires_at > ${new Date().toISOString()}`;
    }));
    return true;
  }
}

export interface PlatformSession {
  readonly organizations: readonly OrganizationMembership[];
  readonly lastOrg: string | null;
}

export function platformTokenDigest(token: string): string {
  return digest(token);
}

function digest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

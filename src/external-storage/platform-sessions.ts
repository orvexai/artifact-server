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
const externalIdentitySchema = z.object({
  displayName: z.string(), email: z.string().nullable(), emailVerified: z.boolean(),
  groups: z.array(z.string()).nullable(), provider: z.string(), subject: z.string(),
  organizations: z.record(z.string(), z.object({id: z.string(), groups: z.array(z.string())})).optional(),
}).strict();

interface PlatformIdentitySnapshot {
  readonly displayName: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly groups: readonly string[] | null;
  readonly organizations?: ExternalIdentity["organizations"];
  readonly provider: string;
  readonly subject: string;
}

/** Shared, opaque browser sessions for the root platform surface. */
export class PlatformSessions {
  readonly #database: PostgresDatabase;
  readonly #memberships: OrganizationMembershipResolver;
  readonly #membershipCache = new Map<string, {readonly organizations: readonly OrganizationMembership[]; readonly expiresAt: number}>();

  constructor(database: PostgresDatabase, memberships: OrganizationMembershipResolver) {
    this.#database = database;
    this.#memberships = memberships;
  }

  async issue(identity: ExternalIdentity): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    const now = new Date();
    const memberships = parseMemberships(await this.#memberships.forIdentity(identity));
    await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`DELETE FROM artifact_platform_sessions WHERE expires_at <= ${now.toISOString()}`;
      yield* sql`INSERT INTO artifact_platform_sessions
        (token_digest, organizations_json, last_org, identity_json, provider, subject, created_at, expires_at)
        VALUES (${digest(token)}, ${JSON.stringify(memberships)}::jsonb, NULL,
          ${JSON.stringify(identitySnapshot(identity))}::jsonb, ${identity.provider}, ${identity.subject},
          ${now.toISOString()}, ${new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()})
        ON CONFLICT (token_digest) DO NOTHING`;
    }));
    return token;
  }

  async find(token: string): Promise<PlatformSession | null> {
    const row = await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const rows = yield* sql`SELECT organizations_json::text AS "organizations", identity_json::text AS "identity",
        last_org AS "lastOrg",
        expires_at AS "expiresAt" FROM artifact_platform_sessions
        WHERE token_digest = ${digest(token)} AND expires_at > ${new Date().toISOString()}`;
      return rows[0] ?? null;
    }));
    if (row === null) return null;
    const parsed = z.object({
      organizations: z.string().transform((value) => JSON.parse(value)).pipe(z.unknown()),
      identity: z.string().transform((value) => JSON.parse(value)).pipe(externalIdentitySchema),
      lastOrg: z.string().nullable(),
      expiresAt: z.string(),
    }).safeParse(row);
    if (!parsed.success) return null;
    const stored = parsed.data.identity;
    const storedIdentity: ExternalIdentity = {
      displayName: stored.displayName, email: stored.email, emailVerified: stored.emailVerified,
      groups: stored.groups, provider: stored.provider, subject: stored.subject,
    };
    if (stored.organizations !== undefined) Object.assign(storedIdentity, {organizations: stored.organizations});
    const cacheKey = digest(token);
    const cached = this.#membershipCache.get(cacheKey);
    let organizations: readonly OrganizationMembership[];
    if (cached !== undefined && cached.expiresAt > Date.now()) organizations = cached.organizations;
    else {
      organizations = parseMemberships(await this.#memberships.forIdentity(storedIdentity));
      this.#membershipCache.set(cacheKey, {organizations, expiresAt: Date.now() + 60_000});
      await this.#database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`UPDATE artifact_platform_sessions SET organizations_json = ${JSON.stringify(organizations)}::jsonb
          WHERE token_digest = ${cacheKey} AND expires_at > ${new Date().toISOString()}`;
      }));
    }
    return {organizations, lastOrg: parsed.data.lastOrg};
  }

  async logout(token: string): Promise<void> {
    this.#membershipCache.delete(digest(token));
    await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`DELETE FROM artifact_platform_sessions WHERE token_digest = ${digest(token)}`;
    }));
  }

  async sweepExpired(): Promise<void> {
    for (const [key, value] of this.#membershipCache) if (value.expiresAt <= Date.now()) this.#membershipCache.delete(key);
    await this.#database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      yield* sql`DELETE FROM artifact_platform_sessions WHERE expires_at <= ${new Date().toISOString()}`;
    }));
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

function identitySnapshot(identity: ExternalIdentity) {
  const snapshot: PlatformIdentitySnapshot = {
    displayName: identity.displayName,
    email: identity.email,
    emailVerified: identity.emailVerified,
    groups: identity.groups,
    provider: identity.provider,
    subject: identity.subject,
  };
  if (identity.organizations !== undefined) Object.assign(snapshot, {organizations: identity.organizations});
  return snapshot;
}

function parseMemberships(value: readonly OrganizationMembership[]): readonly OrganizationMembership[] {
  return value.flatMap((item) => {
    const parsed = membershipsSchema.element.safeParse(item);
    return parsed.success && parsed.data.role.trim().length > 0 ? [parsed.data] : [];
  });
}

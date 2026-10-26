import {type Redacted, Schema} from "effect";
import {z} from "zod";

import type {GroupRoleSeedEntry} from "../core/group-role-policy.js";
import {membershipRoles, type MembershipRole} from "../core/identity.js";
import {
  defaultOidcGroupsClaim,
  type OidcGroupRoles,
} from "../identity/oidc-groups-claim.js";
import {defaultOidcScopes} from "../identity/oidc-identity-provider.js";
import {keycloakAdminBaseUrl, keycloakInternalEndpoints} from "../identity/keycloak-directory.js";
import {
  isLocalOidcIssuer,
  normalizeOidcEndpoint,
  requireOidcIssuer,
} from "../identity/oidc-issuer.js";
import {
  loadOptionalCredential,
  type LoadedSecret,
} from "../lifecycle/runtime-configuration.js";
import {runCliEffect} from "./run-cli-effect.js";

const oidcEnvironmentSchema = z.object({
  ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: z.email().optional(),
  ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_API_RESOURCE: z.url().optional(),
  ARTIFACT_SERVER_OIDC_API_JWKS_URI: z.url().optional(),
  ARTIFACT_SERVER_OIDC_CLIENT_ID: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_DIRECTORY_KEYCLOAK_URL: z.url().optional(),
  ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_GROUPS_CLAIM: z.string().trim().min(1).optional(),
  ARTIFACT_SERVER_OIDC_ISSUER: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_MEMBER_GROUPS: z.string().min(1).optional(),
  ARTIFACT_SERVER_OIDC_SCOPES: z.string().min(1).optional(),
  ARTIFACT_SERVER_ORIGIN: z.url().optional(),
});

/** A directory that lists group members before they ever sign in. */
export interface OidcDirectoryConfiguration {
  /** Admin REST base, from the realm issuer or the internal Keycloak URL. */
  readonly adminBaseUrl: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted;
  readonly provider: "keycloak";
  /** Set with an internal Keycloak URL; otherwise discovery names it. */
  readonly tokenEndpoint?: string;
}

/** Complete optional generic OIDC browser-login configuration. */
export interface OidcConfiguration {
  readonly apiResource: string | null;
  readonly apiJwksUri: string | null;
  readonly applicationOrigin: string;
  readonly bootstrapAdministratorEmail: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted | null;
  /** Directory sync settings; null when the directory is not synced. */
  readonly directory: OidcDirectoryConfiguration | null;
  /** Issuer groups that admit people and set their role; null keeps it manual. */
  readonly groupRoles: OidcGroupRoles | null;
  readonly issuer: string;
  readonly scopes: string;
}

/** Load all-or-nothing OIDC settings, including a file-backed client secret. */
export async function loadOidcConfiguration(
  environment: NodeJS.ProcessEnv,
): Promise<OidcConfiguration | null> {
  const parsed = oidcEnvironmentSchema.parse(environment);
  const clientSecret = await runCliEffect(loadOptionalCredential(
    environment,
    "ARTIFACT_SERVER_OIDC_CLIENT_SECRET",
    Schema.NonEmptyString,
  ));
  const directorySecret = await runCliEffect(loadOptionalCredential(
    environment,
    "ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET",
    Schema.NonEmptyString,
  ));
  if (
    clientSecret === null &&
    directorySecret === null &&
    parsed.ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_CLIENT_ID === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_ISSUER === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_SCOPES === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_GROUPS_CLAIM === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_MEMBER_GROUPS === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_API_RESOURCE === undefined &&
    parsed.ARTIFACT_SERVER_OIDC_API_JWKS_URI === undefined
  ) {
    return null;
  }
  const requiredValues = [
    parsed.ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL,
    parsed.ARTIFACT_SERVER_ORIGIN,
    parsed.ARTIFACT_SERVER_OIDC_CLIENT_ID,
    parsed.ARTIFACT_SERVER_OIDC_ISSUER,
  ];
  if (requiredValues.some((value) => value === undefined)) {
    throw new Error(
      "Generic OIDC authentication requires ARTIFACT_SERVER_ORIGIN, ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL, ARTIFACT_SERVER_OIDC_ISSUER, and ARTIFACT_SERVER_OIDC_CLIENT_ID. ARTIFACT_SERVER_OIDC_CLIENT_SECRET or ARTIFACT_SERVER_OIDC_CLIENT_SECRET_FILE and ARTIFACT_SERVER_OIDC_SCOPES are optional.",
    );
  }
  const issuer = requireOidcIssuer(
    requireString(parsed.ARTIFACT_SERVER_OIDC_ISSUER),
    "ARTIFACT_SERVER_OIDC_ISSUER",
  );
  const apiJwksUri = parsed.ARTIFACT_SERVER_OIDC_API_JWKS_URI ?? null;
  if (
    apiJwksUri !== null &&
    normalizeOidcEndpoint(apiJwksUri, isLocalOidcIssuer(issuer)) === null
  ) {
    throw new Error(
      "ARTIFACT_SERVER_OIDC_API_JWKS_URI must be an HTTPS URL. Plain http is allowed only when the OIDC issuer is local (localhost, 127.0.0.1, or ::1).",
    );
  }
  const groupRoles = oidcGroupRoles(parsed);
  return {
    apiResource: parsed.ARTIFACT_SERVER_OIDC_API_RESOURCE ?? null,
    apiJwksUri,
    applicationOrigin: requireString(parsed.ARTIFACT_SERVER_ORIGIN),
    bootstrapAdministratorEmail: requireString(
      parsed.ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL,
    ),
    clientId: requireString(parsed.ARTIFACT_SERVER_OIDC_CLIENT_ID),
    clientSecret: credentialOrNull(clientSecret),
    directory: oidcDirectory(
      parsed,
      credentialOrNull(directorySecret),
      issuer,
      groupRoles,
    ),
    groupRoles,
    issuer,
    scopes: parsed.ARTIFACT_SERVER_OIDC_SCOPES ?? defaultOidcScopes,
  };
}

/**
 * Refuse an installation that configures WorkOS and generic OIDC together.
 *
 * Presence of any variable in either family selects that provider, matching the
 * Cloudflare worker guard: a leftover `ARTIFACT_SERVER_WORKOS_ISSUER` beside a
 * complete OIDC family must fail startup rather than boot silently on OIDC.
 */
export function assertAtMostOneBrowserLoginProvider(
  environment: NodeJS.ProcessEnv,
): void {
  if (
    !hasBrowserLoginVariable(environment, "ARTIFACT_SERVER_WORKOS_") ||
    !hasBrowserLoginVariable(environment, "ARTIFACT_SERVER_OIDC_")
  ) {
    return;
  }
  throw new Error(
    "One installation has one browser-login provider: configure ARTIFACT_SERVER_WORKOS_* or ARTIFACT_SERVER_OIDC_*, not both.",
  );
}

function hasBrowserLoginVariable(
  environment: NodeJS.ProcessEnv,
  prefix: string,
): boolean {
  return Object.entries(environment).some(([name, value]) =>
    name.startsWith(prefix) && value !== undefined && value.trim() !== ""
  );
}

/**
 * Read the opt-in group roles; with no seed set, admission stays manual. The
 * seed names each group's starting role. It fills only roles that were never
 * set, so roles changed in the application stay as they were. The older
 * member and administrator group lists still work as a seed.
 */
function oidcGroupRoles(
  parsed: z.infer<typeof oidcEnvironmentSchema>,
): OidcGroupRoles | null {
  const seed = groupRoleSeed(parsed.ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED);
  const legacy = [
    ...groupNames(
      "ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS",
      parsed.ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS,
    ).map((selector) => ({role: membershipRoles.administrator, selector})),
    ...groupNames(
      "ARTIFACT_SERVER_OIDC_MEMBER_GROUPS",
      parsed.ARTIFACT_SERVER_OIDC_MEMBER_GROUPS,
    ).map((selector) => ({role: membershipRoles.member, selector})),
  ];
  if (seed.length > 0 && legacy.length > 0) {
    throw new Error(
      "Set ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED or the older ARTIFACT_SERVER_OIDC_MEMBER_GROUPS and ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS, not both.",
    );
  }
  if (seed.length === 0 && legacy.length === 0) {
    if (parsed.ARTIFACT_SERVER_OIDC_GROUPS_CLAIM !== undefined) {
      throw new Error(
        "ARTIFACT_SERVER_OIDC_GROUPS_CLAIM requires ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED.",
      );
    }
    return null;
  }
  // A group named in both older lists keeps its stronger role, as before.
  const entries = seed.length > 0 ? seed : legacy.filter((entry, index) =>
    legacy.findIndex((other) => other.selector === entry.selector) === index
  );
  return {
    claim: parsed.ARTIFACT_SERVER_OIDC_GROUPS_CLAIM ?? defaultOidcGroupsClaim,
    seed: entries,
  };
}

/** Read the opt-in directory sync, which only group roles can give meaning. */
function oidcDirectory(
  parsed: z.infer<typeof oidcEnvironmentSchema>,
  clientSecret: Redacted.Redacted | null,
  issuer: string,
  groupRoles: OidcGroupRoles | null,
): OidcDirectoryConfiguration | null {
  const provider = parsed.ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER;
  const clientId = parsed.ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID;
  if (provider === undefined && clientId === undefined && clientSecret === null) {
    return null;
  }
  if (groupRoles === null) {
    throw new Error(
      "The ARTIFACT_SERVER_OIDC_DIRECTORY_* settings require ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED.",
    );
  }
  if (provider === undefined || clientId === undefined || clientSecret === null) {
    throw new Error(
      "Directory sync requires ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER, ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID, and ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET or ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET_FILE.",
    );
  }
  if (provider !== "keycloak") {
    throw new Error(
      "ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER supports only keycloak.",
    );
  }
  const adminBaseUrl = keycloakAdminBaseUrl(issuer);
  if (adminBaseUrl === null) {
    throw new Error(
      "Keycloak directory sync requires ARTIFACT_SERVER_OIDC_ISSUER in the form <base>/realms/<realm>.",
    );
  }
  const keycloakUrl = parsed.ARTIFACT_SERVER_OIDC_DIRECTORY_KEYCLOAK_URL;
  if (keycloakUrl === undefined) {
    return {adminBaseUrl, clientId, clientSecret, provider};
  }
  const internal = keycloakInternalEndpoints(issuer, keycloakUrl);
  if (internal === null) {
    throw new Error(
      "ARTIFACT_SERVER_OIDC_DIRECTORY_KEYCLOAK_URL must be a Keycloak base URL such as http://keycloak-service.keycloak.svc:8080.",
    );
  }
  return {...internal, clientId, clientSecret, provider};
}

/** The words a seed entry may use for a role, and the role each stores. */
const seedRoles = new Map<string, MembershipRole>([
  ["admin", membershipRoles.administrator],
  ["administrator", membershipRoles.administrator],
  ["member", membershipRoles.member],
  ["operator", membershipRoles.member],
  ["owner", membershipRoles.owner],
  ["viewer", membershipRoles.viewer],
] as const);

/**
 * Parse `Group=role,/Full/Path=role`. Roles are viewer, operator, admin and
 * owner; a selector starting with "/" is a full path, otherwise a group name.
 */
function groupRoleSeed(value: string | undefined): readonly GroupRoleSeedEntry[] {
  if (value === undefined) return [];
  const entries: GroupRoleSeedEntry[] = [];
  for (const item of value.split(",")) {
    if (item.trim() === "") continue;
    const separator = item.lastIndexOf("=");
    const selector = separator < 0 ? "" : item.slice(0, separator).trim();
    const role = separator < 0
      ? undefined
      : seedRoles.get(item.slice(separator + 1).trim());
    if (selector === "" || role === undefined) {
      throw new Error(
        "ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED entries must look like Group=role, with role viewer, operator, admin or owner.",
      );
    }
    if (entries.some((entry) => entry.selector === selector)) {
      throw new Error(`ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED names ${selector} twice.`);
    }
    entries.push({role, selector});
  }
  if (entries.length === 0) {
    throw new Error("ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED must name at least one group.");
  }
  return entries;
}

/** Split one comma-separated list of exact, case-sensitive group names. */
function groupNames(name: string, value: string | undefined): readonly string[] {
  if (value === undefined) return [];
  const groups = [...new Set(
    value.split(",").map((group) => group.trim()).filter((group) => group !== ""),
  )];
  if (groups.length === 0) {
    throw new Error(`${name} must name at least one group.`);
  }
  return groups;
}

function credentialOrNull(value: LoadedSecret | null): Redacted.Redacted | null {
  return value === null ? null : value.value;
}

function requireString(value: string | undefined): string {
  if (value === undefined) throw new Error("A required OIDC value is missing.");
  return value;
}

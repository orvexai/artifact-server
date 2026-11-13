import type {Schema} from "effect";
import {z} from "zod";

/** Roles carried by Keycloak's Organizations token mapper. */
export type KeycloakOrganizationRole = "viewer" | "editor" | "owner";

/** One organization membership read from a verified Keycloak token. */
export interface KeycloakOrganizationMembership {
  readonly alias: string;
  readonly groups: readonly string[];
  readonly id: string;
  readonly role: KeycloakOrganizationRole | null;
}

/** Parsed organization claim and the optional upstream broker label. */
export interface KeycloakOrganizationClaims {
  readonly identityProvider: string | null;
  readonly organizations: readonly KeycloakOrganizationMembership[];
}

export type OrganizationClaimParseResult =
  | {readonly ok: true; readonly value: KeycloakOrganizationClaims}
  | {readonly ok: false; readonly reason: string};

const roleByGroup = new Map<string, KeycloakOrganizationRole>([
  ["/viewer", "viewer"],
  ["/editor", "editor"],
  ["/owner", "owner"],
]);
const rolePrecedence = {
  viewer: 0,
  editor: 1,
  owner: 2,
} satisfies Record<KeycloakOrganizationRole, number>;
const organizationClaimSchema = z.record(z.string().min(1), z.unknown());
const organizationMembershipSchema = z.object({
  id: z.string().uuid(),
  groups: z.array(z.string()),
}).strict();

/**
 * Parse the pinned Keycloak 26 Organizations claim shape. A missing claim is
 * a valid empty membership set. Each entry is strict and malformed siblings
 * are skipped so one bad organization cannot hide valid memberships.
 */
export function parseKeycloakOrganizationClaims(
  organizationClaim: Schema.Json | undefined,
  identityProviderClaim?: Schema.Json,
): OrganizationClaimParseResult {
  const identityProvider = identityProviderClaim === undefined
    ? null
    : z.string().safeParse(identityProviderClaim);
  if (identityProvider !== null && !identityProvider.success) {
    return {ok: false, reason: "identity_provider must be a string when present."};
  }
  if (organizationClaim === undefined) {
    return {
      ok: true,
      value: {
        identityProvider: identityProvider === null ? null : identityProvider.data,
        organizations: [],
      },
    };
  }
  const parsedOrganization = organizationClaimSchema.safeParse(organizationClaim);
  if (!parsedOrganization.success) {
    return {ok: false, reason: describeOrganizationParseFailure(parsedOrganization.error)};
  }

  const organizations: KeycloakOrganizationMembership[] = [];
  for (const [alias, rawMembership] of Object.entries(parsedOrganization.data)) {
    const parsedMembership = organizationMembershipSchema.safeParse(rawMembership);
    if (!parsedMembership.success) continue;
    const role = mapKeycloakOrganizationGroups(parsedMembership.data.groups);
    organizations.push({alias, groups: parsedMembership.data.groups, id: parsedMembership.data.id, role});
  }
  return {
    ok: true,
    value: {
      identityProvider: identityProvider === null ? null : identityProvider.data,
      organizations,
    },
  };
}

function describeOrganizationParseFailure(error: z.ZodError): string {
  const issue = error.issues[0];
  const alias = issue?.path[0];
  if (issue === undefined || issue.path.length === 0) {
    return "organization must be an alias-keyed object.";
  }
  if (issue.code === "unrecognized_keys" && alias !== undefined) {
    return `organization ${String(alias)} has unsupported membership fields.`;
  }
  if (alias === undefined) return "organization must be an alias-keyed object.";
  if (issue.path[1] === "id") {
    return `organization ${String(alias)} must have a UUID id.`;
  }
  if (issue.path[1] === "groups") {
    return `organization ${String(alias)} groups must be a list of strings.`;
  }
  return "organization membership entries must be objects with aliases.";
}

/** Map one org-scoped Keycloak group list, with an empty list meaning viewer. */
export function mapKeycloakOrganizationGroups(
  groups: readonly string[],
): KeycloakOrganizationRole | null {
  if (groups.length === 0) return "viewer";
  let highest: KeycloakOrganizationRole | null = null;
  for (const group of groups) {
    const role = roleByGroup.get(group);
    if (role !== undefined &&
      (highest === null || rolePrecedence[role] > rolePrecedence[highest])) {
      highest = role;
    }
  }
  return highest;
}

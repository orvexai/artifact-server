import {Effect, Redacted, Schema} from "effect";

import {
  DirectoryUnavailable,
  type DirectoryGroup,
  type DirectoryUser,
  type GroupDirectory,
  type MemberDirectory,
} from "../application/directory-sync.js";
import type {DirectoryGroupRecord} from "../core/directory-groups.js";
import {mapKeycloakOrganizationGroups, type KeycloakOrganizationRole} from
  "./oidc-organization-claim.js";
import {loadOidcAuthorizationServer} from "./oidc-oauth-metadata.js";
import {isLocalOidcIssuer, normalizeOidcEndpoint} from "./oidc-issuer.js";

/** Members requested per admin page; a shorter page is the last one. */
export const keycloakDirectoryPageSize = 100;
/** Refuse a group so large that reading it all is no longer a bounded pass. */
const maximumPagesPerGroup = 1_000;
/** Refuse a directory with more groups than one bounded pass lists. */
const maximumGroups = 10_000;
const requestTimeoutMilliseconds = 10_000;
/** Reuse one admin token this long; Keycloak's default lifetime is 5 minutes. */
const tokenReuseMilliseconds = 30_000;
const organizationRolePrecedence = {viewer: 0, editor: 1, owner: 2} as const;
/** Attempts per request; only a timeout, network fault or HTTP 5xx is retried. */
const requestAttempts = 3;
const retryBaseDelayMilliseconds = 500;
const clusterServiceHostPattern = /\.svc(?:\.cluster\.local)?$/u;
const realmPathPattern = /^(?<prefix>(?:\/[^/]+)*)\/realms\/(?<realm>[^/]+)$/u;

const tokenResponse = Schema.Struct({access_token: Schema.NonEmptyString});
const groupList = Schema.Array(Schema.Struct({
  id: Schema.NonEmptyString,
  name: Schema.String,
}));
const groupTree = Schema.Array(Schema.Struct({
  id: Schema.NonEmptyString,
  name: Schema.String,
  path: Schema.optionalKey(Schema.String),
  subGroupCount: Schema.optionalKey(Schema.Number),
}));
const userList = Schema.Array(Schema.Struct({
  email: Schema.optionalKey(Schema.String),
  emailVerified: Schema.optionalKey(Schema.Boolean),
  enabled: Schema.optionalKey(Schema.Boolean),
  firstName: Schema.optionalKey(Schema.String),
  id: Schema.NonEmptyString,
  lastName: Schema.optionalKey(Schema.String),
  username: Schema.String,
}));
const organizationList = Schema.Array(Schema.Struct({
  alias: Schema.NonEmptyString,
  enabled: Schema.optionalKey(Schema.Boolean),
  id: Schema.NonEmptyString,
  name: Schema.NonEmptyString,
}));
const organizationGroupList = Schema.Array(Schema.Struct({
  id: Schema.NonEmptyString,
  path: Schema.String,
}));
const decodeTokenResponse = Schema.decodeUnknownEffect(tokenResponse);
const decodeGroupList = Schema.decodeUnknownEffect(groupList);
const decodeGroupTree = Schema.decodeUnknownEffect(groupTree);
const decodeUserList = Schema.decodeUnknownEffect(userList);
const decodeOrganizationList = Schema.decodeUnknownEffect(organizationList);
const decodeOrganizationGroupList = Schema.decodeUnknownEffect(organizationGroupList);
const decodeGroupByPath = Schema.decodeUnknownEffect(Schema.Struct({
  id: Schema.NonEmptyString,
  path: Schema.String,
}));

export interface DirectoryOrganization {
  readonly alias: string;
  readonly enabled?: boolean;
  readonly id: string;
  readonly name: string;
}

export interface DirectoryOrganizationMember extends DirectoryUser {
  readonly role: KeycloakOrganizationRole | null;
}

/** Keycloak Organizations API used by per-org admission and directory sync. */
export interface OrganizationDirectory {
  readonly listOrganizations: () => Effect.Effect<readonly DirectoryOrganization[], DirectoryUnavailable>;
  readonly listOrganizationMembers: (
    organization: DirectoryOrganization,
  ) => Effect.Effect<readonly DirectoryOrganizationMember[], DirectoryUnavailable>;
  /**
   * Keycloak user ids that are direct members of the realm group at one full
   * path. Org sync uses it to mark admission-policy staff selectors.
   */
  readonly listGroupMemberIdsByPath?: (
    path: string,
  ) => Effect.Effect<readonly string[], DirectoryUnavailable>;
}

/**
 * Derive the Keycloak admin REST base for one realm issuer, or null when the
 * issuer is not `<base>/realms/<realm>`.
 */
export function keycloakAdminBaseUrl(issuer: string): string | null {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return null;
  }
  const match = realmPathPattern.exec(url.pathname.replace(/\/+$/u, ""));
  const realm = match?.groups?.["realm"];
  if (match === null || realm === undefined || url.search !== "" || url.hash !== "") {
    return null;
  }
  const prefix = match.groups?.["prefix"] ?? "";
  return `${url.origin}${prefix}/admin/realms/${realm}`;
}

/**
 * Derive the admin REST base and token endpoint for one realm when Keycloak is
 * reached at a different base URL than the public issuer, such as its
 * in-cluster service. Returns null when the issuer is not
 * `<base>/realms/<realm>` or the base URL is not a plain origin with an
 * optional path. Only the realm is taken from the issuer: a Keycloak served
 * under a path such as `/auth` needs that path in `keycloakUrl` too.
 */
export function keycloakInternalEndpoints(
  issuer: string,
  keycloakUrl: string,
): {readonly adminBaseUrl: string; readonly tokenEndpoint: string} | null {
  const publicAdmin = keycloakAdminBaseUrl(issuer);
  if (publicAdmin === null) return null;
  const realm = publicAdmin.slice(publicAdmin.lastIndexOf("/") + 1);
  let base: URL;
  try {
    base = new URL(keycloakUrl);
  } catch {
    return null;
  }
  if (base.search !== "" || base.hash !== "" || base.username !== "" || base.password !== "") {
    return null;
  }
  const root = `${base.origin}${base.pathname.replace(/\/+$/u, "")}`;
  return {
    adminBaseUrl: `${root}/admin/realms/${realm}`,
    tokenEndpoint: `${root}/realms/${realm}/protocol/openid-connect/token`,
  };
}

/**
 * True for a plain-HTTP URL whose host is a Kubernetes service, where the
 * client secret may travel unencrypted inside the cluster. Any `*.svc` host
 * in any namespace qualifies; the URL comes from operator configuration.
 * Credentials, a query, or a fragment in the URL disqualify it.
 */
export function isClusterServiceUrl(value: string): boolean {
  if (value !== value.trim()) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" &&
      clusterServiceHostPattern.test(url.hostname) &&
      url.username === "" && url.password === "" &&
      url.search === "" && url.hash === "";
  } catch {
    return false;
  }
}

export interface KeycloakDirectoryConfig {
  /** Admin REST base, as {@link keycloakAdminBaseUrl} derives it. */
  readonly adminBaseUrl: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted;
  readonly fetch?: typeof globalThis.fetch;
  /** The realm issuer whose discovery document names the token endpoint. */
  readonly issuer: string;
  /** Token endpoint to use instead of the issuer's discovery document. */
  readonly tokenEndpoint?: string;
  /** Pause between retries; tests pass 0. */
  readonly retryBaseDelayMilliseconds?: number;
}

/**
 * Read group membership through the Keycloak admin REST API with a
 * client-credentials token. The client needs only realm-management
 * view-users and query-groups.
 */
export class KeycloakDirectory implements GroupDirectory, MemberDirectory, OrganizationDirectory {
  readonly #adminBaseUrl: string;
  readonly #clientId: string;
  readonly #clientSecret: Redacted.Redacted;
  readonly #fetch: typeof globalThis.fetch;
  readonly #issuer: string;
  readonly #retryBaseDelayMilliseconds: number;
  #cachedToken: {readonly token: Redacted.Redacted; readonly until: number} | null = null;
  readonly #tokenEndpoint: string | undefined;

  constructor(config: KeycloakDirectoryConfig) {
    const allowLocalHttp = isLocalOidcIssuer(config.issuer);
    const adminBaseUrl = clusterOrNormalized(config.adminBaseUrl, allowLocalHttp);
    if (adminBaseUrl === null) {
      throw new Error("The Keycloak admin URL must be an HTTPS URL or an in-cluster service URL.");
    }
    let tokenEndpoint: string | undefined;
    if (config.tokenEndpoint !== undefined) {
      const normalized = clusterOrNormalized(config.tokenEndpoint, allowLocalHttp);
      if (normalized === null) {
        throw new Error("The Keycloak token URL must be an HTTPS URL or an in-cluster service URL.");
      }
      tokenEndpoint = normalized;
    }
    this.#tokenEndpoint = tokenEndpoint;
    this.#retryBaseDelayMilliseconds = config.retryBaseDelayMilliseconds ?? retryBaseDelayMilliseconds;
    this.#adminBaseUrl = adminBaseUrl.replace(/\/+$/u, "");
    this.#clientId = config.clientId;
    this.#clientSecret = config.clientSecret;
    const providerFetch = config.fetch ?? globalThis.fetch;
    this.#fetch = (input, init) => providerFetch(input, init);
    this.#issuer = config.issuer;
  }

  readonly listGroups = Effect.fn("KeycloakDirectory.listGroups")(
    function*(this: KeycloakDirectory, names: readonly string[]) {
      const token = yield* this.#accessToken();
      const groups: DirectoryGroup[] = [];
      for (const name of names) {
        const id = yield* this.#groupId(token, name);
        groups.push({name, users: yield* this.#groupMembers(token, name, id)});
      }
      return groups;
    },
  );

  readonly listOrganizations = Effect.fn("KeycloakDirectory.listOrganizations")(
    function*(this: KeycloakDirectory) {
      const token = yield* this.#accessToken();
      const organizations: DirectoryOrganization[] = [];
      for (let page = 0; page < maximumPagesPerGroup; page += 1) {
        const url = new URL(`${this.#adminBaseUrl}/organizations`);
        url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
        url.searchParams.set("max", String(keycloakDirectoryPageSize));
        const body = yield* this.#adminGet(token, url, "The Keycloak organization listing");
        const listed = yield* decodeOrganizationList(body).pipe(
          Effect.mapError(() => unavailable("The Keycloak organization listing returned an invalid list.")),
        );
        organizations.push(...listed.map((organization) => ({
          ...organization,
          enabled: organization.enabled ?? true,
        })));
        if (organizations.length > maximumGroups) {
          return yield* unavailable("Keycloak lists more organizations than one sync reads.");
        }
        if (listed.length < keycloakDirectoryPageSize) return organizations;
      }
      return yield* unavailable("The Keycloak organization listing has too many pages.");
    },
  );

  readonly listOrganizationMembers = Effect.fn("KeycloakDirectory.listOrganizationMembers")(
    function*(this: KeycloakDirectory, organization: DirectoryOrganization, retry = 0): Effect.fn.Return<
      readonly DirectoryOrganizationMember[],
      DirectoryUnavailable
    > {
      const token = yield* this.#accessToken();
      const roleByUserId = new Map<string, KeycloakOrganizationRole>();
      const roleGroupMemberIds = new Map<string, string[]>();
      const groups: {id: string; path: string}[] = [];
      for (let page = 0; page < maximumPagesPerGroup; page += 1) {
        const url = new URL(
          `${this.#adminBaseUrl}/organizations/${encodeURIComponent(organization.id)}/groups`,
        );
        url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
        url.searchParams.set("max", String(keycloakDirectoryPageSize));
        const body = yield* this.#adminGet(token, url, `The Keycloak groups of ${organization.alias}`);
        const listed = yield* decodeOrganizationGroupList(body).pipe(
          Effect.mapError(() => unavailable(`The Keycloak groups of ${organization.alias} returned an invalid list.`)),
        );
        groups.push(...listed);
        if (groups.length > maximumGroups) {
          return yield* unavailable(`Keycloak lists too many groups for ${organization.alias}.`);
        }
        if (listed.length < keycloakDirectoryPageSize) break;
        if (page === maximumPagesPerGroup - 1) {
          return yield* unavailable(`The Keycloak groups of ${organization.alias} have too many pages.`);
        }
      }
      const roleGroups = groups.flatMap((group) => {
        const role = mapKeycloakOrganizationGroups([group.path]);
        return role === null ? [] : [{...group, role}];
      });
      for (const group of roleGroups) {
        const groupMemberIds: string[] = [];
        for (let page = 0; page < maximumPagesPerGroup; page += 1) {
          const url = new URL(
            `${this.#adminBaseUrl}/organizations/${encodeURIComponent(organization.id)}` +
              `/groups/${encodeURIComponent(group.id)}/members`,
          );
          url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
          url.searchParams.set("max", String(keycloakDirectoryPageSize));
          const body = yield* this.#adminGet(token, url,
            `The Keycloak members of ${group.path} in ${organization.alias}`);
          const listed = yield* decodeUserList(body).pipe(
            Effect.mapError(() => unavailable(`The Keycloak members of ${group.path} in ${organization.alias} returned an invalid list.`)),
          );
          for (const member of listed) {
            groupMemberIds.push(member.id);
            const current = roleByUserId.get(member.id);
            if (current === undefined ||
              organizationRolePrecedence[group.role] > organizationRolePrecedence[current]) {
              roleByUserId.set(member.id, group.role);
            }
          }
          if (listed.length < keycloakDirectoryPageSize) break;
          if (page === maximumPagesPerGroup - 1) {
            return yield* unavailable(`The Keycloak members of ${group.path} in ${organization.alias} have too many pages.`);
          }
        }
        roleGroupMemberIds.set(group.id, groupMemberIds.toSorted());
      }
      const members: DirectoryOrganizationMember[] = [];
      const seenMemberIds = new Set<string>();
      const memberIds: string[] = [];
      let memberCount = 0;
      for (let page = 0; page < maximumPagesPerGroup; page += 1) {
        const url = new URL(
          `${this.#adminBaseUrl}/organizations/${encodeURIComponent(organization.id)}/members`,
        );
        url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
        url.searchParams.set("max", String(keycloakDirectoryPageSize));
        const body = yield* this.#adminGet(token, url, `The Keycloak members of ${organization.alias}`);
        const listed = yield* decodeUserList(body).pipe(
          Effect.mapError(() => unavailable(`The Keycloak members of ${organization.alias} returned an invalid list.`)),
        );
        memberCount += listed.length;
        if (memberCount > maximumGroups * keycloakDirectoryPageSize) {
          return yield* unavailable(`The Keycloak organization ${organization.alias} has too many members.`);
        }
        for (const member of listed) {
          memberIds.push(member.id);
          seenMemberIds.add(member.id);
          if (member.enabled !== true) continue;
          members.push({
            email: member.email ?? null,
            emailVerified: member.emailVerified === true,
            enabled: true,
            firstName: member.firstName ?? null,
            id: member.id,
            lastName: member.lastName ?? null,
            role: roleByUserId.get(member.id) ?? "viewer",
            username: member.username,
          });
        }
        if (members.length > maximumGroups * keycloakDirectoryPageSize) {
          return yield* unavailable(`The Keycloak organization ${organization.alias} has too many members.`);
        }
        if (listed.length < keycloakDirectoryPageSize) {
          if ([...roleByUserId.keys()].some((id) => !seenMemberIds.has(id))) {
            return yield* unavailable(`Keycloak returned a role-group member missing from organization ${organization.alias}.`);
          }
          break;
        }
        if (page === maximumPagesPerGroup - 1) {
          return yield* unavailable(`The Keycloak organization ${organization.alias} has too many member pages.`);
        }
      }
      // Keycloak's members endpoint has no total-count header. Re-page it once
      // after the snapshot and compare complete sorted ID sets, including each
      // role group, so page-boundary drift cannot hide behind an unchanged count.
      const verificationMemberIds: string[] = [];
      for (let page = 0; page < maximumPagesPerGroup; page += 1) {
        const url = new URL(
          `${this.#adminBaseUrl}/organizations/${encodeURIComponent(organization.id)}/members`,
        );
        url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
        url.searchParams.set("max", String(keycloakDirectoryPageSize));
        const body = yield* this.#adminGet(token, url,
          `The Keycloak member verification for ${organization.alias}`);
        const listed = yield* decodeUserList(body).pipe(
          Effect.mapError(() => unavailable(`The Keycloak member verification for ${organization.alias} returned an invalid list.`)),
        );
        verificationMemberIds.push(...listed.map((member) => member.id));
        if (listed.length < keycloakDirectoryPageSize) break;
        if (page === maximumPagesPerGroup - 1) {
          return yield* unavailable(`The Keycloak organization ${organization.alias} has too many verification pages.`);
        }
      }
      let roleGroupsDrifted = false;
      for (const group of roleGroups) {
        const verificationIds: string[] = [];
        for (let page = 0; page < maximumPagesPerGroup; page += 1) {
          const url = new URL(
            `${this.#adminBaseUrl}/organizations/${encodeURIComponent(organization.id)}` +
              `/groups/${encodeURIComponent(group.id)}/members`,
          );
          url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
          url.searchParams.set("max", String(keycloakDirectoryPageSize));
          const body = yield* this.#adminGet(token, url,
            `The Keycloak verification members of ${group.path} in ${organization.alias}`);
          const listed = yield* decodeUserList(body).pipe(
            Effect.mapError(() => unavailable(`The Keycloak verification members of ${group.path} in ${organization.alias} returned an invalid list.`)),
          );
          verificationIds.push(...listed.map((member) => member.id));
          if (listed.length < keycloakDirectoryPageSize) break;
          if (page === maximumPagesPerGroup - 1) {
            return yield* unavailable(`The Keycloak role group ${group.path} in ${organization.alias} has too many verification pages.`);
          }
        }
        const expectedIds = roleGroupMemberIds.get(group.id) ?? [];
        if (JSON.stringify(verificationIds.toSorted()) !== JSON.stringify(expectedIds)) {
          roleGroupsDrifted = true;
        }
      }
      const drifted = verificationMemberIds.length !== memberCount ||
        JSON.stringify(verificationMemberIds.toSorted()) !== JSON.stringify(memberIds.toSorted()) ||
        roleGroupsDrifted;
      if (drifted) {
        if (retry === 0) return yield* this.listOrganizationMembers(organization, 1);
        return yield* unavailable(`The Keycloak organization ${organization.alias} membership changed during both sync attempts.`);
      }
      return members;
    },
  );

  /**
   * List every group in the realm, subgroups included, by walking Keycloak's
   * paged top-level listing and each group's children.
   */
  readonly listAllGroups = Effect.fn("KeycloakDirectory.listAllGroups")(
    function*(this: KeycloakDirectory) {
      const token = yield* this.#accessToken();
      const groups: DirectoryGroupRecord[] = [];
      const pending = [{parentPath: "", url: `${this.#adminBaseUrl}/groups`}];
      for (let next = pending.shift(); next !== undefined; next = pending.shift()) {
        for (let page = 0; ; page += 1) {
          if (page >= maximumPagesPerGroup) {
            return yield* unavailable("The Keycloak group listing has too many pages.");
          }
          const url = new URL(next.url);
          url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
          url.searchParams.set("max", String(keycloakDirectoryPageSize));
          url.searchParams.set("briefRepresentation", "true");
          const body = yield* this.#adminGet(token, url, "The Keycloak group listing");
          const listed = yield* decodeGroupTree(body).pipe(
            Effect.mapError(() =>
              unavailable("The Keycloak group listing returned an invalid list.")
            ),
          );
          for (const group of listed) {
            const path = group.path ?? `${next.parentPath}/${group.name}`;
            groups.push({id: group.id, name: group.name, path});
            if (groups.length > maximumGroups) {
              return yield* unavailable("Keycloak lists more groups than one sync reads.");
            }
            // An older Keycloak omits the count; ask for children then.
            if (group.subGroupCount !== 0) {
              pending.push({
                parentPath: path,
                url: `${this.#adminBaseUrl}/groups/${encodeURIComponent(group.id)}/children`,
              });
            }
          }
          if (listed.length < keycloakDirectoryPageSize) break;
        }
      }
      return groups;
    },
  );

  /**
   * Read the direct members of the realm group at one full path. A missing
   * group fails the pass: a staff selector that cannot be resolved must never
   * silently admit staff unmasked.
   */
  readonly listGroupMemberIdsByPath = Effect.fn("KeycloakDirectory.listGroupMemberIdsByPath")(
    function*(this: KeycloakDirectory, path: string) {
      const segments = path.split("/").filter((segment) => segment !== "");
      if (!path.startsWith("/") || segments.length === 0) {
        return yield* unavailable(`The staff group selector ${path} is not a full group path.`);
      }
      const token = yield* this.#accessToken();
      const url = new URL(
        `${this.#adminBaseUrl}/group-by-path/${segments.map((segment) => encodeURIComponent(segment)).join("/")}`,
      );
      const body = yield* this.#adminGet(token, url, `The Keycloak staff group ${path}`);
      const group = yield* decodeGroupByPath(body).pipe(
        Effect.mapError(() => unavailable(`The Keycloak staff group ${path} returned an invalid group.`)),
      );
      if (group.path !== path) {
        return yield* unavailable(`The Keycloak staff group ${path} resolved to a different path.`);
      }
      const users = yield* this.#groupMembers(token, path, group.id);
      return users.map(({id}) => id);
    },
  );

  /** Read one group's complete direct membership. */
  readonly listGroupMembers = Effect.fn("KeycloakDirectory.listGroupMembers")(
    function*(this: KeycloakDirectory, group: DirectoryGroupRecord) {
      const token = yield* this.#accessToken();
      return yield* this.#groupMembers(token, group.path, group.id);
    },
  );

  readonly #accessToken = Effect.fn("KeycloakDirectory.accessToken")(
    function*(this: KeycloakDirectory) {
      if (this.#cachedToken !== null && Date.now() < this.#cachedToken.until) {
        return this.#cachedToken.token;
      }
      const tokenEndpoint = this.#tokenEndpoint ?? (yield* Effect.tryPromise({
        try: async () => {
          const server = await loadOidcAuthorizationServer(this.#issuer, {
            fetch: this.#fetch,
          });
          return server.metadata.token_endpoint;
        },
        catch: () => unavailable("The Keycloak discovery document could not be read."),
      }));
      const response = yield* this.#request(tokenEndpoint, {
        body: new URLSearchParams({
          client_id: this.#clientId,
          client_secret: Redacted.value(this.#clientSecret),
          grant_type: "client_credentials",
        }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        method: "POST",
      }, "The Keycloak token request");
      const body = yield* decodeTokenResponse(response).pipe(
        Effect.mapError(() =>
          unavailable("The Keycloak token response carried no access token.")
        ),
      );
      const token = Redacted.make(body.access_token, {label: "keycloak-directory-token"});
      this.#cachedToken = {token, until: Date.now() + tokenReuseMilliseconds};
      return token;
    },
  );

  readonly #groupId = Effect.fn("KeycloakDirectory.groupId")(function*(
    this: KeycloakDirectory,
    token: Redacted.Redacted,
    name: string,
  ) {
    const url = new URL(`${this.#adminBaseUrl}/groups`);
    url.searchParams.set("search", name);
    url.searchParams.set("exact", "true");
    const body = yield* this.#adminGet(token, url, `The Keycloak group ${name}`);
    const groups = yield* decodeGroupList(body).pipe(
      Effect.mapError(() =>
        unavailable(`The Keycloak group search for ${name} returned an invalid list.`)
      ),
    );
    const group = groups.find((candidate) => candidate.name === name);
    if (group === undefined) {
      return yield* unavailable(`The Keycloak group ${name} does not exist.`);
    }
    return group.id;
  });

  readonly #groupMembers = Effect.fn("KeycloakDirectory.groupMembers")(function*(
    this: KeycloakDirectory,
    token: Redacted.Redacted,
    name: string,
    id: string,
  ) {
    const users: DirectoryUser[] = [];
    for (let page = 0; page < maximumPagesPerGroup; page += 1) {
      const url = new URL(
        `${this.#adminBaseUrl}/groups/${encodeURIComponent(id)}/members`,
      );
      url.searchParams.set("first", String(page * keycloakDirectoryPageSize));
      url.searchParams.set("max", String(keycloakDirectoryPageSize));
      url.searchParams.set("briefRepresentation", "true");
      const body = yield* this.#adminGet(
        token,
        url,
        `The Keycloak members of ${name}`,
      );
      const members = yield* decodeUserList(body).pipe(
        Effect.mapError(() =>
          unavailable(`The Keycloak members of ${name} are not a user list.`)
        ),
      );
      for (const member of members) {
        users.push({
          email: member.email ?? null,
          emailVerified: member.emailVerified === true,
          enabled: member.enabled === true,
          firstName: member.firstName ?? null,
          id: member.id,
          lastName: member.lastName ?? null,
          username: member.username,
        });
      }
      if (members.length < keycloakDirectoryPageSize) return users;
    }
    return yield* unavailable(
      `The Keycloak group ${name} has more members than one sync reads.`,
    );
  });

  #adminGet(
    token: Redacted.Redacted,
    url: URL,
    subject: string,
  ): Effect.Effect<Schema.Json, DirectoryUnavailable> {
    return this.#request(url.toString(), {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${Redacted.value(token)}`,
      },
      method: "GET",
    }, subject);
  }

  /**
   * One bounded request whose JSON answer is returned only on HTTP 200. A
   * timeout, network fault or HTTP 5xx is retried with backoff; any other
   * answer fails at once.
   */
  #request(
    url: string,
    init: RequestInit,
    subject: string,
  ): Effect.Effect<Schema.Json, DirectoryUnavailable> {
    const attempt = (number: number): Effect.Effect<Schema.Json, DirectoryUnavailable> =>
      this.#requestOnce(url, init, subject).pipe(
        Effect.catch((failure) =>
          failure.retryable && number < requestAttempts
            ? Effect.sleep(this.#retryBaseDelayMilliseconds * 2 ** (number - 1)).pipe(
              Effect.andThen(attempt(number + 1)),
            )
            : Effect.fail(unavailable(failure.message))
        ),
      );
    return attempt(1);
  }

  #requestOnce(
    url: string,
    init: RequestInit,
    subject: string,
  ): Effect.Effect<Schema.Json, {readonly message: string; readonly retryable: boolean}> {
    return Effect.tryPromise({
      try: async (signal) => {
        const response = await this.#fetch(url, {
          ...init,
          // A followed redirect would replay the client secret or the token.
          redirect: "manual",
          signal: AbortSignal.any([
            signal,
            AbortSignal.timeout(requestTimeoutMilliseconds),
          ]),
        });
        if (response.status !== 200) {
          throw new HttpStatusFailure(
            `${subject} returned HTTP ${response.status}.`,
            response.status >= 500,
          );
        }
        try {
          const body: Schema.Json = await response.json();
          return body;
        } catch (cause) {
          // Only a malformed body is final; a timeout or reset mid-body retries.
          if (cause instanceof SyntaxError) {
            throw new HttpStatusFailure(`${subject} returned invalid JSON.`, false);
          }
          throw cause;
        }
      },
      catch: (cause) =>
        cause instanceof HttpStatusFailure
          ? {message: cause.message, retryable: cause.retryable}
          : {message: `${subject} failed after ${requestAttempts} attempts.`, retryable: true},
    });
  }
}

class HttpStatusFailure extends Error {
  readonly retryable: boolean;

  constructor(message: string, retryable: boolean) {
    super(message);
    this.retryable = retryable;
  }
}

function clusterOrNormalized(value: string, allowLocalHttp: boolean): string | null {
  return isClusterServiceUrl(value) ? value : normalizeOidcEndpoint(value, allowLocalHttp);
}

function unavailable(message: string): DirectoryUnavailable {
  return new DirectoryUnavailable({message});
}

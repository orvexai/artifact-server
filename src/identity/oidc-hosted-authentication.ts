import {Effect, type Redacted} from "effect";

import type {
  ExternalMcpBearerVerifier,
  VerifiedExternalMcpBearer,
} from "../application/authentication.js";
import type {InteractiveIdentityProvider} from "../application/interactive-login.js";
import {
  AuthenticationRequired,
  IdentityProviderFailure,
} from "../core/errors.js";
import type {GroupRolePolicy} from "../core/group-role-policy.js";
import type {ExternalIdentity} from "../core/installation-identity.js";
import type {
  ApiOAuthResourceConfiguration,
  DiscoveredOAuthResources,
  DiscoveredOAuthState,
  McpOAuthResourceConfiguration,
} from "../http/create-http-app.js";
import {
  type DiscoveryEvent,
  type DiscoveryRetryPolicy,
  type DiscoveryState,
  RetryingDiscovery,
  type RetryingDiscoveryOptions,
} from "./discovery-retry.js";
import type {OidcGroupRoles} from "./oidc-groups-claim.js";
import {createOidcIdentityProvider} from "./oidc-identity-provider.js";
import {requireOidcIssuer} from "./oidc-issuer.js";
import {
  OidcMcpBearerVerifier,
  type OidcMcpBearerVerifierConfig,
} from "./oidc-mcp-bearer-verifier.js";
import {
  loadOidcAuthorizationServer,
  OidcDiscoveryMisconfiguration,
} from "./oidc-oauth-metadata.js";

export interface OidcHostedAuthenticationConfig {
  readonly apiJwksUri?: string | null;
  readonly apiResource?: string | null;
  readonly applicationOrigin: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted | null;
  readonly fetch?: typeof globalThis.fetch;
  readonly groupRoles?: OidcGroupRoles | null;
  readonly issuer: string;
  readonly scopes: string;
}

export interface OidcHostedAuthentication {
  readonly apiOAuthResource: ApiOAuthResourceConfiguration;
  readonly externalApiOAuthVerifier: ExternalMcpBearerVerifier;
  readonly externalMcpOAuthVerifier: ExternalMcpBearerVerifier;
  /** Issuer groups that admit people and set their role, when configured. */
  readonly groupRolePolicy: GroupRolePolicy | null;
  readonly interactiveIdentityProvider: InteractiveIdentityProvider;
  readonly mcpOAuthResource: McpOAuthResourceConfiguration;
}

/**
 * Build browser, API, and MCP authentication from one generic OIDC issuer,
 * failing when the issuer cannot be discovered right now.
 */
export async function createOidcHostedAuthentication(
  config: OidcHostedAuthenticationConfig,
): Promise<OidcHostedAuthentication> {
  const issuer = requireOidcIssuer(config.issuer, "ARTIFACT_SERVER_OIDC_ISSUER");
  const apiResource = config.apiResource ??
    new URL("/api", config.applicationOrigin).toString();
  const resource = new URL("/mcp", config.applicationOrigin).toString();
  const groupRoles = config.groupRoles ?? null;
  const authorizationServer = await loadOidcAuthorizationServer(
    issuer,
    config.fetch === undefined ? {} : {fetch: config.fetch},
  );
  let verifierConfig: OidcMcpBearerVerifierConfig = {
    audience: resource,
    groupsClaim: groupRoles?.claim ?? null,
    issuer,
    jwksUri: authorizationServer.jwksUri,
    userInfoEndpoint: authorizationServer.userInfoEndpoint,
  };
  if (config.fetch !== undefined) {
    verifierConfig = {...verifierConfig, fetch: config.fetch};
  }
  const apiVerifierConfig = {
    ...verifierConfig,
    audience: apiResource,
    jwksUri: config.apiJwksUri ?? authorizationServer.jwksUri,
  };
  return {
    apiOAuthResource: {
      authorizationServers: [issuer],
      resource: apiResource,
    },
    externalApiOAuthVerifier: new OidcMcpBearerVerifier(apiVerifierConfig),
    externalMcpOAuthVerifier: new OidcMcpBearerVerifier(verifierConfig),
    groupRolePolicy: groupRoles,
    interactiveIdentityProvider: createOidcIdentityProvider({
      applicationOrigin: config.applicationOrigin,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      groupRoles,
      issuer,
      scopes: config.scopes,
    }),
    mcpOAuthResource: {
      authorizationServerMetadata: authorizationServer.metadata,
      resource,
    },
  };
}

/**
 * Generic OIDC authentication whose OAuth half follows issuer discovery.
 *
 * Browser login is always present and discovers lazily on its own. API OAuth,
 * MCP OAuth, and both protected-resource documents appear the moment discovery
 * succeeds, without a restart, and never disappear afterwards.
 */
export interface StartedOidcHostedAuthentication {
  readonly discoveredOAuth: DiscoveredOAuthResources;
  readonly externalApiOAuthVerifier: ExternalMcpBearerVerifier;
  readonly externalMcpOAuthVerifier: ExternalMcpBearerVerifier;
  readonly groupRolePolicy: GroupRolePolicy | null;
  readonly interactiveIdentityProvider: InteractiveIdentityProvider;
  /** Stop background discovery retries. */
  close(): void;
}

export interface StartOidcHostedAuthenticationOptions {
  readonly now?: () => number;
  readonly onEvent?: (event: DiscoveryEvent) => void;
  readonly policy?: DiscoveryRetryPolicy;
  readonly random?: () => number;
}

/**
 * Try discovery once, then keep retrying a transient failure in the background.
 *
 * The first attempt is awaited, so a healthy issuer starts the process with
 * OAuth on exactly as before. An issuer that is down, slow, or answering with
 * an error leaves the process running and not ready until a later attempt, or
 * a request that needs OAuth, succeeds. A discovery document that contradicts
 * this installation (another issuer, no S256 PKCE, a non-HTTPS endpoint) is a
 * permanent misconfiguration: OAuth stays off and nothing is retried.
 */
export async function startOidcHostedAuthentication(
  config: OidcHostedAuthenticationConfig,
  options: StartOidcHostedAuthenticationOptions = {},
): Promise<StartedOidcHostedAuthentication> {
  const issuer = requireOidcIssuer(config.issuer, "ARTIFACT_SERVER_OIDC_ISSUER");
  const mcpResource = new URL("/mcp", config.applicationOrigin).toString();
  const groupRoles = config.groupRoles ?? null;
  let discoveryOptions: RetryingDiscoveryOptions<OidcHostedAuthentication> = {
    attempt: () => createOidcHostedAuthentication({...config, issuer}),
    classify: (cause) => cause instanceof OidcDiscoveryMisconfiguration
      ? "misconfigured"
      : "transient",
    describe: (cause) => cause instanceof Error
      ? cause.message
      : "the request failed",
  };
  if (options.now !== undefined) {
    discoveryOptions = {...discoveryOptions, now: options.now};
  }
  if (options.onEvent !== undefined) {
    discoveryOptions = {...discoveryOptions, onEvent: options.onEvent};
  }
  if (options.policy !== undefined) {
    discoveryOptions = {...discoveryOptions, policy: options.policy};
  }
  if (options.random !== undefined) {
    discoveryOptions = {...discoveryOptions, random: options.random};
  }
  const discovery = new RetryingDiscovery(discoveryOptions);
  await discovery.start();
  const now = options.now ?? Date.now;
  return {
    discoveredOAuth: {
      current: () => discoveredOAuthState(discovery.current(), now),
      mcpResource,
      refresh: async () => discoveredOAuthState(await discovery.refresh(), now),
    },
    externalApiOAuthVerifier: new DiscoveredOidcBearerVerifier(
      discovery,
      (hosted) => hosted.externalApiOAuthVerifier,
      "A valid Artifact Server API key is required.",
    ),
    externalMcpOAuthVerifier: new DiscoveredOidcBearerVerifier(
      discovery,
      (hosted) => hosted.externalMcpOAuthVerifier,
      "A valid Artifact Server MCP credential is required.",
    ),
    groupRolePolicy: groupRoles,
    interactiveIdentityProvider: createOidcIdentityProvider({
      applicationOrigin: config.applicationOrigin,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      groupRoles,
      issuer,
      scopes: config.scopes,
    }),
    close: () => discovery.close(),
  };
}

function discoveredOAuthState(
  state: DiscoveryState<OidcHostedAuthentication>,
  now: () => number,
): DiscoveredOAuthState {
  if (state.status === "ready") {
    return {
      api: state.value.apiOAuthResource,
      mcp: state.value.mcpOAuthResource,
      status: "enabled",
    };
  }
  if (state.status === "misconfigured") return {status: "misconfigured"};
  return {
    retryAfterSeconds: state.nextAttemptAt === null
      ? 1
      : Math.max(1, Math.ceil((state.nextAttemptAt - now()) / 1_000)),
    status: "discovering",
  };
}

/**
 * A bearer verifier that exists before its issuer is discovered.
 *
 * Once discovery succeeds it is exactly the discovered verifier. Before that,
 * a token asks for one more discovery attempt and, if the issuer is still
 * unknown, fails as an unavailable provider rather than as a bad token. A
 * misconfigured issuer leaves OAuth off, so a token is simply not a credential.
 */
class DiscoveredOidcBearerVerifier implements ExternalMcpBearerVerifier {
  readonly #discovery: RetryingDiscovery<OidcHostedAuthentication>;
  readonly #select: (
    hosted: OidcHostedAuthentication,
  ) => ExternalMcpBearerVerifier;
  readonly #unconfiguredMessage: string;

  constructor(
    discovery: RetryingDiscovery<OidcHostedAuthentication>,
    select: (hosted: OidcHostedAuthentication) => ExternalMcpBearerVerifier,
    unconfiguredMessage: string,
  ) {
    this.#discovery = discovery;
    this.#select = select;
    this.#unconfiguredMessage = unconfiguredMessage;
  }

  readonly verify = (
    credential: Redacted.Redacted,
  ): Effect.Effect<
    VerifiedExternalMcpBearer,
    AuthenticationRequired | IdentityProviderFailure
  > => this.#verifier().pipe(
    Effect.flatMap((verifier) => verifier.verify(credential)),
  );

  readonly resolveIdentity = (
    verified: VerifiedExternalMcpBearer,
    credential: Redacted.Redacted,
  ): Effect.Effect<
    ExternalIdentity,
    AuthenticationRequired | IdentityProviderFailure
  > => this.#verifier().pipe(
    Effect.flatMap((verifier) => verifier.resolveIdentity(verified, credential)),
  );

  #verifier(): Effect.Effect<
    ExternalMcpBearerVerifier,
    AuthenticationRequired | IdentityProviderFailure
  > {
    const current = this.#discovery.current();
    if (current.status !== "discovering") {
      return Effect.suspend(() => this.#settled(current));
    }
    return Effect.promise(() => this.#discovery.refresh()).pipe(
      Effect.flatMap((state) => this.#settled(state)),
    );
  }

  #settled(
    state: DiscoveryState<OidcHostedAuthentication>,
  ): Effect.Effect<
    ExternalMcpBearerVerifier,
    AuthenticationRequired | IdentityProviderFailure
  > {
    if (state.status === "ready") {
      return Effect.succeed(this.#select(state.value));
    }
    if (state.status === "misconfigured") {
      return Effect.fail(new AuthenticationRequired({
        message: this.#unconfiguredMessage,
      }));
    }
    return Effect.fail(new IdentityProviderFailure({
      message:
        "The OIDC issuer has not been discovered yet, so OAuth access tokens cannot be verified. Retry shortly.",
    }));
  }
}

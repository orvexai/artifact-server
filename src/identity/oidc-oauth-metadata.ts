import type {OAuthMetadata} from "@modelcontextprotocol/server";
import {z} from "zod";

import {
  isLocalOidcIssuer,
  normalizeOidcEndpoint,
  normalizeOidcIssuer,
  requireOidcIssuer,
} from "./oidc-issuer.js";

const openIdConfigurationPath = "/.well-known/openid-configuration";
const defaultTimeoutMilliseconds = 5_000;

const discoveryDocumentSchema = z.looseObject({
  authorization_endpoint: z.string().min(1),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  issuer: z.string().min(1),
  jwks_uri: z.string().min(1),
  registration_endpoint: z.string().min(1).optional(),
  response_types_supported: z.array(z.string()),
  revocation_endpoint: z.string().min(1).optional(),
  token_endpoint: z.string().min(1),
  userinfo_endpoint: z.string().min(1).optional(),
});

/**
 * A discovery document that was fetched and read, but contradicts what this
 * installation requires. Retrying cannot help until the issuer is reconfigured,
 * unlike an outage, a timeout, or an unreadable answer.
 */
export class OidcDiscoveryMisconfiguration extends Error {
  override readonly name = "OidcDiscoveryMisconfiguration";
}

/** Authorization-server contract one OIDC issuer offers to MCP clients. */
export interface OidcAuthorizationServer {
  readonly jwksUri: string;
  readonly metadata: OAuthMetadata;
  readonly userInfoEndpoint: string | null;
}

export interface OidcOAuthMetadataOptions {
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMilliseconds?: number;
}

/**
 * Fetch and validate the OIDC authorization-server contract.
 *
 * A contradiction in a document that was read throws
 * {@link OidcDiscoveryMisconfiguration}; every other failure is an ordinary
 * error a caller may retry.
 */
export async function loadOidcAuthorizationServer(
  issuer: string,
  options: OidcOAuthMetadataOptions = {},
): Promise<OidcAuthorizationServer> {
  const exactIssuer = requireOidcIssuer(issuer, "The OIDC issuer");
  const timeoutMilliseconds = options.timeoutMilliseconds ??
    defaultTimeoutMilliseconds;
  let response: Response;
  try {
    response = await (options.fetch ?? globalThis.fetch)(
      `${exactIssuer}${openIdConfigurationPath}`,
      {
        headers: {Accept: "application/json"},
        // Never follow discovery off the validated issuer origin.
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMilliseconds),
      },
    );
  } catch (cause) {
    throw new Error(discoveryRequestFailure(cause, timeoutMilliseconds), {
      cause,
    });
  }
  if (!response.ok) {
    throw new Error(`OIDC discovery returned HTTP ${response.status}.`);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch (cause) {
    throw new Error("OIDC discovery returned a document that is not JSON.", {
      cause,
    });
  }
  const parsed = discoveryDocumentSchema.safeParse(body);
  if (!parsed.success) {
    throw new Error(
      "OIDC discovery returned a document without the required issuer, endpoints, and response types.",
    );
  }
  const document = parsed.data;
  if (normalizeOidcIssuer(document.issuer) !== exactIssuer) {
    throw new OidcDiscoveryMisconfiguration(
      "OIDC discovery returned a different issuer.",
    );
  }
  const allowLocalHttp = isLocalOidcIssuer(exactIssuer);
  const authorizationEndpoint = requireEndpoint(
    document.authorization_endpoint,
    "authorization endpoint",
    allowLocalHttp,
  );
  const tokenEndpoint = requireEndpoint(
    document.token_endpoint,
    "token endpoint",
    allowLocalHttp,
  );
  const jwksUri = requireEndpoint(document.jwks_uri, "JWKS URI", allowLocalHttp);
  const userInfoEndpoint = optionalEndpoint(
    document.userinfo_endpoint,
    "userinfo endpoint",
    allowLocalHttp,
  );
  // The document is served back as the issuer publishes it, and an MCP client
  // reads the same document from the issuer anyway. These two endpoints are
  // still checked, because a client sends its registration and its tokens to
  // them, and this server must not advertise one it would refuse to use.
  const registrationEndpoint = optionalEndpoint(
    document.registration_endpoint,
    "registration endpoint",
    allowLocalHttp,
  );
  const revocationEndpoint = optionalEndpoint(
    document.revocation_endpoint,
    "revocation endpoint",
    allowLocalHttp,
  );
  if (!document.response_types_supported.includes("code")) {
    throw new OidcDiscoveryMisconfiguration(
      "OIDC discovery does not support authorization code login.",
    );
  }
  if (!document.code_challenge_methods_supported?.includes("S256")) {
    throw new OidcDiscoveryMisconfiguration(
      "OIDC discovery does not advertise S256 PKCE.",
    );
  }
  let metadata: OAuthMetadata = {
    ...document,
    authorization_endpoint: authorizationEndpoint,
    issuer: exactIssuer,
    jwks_uri: jwksUri,
    token_endpoint: tokenEndpoint,
  };
  if (registrationEndpoint !== null) {
    metadata = {...metadata, registration_endpoint: registrationEndpoint};
  }
  if (revocationEndpoint !== null) {
    metadata = {...metadata, revocation_endpoint: revocationEndpoint};
  }
  return {jwksUri, metadata, userInfoEndpoint};
}

function optionalEndpoint(
  value: string | undefined,
  name: string,
  allowLocalHttp: boolean,
): string | null {
  return value === undefined
    ? null
    : requireEndpoint(value, name, allowLocalHttp);
}

function requireEndpoint(
  value: string,
  name: string,
  allowLocalHttp: boolean,
): string {
  const endpoint = normalizeOidcEndpoint(value, allowLocalHttp);
  if (endpoint === null) {
    throw new OidcDiscoveryMisconfiguration(
      `The OIDC ${name} must be an HTTPS URL.`,
    );
  }
  return endpoint;
}

function discoveryRequestFailure(
  cause: unknown,
  timeoutMilliseconds: number,
): string {
  if (
    cause instanceof Error &&
    (cause.name === "TimeoutError" || cause.name === "AbortError")
  ) {
    return `OIDC discovery did not answer within ${
      timeoutMilliseconds / 1_000
    } seconds.`;
  }
  const reason = cause instanceof Error ? cause.message : "the request failed";
  return `OIDC discovery could not reach the issuer: ${reason}.`;
}

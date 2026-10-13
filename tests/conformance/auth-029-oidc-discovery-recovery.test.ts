import {createServer, type Server} from "node:http";

import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {Effect} from "effect";
import {
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JWK,
  SignJWT,
} from "jose";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {refreshCliOAuthCredential} from "../../src/cli/cli-oauth-client.js";
import {oauthCredential} from "../../src/cli/cli-profile-credential.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import type {DiscoveryEvent, DiscoveryRetryPolicy} from
  "../../src/identity/discovery-retry.js";
import {
  startOidcHostedAuthentication,
  type StartedOidcHostedAuthentication,
} from "../../src/identity/oidc-hosted-authentication.js";
import {
  createTestInstallation,
  removeTestInstallation,
  reserveLoopbackPort,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

const protocolVersion = "2026-07-28";
const realmPath = "/realms/artifact";
const subject = "5c0ffee0-0000-4000-8000-artifactserver";
const userEmail = "administrator@example.test";
const mcpMetadataPath = "/.well-known/oauth-protected-resource/mcp";
const apiMetadataPath = "/.well-known/oauth-protected-resource/api";
const authorizationServerPath = "/.well-known/oauth-authorization-server";
const metadataPaths = [mcpMetadataPath, apiMetadataPath, authorizationServerPath];

const readinessSchema = z.object({
  components: z.object({
    identity: z.object({
      latencyMilliseconds: z.number(),
      oauth: z.enum(["discovering", "enabled", "misconfigured"]),
      status: z.enum(["ready", "unavailable"]),
    }),
  }).loose(),
  status: z.enum(["ready", "not_ready"]),
}).loose();
const temporarilyUnavailableSchema = z.object({
  error: z.literal("temporarily_unavailable"),
  error_description: z.string().min(1),
});
const apiFailureSchema = z.object({
  error: z.object({code: z.string(), message: z.string()}),
});

/** No background retry: only requests that need OAuth can discover. */
const onDemandOnly: DiscoveryRetryPolicy = {
  initialDelayMilliseconds: 600_000,
  maximumDelayMilliseconds: 600_000,
  onDemandIntervalMilliseconds: 0,
};
/** Fast background retry; requests never trigger an attempt of their own. */
const backgroundOnly: DiscoveryRetryPolicy = {
  initialDelayMilliseconds: 40,
  maximumDelayMilliseconds: 160,
  onDemandIntervalMilliseconds: 600_000,
};

describe("OIDC discovery that fails at startup", {timeout: 30_000}, () => {
  let authentication: StartedOidcHostedAuthentication | null = null;
  let events: DiscoveryEvent[];
  let installation: TestInstallation;
  let issuer: FakeIssuer;
  let keyId: string;
  let privateKey: CryptoKey;
  let server: RunningTestServer | null = null;

  beforeEach(async () => {
    const keys = await generateKeyPair("RS256");
    privateKey = keys.privateKey;
    keyId = crypto.randomUUID();
    issuer = await startFakeIssuer({
      ...await exportJWK(keys.publicKey),
      alg: "RS256",
      kid: keyId,
      use: "sig",
    });
    installation = await createTestInstallation();
    events = [];
  });

  afterEach(async () => {
    if (server !== null) await server.stop();
    server = null;
    authentication?.close();
    authentication = null;
    await issuer.close();
    await removeTestInstallation(installation);
  });

  /** Start OIDC authentication and the real server around it, once. */
  async function startServer(policy: DiscoveryRetryPolicy): Promise<string> {
    const port = await reserveLoopbackPort();
    const applicationOrigin = `http://127.0.0.1:${port}`;
    const started = await startOidcHostedAuthentication({
      applicationOrigin,
      clientId: "artifact-server",
      clientSecret: null,
      issuer: issuer.issuer,
      scopes: "openid email profile",
    }, {onEvent: (event) => events.push(event), policy});
    authentication = started;
    server = await startTestServer(installation, {
      applicationOrigin,
      bootstrapAdministratorEmail: userEmail,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      discoveredOAuth: started.discoveredOAuth,
      externalApiOAuthVerifier: started.externalApiOAuthVerifier,
      externalMcpOAuthVerifier: started.externalMcpOAuthVerifier,
      interactiveIdentityProvider: started.interactiveIdentityProvider,
      port,
    });
    return applicationOrigin;
  }

  test("AUTH-029-B: an issuer that is down at startup holds readiness, then turns API and MCP OAuth on without a restart", async () => {
    issuer.setDiscovery("unavailable");
    const origin = await startServer(backgroundOnly);
    const runningServer = requireServer(server);
    const mcpToken = await issueToken(`${origin}/mcp`);
    const apiToken = await issueToken(`${origin}/api`);

    // Liveness stays up so the pod is not killed; readiness holds the rollout.
    expect((await fetch(`${origin}/health`)).status).toBe(200);
    const notReady = await fetch(`${origin}/ready`);
    expect(notReady.status).toBe(503);
    expect(readinessSchema.parse(await notReady.json())).toMatchObject({
      components: {
        identity: {oauth: "discovering", status: "unavailable"},
      },
      status: "not_ready",
    });

    // OAuth is temporarily unavailable, never "not configured".
    const heldMetadata = await Promise.all(
      metadataPaths.map((metadataPath) => fetch(`${origin}${metadataPath}`)),
    );
    expect(heldMetadata.map((metadata) => metadata.status)).toEqual([503, 503, 503]);
    for (const metadata of heldMetadata) {
      expect(Number(metadata.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
      expect(metadata.headers.get("cache-control")).toBe("no-store");
    }
    await Promise.all(heldMetadata.map(async (metadata) =>
      temporarilyUnavailableSchema.parse(await metadata.json())
    ));
    const heldMcp = await mcpDiscovery(origin, mcpToken);
    expect(heldMcp.status).toBe(503);
    expect(heldMcp.headers.get("retry-after")).not.toBeNull();
    temporarilyUnavailableSchema.parse(await heldMcp.json());
    const heldApi = await apiSession(origin, apiToken);
    expect(heldApi.status).toBe(503);
    expect(heldApi.headers.get("retry-after")).not.toBeNull();
    expect(apiFailureSchema.parse(await heldApi.json()).error.code)
      .toBe("IDENTITY_PROVIDER_UNAVAILABLE");

    // Managed API keys never needed the issuer and keep working throughout.
    expect((await apiSession(origin, installation.apiToken)).status).toBe(200);
    expect((await mcpDiscovery(origin, installation.apiToken)).status).toBe(200);

    // Discovery keeps retrying in the background while the issuer is down.
    const retriesBefore = issuer.discoveryRequests();
    await waitUntil(() => issuer.discoveryRequests() >= retriesBefore + 2);
    expect(events.filter((event) => event.kind === "retrying").length)
      .toBeGreaterThanOrEqual(3);

    issuer.setDiscovery("valid");
    await waitUntil(async () => (await fetch(`${origin}/ready`)).status === 200);
    const ready = await fetch(`${origin}/ready`);
    expect(readinessSchema.parse(await ready.json())).toMatchObject({
      components: {identity: {oauth: "enabled", status: "ready"}},
      status: "ready",
    });
    expect(events.at(-1)).toMatchObject({kind: "recovered"});

    const mcpMetadata = await fetch(`${origin}${mcpMetadataPath}`);
    expect(mcpMetadata.status).toBe(200);
    expect(await mcpMetadata.json()).toMatchObject({
      authorization_servers: [issuer.issuer],
      bearer_methods_supported: ["header"],
      resource: `${origin}/mcp`,
    });
    const apiMetadata = await fetch(`${origin}${apiMetadataPath}`);
    expect(apiMetadata.status).toBe(200);
    expect(await apiMetadata.json()).toMatchObject({
      authorization_servers: [issuer.issuer],
      resource: `${origin}/api`,
    });
    const authorizationServer = await fetch(`${origin}${authorizationServerPath}`);
    expect(authorizationServer.status).toBe(200);
    expect(await authorizationServer.json()).toMatchObject({issuer: issuer.issuer});

    const challenge = await mcpDiscovery(origin, null);
    expect(challenge.status).toBe(401);
    expect(challenge.headers.get("www-authenticate"))
      .toContain(`resource_metadata="${origin}${mcpMetadataPath}"`);

    // The very tokens refused during the outage are accepted now.
    expect((await mcpDiscovery(origin, mcpToken)).status).toBe(200);
    expect((await apiSession(origin, apiToken)).status).toBe(200);
    const wrongAudience = await apiSession(origin, mcpToken);
    expect(wrongAudience.status).toBe(401);
    expect(wrongAudience.headers.get("www-authenticate"))
      .toContain(`resource_metadata="${origin}${apiMetadataPath}"`);

    // Same process, same listener: nothing was restarted, and retries stopped.
    expect(requireServer(server)).toBe(runningServer);
    const settled = issuer.discoveryRequests();
    await delay(400);
    expect(issuer.discoveryRequests()).toBe(settled);
  });

  test("the first request that needs OAuth discovers a recovered issuer at once", async () => {
    issuer.setDiscovery("unavailable");
    const origin = await startServer(onDemandOnly);
    const mcpToken = await issueToken(`${origin}/mcp`);
    expect((await mcpDiscovery(origin, mcpToken)).status).toBe(503);

    issuer.setDiscovery("valid");
    // Readiness only reports; it does not reach the issuer itself.
    expect((await fetch(`${origin}/ready`)).status).toBe(503);
    expect((await mcpDiscovery(origin, mcpToken)).status).toBe(200);
    expect((await fetch(`${origin}/ready`)).status).toBe(200);
    expect((await fetch(`${origin}${apiMetadataPath}`)).status).toBe(200);
  });

  test("the CLI reads a server still discovering its issuer as temporarily unavailable, not as a revoked grant", async () => {
    issuer.setDiscovery("unavailable");
    const origin = await startServer(onDemandOnly);
    const failure = await Effect.runPromise(Effect.flip(refreshCliOAuthCredential(
      origin,
      oauthCredential({
        clientInformation: {client_id: "artifact-cli"},
        redirectUrl: "http://127.0.0.1:9/callback",
        tokens: {
          access_token: "expired-access-token",
          expires_in: 60,
          refresh_token: "refresh-token",
          token_type: "Bearer",
        },
        tokensSavedAt: "2026-01-01T00:00:00.000Z",
      }),
      {},
      true,
    )));
    expect(failure).toMatchObject({reason: "server_unavailable"});
    expect(failure.message).toContain("temporarily unavailable");
  });

  test("AUTH-029-F: an unreadable issuer never reports ready or unconfigured, a burst reaches it once, and a misconfigured issuer is not retried", async () => {
    issuer.setDiscovery("unreadable");
    const origin = await startServer(onDemandOnly);
    const mcpToken = await issueToken(`${origin}/mcp`);
    expect((await fetch(`${origin}/ready`)).status).toBe(503);
    expect(await metadataStatuses(origin)).toEqual([503, 503, 503]);
    expect((await mcpDiscovery(origin, mcpToken)).status).toBe(503);
    expect((await mcpDiscovery(origin, null)).status).toBe(503);

    // A slow issuer and a burst of requests: one attempt in flight, joined.
    issuer.setDiscoveryDelay(300);
    const before = issuer.discoveryRequests();
    const burst = await Promise.all(
      Array.from({length: 8}, () => mcpDiscovery(origin, mcpToken)),
    );
    expect(burst.map((response) => response.status))
      .toEqual(Array.from({length: 8}, () => 503));
    expect(issuer.discoveryRequests()).toBe(before + 1);
    expect(events.every((event) => event.kind === "retrying")).toBe(true);
    await requireServer(server).stop();
    server = null;
    authentication?.close();

    // A document that names another issuer cannot become right by waiting.
    issuer.setDiscoveryDelay(0);
    issuer.setDiscovery("foreign-issuer");
    events = [];
    const misconfiguredOrigin = await startServer({
      ...backgroundOnly,
      onDemandIntervalMilliseconds: 0,
    });
    const attempts = issuer.discoveryRequests();
    const ready = await fetch(`${misconfiguredOrigin}/ready`);
    expect(ready.status).toBe(200);
    expect(readinessSchema.parse(await ready.json())).toMatchObject({
      components: {identity: {oauth: "misconfigured", status: "ready"}},
      status: "ready",
    });
    expect(await metadataStatuses(misconfiguredOrigin)).toEqual([404, 404, 404]);
    const refused = await mcpDiscovery(
      misconfiguredOrigin,
      await issueToken(`${misconfiguredOrigin}/mcp`),
    );
    expect(refused.status).toBe(401);
    expect(refused.headers.get("www-authenticate")).not.toContain("resource_metadata");
    expect((await mcpDiscovery(misconfiguredOrigin, installation.apiToken)).status)
      .toBe(200);
    await delay(400);
    expect(issuer.discoveryRequests()).toBe(attempts);
    expect(events).toEqual([{
      kind: "misconfigured",
      reason: "OIDC discovery returned a different issuer.",
    }]);
  });

  async function issueToken(audience: string): Promise<string> {
    return new SignJWT({
      azp: "artifact-cli",
      email: userEmail,
      email_verified: true,
      name: "Artifact Administrator",
      scope: "openid profile email",
    })
      .setProtectedHeader({alg: "RS256", kid: keyId, typ: "at+jwt"})
      .setIssuer(issuer.issuer)
      .setAudience(audience)
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1_000) + 300)
      .sign(privateKey);
  }
});

function requireServer(server: RunningTestServer | null): RunningTestServer {
  if (server === null) throw new Error("The test server is not running.");
  return server;
}

function apiSession(origin: string, bearer: string): Promise<Response> {
  return fetch(`${origin}/api/v1/session`, {
    headers: {Authorization: `Bearer ${bearer}`},
  });
}

function mcpDiscovery(origin: string, token: string | null): Promise<Response> {
  const headers = new Headers({
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": protocolVersion,
    "Mcp-Method": "server/discover",
  });
  if (token !== null) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${origin}/mcp`, {
    body: JSON.stringify({
      id: crypto.randomUUID(),
      jsonrpc: "2.0",
      method: "server/discover",
      params: {
        _meta: {
          [CLIENT_CAPABILITIES_META_KEY]: {},
          [CLIENT_INFO_META_KEY]: {name: "oidc-recovery-test", version: "1"},
          [PROTOCOL_VERSION_META_KEY]: protocolVersion,
        },
      },
    }),
    headers,
    method: "POST",
  });
}

async function metadataStatuses(origin: string): Promise<readonly number[]> {
  const responses = await Promise.all(
    metadataPaths.map((metadataPath) => fetch(`${origin}${metadataPath}`)),
  );
  return responses.map((response) => response.status);
}

async function waitUntil(
  condition: () => boolean | Promise<boolean>,
  deadline = Date.now() + 10_000,
): Promise<void> {
  if (await condition()) return;
  if (Date.now() > deadline) throw new Error("The condition never held.");
  await delay(20);
  return waitUntil(condition, deadline);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

type DiscoveryAnswer = "foreign-issuer" | "unavailable" | "unreadable" | "valid";

interface FakeIssuer {
  readonly issuer: string;
  close(): Promise<void>;
  discoveryRequests(): number;
  setDiscovery(answer: DiscoveryAnswer): void;
  setDiscoveryDelay(milliseconds: number): void;
}

/** A Keycloak-shaped issuer whose discovery answer the test switches live. */
async function startFakeIssuer(jwk: JWK): Promise<FakeIssuer> {
  let answer: DiscoveryAnswer = "unavailable";
  let discoveryDelay = 0;
  let discoveryRequestCount = 0;
  let issuer = "";
  const server = createServer((request, response) => {
    if (request.url === `${realmPath}/.well-known/openid-configuration`) {
      discoveryRequestCount += 1;
      setTimeout(() => {
        if (answer === "unavailable") {
          response.writeHead(503).end();
          return;
        }
        if (answer === "unreadable") {
          response.writeHead(200, {"Content-Type": "text/html"})
            .end("<html>maintenance</html>");
          return;
        }
        response.writeHead(200, {"Content-Type": "application/json"}).end(
          JSON.stringify({
            authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
            code_challenge_methods_supported: ["S256"],
            issuer: answer === "foreign-issuer"
              ? "https://attacker.example.test/realms/artifact"
              : issuer,
            jwks_uri: `${issuer}/protocol/openid-connect/certs`,
            response_types_supported: ["code"],
            token_endpoint: `${issuer}/protocol/openid-connect/token`,
            userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
          }),
        );
      }, discoveryDelay);
      return;
    }
    if (request.url === `${realmPath}/protocol/openid-connect/certs`) {
      response.writeHead(200, {"Content-Type": "application/json"})
        .end(JSON.stringify({keys: [jwk]}));
      return;
    }
    response.writeHead(404).end();
  });
  await listen(server);
  const address = z.object({port: z.number()}).parse(server.address());
  issuer = `http://127.0.0.1:${address.port}${realmPath}`;
  return {
    close: () => close(server),
    discoveryRequests: () => discoveryRequestCount,
    issuer,
    setDiscovery: (next) => {
      answer = next;
    },
    setDiscoveryDelay: (milliseconds) => {
      discoveryDelay = milliseconds;
    },
  };
}

function listen(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.closeAllConnections();
    server.close((error) => error === undefined ? resolve() : reject(error));
  });
}

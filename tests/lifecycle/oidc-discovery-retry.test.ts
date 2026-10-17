import {Effect, Redacted} from "effect";
import {afterEach, describe, expect, test, vi} from "vitest";

import {
  type DiscoveryEvent,
  defaultDiscoveryRetryPolicy,
  discoveryRetryDelayMilliseconds,
  RetryingDiscovery,
} from "../../src/identity/discovery-retry.js";
import {
  startOidcHostedAuthentication,
  type StartedOidcHostedAuthentication,
} from "../../src/identity/oidc-hosted-authentication.js";
import {OidcDiscoveryMisconfiguration} from
  "../../src/identity/oidc-oauth-metadata.js";

const issuer = "https://identity.example.test/realms/artifact";
const applicationOrigin = "https://artifacts.example.test";
const quietPolicy = {
  // Background retries are pushed far out so only explicit refreshes run.
  initialDelayMilliseconds: 600_000,
  maximumDelayMilliseconds: 600_000,
  onDemandIntervalMilliseconds: 0,
};

describe("discovery retry backoff", () => {
  test("the ceiling doubles from one second to thirty and the delay stays in its upper half", () => {
    const policy = defaultDiscoveryRetryPolicy;
    const lowest = [1, 2, 3, 4, 5, 6, 7, 50].map((failures) =>
      discoveryRetryDelayMilliseconds(failures, policy, () => 0)
    );
    expect(lowest).toEqual([500, 1_000, 2_000, 4_000, 8_000, 15_000, 15_000, 15_000]);
    const highest = [1, 2, 3, 4, 5, 6, 7, 50].map((failures) =>
      discoveryRetryDelayMilliseconds(failures, policy, () => 0.999_999)
    );
    expect(highest).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]);
  });

  test("absurd failure counts and random values never escape the bounds", () => {
    const policy = defaultDiscoveryRetryPolicy;
    for (const failures of [0, -3, 31, 1_000, Number.MAX_SAFE_INTEGER]) {
      for (const random of [-1, 0, 0.5, 1, 2]) {
        const delay = discoveryRetryDelayMilliseconds(failures, policy, () => random);
        expect(Number.isFinite(delay)).toBe(true);
        expect(delay).toBeGreaterThanOrEqual(1);
        expect(delay).toBeLessThanOrEqual(policy.maximumDelayMilliseconds);
      }
    }
  });
});

describe("retrying discovery", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test("a transient failure retries in the background with growing delays until it succeeds", async () => {
    vi.useFakeTimers();
    const events: DiscoveryEvent[] = [];
    let attempts = 0;
    const discovery = new RetryingDiscovery({
      attempt: async () => {
        attempts += 1;
        if (attempts <= 3) throw new Error(`outage ${attempts}`);
        return "discovered";
      },
      classify: () => "transient",
      describe: messageOf,
      onEvent: (event) => events.push(event),
      random: () => 0.999_999,
    });
    try {
      expect(await discovery.start()).toMatchObject({
        failures: 1,
        lastFailure: "outage 1",
        status: "discovering",
      });
      await vi.advanceTimersByTimeAsync(999);
      expect(attempts).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(attempts).toBe(2);
      await vi.advanceTimersByTimeAsync(2_000);
      expect(attempts).toBe(3);
      await vi.advanceTimersByTimeAsync(4_000);
      expect(attempts).toBe(4);
      await settle();
      expect(discovery.current()).toEqual({status: "ready", value: "discovered"});
      await vi.advanceTimersByTimeAsync(120_000);
      expect(attempts).toBe(4);
      expect(events).toEqual([
        {failures: 1, kind: "retrying", reason: "outage 1", retryInMilliseconds: 1_000},
        {failures: 2, kind: "retrying", reason: "outage 2", retryInMilliseconds: 2_000},
        {failures: 3, kind: "retrying", reason: "outage 3", retryInMilliseconds: 4_000},
        {failures: 3, kind: "recovered"},
      ]);
    } finally {
      discovery.close();
    }
  });

  test("requests join one attempt in flight and are debounced after it", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    const pending: PendingAttempt = {release: () => undefined};
    const discovery = new RetryingDiscovery<string>({
      attempt: () => {
        attempts += 1;
        return new Promise((_resolve, reject) => {
          pending.release = () => reject(new Error("still down"));
        });
      },
      classify: () => "transient",
      describe: messageOf,
      policy: {...quietPolicy, onDemandIntervalMilliseconds: 2_000},
    });
    try {
      const started = discovery.start();
      const joined = Promise.all([discovery.refresh(), discovery.refresh()]);
      expect(attempts).toBe(1);
      pending.release();
      await started;
      await joined;
      expect(attempts).toBe(1);
      expect(discovery.current()).toMatchObject({failures: 1, status: "discovering"});

      // Within the on-demand interval a request reads the state and moves on.
      await discovery.refresh();
      expect(attempts).toBe(1);

      await vi.advanceTimersByTimeAsync(2_000);
      const refreshed = discovery.refresh();
      expect(attempts).toBe(2);
      pending.release();
      expect(await refreshed).toMatchObject({failures: 2, status: "discovering"});
    } finally {
      discovery.close();
    }
  });

  test("a misconfiguration is reported once and never retried", async () => {
    vi.useFakeTimers();
    const events: DiscoveryEvent[] = [];
    let attempts = 0;
    const discovery = new RetryingDiscovery<string>({
      attempt: async () => {
        attempts += 1;
        throw new OidcDiscoveryMisconfiguration("another issuer");
      },
      classify: (cause) => cause instanceof OidcDiscoveryMisconfiguration
        ? "misconfigured"
        : "transient",
      describe: messageOf,
      onEvent: (event) => events.push(event),
      policy: {...defaultDiscoveryRetryPolicy, onDemandIntervalMilliseconds: 0},
    });
    try {
      expect(await discovery.start()).toEqual({
        reason: "another issuer",
        status: "misconfigured",
      });
      await vi.advanceTimersByTimeAsync(600_000);
      expect(await discovery.refresh()).toMatchObject({status: "misconfigured"});
      expect(attempts).toBe(1);
      expect(events).toEqual([{kind: "misconfigured", reason: "another issuer"}]);
    } finally {
      discovery.close();
    }
  });

  test("closing stops background retries", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    const discovery = new RetryingDiscovery<string>({
      attempt: async () => {
        attempts += 1;
        throw new Error("down");
      },
      classify: () => "transient",
      describe: () => "down",
    });
    await discovery.start();
    discovery.close();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(attempts).toBe(1);
    expect(await discovery.refresh()).toMatchObject({status: "discovering"});
    expect(attempts).toBe(1);
  });
});

describe("OIDC discovery failure classification", () => {
  const started: StartedOidcHostedAuthentication[] = [];

  afterEach(() => {
    for (const authentication of started.splice(0)) authentication.close();
  });

  async function startWith(
    answer: () => Promise<Response>,
  ): Promise<StartedOidcHostedAuthentication> {
    const authentication = await startOidcHostedAuthentication({
      applicationOrigin,
      clientId: "artifact-server",
      clientSecret: null,
      fetch: async () => answer(),
      issuer,
      scopes: "openid email profile",
    }, {policy: quietPolicy});
    started.push(authentication);
    return authentication;
  }

  test.each([
    ["HTTP 503", () => Promise.resolve(new Response(null, {status: 503}))],
    ["HTTP 404", () => Promise.resolve(new Response(null, {status: 404}))],
    ["a redirect", () => Promise.resolve(new Response(null, {
      headers: {Location: "https://elsewhere.example.test/"},
      status: 302,
    }))],
    ["a network error", () => Promise.reject(new TypeError("fetch failed"))],
    ["a timeout", () => Promise.reject(
      new DOMException("The operation timed out.", "TimeoutError"),
    )],
    ["a document that is not JSON", () => Promise.resolve(
      new Response("<html>maintenance</html>", {status: 200}),
    )],
    ["a document without endpoints", () => Promise.resolve(
      Response.json({issuer}),
    )],
  ])("%s is transient and keeps OAuth discovering", async (_name, answer) => {
    const authentication = await startWith(answer);
    expect(authentication.discoveredOAuth.current()).toMatchObject({
      status: "discovering",
    });
  });

  test.each([
    ["a different issuer", {issuer: "https://attacker.example.test"}],
    ["no S256 PKCE", {code_challenge_methods_supported: ["plain"]}],
    ["no authorization code flow", {response_types_supported: ["token"]}],
    ["a plain-http token endpoint", {
      token_endpoint: "http://identity.example.test/token",
    }],
  ])("%s is a permanent misconfiguration", async (_name, change) => {
    const authentication = await startWith(async () =>
      Response.json({...discoveryDocument(), ...change})
    );
    expect(authentication.discoveredOAuth.current()).toEqual({
      status: "misconfigured",
    });
    await expect(Effect.runPromise(
      authentication.externalMcpOAuthVerifier.verify(Redacted.make("token")),
    )).rejects.toThrow("A valid Artifact Server MCP credential is required.");
  });

  test("an invalid configured issuer still fails startup", async () => {
    await expect(startOidcHostedAuthentication({
      applicationOrigin,
      clientId: "artifact-server",
      clientSecret: null,
      issuer: "http://identity.example.test",
      scopes: "openid email profile",
    })).rejects.toThrow("must be an HTTPS URL");
  });

  test("an undiscovered issuer refuses tokens as unavailable, and a refresh enables OAuth", async () => {
    let healthy = false;
    const authentication = await startWith(async () => healthy
      ? Response.json(discoveryDocument())
      : new Response(null, {status: 503}));
    await expect(Effect.runPromise(
      authentication.externalApiOAuthVerifier.verify(Redacted.make("token")),
    )).rejects.toThrow("has not been discovered yet");

    healthy = true;
    expect(await authentication.discoveredOAuth.refresh()).toMatchObject({
      api: {authorizationServers: [issuer], resource: `${applicationOrigin}/api`},
      mcp: {resource: `${applicationOrigin}/mcp`},
      status: "enabled",
    });
    expect(authentication.discoveredOAuth.mcpResource)
      .toBe(`${applicationOrigin}/mcp`);
    // The discovered verifier now judges the token itself.
    await expect(Effect.runPromise(
      authentication.externalApiOAuthVerifier.verify(Redacted.make("token")),
    )).rejects.toThrow("invalid, expired, or for another resource");
  });
});

function discoveryDocument() {
  return {
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    code_challenge_methods_supported: ["S256"],
    issuer,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    response_types_supported: ["code"],
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
  };
}

interface PendingAttempt {
  release: () => void;
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/** Let promise continuations queued by a fired timer run. */
async function settle(turns = 10): Promise<void> {
  if (turns === 0) return;
  await Promise.resolve();
  return settle(turns - 1);
}

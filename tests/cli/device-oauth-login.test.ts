import {createHash} from "node:crypto";
import {createServer, type IncomingMessage, type Server, type ServerResponse} from "node:http";

import {Command} from "commander";
import {Effect} from "effect";
import {describe, expect, it, vi} from "vitest";
import {z} from "zod";

import {configureCliAuthCommands} from "../../src/cli/cli-auth-commands.js";
import {CliAuthenticationError} from "../../src/cli/cli-profile-credential.js";
import {loginWithDeviceOAuth, type DeviceLoginIo} from "../../src/cli/cli-oauth-client.js";

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";

type TokenAnswer = "authorization_pending" | "slow_down" | "access_denied" | "expired_token" | "invalid_grant" | "server_error" | "drop" | "tokens";

interface FakeIssuerOptions {
  readonly answers?: ReadonlyArray<TokenAnswer>;
  readonly deviceEndpoint?: string | false;
  readonly expiresIn?: number;
  readonly interval?: number;
  readonly issuerUrl?: string;
  readonly issuerMismatch?: boolean;
  readonly metadataFirstStatus?: number;
  readonly rfc8414?: boolean;
  readonly userCode?: string;
  readonly tokenType?: string;
}

interface DeviceRequest {
  readonly form: URLSearchParams;
  readonly status: number;
}

interface TokenRequest {
  readonly form: URLSearchParams;
  readonly time: number;
}

type FakeJsonValue = string | number | boolean | null | ReadonlyArray<string> | undefined;

interface FakeJsonObject {
  readonly [key: string]: FakeJsonValue;
}

type FakeIssuerMetadata = FakeJsonObject & {
  authorization_endpoint: string;
  code_challenge_methods_supported?: ReadonlyArray<string>;
  device_authorization_endpoint?: string;
  grant_types_supported: ReadonlyArray<string>;
  id_token_signing_alg_values_supported?: ReadonlyArray<string>;
  issuer: string;
  jwks_uri?: string;
  response_types_supported: ReadonlyArray<string>;
  subject_types_supported?: ReadonlyArray<string>;
  token_endpoint: string;
};

interface FakeIssuer {
  readonly origin: string;
  readonly deviceRequests: Array<DeviceRequest>;
  readonly tokenRequests: Array<TokenRequest>;
  readonly metadataPaths: Array<string>;
  setNowSource(now: () => number): void;
  close(): Promise<void>;
}

describe("CLI-004 device authorization", () => {
  it.each([
    "http://issuer.example/realms/artifact",
    "http://user:pw@127.0.0.1:1/realms/artifact",
    "https://issuer.example/realms/artifact?x=1",
  ])("rejects unsafe issuer %s before discovery", async (issuerUrl) => {
    const fake = await startFakeIssuer({issuerUrl});
    const fetch = vi.spyOn(globalThis, "fetch");
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "invalid_metadata"});
      expect(fake.metadataPaths).toEqual([]);
      expect(fake.deviceRequests).toEqual([]);
      expect(fetch.mock.calls.some(([url]) => {
        const value = url instanceof Request ? url.url : url.toString();
        return value.includes("/.well-known/oauth-authorization-server") || value.includes("openid-configuration");
      })).toBe(false);
    } finally {
      fetch.mockRestore();
      await fake.close();
    }
  });

  it("clamps pending sleeps to the device deadline", async () => {
    const fake = await startFakeIssuer({answers: ["authorization_pending"], expiresIn: 30, interval: 7});
    const clock = fakeClock();
    fake.setNowSource(clock.now);
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(clock.sleeps).toEqual([7_000, 7_000, 7_000, 7_000, 2_000]);
      expect(fake.tokenRequests).toHaveLength(4);
      expect(fake.tokenRequests.every((request) => request.time < 30_000)).toBe(true);
      expect(clock.now()).toBe(30_000);
    } finally {
      await fake.close();
    }
  });

  it("caps a huge issuer interval at the remaining lifetime", async () => {
    const fake = await startFakeIssuer({expiresIn: 300, interval: 3_600});
    const clock = fakeClock();
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(clock.sleeps).toEqual([300_000]);
      expect(fake.tokenRequests).toHaveLength(0);
      expect(clock.now()).toBe(300_000);
    } finally {
      await fake.close();
    }
  });

  it("caps the device lifetime at 15 minutes", async () => {
    const fake = await startFakeIssuer({answers: ["authorization_pending"], expiresIn: 3_600, interval: 60});
    const clock = fakeClock();
    fake.setNowSource(clock.now);
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(clock.sleeps).toEqual(Array.from({length: 15}, () => 60_000));
      expect(fake.tokenRequests).toHaveLength(14);
      expect(fake.tokenRequests.every((request) => request.time < 900_000)).toBe(true);
      expect(clock.now()).toBe(900_000);
    } finally {
      await fake.close();
    }
  });

  it("clamps slow_down polling to the device deadline", async () => {
    const fake = await startFakeIssuer({answers: ["slow_down"], expiresIn: 30, interval: 5});
    const clock = fakeClock();
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(clock.sleeps).toEqual([5_000, 10_000, 15_000]);
      expect(fake.tokenRequests).toHaveLength(2);
      expect(clock.now()).toBe(30_000);
    } finally {
      await fake.close();
    }
  });

  it("backs off after transient errors and accepts tokens", async () => {
    const fake = await startFakeIssuer({answers: ["server_error", "drop", "tokens"]});
    const clock = fakeClock();
    try {
      const result = await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, [])));
      expect(clock.sleeps).toEqual([5_000, 10_000, 20_000]);
      expect(fake.tokenRequests).toHaveLength(3);
      expect(result.credential.kind).toBe("oauth");
      const verifiers = fake.tokenRequests.map((request) => request.form.get("code_verifier"));
      expect(new Set(verifiers).size).toBe(1);
    } finally {
      await fake.close();
    }
  });

  it("backs off on persistent server errors until expiry", async () => {
    const fake = await startFakeIssuer({answers: ["server_error"], expiresIn: 60, interval: 5});
    const clock = fakeClock();
    fake.setNowSource(clock.now);
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(clock.sleeps).toEqual([5_000, 10_000, 20_000, 25_000]);
      expect(fake.tokenRequests).toHaveLength(3);
      expect(clock.now()).toBe(60_000);
    } finally {
      await fake.close();
    }
  });

  it("CLI-004-B completes pending and slow_down with S256, keeping secrets out of output and the credential", async () => {
    const fake = await startFakeIssuer({answers: ["authorization_pending", "slow_down", "tokens"]});
    const clock = fakeClock();
    const prompt: string[] = [];
    const stdout = vi.spyOn(process.stdout, "write");
    try {
      const result = await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, prompt)));
      const device = fake.deviceRequests[0];
      const deviceCode = "device-secret-value";
      const challenge = device?.form.get("code_challenge");
      const verifiers = fake.tokenRequests.map((request) => request.form.get("code_verifier"));
      const credentialJson = JSON.stringify(result.credential);
      expect(result.credential.kind).toBe("oauth");
      expect(result.credential.tokens.access_token).toBe("access-secret-value");
      expect(result.credential.tokens.refresh_token).toBe("refresh-secret-value");
      expect(result.credential.clientInformation.client_id).toBe("artifact-server");
      expect(result.credential.redirectUrl).toBe("http://127.0.0.1:45678/oauth/callback");
      expect(device?.status).toBe(200);
      expect(device?.form.get("client_id")).toBe("artifact-server");
      expect(device?.form.get("scope")).toBe("artifactserver offline_access");
      expect(device?.form.get("resource")).toBe(`${fake.origin}/api`);
      expect(fake.metadataPaths).toEqual([
        "/.well-known/oauth-authorization-server/realms/artifact",
        "/.well-known/openid-configuration/realms/artifact",
        "/realms/artifact/.well-known/openid-configuration",
      ]);
      expect(device?.form.get("code_challenge_method")).toBe("S256");
      expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(fake.tokenRequests).toHaveLength(3);
      expect(verifiers.every((value) => value !== null && /^[A-Za-z0-9_-]{43,128}$/u.test(value))).toBe(true);
      expect(new Set(verifiers).size).toBe(1);
      expect(base64urlSha256(verifiers[0] ?? "")).toBe(challenge);
      expect(clock.sleeps).toEqual([5_000, 5_000, 10_000]);
      expect(prompt.join("")).toContain(`${fake.origin}/verify`);
      expect(prompt.join("")).toContain("ABCD-EFGH");
      expect(prompt.join("")).not.toContain(deviceCode);
      expect(prompt.join("")).not.toContain("access-secret-value");
      expect(prompt.join("")).not.toContain(verifiers[0] ?? "missing-verifier");
      expect(credentialJson).not.toContain(deviceCode);
      expect(credentialJson).not.toContain(verifiers[0] ?? "missing-verifier");
      expect(stdout).not.toHaveBeenCalled();
    } finally {
      stdout.mockRestore();
      await fake.close();
    }
  });

  it("reuses one verifier for all four pending polls", async () => {
    const fake = await startFakeIssuer({answers: ["authorization_pending", "authorization_pending", "authorization_pending", "tokens"]});
    try {
      await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), [])));
      expect(fake.tokenRequests).toHaveLength(4);
      const verifiers = fake.tokenRequests.map((request) => request.form.get("code_verifier"));
      expect(verifiers.every((value) => value !== null)).toBe(true);
      expect(new Set(verifiers).size).toBe(1);
    } finally {
      await fake.close();
    }
  });

  it("creates a fresh PKCE pair for each authorization", async () => {
    const fake = await startFakeIssuer({answers: ["tokens", "tokens"]});
    try {
      await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), [])));
      await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), [])));
      expect(fake.deviceRequests).toHaveLength(2);
      const challenges = fake.deviceRequests.map((request) => request.form.get("code_challenge"));
      const verifiers = fake.tokenRequests.map((request) => request.form.get("code_verifier"));
      expect(new Set(challenges).size).toBe(2);
      expect(new Set(verifiers).size).toBe(2);
    } finally {
      await fake.close();
    }
  });

  it("CLI-004-F reports access_denied without exposing a credential", async () => {
    const fake = await startFakeIssuer({answers: ["access_denied"]});
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("denied")});
      expect(fake.tokenRequests).toHaveLength(1);
    } finally {
      await fake.close();
    }
  });

  it("reports expired_token and stops polling", async () => {
    const fake = await startFakeIssuer({answers: ["expired_token"]});
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(fake.tokenRequests).toHaveLength(1);
    } finally {
      await fake.close();
    }
  });

  it("stops never-approved polling at the deadline", async () => {
    const fake = await startFakeIssuer({answers: ["authorization_pending"], expiresIn: 30, interval: 5});
    const clock = fakeClock();
    fake.setNowSource(clock.now);
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(clock, []))))
        .rejects.toMatchObject({reason: "oauth_failed", message: expect.stringContaining("expired")});
      expect(fake.tokenRequests.length).toBeGreaterThan(0);
      expect(fake.tokenRequests.every((request) => request.time < 30_000)).toBe(true);
      expect(clock.now()).toBe(30_000);
    } finally {
      await fake.close();
    }
  });

  it("reports an issuer without device authorization as unavailable", async () => {
    const fake = await startFakeIssuer({deviceEndpoint: false});
    const prompt: string[] = [];
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), prompt))))
        .rejects.toMatchObject({reason: "device_authorization_unavailable"});
      expect(fake.deviceRequests).toHaveLength(0);
      expect(prompt).toEqual([]);
    } finally {
      await fake.close();
    }
  });

  it("reports a client that has not enabled device authorization", async () => {
    const fake = await startFakeIssuer({deviceEndpoint: "unauthorized"});
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "device_authorization_unavailable"});
      expect(fake.deviceRequests).toHaveLength(1);
      expect(fake.tokenRequests).toHaveLength(0);
    } finally {
      await fake.close();
    }
  });

  it("accepts RFC 8414 metadata at the first discovery URL", async () => {
    const fake = await startFakeIssuer({rfc8414: true});
    try {
      await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), [])));
      expect(fake.metadataPaths).toEqual(["/.well-known/oauth-authorization-server/realms/artifact"]);
      expect(fake.deviceRequests).toHaveLength(1);
    } finally {
      await fake.close();
    }
  });

  it("rejects metadata whose issuer differs from the verified issuer", async () => {
    const fake = await startFakeIssuer({issuerMismatch: true});
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "invalid_metadata"});
      expect(fake.deviceRequests).toHaveLength(0);
    } finally {
      await fake.close();
    }
  });

  it("fails on metadata URL 1 status 500 without trying later URLs", async () => {
    const fake = await startFakeIssuer({metadataFirstStatus: 500});
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), []))))
        .rejects.toMatchObject({reason: "invalid_metadata"});
      expect(fake.metadataPaths).toEqual(["/.well-known/oauth-authorization-server/realms/artifact"]);
      expect(fake.deviceRequests).toHaveLength(0);
    } finally {
      await fake.close();
    }
  });

  it("rejects unsafe endpoints and terminal-control user codes without prompting", async () => {
    const unsafeEndpoint = await startFakeIssuer({deviceEndpoint: "http://evil.example/device"});
    const badUserCode = await startFakeIssuer({userCode: "BAD\u001b[31mCODE"});
    const prompt: string[] = [];
    try {
      await expect(Effect.runPromise(loginWithDeviceOAuth(unsafeEndpoint.origin, "", ioFor(fakeClock(), prompt))))
        .rejects.toMatchObject({reason: "invalid_metadata"});
      await expect(Effect.runPromise(loginWithDeviceOAuth(badUserCode.origin, "", ioFor(fakeClock(), prompt))))
        .rejects.toMatchObject({reason: "oauth_failed"});
      expect(prompt).toEqual([]);
    } finally {
      await unsafeEndpoint.close();
      await badUserCode.close();
    }
  });

  it("rejects a PKCE verifier mismatch without retrying or disclosing the verifier", async () => {
    const fake = await startFakeIssuer({answers: ["invalid_grant"]});
    try {
      const error = await Effect.runPromise(loginWithDeviceOAuth(fake.origin, "", ioFor(fakeClock(), [])))
        .then(() => undefined, (cause: unknown) => cause instanceof CliAuthenticationError ? cause : undefined);
      expect(error?.reason).toBe("oauth_failed");
      expect(fake.tokenRequests).toHaveLength(1);
      expect(error?.message).not.toContain(fake.tokenRequests[0]?.form.get("code_verifier") ?? "missing-verifier");
    } finally {
      await fake.close();
    }
  });

  it.each(["--headless", "--api-key-stdin"])("rejects --device with %s before making a network request", async (conflict) => {
      const program = new Command();
      configureCliAuthCommands(program, {defaultProfileDirectory: "/unused"});
      program.exitOverride((error) => { throw new Error(error.message); });
      const fetch = vi.spyOn(globalThis, "fetch");
      const stderr = vi.spyOn(process.stderr, "write");
      try {
        await expect(program.parseAsync([
          "auth", "login", "http://127.0.0.1:1", "--device", conflict,
        ], {from: "user"})).rejects.toThrow(/process.exit unexpectedly/u);
        expect(stderr.mock.calls.map(([chunk]) => String(chunk)).join("")).toContain(`cannot be used with option '${conflict}'`);
        expect(fetch).not.toHaveBeenCalled();
      } finally {
        stderr.mockRestore();
        fetch.mockRestore();
      }
  });
});

async function startFakeIssuer(options: FakeIssuerOptions = {}): Promise<FakeIssuer> {
  const deviceRequests: Array<DeviceRequest> = [];
  const tokenRequests: Array<TokenRequest> = [];
  const metadataPaths: Array<string> = [];
  const challenges = new Map<string, string>();
  const answers = [...(options.answers ?? ["tokens"])];
  let nowSource = (): number => 0;
  let origin = "";
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", origin).pathname;
    if (request.method === "GET" && path === "/api/v1/installation") {
      response.writeHead(401, {
        "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/api"`,
      }).end();
      return;
    }
    if (request.method === "GET" && path === "/.well-known/oauth-protected-resource/api") {
      sendJson(response, 200, {
        authorization_servers: [options.issuerUrl ?? `${origin}/realms/artifact`],
        resource: `${origin}/api`,
        scopes_supported: ["artifactserver"],
      });
      return;
    }
    if (
      request.method === "GET"
      && (path.startsWith("/.well-known/") || path === "/realms/artifact/.well-known/openid-configuration")
    ) {
      metadataPaths.push(path);
      if (path === "/.well-known/oauth-authorization-server/realms/artifact" && options.metadataFirstStatus !== undefined) {
        response.writeHead(options.metadataFirstStatus).end();
        return;
      }
      if (path === "/.well-known/oauth-authorization-server/realms/artifact" && !options.rfc8414) {
        response.writeHead(404).end();
        return;
      }
      if (path === "/.well-known/openid-configuration/realms/artifact") {
        response.writeHead(404).end();
        return;
      }
      if (
        path !== "/realms/artifact/.well-known/openid-configuration"
        && path !== "/.well-known/oauth-authorization-server/realms/artifact"
      ) {
        response.writeHead(404).end();
        return;
      }
      const isRfc8414 = path === "/.well-known/oauth-authorization-server/realms/artifact";
      const issuer = options.issuerUrl ?? `${origin}/realms/${options.issuerMismatch ? "other" : "artifact"}`;
      const metadata: FakeIssuerMetadata = {
        authorization_endpoint: `${issuer}/authorize`,
        grant_types_supported: [deviceGrant],
        issuer,
        response_types_supported: ["code"],
        token_endpoint: `${origin}/token`,
      };
      if (options.deviceEndpoint !== false) {
        metadata["device_authorization_endpoint"] = options.deviceEndpoint === "unauthorized"
          ? `${origin}/device`
          : options.deviceEndpoint ?? `${origin}/device`;
      }
      if (!isRfc8414) {
        metadata["jwks_uri"] = `${issuer}/jwks`;
        metadata["subject_types_supported"] = ["public"];
        metadata["id_token_signing_alg_values_supported"] = ["RS256"];
        metadata["code_challenge_methods_supported"] = ["S256"];
      }
      sendJson(response, 200, metadata);
      return;
    }
    if (request.method === "POST" && path === "/device") {
      const form = await readForm(request);
      const challenge = form.get("code_challenge") ?? "";
      if (form.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/u.test(challenge)) {
        deviceRequests.push({form, status: 400});
        sendJson(response, 400, {error: "invalid_request", error_description: "Missing parameter: code_challenge_method"});
        return;
      }
      deviceRequests.push({form, status: options.deviceEndpoint === "unauthorized" ? 400 : 200});
      if (options.deviceEndpoint === "unauthorized") {
        sendJson(response, 400, {error: "unauthorized_client"});
        return;
      }
      challenges.set("device-secret-value", challenge);
      sendJson(response, 200, {
        device_code: "device-secret-value",
        expires_in: options.expiresIn ?? 300,
        interval: options.interval ?? 5,
        user_code: options.userCode ?? "ABCD-EFGH",
        verification_uri: `${origin}/verify`,
      });
      return;
    }
    if (request.method === "POST" && path === "/token") {
      const form = await readForm(request);
      tokenRequests.push({form, time: nowSource()});
      if (base64urlSha256(form.get("code_verifier") ?? "") !== challenges.get(form.get("device_code") ?? "")) {
        sendJson(response, 400, {error: "invalid_grant", error_description: "PKCE verification failed"});
        return;
      }
      const answer = answers.shift() ?? options.answers?.at(-1) ?? "authorization_pending";
      if (answer === "tokens") {
        sendJson(response, 200, {
          access_token: "access-secret-value",
          expires_in: 3600,
          refresh_token: "refresh-secret-value",
          token_type: options.tokenType ?? "Bearer",
        });
        return;
      }
      if (answer === "server_error") {
        sendJson(response, 503, {error: "temporarily_unavailable"});
        return;
      }
      if (answer === "drop") {
        request.socket.destroy();
        return;
      }
      sendJson(response, 400, {error: answer});
      return;
    }
    response.writeHead(404).end();
  });
  await listen(server);
  const address = z.object({port: z.number().int().positive()}).safeParse(server.address());
  if (!address.success) throw new Error("Fake issuer did not bind a TCP port.");
  origin = `http://127.0.0.1:${address.data.port}`;
  return {
    origin,
    deviceRequests,
    tokenRequests,
    metadataPaths,
    setNowSource: (source) => { nowSource = source; },
    close: () => close(server),
  };
}

function fakeClock() {
  let current = 0;
  const sleeps: number[] = [];
  return {
    now: () => current,
    sleeps,
    sleep: async (milliseconds: number) => {
      sleeps.push(milliseconds);
      current += milliseconds;
    },
  };
}

function ioFor(clock: ReturnType<typeof fakeClock>, output: Array<string>): DeviceLoginIo {
  return {now: clock.now, sleep: clock.sleep, write: (text) => output.push(text)};
}

async function readForm(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Array<Buffer> = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response: ServerResponse, status: number, body: FakeJsonObject): void {
  response.writeHead(status, {"Content-Type": "application/json"}).end(JSON.stringify(body));
}

function base64urlSha256(value: string): string {
  return createHash("sha256").update(value, "ascii").digest("base64url");
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

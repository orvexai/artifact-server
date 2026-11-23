import {type ChildProcess, spawn} from "node:child_process";
import {createInterface} from "node:readline/promises";
import {createHash, randomBytes} from "node:crypto";
import {createServer, type Server} from "node:http";
import path from "node:path";
import {setTimeout as delay} from "node:timers/promises";

import {
  auth,
  buildDiscoveryUrls,
  discoverOAuthServerInfo,
  type OAuthClientInformationContext,
  type OAuthClientMetadata,
  type OAuthClientProvider,
  type OAuthDiscoveryState,
  type StoredOAuthClientInformation,
  type StoredOAuthTokens,
} from "@modelcontextprotocol/client";
import {Effect} from "effect";
import {z} from "zod";

import {
  artifactServerProtectedResourceMetadataUrl,
} from "../core/server-address.js";
import {discoverCliApi} from "./cli-api-discovery.js";
import {houstonServerPageMark} from "../shared/houston-server-pages.js";

import {
  CliAuthenticationError,
  oauthAccessTokenIsFresh,
  oauthCredential,
  type StoredCliCredential,
} from "./cli-profile-credential.js";

const cliScope = "artifactserver";
const cliOAuthClientId = "artifact-server";
const callbackTimeoutMilliseconds = 5 * 60 * 1_000;
const cliOAuthCallbackPort = 45678;
const deviceLifetimeCapSeconds = 900;
const deviceIntervalCapSeconds = 900;
const deviceSlowDownSeconds = 5;
const deviceRequestTimeoutMs = 10_000;
// Openers such as xdg-open fail within milliseconds when no browser exists.
const browserLaunchGraceMilliseconds = 1_500;
const protectedResourceMetadataSchema = z.object({
  authorization_servers: z.array(z.url()).min(1),
  bearer_methods_supported: z.array(z.string()).optional(),
  resource: z.url(),
  scopes_supported: z.array(z.string()).optional(),
}).passthrough();
const callbackQuerySchema = z.object({
  code: z.string().min(1).max(4_096),
  iss: z.url().optional(),
  state: z.string().min(16).max(4_096),
});
const deviceMetadataSchema = z.object({
  device_authorization_endpoint: z.url(),
  grant_types_supported: z.array(z.string()).optional(),
  token_endpoint: z.url(),
}).passthrough();
const deviceAuthorizationSchema = z.object({
  device_code: z.string().min(1).max(4_096),
  expires_in: z.number().int().positive(),
  interval: z.number().int().positive().optional(),
  user_code: z.string().min(1).max(64).regex(/^[\x21-\x7E]+(?: [\x21-\x7E]+)*$/u),
  verification_uri: z.url(),
  verification_uri_complete: z.url().optional(),
}).passthrough();
const oauthErrorSchema = z.object({error: z.string()}).passthrough();
const oauthTokensSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.number().int().positive().optional(),
  issuer: z.url().optional(),
  refresh_token: z.string().min(1).optional(),
  scope: z.string().optional(),
  token_type: z.string().min(1),
}).passthrough();
const assignedAddressSchema = z.object({
  address: z.string(),
  port: z.number().int().positive(),
});
const revocationMetadataSchema = z.object({
  revocation_endpoint: z.url(),
}).passthrough();
const ignoreCallbackResult = (): void => undefined;

/** Result of one successful browser OAuth login. */
export interface CliOAuthLoginResult {
  readonly apiBasePath: string;
  readonly credential: Extract<StoredCliCredential, {readonly kind: "oauth"}>;
}

/** Injectable time and prompt operations for an OAuth device authorization. */
export interface DeviceLoginIo {
  readonly now: () => number;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly write: (text: string) => void;
}

const defaultDeviceLoginIo: DeviceLoginIo = {
  now: Date.now,
  sleep: (milliseconds) => delay(milliseconds),
  write: (text) => { process.stderr.write(text); },
};

/** Complete protected-resource discovery and S256 PKCE in the system browser. */
export const loginWithBrowserOAuth = Effect.fn("CliOAuth.login")(
  function*(
    origin: string,
    environment: NodeJS.ProcessEnv = process.env,
    basePath = "",
  ): Effect.fn.Return<CliOAuthLoginResult, CliAuthenticationError> {
    return yield* loginWithOAuth(origin, false, environment, basePath);
  },
);

/** Complete OAuth login on a headless host by accepting a pasted redirect code. */
export const loginWithHeadlessOAuth = Effect.fn("CliOAuth.loginHeadless")(
  function*(
    origin: string,
    environment: NodeJS.ProcessEnv = process.env,
    basePath = "",
  ): Effect.fn.Return<CliOAuthLoginResult, CliAuthenticationError> {
    return yield* loginWithOAuth(origin, true, environment, basePath);
  },
);

/** Sign in without a local browser using the issuer's RFC 8628 device grant. */
export const loginWithDeviceOAuth = Effect.fn("CliOAuth.loginDevice")(
  function*(
    origin: string,
    basePath = "",
    io: DeviceLoginIo = defaultDeviceLoginIo,
  ): Effect.fn.Return<CliOAuthLoginResult, CliAuthenticationError> {
    const discovery = yield* Effect.tryPromise({
      try: () => discoverCliApi(origin, basePath),
      catch: () => new CliAuthenticationError({
        message: "The Artifact Server CLI authorization metadata is invalid or unavailable.",
        reason: "invalid_metadata",
      }),
    });
    const issuer = yield* verifyProtectedResourceMetadata(discovery.resource, discovery.metadataUrl);
    const result = yield* Effect.tryPromise({
      try: async () => {
        try {
          const metadata = await fetchDeviceIssuerMetadata(issuer);
          const deviceEndpoint = checkedOAuthEndpoint(metadata.device_authorization_endpoint);
          const tokenEndpoint = checkedOAuthEndpoint(metadata.token_endpoint);
          const pkce = createDevicePkce();
          const deviceResponse = await postOAuthForm(deviceEndpoint, {
            client_id: cliOAuthClientId,
            scope: `${cliScope} offline_access`,
            resource: discovery.resource.toString(),
            code_challenge: pkce.challenge,
            code_challenge_method: "S256",
          });
          if (deviceResponse.status !== 200) {
            const error = oauthErrorSchema.safeParse(deviceResponse.body);
            if (
              deviceResponse.status === 400
              && error.success
              && ["unauthorized_client", "invalid_client"].includes(error.data.error)
            ) {
              throw new CliAuthenticationError({
                message: "The identity provider has not enabled device sign-in for the artifact-server client. Ask an administrator to enable it, or use --headless.",
                reason: "device_authorization_unavailable",
              });
            }
            throw oauthDeviceFailed();
          }
          const authorization = deviceAuthorizationSchema.safeParse(deviceResponse.body);
          if (!authorization.success) throw oauthDeviceFailed();
          const verificationUri = checkedOAuthEndpoint(authorization.data.verification_uri);
          const verificationComplete = authorization.data.verification_uri_complete === undefined
            ? undefined
            : checkedOAuthEndpoint(authorization.data.verification_uri_complete);
          const lifetimeSeconds = Math.min(authorization.data.expires_in, deviceLifetimeCapSeconds);
          const intervalSeconds = Math.min(Math.max(authorization.data.interval ?? 5, 1), deviceIntervalCapSeconds);
          const deadline = io.now() + lifetimeSeconds * 1_000;
          io.write(
            `\nSign in to Artifact Server from any device with a browser:\n\n  1. Open ${terminalLink(verificationUri)}\n  2. Enter the code ${authorization.data.user_code}\n\n`
            + (verificationComplete === undefined
              ? ""
              : `Or open ${terminalLink(verificationComplete)} to skip typing the code.\n\n`)
            + `Waiting for approval (expires in ${Math.ceil(lifetimeSeconds / 60)} minutes)...\n`,
          );
          const tokens = await pollForDeviceTokens({
            deviceCode: authorization.data.device_code,
            deadline,
            intervalSeconds,
            io,
            pkceVerifier: pkce.verifier,
            resource: discovery.resource.toString(),
            tokenEndpoint,
          });
          const loopbackRedirectUrl = `http://127.0.0.1:${cliOAuthCallbackPort}/oauth/callback`;
          return oauthCredential({
            clientInformation: {
              client_id: cliOAuthClientId,
              issuer,
              redirect_uris: [loopbackRedirectUrl],
              token_endpoint_auth_method: "none",
            },
            redirectUrl: loopbackRedirectUrl,
            tokens,
            tokensSavedAt: new Date(io.now()).toISOString(),
          });
        } catch (cause) {
          if (cause instanceof CliAuthenticationError) throw cause;
          throw oauthDeviceFailed();
        }
      },
      catch: (cause) => cause instanceof CliAuthenticationError
        ? cause
        : oauthDeviceFailed(),
    });
    return {apiBasePath: discovery.apiBasePath, credential: result};
  },
);

interface OAuthHttpResponse {
  readonly status: number;
  readonly body: unknown;
}

const createDevicePkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return {verifier, challenge: createHash("sha256").update(verifier, "ascii").digest("base64url")};
};

function checkedOAuthEndpoint(value: string): URL {
  const url = new URL(value);
  const isLoopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback))
    || url.username !== ""
    || url.password !== ""
  ) {
    throw new CliAuthenticationError({
      message: "The Artifact Server CLI authorization metadata is invalid or unavailable.",
      reason: "invalid_metadata",
    });
  }
  return url;
}

function deviceAuthorizationUnavailable(): CliAuthenticationError {
  return new CliAuthenticationError({
    message: "This server's identity provider does not offer device sign-in. Run artifactserver auth login <server> --headless instead.",
    reason: "device_authorization_unavailable",
  });
}

async function fetchDeviceIssuerMetadata(issuer: string): Promise<z.infer<typeof deviceMetadataSchema>> {
  try {
    const issuerUrl = checkedOAuthEndpoint(issuer);
    if (issuerUrl.search !== "" || issuerUrl.hash !== "") {
      throw new CliAuthenticationError({
        message: "The Artifact Server CLI authorization metadata is invalid or unavailable.",
        reason: "invalid_metadata",
      });
    }
    const invalidMetadata = (): CliAuthenticationError => new CliAuthenticationError({
      message: "The Artifact Server CLI authorization metadata is invalid or unavailable.",
      reason: "invalid_metadata",
    });
    const discoveryUrls = buildDiscoveryUrls(issuer);
    const fetchAt = async (index: number): Promise<z.infer<typeof deviceMetadataSchema>> => {
      const discoveryUrl = discoveryUrls[index];
      if (discoveryUrl === undefined) throw invalidMetadata();
      const {url} = discoveryUrl;
      const response = await fetch(url, {
        headers: {Accept: "application/json"},
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if ((response.status >= 400 && response.status < 500) || response.status === 502) {
        await response.text().catch(() => undefined);
        return fetchAt(index + 1);
      }
      if (!response.ok) throw invalidMetadata();
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        throw invalidMetadata();
      }
      const issuerCheck = z.object({issuer: z.string()}).passthrough().safeParse(body);
      if (!issuerCheck.success || issuerCheck.data.issuer !== issuer) throw invalidMetadata();
      if (!Object.hasOwn(issuerCheck.data, "device_authorization_endpoint")) {
        throw deviceAuthorizationUnavailable();
      }
      const parsedMetadata = deviceMetadataSchema.safeParse(body);
      if (!parsedMetadata.success) throw invalidMetadata();
      if (
        parsedMetadata.data.grant_types_supported !== undefined
        && !parsedMetadata.data.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:device_code")
      ) {
        throw deviceAuthorizationUnavailable();
      }
      return parsedMetadata.data;
    };
    return await fetchAt(0);
  } catch (cause) {
    if (cause instanceof CliAuthenticationError) throw cause;
    throw new CliAuthenticationError({
      message: "The Artifact Server CLI authorization metadata is invalid or unavailable.",
      reason: "invalid_metadata",
    });
  }
}

async function pollForDeviceTokens(input: {
  readonly deadline: number;
  readonly deviceCode: string;
  readonly intervalSeconds: number;
  readonly io: DeviceLoginIo;
  readonly pkceVerifier: string;
  readonly resource: string;
  readonly tokenEndpoint: URL;
}): Promise<StoredOAuthTokens> {
  const polls = deviceTokenPollSequence(input);
  for await (const result of polls) {
    if (result.retry) continue;
    const tokenResponse = result.response;
    if (tokenResponse.status === 200) {
      const parsedTokens = oauthTokensSchema.safeParse(tokenResponse.body);
      if (!parsedTokens.success || parsedTokens.data.token_type.toLowerCase() !== "bearer") {
        throw oauthDeviceFailed();
      }
      return parsedTokens.data;
    }
    const tokenError = oauthErrorSchema.safeParse(tokenResponse.body);
    const errorCode = tokenError.success ? tokenError.data.error : "";
    if (tokenResponse.status === 400 && errorCode === "authorization_pending") continue;
    if (tokenResponse.status === 400 && errorCode === "slow_down") {
      polls.slowDown();
      continue;
    }
    if (tokenResponse.status === 400 && errorCode === "access_denied") {
      throw new CliAuthenticationError({
        message: "Sign-in was denied in the browser. Run artifactserver auth login again.",
        reason: "oauth_failed",
      });
    }
    if (tokenResponse.status === 400 && errorCode === "expired_token") {
      throw new CliAuthenticationError({
        message: "The sign-in code expired before it was approved. Run artifactserver auth login --device again.",
        reason: "oauth_failed",
      });
    }
    throw oauthDeviceFailed();
  }
  throw deviceAuthorizationExpired();
}

type DevicePollResult = {readonly retry: true} | {readonly retry: false; readonly response: OAuthHttpResponse};

interface DeviceTokenPollSequence extends AsyncIterableIterator<DevicePollResult> {
  slowDown(): void;
}

function deviceTokenPollSequence(input: {
  readonly deadline: number;
  readonly deviceCode: string;
  readonly intervalSeconds: number;
  readonly io: DeviceLoginIo;
  readonly pkceVerifier: string;
  readonly resource: string;
  readonly tokenEndpoint: URL;
}): DeviceTokenPollSequence {
  let intervalSeconds = Math.min(input.intervalSeconds, deviceIntervalCapSeconds);
  return {
    [Symbol.asyncIterator]() { return this; },
    async next(): Promise<IteratorResult<DevicePollResult>> {
      const remainingMilliseconds = input.deadline - input.io.now();
      if (remainingMilliseconds <= 0) throw deviceAuthorizationExpired();
      await input.io.sleep(Math.min(intervalSeconds * 1_000, remainingMilliseconds));
      const requestRemainingMilliseconds = input.deadline - input.io.now();
      if (requestRemainingMilliseconds <= 0) throw deviceAuthorizationExpired();
      try {
        const response = await postOAuthForm(input.tokenEndpoint, {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: input.deviceCode,
          client_id: cliOAuthClientId,
          resource: input.resource,
          code_verifier: input.pkceVerifier,
        }, Math.min(deviceRequestTimeoutMs, requestRemainingMilliseconds));
        if (response.status >= 500) {
          intervalSeconds = Math.min(intervalSeconds * 2, deviceIntervalCapSeconds);
          return {done: false, value: {retry: true}};
        }
        return {done: false, value: {retry: false, response}};
      } catch {
        intervalSeconds = Math.min(intervalSeconds * 2, deviceIntervalCapSeconds);
        return {done: false, value: {retry: true}};
      }
    },
    async return(): Promise<IteratorResult<DevicePollResult>> { return {done: true, value: undefined}; },
    slowDown() {
      intervalSeconds = Math.min(intervalSeconds + deviceSlowDownSeconds, deviceIntervalCapSeconds);
    },
  };
}

function deviceAuthorizationExpired(): CliAuthenticationError {
  return new CliAuthenticationError({
    message: "The sign-in code expired before it was approved. Run artifactserver auth login --device again.",
    reason: "oauth_failed",
  });
}

function oauthDeviceFailed(): CliAuthenticationError {
  return new CliAuthenticationError({
    message: "Device sign-in did not complete. Check the server's OAuth configuration and run auth login --device again.",
    reason: "oauth_failed",
  });
}

async function postOAuthForm(
  endpoint: URL,
  values: Record<string, string>,
  timeoutMs = deviceRequestTimeoutMs,
): Promise<OAuthHttpResponse> {
  const response = await fetch(endpoint, {
    body: new URLSearchParams(values),
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body: unknown = await response.json().catch(() => undefined);
  return {status: response.status, body};
}

function loginWithOAuth(
  origin: string,
  headless: boolean,
  environment: NodeJS.ProcessEnv,
  basePath: string,
): Effect.Effect<CliOAuthLoginResult, CliAuthenticationError> {
  return Effect.gen(function*() {
    const discovery = yield* Effect.tryPromise({
      try: () => discoverCliApi(origin, basePath),
      catch: (cause) => new CliAuthenticationError({
        message: cause instanceof Error ? cause.message : "The Artifact Server API resource could not be discovered.",
        reason: "invalid_metadata",
      }),
    });
    const {metadataUrl, resource} = discovery;
    const issuer = yield* verifyProtectedResourceMetadata(resource, metadataUrl);
    const state = randomBytes(32).toString("base64url");
    const callback = yield* openLoopbackCallback(state);
    const provider = new ArtifactServerOAuthProvider({
      environment,
      issuer,
      redirectUrl: callback.redirectUrl,
      state,
      headless,
    });
    const result = yield* Effect.tryPromise({
      try: async () => {
        try {
          const started = await auth(provider, {
            resourceMetadataUrl: metadataUrl,
            scope: cliScope,
            serverUrl: resource,
          });
          if (started !== "REDIRECT") {
            throw new Error("OAuth login did not require browser authorization.");
          }
          const query = await waitForAuthorizationResponse({
            browserFailure: provider.browserLaunchFailure(),
            callback,
            expectedState: state,
            headless,
          });
          if (query.state !== state) throw new Error("The OAuth callback state was invalid.");
          const completed = query.iss === undefined
            ? await auth(provider, {
              authorizationCode: query.code,
              resourceMetadataUrl: metadataUrl,
              scope: cliScope,
              serverUrl: resource,
            })
            : await auth(provider, {
              authorizationCode: query.code,
              iss: query.iss,
              resourceMetadataUrl: metadataUrl,
              scope: cliScope,
              serverUrl: resource,
            });
          if (completed !== "AUTHORIZED") {
            throw new Error("OAuth authorization did not complete.");
          }
          return provider.storedCredential();
        } finally {
          await callback.close();
        }
      },
      catch: (cause) => cause instanceof CliAuthenticationError
        ? cause
        : new CliAuthenticationError({
          message: headless
            ? "Headless OAuth authorization did not complete. Check the pasted code and server OAuth configuration, then run auth login again."
            : "Browser authorization did not complete. Check the server's OAuth configuration and run auth login again.",
          reason: "oauth_failed",
        }),
    });
    return {apiBasePath: discovery.apiBasePath, credential: result};
  });
}

export function parseHeadlessCallbackPaste(value: string, expectedState: string): z.infer<typeof callbackQuerySchema> {
  const pasted = value.trim();
  if (!pasted) throw new Error("Paste the authorization code or redirect URL.");
  if (!pasted.includes("://")) {
    return callbackQuerySchema.parse({code: pasted, state: expectedState});
  }
  const url = new URL(pasted);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    || url.pathname !== "/oauth/callback") {
    throw new Error("Paste the full loopback OAuth redirect URL or its authorization code.");
  }
  const parsed = callbackQuerySchema.parse(Object.fromEntries(url.searchParams));
  if (parsed.state !== expectedState) throw new Error("The OAuth callback state was invalid.");
  return parsed;
}

interface AuthorizationWait {
  readonly browserFailure: Promise<string> | undefined;
  readonly callback: LoopbackCallback;
  readonly expectedState: string;
  readonly headless: boolean;
}

type CallbackQuery = z.infer<typeof callbackQuerySchema>;

/**
 * Wait for whichever authorization response arrives first: the loopback
 * redirect from a browser on this machine, or a redirect URL pasted by a
 * person whose browser cannot reach this machine. Never waits silently on a
 * browser that failed to open.
 */
async function waitForAuthorizationResponse(
  wait: AuthorizationWait,
): Promise<CallbackQuery> {
  const interactive = process.stdin.isTTY;
  const browserFailure = wait.browserFailure ?? new Promise<string>(ignoreCallbackResult);
  const early = wait.headless
    ? {kind: "pending" as const}
    : await Promise.race([
      wait.callback.result.then(
        (query) => ({kind: "callback" as const, query}),
        () => ({kind: "pending" as const}),
      ),
      browserFailure.then((reason) => ({kind: "browser_failed" as const, reason})),
      delay(browserLaunchGraceMilliseconds, {kind: "pending" as const}, {ref: false}),
    ]);
  if (early.kind === "callback") return early.query;
  if (early.kind === "browser_failed" && !interactive) {
    throw noBrowserError(early.reason);
  }
  const acceptPaste = wait.headless || interactive;
  if (early.kind === "browser_failed") {
    process.stderr.write(`Could not open a browser on this machine (${early.reason}).\n`);
  }
  if (acceptPaste) {
    process.stderr.write(wait.headless || early.kind === "browser_failed"
      ? "Paste the 127.0.0.1 address from your browser here: "
      : `Waiting for the browser. If you signed in on another computer, copy the http://127.0.0.1:${cliOAuthCallbackPort}/... address its error page shows and paste it here: `);
  }
  const abort = new AbortController();
  let answered = false;
  const outcomes: Promise<CallbackQuery>[] = [wait.callback.result];
  if (acceptPaste) {
    outcomes.push(readPastedCallback(abort.signal).then((value) => {
      answered = true;
      return parseHeadlessCallbackPaste(value, wait.expectedState);
    }));
  } else {
    outcomes.push(browserFailure.then((reason) => Promise.reject(noBrowserError(reason))));
  }
  // The losing outcomes settle after the race; observe them so a late
  // rejection is not reported as unhandled.
  for (const outcome of outcomes) void outcome.catch(ignoreCallbackResult);
  try {
    return await Promise.race(outcomes);
  } finally {
    abort.abort();
    // End the pending prompt line when the browser completed sign-in instead.
    if (acceptPaste && !answered) process.stderr.write("\n");
  }
}

/**
 * Read one pasted line. When standard input ends first, nothing can be pasted,
 * so this never settles and the loopback callback, or its timeout, decides.
 */
async function readPastedCallback(signal: AbortSignal): Promise<string> {
  const terminal = createInterface({input: process.stdin, output: process.stderr});
  let finished = false;
  // readline leaves question() pending without notice once its input ends.
  const inputEnded = new Promise<never>((_resolve) => {
    // A pasted last line and end of input can arrive together; let the answer
    // settle first so only a genuinely unanswered prompt reports the wait.
    terminal.once("close", () => setImmediate(() => {
      if (finished || signal.aborted) return;
      process.stderr.write(
        `\nStandard input closed; waiting up to ${callbackTimeoutMilliseconds / 60_000} minutes for the browser to return to http://127.0.0.1:${cliOAuthCallbackPort}/oauth/callback.\n`,
      );
    }));
  });
  try {
    return await Promise.race([terminal.question("", {signal}), inputEnded]);
  } finally {
    finished = true;
    terminal.close();
  }
}

function noBrowserError(reason: string): CliAuthenticationError {
  return new CliAuthenticationError({
    message:
      `No browser could be opened on this machine (${reason}). Run artifactserver auth login with --headless in an interactive terminal, open the printed URL in any browser, and paste the final redirect URL.`,
    reason: "browser_authorization_unavailable",
  });
}

/** Refresh an OAuth profile without opening a browser. */
export const refreshCliOAuthCredential = Effect.fn("CliOAuth.refresh")(
  function*(
    origin: string,
    credential: Extract<StoredCliCredential, {readonly kind: "oauth"}>,
    environment: NodeJS.ProcessEnv = process.env,
    forceRefresh = false,
    apiBasePath = "",
  ): Effect.fn.Return<
    Extract<StoredCliCredential, {readonly kind: "oauth"}>,
    CliAuthenticationError
  > {
    if (!forceRefresh && oauthAccessTokenIsFresh(credential)) return credential;
    const provider = new ArtifactServerOAuthProvider({
      environment,
      redirectUrl: credential.redirectUrl,
      state: randomBytes(32).toString("base64url"),
      stored: credential,
      rejectBrowserRedirect: true,
    });
    return yield* Effect.tryPromise({
      try: async () => {
        try {
          const discovery = await discoverCliApi(origin, apiBasePath);
          await Effect.runPromise(
            verifyProtectedResourceMetadata(discovery.resource, discovery.metadataUrl),
          );
          const result = await auth(provider, {
            resourceMetadataUrl: discovery.metadataUrl,
            scope: cliScope,
            serverUrl: discovery.resource,
          });
          if (result !== "AUTHORIZED") {
            throw new Error("OAuth refresh requires a new login.");
          }
        } catch (cause) {
          // A server still discovering its issuer cannot renew anything yet,
          // and a new login would fail the same way: say so, and keep the grant.
          if (await oauthTemporarilyUnavailable(origin)) {
            throw temporarilyUnavailableError();
          }
          throw cause;
        }
        return provider.storedCredential();
      },
      catch: (cause) => cause instanceof CliAuthenticationError
        ? cause
        : new CliAuthenticationError({
          message:
            "The Artifact Server browser grant could not be renewed. Run artifactserver auth login again.",
          reason: "credential_revoked",
        }),
    });
  },
);

/** Best-effort remote OAuth revocation; local credential deletion remains separate. */
export const revokeCliOAuthCredential = Effect.fn("CliOAuth.revoke")(
  function*(
    origin: string,
    credential: Extract<StoredCliCredential, {readonly kind: "oauth"}>,
    apiBasePath = "",
  ): Effect.fn.Return<boolean> {
    return yield* Effect.promise(async () => {
      try {
        const api = await discoverCliApi(origin, apiBasePath);
        const discovered = await discoverOAuthServerInfo(api.resource, {resourceMetadataUrl: api.metadataUrl});
        const metadata = revocationMetadataSchema.safeParse(
          discovered.authorizationServerMetadata,
        );
        if (!metadata.success) return false;
        const token = credential.tokens.refresh_token
          ?? credential.tokens.access_token;
        const body = new URLSearchParams({
          client_id: credential.clientInformation.client_id,
          token,
          token_type_hint: credential.tokens.refresh_token === undefined
            ? "access_token"
            : "refresh_token",
        });
        const response = await fetch(metadata.data.revocation_endpoint, {
          body,
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          method: "POST",
          signal: AbortSignal.timeout(10_000),
        });
        return response.ok;
      } catch {
        return false;
      }
    });
  },
);

/** Report whether the API metadata answers 503: OAuth exists but is not up yet. */
async function oauthTemporarilyUnavailable(origin: string): Promise<boolean> {
  try {
    const response = await fetch(protectedResourceMetadataUrl(origin), {
      headers: {Accept: "application/json"},
      signal: AbortSignal.timeout(10_000),
    });
    await response.body?.cancel();
    return response.status === 503;
  } catch {
    return false;
  }
}

function temporarilyUnavailableError(): CliAuthenticationError {
  return new CliAuthenticationError({
    message:
      "This Artifact Server has not connected to its identity provider yet, so browser authorization is temporarily unavailable. Try again shortly.",
    reason: "server_unavailable",
  });
}

/** Exact RFC 9728 path for the Artifact Server HTTP API resource. */
export function protectedResourceMetadataUrl(origin: string): URL {
  return artifactServerProtectedResourceMetadataUrl(origin, "api");
}

interface OAuthProviderOptions {
  readonly environment: NodeJS.ProcessEnv;
  readonly issuer?: string;
  readonly redirectUrl: string;
  readonly rejectBrowserRedirect?: boolean;
  readonly headless?: boolean;
  readonly state: string;
  readonly stored?: Extract<StoredCliCredential, {readonly kind: "oauth"}>;
}

class ArtifactServerOAuthProvider implements OAuthClientProvider {
  readonly clientMetadataUrl = "https://artifactserver.com/oauth/client-metadata.json";
  readonly redirectUrl: string;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #rejectBrowserRedirect: boolean;
  readonly #headless: boolean;
  readonly #state: string;
  #browserLaunchFailure: Promise<string> | undefined;
  #clientInformation: StoredOAuthClientInformation | undefined;
  #codeVerifier: string | undefined;
  #discoveryState: OAuthDiscoveryState | undefined;
  #tokens: StoredOAuthTokens | undefined;
  #tokensSavedAt: string | undefined;

  constructor(options: OAuthProviderOptions) {
    this.#environment = options.environment;
    this.#rejectBrowserRedirect = options.rejectBrowserRedirect ?? false;
    this.#headless = options.headless ?? false;
    this.#state = options.state;
    this.redirectUrl = options.redirectUrl;
    const storedClientInformation = options.stored?.clientInformation;
    if (storedClientInformation !== undefined) {
      this.#clientInformation = storedClientInformation;
    } else {
      const clientInformation: StoredOAuthClientInformation = {
        client_id: cliOAuthClientId,
        redirect_uris: [this.redirectUrl],
        token_endpoint_auth_method: "none",
      };
      if (options.issuer !== undefined) {
        clientInformation.issuer = options.issuer;
      }
      this.#clientInformation = clientInformation;
    }
    this.#tokens = options.stored?.tokens;
    this.#tokensSavedAt = options.stored?.tokensSavedAt;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      application_type: "native",
      client_name: "Artifact Server CLI",
      grant_types: ["authorization_code", "refresh_token"],
      redirect_uris: [this.redirectUrl],
      response_types: ["code"],
      scope: `${cliScope} offline_access`,
      token_endpoint_auth_method: "none",
    };
  }

  state(): string {
    return this.#state;
  }

  clientInformation(
    _context?: OAuthClientInformationContext,
  ): StoredOAuthClientInformation | undefined {
    return this.#clientInformation;
  }

  saveClientInformation(
    information: StoredOAuthClientInformation,
    _context?: OAuthClientInformationContext,
  ): void {
    this.#clientInformation = information;
  }

  tokens(
    _context?: OAuthClientInformationContext,
  ): StoredOAuthTokens | undefined {
    return this.#tokens;
  }

  saveTokens(
    tokens: StoredOAuthTokens,
    _context?: OAuthClientInformationContext,
  ): void {
    this.#tokens = tokens;
    this.#tokensSavedAt = new Date().toISOString();
  }

  redirectToAuthorization(url: URL): Promise<void> {
    if (this.#rejectBrowserRedirect) {
      return Promise.reject(new Error("A new browser login is required."));
    }
    if (this.#headless) {
      process.stderr.write(`
Sign in to Artifact Server from any computer with a browser:

  1. Open this link (click it, or copy it into your browser):
     ${terminalLink(url)}
  2. Sign in. Your browser then tries to open an address starting with
     http://127.0.0.1:${cliOAuthCallbackPort}/oauth/callback and shows an error such as
     "This site can't be reached". That is expected: the address is meant
     for this machine, not the computer your browser runs on.
  3. Copy the whole address from the browser's address bar and paste it below.

`);
      return Promise.resolve();
    }
    // Print the address before launching so sign-in never depends on the
    // opener actually reaching a browser.
    process.stderr.write(`
Opening a browser to sign in to Artifact Server. If it does not open, visit:
${terminalLink(url)}

`);
    this.#browserLaunchFailure = launchBrowserForLogin(url, this.#environment);
    return Promise.resolve();
  }

  /** Settles with a reason only if the browser opener failed. */
  browserLaunchFailure(): Promise<string> | undefined {
    return this.#browserLaunchFailure;
  }

  saveCodeVerifier(verifier: string): void {
    this.#codeVerifier = verifier;
  }

  codeVerifier(): string {
    if (this.#codeVerifier === undefined) {
      throw new Error("The OAuth PKCE verifier is unavailable.");
    }
    return this.#codeVerifier;
  }

  saveDiscoveryState(discovery: OAuthDiscoveryState): void {
    this.#discoveryState = discovery;
  }

  discoveryState(): OAuthDiscoveryState | undefined {
    return this.#discoveryState;
  }

  invalidateCredentials(
    scope: "all" | "client" | "tokens" | "verifier" | "discovery",
  ): void {
    if (scope === "all" || scope === "client") this.#clientInformation = undefined;
    if (scope === "all" || scope === "tokens") this.#tokens = undefined;
    if (scope === "all" || scope === "verifier") this.#codeVerifier = undefined;
    if (scope === "all" || scope === "discovery") this.#discoveryState = undefined;
  }

  storedCredential(): Extract<StoredCliCredential, {readonly kind: "oauth"}> {
    if (
      this.#clientInformation === undefined
      || this.#tokens === undefined
      || this.#tokensSavedAt === undefined
    ) {
      throw new Error("OAuth did not return complete reusable credentials.");
    }
    return oauthCredential({
      clientInformation: this.#clientInformation,
      redirectUrl: this.redirectUrl,
      tokens: this.#tokens,
      tokensSavedAt: this.#tokensSavedAt,
    });
  }
}

function verifyProtectedResourceMetadata(
  resource: URL,
  metadataUrl: URL,
): Effect.Effect<string, CliAuthenticationError> {
  return Effect.tryPromise({
    try: async () => {
      const response = await fetch(metadataUrl, {
        headers: {Accept: "application/json"},
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      if (response.status === 404) {
        throw new CliAuthenticationError({
          message:
            "This Artifact Server does not advertise browser authorization for the CLI. Use --api-key-stdin with an administrator-issued key.",
          reason: "browser_authorization_unavailable",
        });
      }
      if (response.status === 503) throw temporarilyUnavailableError();
      if (!response.ok) throw new Error("metadata request failed");
      const metadata = protectedResourceMetadataSchema.parse(await response.json());
      if (
        metadata.resource !== resource.toString()
        || metadata.scopes_supported?.includes(cliScope) === false
      ) {
        throw new Error("metadata resource or scope mismatch");
      }
      const issuer = metadata.authorization_servers[0];
      if (issuer === undefined) {
        throw new Error("The Artifact Server omitted its authorization server.");
      }
      return issuer;
    },
    catch: (cause) => cause instanceof CliAuthenticationError
      ? cause
      : new CliAuthenticationError({
        message:
          "The Artifact Server CLI authorization metadata is invalid or unavailable.",
        reason: "invalid_metadata",
      }),
  });
}

interface LoopbackCallback {
  readonly close: () => Promise<void>;
  readonly redirectUrl: string;
  readonly result: Promise<z.infer<typeof callbackQuerySchema>>;
}

function openLoopbackCallback(
  expectedState: string,
): Effect.Effect<LoopbackCallback, CliAuthenticationError> {
  return Effect.tryPromise({
    try: () => createLoopbackCallback(expectedState),
    catch: () => new CliAuthenticationError({
      message:
        `Artifact Server could not open a private loopback OAuth callback on 127.0.0.1:${cliOAuthCallbackPort}. Another artifactserver auth login may still be running; stop it and try again.`,
      reason: "oauth_failed",
    }),
  });
}

async function createLoopbackCallback(
  expectedState: string,
): Promise<LoopbackCallback> {
  let resolveResult: (value: z.infer<typeof callbackQuerySchema>) => void =
    ignoreCallbackResult;
  let rejectResult: (cause: Error) => void = ignoreCallbackResult;
  const result = new Promise<z.infer<typeof callbackQuerySchema>>(
    (resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    },
  );
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method !== "GET" || url.pathname !== "/oauth/callback") {
      response.writeHead(404).end();
      return;
    }
    const parsed = callbackQuerySchema.safeParse(Object.fromEntries(url.searchParams));
    if (!parsed.success || parsed.data.state !== expectedState) {
      response.writeHead(400, {"Content-Type": "text/plain; charset=utf-8"});
      response.end("Artifact Server rejected this authorization response.");
      rejectResult(new Error("The OAuth callback state was invalid."));
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      "Content-Type": "text/html; charset=utf-8",
      "Referrer-Policy": "no-referrer",
    });
    response.end(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><title>Houston Artifacts connected</title><style>body{--bg:#f8fafc;--surface:#fff;--text:#0f172a;--accent:#0891b2;margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}.card{max-width:42rem;margin:24px;padding:32px;border:1px solid #cbd5e1;border-radius:12px;background:var(--surface)}.top{display:flex;align-items:center;gap:12px;margin-bottom:24px}.mark{width:32px;height:32px}h1{font-size:1.5rem;margin:0 0 8px}@media(prefers-color-scheme:dark){body{--bg:#0c1017;--surface:#131922;--text:#f1f5f9;--accent:#23b5d1}.card{border-color:#243041}}.brand{font-weight:600}</style></head><body><main class="card"><div class="top">${houstonServerPageMark()}<span class="brand">Houston Artifacts</span></div><h1>Houston Artifacts is connected.</h1><p>You can close this tab.</p></main></body></html>`
    );
    resolveResult(parsed.data);
  });
  await listenLoopback(server);
  const address = assignedAddressSchema.parse(server.address());
  const timeout = setTimeout(() => {
    rejectResult(new Error("Browser authorization timed out."));
    server.close();
  }, callbackTimeoutMilliseconds);
  timeout.unref();
  return {
    close: async () => {
      clearTimeout(timeout);
      await closeServer(server);
    },
    redirectUrl: `http://127.0.0.1:${address.port}/oauth/callback`,
    result,
  };
}

function listenLoopback(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(cliOAuthCallbackPort, "127.0.0.1", resolve);
  });
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => error === undefined ? resolve() : reject(error));
  });
}

/**
 * Render a URL for a person at a terminal. A long OAuth address that a
 * terminal or tmux wraps is often no longer detected as one link, and copying
 * it can carry the wrap breaks into the browser's address bar. An OSC 8
 * hyperlink (as Claude Code and gh print) stays one clickable link however it
 * wraps. The visible text is the full URL, so selecting and copying it still
 * works; pipes, files and `TERM=dumb` get the plain URL unchanged.
 */
export function terminalLink(
  url: URL | string,
  stream: {readonly isTTY?: boolean} = process.stderr,
  environment: NodeJS.ProcessEnv = process.env,
): string {
  const text = url.toString();
  if (stream.isTTY !== true || environment["TERM"] === "dumb") return text;
  return `\u001B]8;;${text}\u001B\\${text}\u001B]8;;\u001B\\`;
}

/** Open one trusted browser address with the configured operating-system command. */
export function openSystemBrowser(
  url: URL,
  environment: NodeJS.ProcessEnv,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const {child} = spawnBrowser(url, environment);
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

/**
 * Start the browser opener for login. The promise settles, with a reason, only
 * if the opener cannot start or exits unsuccessfully; a successful opener may
 * keep running for as long as the browser does.
 */
function launchBrowserForLogin(
  url: URL,
  environment: NodeJS.ProcessEnv,
): Promise<string> {
  return new Promise((resolve) => {
    let launched: SpawnedBrowser;
    try {
      launched = spawnBrowser(url, environment);
    } catch (cause) {
      resolve(cause instanceof Error ? cause.message : "the browser command could not start");
      return;
    }
    const name = path.basename(launched.command);
    launched.child.once("error", (error) => resolve(`${name}: ${error.message}`));
    launched.child.once("exit", (code, signal) => {
      if (code === 0) return;
      resolve(code === null
        ? `${name} stopped by ${signal ?? "a signal"}`
        : `${name} exited with code ${code}`);
    });
    launched.child.unref();
  });
}

interface SpawnedBrowser {
  readonly child: ChildProcess;
  readonly command: string;
}

function spawnBrowser(url: URL, environment: NodeJS.ProcessEnv): SpawnedBrowser {
  const configured = environment["ARTIFACT_SERVER_BROWSER_COMMAND"];
  if (configured !== undefined && !path.isAbsolute(configured)) {
    throw new Error(
      "ARTIFACT_SERVER_BROWSER_COMMAND must be an absolute executable path.",
    );
  }
  const command = configured ?? browserCommand();
  const childArguments = process.platform === "win32" && configured === undefined
    ? ["url.dll,FileProtocolHandler", url.toString()]
    : [url.toString()];
  const child = spawn(command, childArguments, {
    detached: configured === undefined,
    env: environment,
    stdio: "ignore",
    windowsHide: true,
  });
  return {child, command};
}

function browserCommand(): string {
  switch (process.platform) {
    case "darwin":
      return "/usr/bin/open";
    case "win32":
      return "rundll32.exe";
    default:
      return "xdg-open";
  }
}

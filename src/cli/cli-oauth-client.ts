import {type ChildProcess, spawn} from "node:child_process";
import {createInterface} from "node:readline/promises";
import {randomBytes} from "node:crypto";
import {createServer, type Server} from "node:http";
import path from "node:path";
import {setTimeout as delay} from "node:timers/promises";

import {
  auth,
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
  CliAuthenticationError,
  oauthAccessTokenIsFresh,
  oauthCredential,
  type StoredCliCredential,
} from "./cli-profile-credential.js";

const cliScope = "artifactserver";
const cliOAuthClientId = "artifact-server";
const callbackTimeoutMilliseconds = 5 * 60 * 1_000;
const cliOAuthCallbackPort = 45678;
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
  readonly credential: Extract<StoredCliCredential, {readonly kind: "oauth"}>;
}

/** Complete protected-resource discovery and S256 PKCE in the system browser. */
export const loginWithBrowserOAuth = Effect.fn("CliOAuth.login")(
  function*(
    origin: string,
    environment: NodeJS.ProcessEnv = process.env,
  ): Effect.fn.Return<CliOAuthLoginResult, CliAuthenticationError> {
    return yield* loginWithOAuth(origin, false, environment);
  },
);

/** Complete OAuth login on a headless host by accepting a pasted redirect code. */
export const loginWithHeadlessOAuth = Effect.fn("CliOAuth.loginHeadless")(
  function*(
    origin: string,
    environment: NodeJS.ProcessEnv = process.env,
  ): Effect.fn.Return<CliOAuthLoginResult, CliAuthenticationError> {
    return yield* loginWithOAuth(origin, true, environment);
  },
);

function loginWithOAuth(
  origin: string,
  headless: boolean,
  environment: NodeJS.ProcessEnv,
): Effect.Effect<CliOAuthLoginResult, CliAuthenticationError> {
  return Effect.gen(function*() {
    const resource = new URL("/api", origin);
    const metadataUrl = protectedResourceMetadataUrl(origin);
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
    return {credential: result};
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
      ? "Open the URL above in any browser, sign in, then paste the authorization code or the full redirect URL: "
      : "Waiting for the browser. If it runs on another machine, paste the final redirect URL here: ");
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
          const result = await auth(provider, {
            resourceMetadataUrl: protectedResourceMetadataUrl(origin),
            scope: cliScope,
            serverUrl: new URL("/api", origin),
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
  ): Effect.fn.Return<boolean> {
    return yield* Effect.promise(async () => {
      try {
        const discovered = await discoverOAuthServerInfo(
          new URL("/api", origin),
          {resourceMetadataUrl: protectedResourceMetadataUrl(origin)},
        );
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
  return new URL("/.well-known/oauth-protected-resource/api", origin);
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
Open this authorization URL on a machine with a browser:
${terminalLink(url)}

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
      "<!doctype html><meta charset=utf-8><title>Artifact Server connected</title><style>body{font:16px system-ui;margin:3rem;max-width:42rem}h1{font-size:1.5rem}</style><h1>Artifact Server is connected.</h1><p>You can close this tab.</p>",
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

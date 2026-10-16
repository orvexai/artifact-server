import {Effect, Redacted} from "effect";

import {resolveVerifiedProfileCredential} from "./cli-auth-commands.js";
import {CliAuthenticationError} from "./cli-profile-credential.js";
import {authenticatedCliHttpClientLayer} from "./cli-server-connection.js";
import {
  CliProfileError,
  readCliProfileState,
  type CliProfileState,
} from "./cli-profile-store.js";
import {CliCredentialStoreError, createSystemCredentialStore} from
  "./system-credential-store.js";

const tokenCacheMilliseconds = 30_000;

/** Authenticated remote profile used by the local MCP stdio bridge. */
export interface McpCliProfileConnection {
  readonly origin: string;
  readonly token: () => Promise<string>;
}

/**
 * Resolve the default CLI profile for MCP, or return null when it is absent or
 * cannot authenticate so the caller can preserve the legacy local bridge.
 */
export async function resolveDefaultMcpCliProfile(
  profileDirectory: string,
): Promise<McpCliProfileConnection | null> {
  let state: CliProfileState;
  try {
    state = await Effect.runPromise(readCliProfileState(profileDirectory));
  } catch (cause) {
    if (cause instanceof CliProfileError) return null;
    throw cause;
  }
  if (state.defaultProfileId === null) return null;
  const profile = state.profiles.find(({id}) => id === state.defaultProfileId);
  if (profile === undefined) return null;

  const store = createSystemCredentialStore();
  try {
    await resolveCredential(profileDirectory, profile, store);
  } catch (cause) {
    if (isUnavailableCredential(cause)) return null;
    throw cause;
  }

  let cachedToken: string | null = null;
  let cachedAt = 0;
  return {
    origin: profile.origin,
    token: async () => {
      if (cachedToken !== null && Date.now() - cachedAt < tokenCacheMilliseconds) {
        return cachedToken;
      }
      const credential = await resolveCredential(profileDirectory, profile, store);
      cachedToken = Redacted.value(credential.bearer);
      cachedAt = Date.now();
      return cachedToken;
    },
  };
}

function resolveCredential(
  profileDirectory: string,
  profile: Parameters<typeof resolveVerifiedProfileCredential>[1],
  store: ReturnType<typeof createSystemCredentialStore>,
) {
  return Effect.runPromise(
    resolveVerifiedProfileCredential(profileDirectory, profile, store).pipe(
      Effect.provide(authenticatedCliHttpClientLayer),
    ),
  );
}

function isUnavailableCredential(cause: unknown): boolean {
  if (cause instanceof CliCredentialStoreError) return true;
  return cause instanceof CliAuthenticationError;
}

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
const profileLookupCacheMilliseconds = 2_000;
const profileLookupCache = new Map<string, {
  readonly expiresAt: number;
  readonly promise: Promise<McpCliProfileConnection | null>;
}>();

/** Authenticated remote profile used by local MCP transports. */
export interface McpCliProfileConnection {
  readonly origin: string;
  readonly token: () => Promise<string>;
}

/**
 * Resolve the default CLI profile for MCP, or return null when it is absent or
 * cannot authenticate. The short shared cache coalesces auth lookups from many
 * concurrent local relay requests while still noticing login changes quickly.
 */
export async function resolveDefaultMcpCliProfile(
  profileDirectory: string,
): Promise<McpCliProfileConnection | null> {
  const cached = profileLookupCache.get(profileDirectory);
  if (cached !== undefined && cached.expiresAt > Date.now()) return cached.promise;
  const promise = resolveProfile(profileDirectory);
  const entry = {expiresAt: Number.POSITIVE_INFINITY, promise};
  profileLookupCache.set(profileDirectory, entry);
  try {
    const profile = await promise;
    entry.expiresAt = Date.now() + profileLookupCacheMilliseconds;
    return profile;
  } catch (error) {
    if (profileLookupCache.get(profileDirectory)?.promise === promise) {
      profileLookupCache.delete(profileDirectory);
    }
    throw error;
  }
}

async function resolveProfile(
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

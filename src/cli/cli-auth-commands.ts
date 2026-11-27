import {randomUUID} from "node:crypto";
import path from "node:path";
import {createInterface} from "node:readline/promises";

import * as FetchHttpClient from "effect/unstable/http/FetchHttpClient";
import type * as HttpClient from "effect/unstable/http/HttpClient";
import {type Command, Option} from "commander";
import {Effect, Redacted} from "effect";
import {z} from "zod";

import {
  apiKeyCredential,
  bearerFromStoredCredential,
  CliAuthenticationError,
  decodeStoredCliCredential,
  encodeStoredCliCredential,
  oauthAccessTokenIsFresh,
  type StoredCliCredential,
  verifyCliCredential,
} from "./cli-profile-credential.js";
import {
  loginWithBrowserOAuth,
  loginWithDeviceOAuth,
  loginWithHeadlessOAuth,
  refreshCliOAuthCredential,
  revokeCliOAuthCredential,
} from "./cli-oauth-client.js";
import {
  markCliProfileVerified,
  parseArtifactServerOrigin,
  readCliProfileState,
  removeCliProfile,
  resolveCliProfile,
  saveCliProfile,
  type CliProfile,
  type CliProfileSelection,
} from "./cli-profile-store.js";
import {
  createSystemCredentialStore,
  type CliCredentialStoreOperations,
} from "./system-credential-store.js";
import {runCliEffect} from "./run-cli-effect.js";

const organizationListSchema = z.array(z.object({
  displayName: z.string().min(1),
  role: z.string().min(1),
  slug: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u),
}).strict());

const maximumStdinCredentialBytes = 4_096;

interface LoginOptions {
  readonly apiKeyStdin: boolean;
  readonly device: boolean;
  readonly headless: boolean;
  readonly name?: string;
  readonly org?: string;
  readonly profileData: string;
}

interface ProfileSelectionOptions {
  readonly profileData: string;
  readonly server?: string;
}

/** User-local directory used by CLI profiles and no remote server state. */
export interface CliAuthCommandOptions {
  readonly defaultProfileDirectory: string;
}

/** Register secure CLI login, status, and logout commands. */
export function configureCliAuthCommands(
  program: Command,
  options: CliAuthCommandOptions,
): void {
  const authCommand = program.command("auth")
    .description("Manage authenticated Houston Artifacts CLI profiles.");
  authCommand
    .command("login")
    .description("Sign the CLI in to one exact Houston Artifacts origin.")
    .argument("<server>", "Houston Artifacts origin")
    .addOption(new Option("--name <profile>", "saved profile name"))
    .addOption(new Option("--org <slug>", "select one organization for a root sign-in"))
    .addOption(new Option("--headless", "sign in from another computer: open the printed link there, then paste back the 127.0.0.1 address the browser ends on").default(false))
    .addOption(new Option("--device", "sign in on a host without a browser: open the printed address on any device and enter the printed code").conflicts(["headless", "apiKeyStdin"]).default(false))
    .addOption(
      new Option(
        "--api-key-stdin",
        "read an administrator-issued API key from standard input",
      ).default(false),
    )
    .addOption(profileDataOption(options.defaultProfileDirectory))
    .action(async (server: string, commandOptions: LoginOptions) => {
      const store = createSystemCredentialStore();
      const profile = await runCliAuthEffect(loginProfile(
        path.resolve(commandOptions.profileData),
        server,
        commandOptions,
        store,
      ));
      console.log(JSON.stringify(profileOutput(profile, "authenticated"), null, 2));
    });

  authCommand
    .command("status [profile]")
    .description("Verify saved CLI profiles without printing credentials.")
    .addOption(new Option("--server <origin>", "exact Houston Artifacts origin"))
    .addOption(profileDataOption(options.defaultProfileDirectory))
    .action(async (
      profileName: string | undefined,
      commandOptions: ProfileSelectionOptions,
    ) => {
      const dataDirectory = path.resolve(commandOptions.profileData);
      const store = createSystemCredentialStore();
      const profiles = profileName === undefined && commandOptions.server === undefined
        ? (await runCliEffect(readCliProfileState(dataDirectory))).profiles
        : [await runCliEffect(resolveCliProfile(
          dataDirectory,
          profileSelection(profileName, commandOptions.server),
        ))];
      const statuses = await Promise.all(profiles.map((profile) =>
        runCliAuthEffect(inspectProfile(dataDirectory, profile, store))
          .catch((cause) => profileOutput(
            profile,
            "invalid",
            cause instanceof Error ? cause.message : String(cause),
          ))
      ));
      console.log(JSON.stringify({profiles: statuses}, null, 2));
      if (statuses.some((status) => status.status === "invalid")) {
        process.exitCode = 2;
      }
    });

  authCommand
    .command("logout [profile]")
    .description("Remove one saved CLI credential and profile.")
    .addOption(new Option("--server <origin>", "exact Houston Artifacts origin"))
    .addOption(profileDataOption(options.defaultProfileDirectory))
    .action(async (
      profileName: string | undefined,
      commandOptions: ProfileSelectionOptions,
    ) => {
      const dataDirectory = path.resolve(commandOptions.profileData);
      const store = createSystemCredentialStore();
      const profile = await runCliEffect(resolveCliProfile(
        dataDirectory,
        profileSelection(profileName, commandOptions.server),
      ));
      const result = await runCliAuthEffect(logoutProfile(
        dataDirectory,
        profile,
        store,
      ));
      console.log(JSON.stringify(result, null, 2));
    });
}

/** Load, renew when needed, and verify one saved profile credential. */
export const resolveVerifiedProfileCredential = Effect.fn(
  "CliAuth.resolveVerifiedProfileCredential",
)(function*(
  dataDirectory: string,
  profile: CliProfile,
  store: CliCredentialStoreOperations,
  forceRefresh = false,
) {
  const encoded = yield* store.read(profile.credentialId);
  let credential = yield* decodeStoredCliCredential(encoded);
  if (
    credential.kind === "oauth"
    && (forceRefresh || !oauthAccessTokenIsFresh(credential))
  ) {
    const originalApiBasePath = profile.apiBasePath ?? new URL(profile.origin).pathname.replace(/\/$/u, "");
    credential = yield* refreshCliOAuthCredential(
      profile.origin,
      credential,
      process.env,
      forceRefresh,
      originalApiBasePath,
    );
    yield* store.write(
      profile.credentialId,
      encodeStoredCliCredential(credential),
    );
  }
  let bearer = bearerFromStoredCredential(credential);
  let apiBasePath = profile.apiBasePath ?? new URL(profile.origin).pathname.replace(/\/$/u, "");
  let account = yield* verifyCliCredential(profile.origin, bearer, apiBasePath).pipe(
    Effect.catchTag("CliAuthenticationError", (error) => {
      if (
        error.reason !== "credential_revoked"
        || credential.kind !== "oauth"
        || forceRefresh
      ) return Effect.fail(error);
      const currentOAuthCredential = credential;
      return Effect.gen(function*() {
        credential = yield* refreshCliOAuthCredential(
          profile.origin,
          currentOAuthCredential,
          process.env,
          true,
          apiBasePath,
        );
        yield* store.write(
          profile.credentialId,
          encodeStoredCliCredential(credential),
        );
        bearer = bearerFromStoredCredential(credential);
        return yield* verifyCliCredential(profile.origin, bearer, apiBasePath);
      });
    }),
  );
  apiBasePath = account.apiBasePath;
  if (
    account.principal.id !== profile.accountId
    || account.principal.installationId !== profile.installationId
  ) {
    return yield* new CliAuthenticationError({
      message:
        "The saved credential belongs to a different Houston Artifacts account or installation.",
      reason: "credential_invalid",
    });
  }
  const updatedProfile = yield* markCliProfileVerified(dataDirectory, profile.id, apiBasePath);
  return {bearer, credential, profile: updatedProfile};
});

const loginProfile = Effect.fn("CliAuth.login")(
  function*(
    dataDirectory: string,
    server: string,
    options: LoginOptions,
    store: CliCredentialStoreOperations,
  ) {
    let origin = yield* parseArtifactServerOrigin(server);
    const requestedBasePath = new URL(origin).pathname.replace(/\/$/u, "");
    let apiBasePath = requestedBasePath;
    let credential: StoredCliCredential;
    if (options.apiKeyStdin) {
      credential = apiKeyCredential(yield* readApiKeyFromStandardInput());
    } else {
      const initial = options.device
        ? yield* loginWithDeviceOAuth(origin, apiBasePath)
        : options.headless
          ? yield* loginWithHeadlessOAuth(origin, process.env, apiBasePath)
          : yield* loginWithBrowserOAuth(origin, process.env, apiBasePath);
      credential = initial.credential;
      apiBasePath = initial.apiBasePath;
      if (requestedBasePath === "") {
        const organizations = yield* Effect.tryPromise({
          try: () => listOAuthOrganizations(origin, credential),
          catch: (cause) => new CliAuthenticationError({
            message: cause instanceof Error ? cause.message : "The signed-in account's organizations could not be read.",
            reason: "credential_invalid",
          }),
        });
        const selected = yield* Effect.tryPromise({
          try: () => selectOrganization(organizations, options.org),
          catch: (cause) => new CliAuthenticationError({
            message: cause instanceof Error ? cause.message : "An organization could not be selected.",
            reason: "credential_invalid",
          }),
        });
        apiBasePath = `/o/${selected.slug}`;
        if (selected.slug !== "orvex") {
          process.stderr.write(`Signing in to ${selected.displayName} (${selected.slug}) to finish setup.\n`);
          origin = `${new URL(origin).origin}${apiBasePath}`;
          const scoped = options.device
            ? yield* loginWithDeviceOAuth(origin, apiBasePath)
            : options.headless
              ? yield* loginWithHeadlessOAuth(origin, process.env, apiBasePath)
              : yield* loginWithBrowserOAuth(origin, process.env, apiBasePath);
          credential = scoped.credential;
          apiBasePath = scoped.apiBasePath;
        }
      }
      if (requestedBasePath !== "" && options.org !== undefined) {
        return yield* new CliAuthenticationError({
          message: "--org can only be used when signing in with the root server address.",
          reason: "credential_invalid",
        });
      }
    }
    const account = yield* verifyCliCredential(
      origin,
      bearerFromStoredCredential(credential),
      apiBasePath,
    );
    const currentState = yield* readCliProfileState(dataDirectory);
    const previous = currentState.profiles.find((profile) =>
      profile.origin === origin && profile.accountId === account.principal.id
    );
    const credentialId = randomUUID();
    yield* store.write(credentialId, encodeStoredCliCredential(credential));
    const profileInput = {
      accountId: account.principal.id,
      authentication: credential.kind,
      apiBasePath: account.apiBasePath,
      credentialId,
      installationId: account.principal.installationId,
      origin,
    };
    const profile = yield* (options.name === undefined
      ? saveCliProfile(dataDirectory, profileInput)
      : saveCliProfile(dataDirectory, {...profileInput, name: options.name})).pipe(
      Effect.tapError(() => store.delete(credentialId).pipe(Effect.ignore)),
    );
    if (
      previous !== undefined
      && previous.credentialId !== credentialId
    ) {
      yield* store.delete(previous.credentialId).pipe(Effect.ignore);
    }
    return profile;
  },
);

const inspectProfile = Effect.fn("CliAuth.status")(
  function*(
    dataDirectory: string,
    profile: CliProfile,
    store: CliCredentialStoreOperations,
  ) {
    yield* resolveVerifiedProfileCredential(dataDirectory, profile, store);
    return profileOutput(profile, "authenticated");
  },
);

const logoutProfile = Effect.fn("CliAuth.logout")(
  function*(
    dataDirectory: string,
    profile: CliProfile,
    store: CliCredentialStoreOperations,
  ) {
    const stored = yield* store.read(profile.credentialId).pipe(
      Effect.flatMap(decodeStoredCliCredential),
      Effect.catchTag("CliCredentialStoreError", (error) =>
        error.reason === "credential_missing"
          ? Effect.succeed(null)
          : Effect.fail(error)),
    );
    let remoteRevocation:
      | "confirmed"
      | "not_applicable"
      | "not_confirmed" = "not_applicable";
    if (stored?.kind === "oauth") {
      remoteRevocation = (yield* revokeCliOAuthCredential(
        profile.origin,
        stored,
        profile.apiBasePath ?? new URL(profile.origin).pathname.replace(/\/$/u, ""),
      ))
        ? "confirmed"
        : "not_confirmed";
    }
    yield* store.delete(profile.credentialId);
    yield* removeCliProfile(dataDirectory, profile.id);
    return {
      ...profileOutput(profile, "logged_out"),
      remoteRevocation,
    };
  },
);

function readApiKeyFromStandardInput(): Effect.Effect<
  string,
  CliAuthenticationError
> {
  return Effect.tryPromise({
    try: async () => {
      if (process.stdin.isTTY) {
        throw new Error(
          "Pipe the administrator-issued key to --api-key-stdin so it does not enter shell history.",
        );
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of process.stdin) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > maximumStdinCredentialBytes) {
          throw new Error("The API key on standard input exceeds the safe limit.");
        }
        chunks.push(buffer);
      }
      const credential = Buffer.concat(chunks).toString("utf8").trim();
      if (credential.length < 32) {
        throw new Error("Standard input did not contain a valid Houston Artifacts API key.");
      }
      return credential;
    },
    catch: (cause) => new CliAuthenticationError({
      message: cause instanceof Error
        ? cause.message
        : "The Houston Artifacts API key could not be read from standard input.",
      reason: "credential_invalid",
    }),
  });
}

function profileOutput(
  profile: CliProfile,
  status: "authenticated" | "invalid" | "logged_out",
  detail?: string,
) {
  const output = {
    accountId: profile.accountId,
    apiBasePath: profile.apiBasePath ?? new URL(profile.origin).pathname.replace(/\/$/u, ""),
    authentication: profile.authentication,
    installationId: profile.installationId,
    name: profile.name,
    origin: profile.origin,
    status,
  };
  if (detail !== undefined) return {...output, error: detail};
  return output;
}

async function listOAuthOrganizations(
  origin: string,
  credential: StoredCliCredential,
): Promise<z.infer<typeof organizationListSchema>> {
  const url = new URL("/api/v1/platform/me/orgs", new URL(origin).origin);
  const response = await fetch(url, {
    headers: {Authorization: `Bearer ${Redacted.value(bearerFromStoredCredential(credential))}`},
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Organization lookup at ${url} returned HTTP ${response.status}.`);
  }
  return organizationListSchema.parse(await response.json());
}

async function selectOrganization(
  organizations: z.infer<typeof organizationListSchema>,
  requestedSlug: string | undefined,
): Promise<z.infer<typeof organizationListSchema>[number]> {
  if (organizations.length === 0) throw new Error("The signed-in account belongs to no active organizations. Use an account with a verified email address that belongs to an organization, or ask an organization owner to add it.");
  if (requestedSlug !== undefined) {
    const selected = organizations.find(({slug}) => slug === requestedSlug);
    if (selected === undefined) {
      throw new Error(`Organization ${requestedSlug} is unavailable. Available organizations: ${organizations.map(({slug}) => slug).join(", ")}.`);
    }
    return selected;
  }
  if (organizations.length === 1) {
    const only = organizations[0];
    if (only !== undefined) return only;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(`Several organizations are available: ${organizations.map(({slug}) => slug).join(", ")}. Rerun with --org <slug>.`);
  }
  process.stderr.write(`Select an organization:\n${organizations.map(({displayName, slug}, index) => `  ${index + 1}) ${displayName} (${slug})`).join("\n")}\n`);
  const terminal = createInterface({input: process.stdin, output: process.stderr});
  try {
    const answer = await terminal.question("Organization number: ");
    const index = Number(answer.trim()) - 1;
    const selected = organizations[index];
    if (selected === undefined) throw new Error("Enter one of the listed organization numbers.");
    return selected;
  } finally {
    terminal.close();
  }
}

function profileDataOption(defaultDirectory: string): Option {
  return new Option(
    "--profile-data <directory>",
    "user-local CLI profile directory",
  ).default(defaultDirectory).env("ARTIFACT_SERVER_HOME");
}

function profileSelection(
  name: string | undefined,
  origin: string | undefined,
): CliProfileSelection {
  if (name !== undefined && origin !== undefined) return {name, origin};
  if (name !== undefined) return {name};
  if (origin !== undefined) return {origin};
  return {};
}

function runCliAuthEffect<A, E extends {_tag: string; message: string}>(
  effect: Effect.Effect<A, E, HttpClient.HttpClient>,
): Promise<A> {
  return runCliEffect(effect.pipe(Effect.provide(FetchHttpClient.layer)));
}

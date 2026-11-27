import {spawn, type ChildProcessWithoutNullStreams} from "node:child_process";
import {createHash} from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from "node:http";
import {createServer} from "node:net";
import {tmpdir} from "node:os";
import path from "node:path";

import {afterEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {fetchLoopbackContent} from "../support/fetch-loopback-content.js";
import {
  artifactServerProtectedResourceMetadataUrl,
  artifactServerRouteUrl,
} from "../../src/core/server-address.js";

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const cliExecutable = path.join(repositoryRoot, "node_modules/.bin/tsx");
const cliEntrypoint = path.join(repositoryRoot, "src/cli/main.ts");
const runningProcesses = new Set<ChildProcessWithoutNullStreams>();
const assignedAddressSchema = z.object({port: z.number().int().positive()});
const profileOutputSchema = z.object({
  accountId: z.string(),
  authentication: z.enum(["api_key", "oauth"]),
  installationId: z.string(),
  name: z.string(),
  origin: z.url(),
  status: z.enum(["authenticated", "invalid", "logged_out"]),
});
const publicationSchema = z.object({
  artifact: z.object({id: z.string(), projectId: z.string()}),
  links: z.object({artifact: z.url(), version: z.url()}),
  version: z.object({id: z.string(), number: z.number().int().positive()}),
});
type JsonValue =
  | boolean
  | null
  | number
  | string
  | {readonly [key: string]: JsonValue}
  | readonly JsonValue[];

afterEach(async () => {
  await Promise.all([...runningProcesses].map(stopProcess));
});

describe("authenticated CLI profiles and remote publication", () => {
  test("CLI-ORG-001: logs in and publishes through an organization base path", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-org-address-"),
    );
    const serverData = path.join(temporaryDirectory, "server");
    const profileData = path.join(temporaryDirectory, "profiles");
    const helperState = path.join(temporaryDirectory, "credential-helper.json");
    const helper = path.join(temporaryDirectory, "credential-helper.mjs");
    const fixture = path.join(temporaryDirectory, "org-report.html");
    const environment = await credentialHelperEnvironment(helper, helperState);
    await writeFile(fixture, "<h1>Organization path</h1>");
    const port = await availablePort();
    const backend = startServer(serverData, port);
    let proxy: OrganizationAddressProxy | null = null;
    try {
      await waitForReady(backend, port);
      const backendOrigin = `http://127.0.0.1:${port}`;
      proxy = await startOrganizationAddressProxy(backendOrigin);
      const token = (await readFile(path.join(serverData, "local-api-token"), "utf8")).trim();
      const address = proxy.origin;
      expect(artifactServerRouteUrl("/api", address).toString()).toBe(`${address}/api`);
      expect(artifactServerProtectedResourceMetadataUrl(address, "api").toString())
        .toBe(`${proxy.origin}/.well-known/oauth-protected-resource/api`);
      const login = await runCli([
        "auth", "login", address, "--api-key-stdin", "--name", "organization",
        "--profile-data", profileData,
      ], environment, `${token}\n`);
      expect({exitCode: login.exitCode, stderr: login.stderr}).toEqual({exitCode: 0, stderr: ""});
      expect(profileOutputSchema.parse(JSON.parse(login.stdout))).toMatchObject({
        authentication: "api_key",
        name: "organization",
        origin: address,
        status: "authenticated",
      });
      expect(JSON.parse(login.stdout)).toMatchObject({apiBasePath: "/o/orvex"});

      const published = await runCli([
        "publish", fixture, "--public", "--profile-data", profileData,
      ], environment);
      expect({exitCode: published.exitCode, stderr: published.stderr}).toEqual({
        exitCode: 0,
        stderr: "",
      });
      expect(publicationSchema.parse(JSON.parse(published.stdout)).version.number).toBe(1);
      expect(proxy.paths().length).toBeGreaterThan(3);
      expect(proxy.paths().some((pathname) => pathname.startsWith("/o/orvex/api/"))).toBe(true);
      expect(proxy.paths().filter((pathname) => pathname.endsWith("/api/v1/session"))
        .every((pathname) => pathname.startsWith("/o/orvex/api/"))).toBe(true);

      const tenantAddress = `${proxy.origin}/o/orvex`;
      const tenantLogin = await runCli([
        "auth", "login", tenantAddress, "--api-key-stdin", "--name", "tenant",
        "--profile-data", profileData,
      ], environment, `${token}\n`);
      expect(tenantLogin.exitCode).toBe(0);
      expect(JSON.parse(tenantLogin.stdout)).toMatchObject({apiBasePath: "/o/orvex"});
      const tenantPublish = await runCli([
        "publish", fixture, "--public", "--profile", "tenant", "--profile-data", profileData,
      ], environment);
      expect(tenantPublish.exitCode).toBe(0);
    } finally {
      await proxy?.stop();
      await stopProcess(backend);
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 90_000);

  test("CLI-003-B CLI-003-F: resumes a lost commit response across CLI process restarts", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-publication-recovery-"),
    );
    const serverData = path.join(temporaryDirectory, "server");
    const profileData = path.join(temporaryDirectory, "profiles");
    const fixture = path.join(temporaryDirectory, "report.html");
    await writeFile(fixture, "<h1>Recover this exact publication</h1>");
    const port = await availablePort();
    const server = startServer(serverData, port);
    let proxy: LostCommitResponseProxy | null = null;
    try {
      await waitForReady(server, port);
      const token = (await readFile(
        path.join(serverData, "local-api-token"),
        "utf8",
      )).trim();
      const serverOrigin = `http://127.0.0.1:${port}`;
      proxy = await startLostCommitResponseProxy(serverOrigin);
      const environment = {
        ...process.env,
        ARTIFACT_SERVER_API_TOKEN: token,
        ARTIFACT_SERVER_URL: proxy.origin,
      };
      const publicationArguments = [
        "publish",
        fixture,
        "--name",
        "Recoverable report",
        "--profile-data",
        profileData,
        "--public",
      ];

      const lost = await runCli(publicationArguments, environment);
      expect(proxy.errors()).toEqual([]);
      expect(lost.exitCode).not.toBe(0);
      expect(lost.stderr).toContain("Artifact Server could not be reached");
      expect(proxy.droppedResponses()).toBe(1);
      const operationDirectory = path.join(profileData, "publication-operations");
      const pendingOperations = await readdir(operationDirectory);
      expect(pendingOperations).toHaveLength(1);
      const pendingOperation = pendingOperations[0];
      expect(pendingOperation).toBeDefined();
      expect((await stat(path.join(
        operationDirectory,
        pendingOperation ?? "missing",
      ))).mode & 0o777).toBe(0o600);
      expect((await stat(operationDirectory)).mode & 0o777).toBe(0o700);

      await writeFile(fixture, "<h1>This is a different publication</h1>");
      const changedInput = await runCli(publicationArguments, environment);
      expect(changedInput.exitCode).not.toBe(0);
      expect(changedInput.stderr).toContain(
        "input changed while an earlier attempt is still pending",
      );
      expect(await readdir(operationDirectory)).toHaveLength(1);
      await writeFile(fixture, "<h1>Recover this exact publication</h1>");

      const recovered = await runCli(publicationArguments, environment);
      expect({exitCode: recovered.exitCode, stderr: recovered.stderr}).toEqual({
        exitCode: 0,
        stderr: "",
      });
      expect(publicationSchema.extend({replayed: z.literal(true)}).parse(
        JSON.parse(recovered.stdout),
      ).version.number).toBe(1);
      expect(await readdir(operationDirectory)).toHaveLength(0);

      const listed = await fetch(`${serverOrigin}/api/v1/artifacts?limit=100`, {
        headers: {Authorization: `Bearer ${token}`},
      });
      expect(listed.status).toBe(200);
      expect(z.object({artifacts: z.array(z.unknown())}).parse(
        await listed.json(),
      ).artifacts).toHaveLength(1);
    } finally {
      if (proxy !== null) await proxy.stop();
      await stopProcess(server);
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 75_000);

  test("CLI-002-B PUB-012-B: stores a verified profile outside the project and publishes through it after restart", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-profile-"),
    );
    const serverData = path.join(temporaryDirectory, "server");
    const profileData = path.join(temporaryDirectory, "profiles");
    const helperState = path.join(temporaryDirectory, "credential-helper.json");
    const helper = path.join(temporaryDirectory, "credential-helper.mjs");
    const fixture = path.join(temporaryDirectory, "report.txt");
    const site = path.join(temporaryDirectory, "site");
    const environment = await credentialHelperEnvironment(helper, helperState);
    await mkdir(site);
    await writeFile(fixture, "remote profile publication\n");
    await writeFile(path.join(site, "index.html"), "<h1>Remote site</h1>");
    await writeFile(path.join(site, "site.css"), "h1 { color: navy; }");

    const firstPort = await availablePort();
    let server = startServer(serverData, firstPort);
    try {
      await waitForReady(server, firstPort);
      const token = (await readFile(
        path.join(serverData, "local-api-token"),
        "utf8",
      )).trim();
      const firstOrigin = `http://127.0.0.1:${firstPort}`;
      const ciPublication = await runCli(
        ["publish", fixture, "--public", "--profile-data", profileData],
        {
          ...environment,
          ARTIFACT_SERVER_API_TOKEN: token,
          ARTIFACT_SERVER_URL: firstOrigin,
        },
      );
      expect(ciPublication.exitCode).toBe(0);
      expect(publicationSchema.parse(JSON.parse(ciPublication.stdout)).artifact.id)
        .toBeTruthy();
      await expect(readFile(path.join(profileData, "cli-profiles.json"), "utf8"))
        .rejects.toMatchObject({code: "ENOENT"});

      const login = await runCli(
        [
          "auth",
          "login",
          firstOrigin,
          "--api-key-stdin",
          "--name",
          "team",
          "--profile-data",
          profileData,
        ],
        environment,
        `${token}\n`,
      );
      expect({exitCode: login.exitCode, stderr: login.stderr}).toEqual({
        exitCode: 0,
        stderr: "",
      });
      expect(profileOutputSchema.parse(JSON.parse(login.stdout))).toMatchObject({
        authentication: "api_key",
        name: "team",
        origin: firstOrigin,
        status: "authenticated",
      });
      // This fixture starts the server at its root address, so discovery keeps the root API base.
      expect(JSON.parse(login.stdout)).toMatchObject({apiBasePath: ""});
      expect(login.stdout).not.toContain(token);
      expect(login.stderr).not.toContain(token);

      const profileIndex = await readFile(
        path.join(profileData, "cli-profiles.json"),
        "utf8",
      );
      expect(profileIndex).not.toContain(token);
      expect((await stat(path.join(profileData, "cli-profiles.json"))).mode & 0o777)
        .toBe(0o600);
      const helperDatabase = await readFile(helperState, "utf8");
      expect(helperDatabase).toContain(token);

      const status = await runCli(
        ["auth", "status", "team", "--profile-data", profileData],
        environment,
      );
      expect(status.exitCode).toBe(0);
      expect(status.stdout).not.toContain(token);
      expect(JSON.parse(status.stdout)).toMatchObject({
        profiles: [{name: "team", status: "authenticated"}],
      });

      const firstPublication = await runCli(
        [
          "publish",
          fixture,
          "--profile",
          "team",
          "--profile-data",
          profileData,
          "--public",
        ],
        environment,
      );
      expect(firstPublication.exitCode).toBe(0);
      const firstResult = publicationSchema.parse(JSON.parse(firstPublication.stdout));
      expect(await fetchLoopbackContent(firstResult.links.version).then((response) =>
        response.text()
      ))
        .toBe("remote profile publication\n");

      const directoryPublication = await runCli(
        [
          "publish",
          site,
          "--profile",
          "team",
          "--profile-data",
          profileData,
          "--public",
        ],
        environment,
      );
      expect(directoryPublication.exitCode).toBe(0);
      const directoryResult = publicationSchema.parse(
        JSON.parse(directoryPublication.stdout),
      );
      expect(await fetchLoopbackContent(directoryResult.links.version).then((response) =>
        response.text()
      )).toBe("<h1>Remote site</h1>");

      await stopProcess(server);
      server = startServer(serverData, firstPort);
      await waitForReady(server, firstPort);
      const afterRestart = await runCli(
        [
          "publish",
          fixture,
          "--profile",
          "team",
          "--profile-data",
          profileData,
          "--public",
        ],
        environment,
      );
      expect(afterRestart.exitCode).toBe(0);
      expect(publicationSchema.parse(JSON.parse(afterRestart.stdout)).artifact.id)
        .not.toBe(firstResult.artifact.id);

      const mismatchedOrigin = await runCli(
        [
          "publish",
          fixture,
          "--profile",
          "team",
          "--server",
          `http://localhost:${firstPort}`,
          "--profile-data",
          profileData,
        ],
        environment,
      );
      expect(mismatchedOrigin.exitCode).not.toBe(0);
      expect(mismatchedOrigin.stderr).toContain("CliProfileError");
      expect(mismatchedOrigin.stderr).not.toContain(token);

      const logout = await runCli(
        ["auth", "logout", "team", "--profile-data", profileData],
        environment,
      );
      expect(logout.exitCode).toBe(0);
      expect(profileOutputSchema.parse(JSON.parse(logout.stdout))).toMatchObject({
        name: "team",
        status: "logged_out",
      });
      expect(logout.stdout).not.toContain(token);
      const removed = await runCli(
        ["auth", "status", "team", "--profile-data", profileData],
        environment,
      );
      expect(removed.exitCode).not.toBe(0);
      expect(removed.stderr).toContain("CliProfileError");
    } finally {
      await stopProcess(server);
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 210_000);

  test("CLI-002-F PUB-012-F: rejects an invalid credential without saving it and never sends one profile to another origin", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-profile-failure-"),
    );
    const profileData = path.join(temporaryDirectory, "profiles");
    const helperState = path.join(temporaryDirectory, "credential-helper.json");
    const helper = path.join(temporaryDirectory, "credential-helper.mjs");
    const firstData = path.join(temporaryDirectory, "first-server");
    const secondData = path.join(temporaryDirectory, "second-server");
    const environment = await credentialHelperEnvironment(helper, helperState);
    const firstPort = await availablePort();
    const secondPort = await availablePort();
    const first = startServer(firstData, firstPort);
    const second = startServer(secondData, secondPort);
    try {
      await Promise.all([
        waitForReady(first, firstPort),
        waitForReady(second, secondPort),
      ]);
      const invalidCredential = "invalid-credential-with-sufficient-entropy";
      const rejected = await runCli(
        [
          "auth",
          "login",
          `http://127.0.0.1:${firstPort}`,
          "--api-key-stdin",
          "--profile-data",
          profileData,
        ],
        environment,
        `${invalidCredential}\n`,
      );
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.stderr).not.toContain(invalidCredential);
      await expect(readFile(path.join(profileData, "cli-profiles.json"), "utf8"))
        .rejects.toMatchObject({code: "ENOENT"});
      await expect(readFile(helperState, "utf8"))
        .rejects.toMatchObject({code: "ENOENT"});

      const firstToken = (await readFile(
        path.join(firstData, "local-api-token"),
        "utf8",
      )).trim();
      const login = await runCli(
        [
          "auth",
          "login",
          `http://127.0.0.1:${firstPort}`,
          "--api-key-stdin",
          "--name",
          "first",
          "--profile-data",
          profileData,
        ],
        environment,
        `${firstToken}\n`,
      );
      expect(login.exitCode).toBe(0);
      const wrongOrigin = await runCli(
        [
          "auth",
          "status",
          "first",
          "--server",
          `http://127.0.0.1:${secondPort}`,
          "--profile-data",
          profileData,
        ],
        environment,
      );
      expect(wrongOrigin.exitCode).not.toBe(0);
      expect(wrongOrigin.stderr).toContain("CliProfileError");
      expect(wrongOrigin.stderr).not.toContain(firstToken);

      const unavailableLogout = await runCli(
        ["auth", "logout", "first", "--profile-data", profileData],
        {
          ...environment,
          ARTIFACT_SERVER_CREDENTIAL_STORE: "keyring",
          ARTIFACT_SERVER_CREDENTIAL_HELPER: path.join(
            temporaryDirectory,
            "missing-helper",
          ),
        },
      );
      expect(unavailableLogout.exitCode).not.toBe(0);
      expect(unavailableLogout.stderr).toContain("credential store is unavailable");
      const retainedProfile = await runCli(
        ["auth", "status", "first", "--profile-data", profileData],
        environment,
      );
      expect(retainedProfile.exitCode).toBe(0);
    } finally {
      await Promise.all([stopProcess(first), stopProcess(second)]);
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 120_000);

  test("completes browser PKCE, refresh, status, and revocation against real HTTP boundaries", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-oauth-"),
    );
    const profileData = path.join(temporaryDirectory, "profiles");
    const helperState = path.join(temporaryDirectory, "credential-helper.json");
    const helper = path.join(temporaryDirectory, "credential-helper.mjs");
    const browser = path.join(temporaryDirectory, "browser.mjs");
    const environment = await credentialHelperEnvironment(helper, helperState);
    await writeBrowserHelper(browser);
    environment["ARTIFACT_SERVER_BROWSER_COMMAND"] = browser;
    const oauth = await startOAuthFixture();
    try {
      const login = await runCli([
        "auth",
        "login",
        oauth.origin,
        "--name",
        "browser-team",
        "--profile-data",
        profileData,
      ], environment);
      expect(login.exitCode).toBe(0);
      // The address is always printed so sign-in never depends on the opener.
      expect(login.stderr).toContain("If it does not open, visit:");
      expect(login.stderr).toContain(`${oauth.origin}/authorize?`);
      expect(login.stderr).not.toContain("oauth-access-one");
      expect(profileOutputSchema.parse(JSON.parse(login.stdout))).toMatchObject({
        authentication: "oauth",
        name: "browser-team",
        status: "authenticated",
      });
      expect(oauth.observations).toMatchObject({
        authorizationCount: 1,
        codeExchangeCount: 1,
        lastClientId: "artifact-server",
        registrationCount: 0,
      });
      expect(oauth.observations.pkceVerified).toBe(true);
      expect(oauth.observations.lastRedirectUri)
        .toBe("http://127.0.0.1:45678/oauth/callback");
      expect(login.stdout).not.toContain("oauth-access-one");
      expect(login.stdout).not.toContain("oauth-refresh-one");

      const status = await runCli([
        "auth",
        "status",
        "browser-team",
        "--profile-data",
        profileData,
      ], environment);
      expect(status.exitCode).toBe(0);
      expect(oauth.observations.refreshCount).toBe(1);
      expect(oauth.observations.lastSessionBearer).toBe("oauth-access-two");
      expect(status.stdout).not.toContain("oauth-access-two");
      expect(status.stdout).not.toContain("oauth-refresh-two");

      const logout = await runCli([
        "auth",
        "logout",
        "browser-team",
        "--profile-data",
        profileData,
      ], environment);
      expect(logout.exitCode).toBe(0);
      expect(JSON.parse(logout.stdout)).toMatchObject({
        remoteRevocation: "confirmed",
        status: "logged_out",
      });
      expect(oauth.observations.revocationCount).toBe(1);
      expect(oauth.observations.revokedToken).toBe("oauth-refresh-two");

      oauth.advertiseWrongResource();
      const rejected = await runCli([
        "auth",
        "login",
        oauth.origin,
        "--name",
        "wrong-resource",
        "--profile-data",
        profileData,
      ], environment);
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.stderr).toContain("advertised an unexpected resource");
      expect(oauth.observations.authorizationCount).toBe(1);
    } finally {
      await oauth.stop();
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 75_000);

  test("selects one root-login organization, rejects ambiguous noninteractive and zero-org access, and keeps audiences scoped", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-oauth-orgs-"),
    );
    const profileData = path.join(temporaryDirectory, "profiles");
    const helperState = path.join(temporaryDirectory, "credential-helper.json");
    const helper = path.join(temporaryDirectory, "credential-helper.mjs");
    const browser = path.join(temporaryDirectory, "browser.mjs");
    const environment = await credentialHelperEnvironment(helper, helperState);
    await writeBrowserHelper(browser);
    environment["ARTIFACT_SERVER_BROWSER_COMMAND"] = browser;
    const oauth = await startOAuthFixture([
      {displayName: "Acme", role: "owner", slug: "acme"},
      {displayName: "Orvex", role: "administrator", slug: "orvex"},
    ]);
    try {
      const ambiguous = await runCli([
        "auth", "login", oauth.origin, "--profile-data", profileData,
      ], environment);
      expect(ambiguous.exitCode).not.toBe(0);
      expect(ambiguous.stderr).toContain("Several organizations are available: acme, orvex");

      const selected = await runCli([
        "auth", "login", oauth.origin, "--org", "acme", "--profile-data", profileData,
      ], environment);
      expect(selected.exitCode).toBe(0);
      expect(JSON.parse(selected.stdout)).toMatchObject({
        apiBasePath: "/o/acme",
        origin: `${oauth.origin}/o/acme`,
        status: "authenticated",
      });
      expect(selected.stderr).toContain("Signing in to Acme (acme) to finish setup.");
      const reused = await fetch(`${oauth.origin}/o/orvex/api/v1/session`, {
        headers: {Authorization: "Bearer oauth-access-acme"},
      });
      expect(reused.status).toBe(401);

      const empty = await startOAuthFixture([]);
      try {
        const noOrganizations = await runCli([
          "auth", "login", empty.origin, "--profile-data", path.join(temporaryDirectory, "empty-profiles"),
        ], environment);
        expect(noOrganizations.exitCode).not.toBe(0);
        expect(noOrganizations.stderr).toContain("belongs to no active organizations");
        expect(noOrganizations.stderr).toContain(
          "Use an account with a verified email address that belongs to an organization, or ask an organization owner to add it.",
        );
      } finally {
        await empty.stop();
      }
    } finally {
      await oauth.stop();
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 75_000);

  test("fails fast with the authorization URL when no browser can be opened", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-no-browser-"),
    );
    const browser = path.join(temporaryDirectory, "no-browser.mjs");
    const environment = await credentialHelperEnvironment(
      path.join(temporaryDirectory, "credential-helper.mjs"),
      path.join(temporaryDirectory, "credential-helper.json"),
    );
    // Mirrors xdg-open on a host without a graphical session.
    await writeFile(browser, "#!/usr/bin/env node\nprocess.exit(3);\n", {mode: 0o700});
    environment["ARTIFACT_SERVER_BROWSER_COMMAND"] = browser;
    const oauth = await startOAuthFixture();
    try {
      const startedAt = Date.now();
      const login = await runCli([
        "auth",
        "login",
        oauth.origin,
        "--profile-data",
        path.join(temporaryDirectory, "profiles"),
      ], environment);
      expect(Date.now() - startedAt).toBeLessThan(15_000);
      expect(login.exitCode).not.toBe(0);
      expect(login.stderr).toContain(`${oauth.origin}/authorize?`);
      expect(login.stderr).toContain("No browser could be opened on this machine");
      expect(login.stderr).toContain("exited with code 3");
      expect(login.stderr).toContain("--headless");
      expect(oauth.observations.codeExchangeCount).toBe(0);
    } finally {
      await oauth.stop();
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 30_000);

  test("completes headless login from a pasted redirect URL", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-headless-paste-"),
    );
    const environment = await credentialHelperEnvironment(
      path.join(temporaryDirectory, "credential-helper.mjs"),
      path.join(temporaryDirectory, "credential-helper.json"),
    );
    const oauth = await startOAuthFixture();
    try {
      const login = startCliSession([
        "auth",
        "login",
        oauth.origin,
        "--headless",
        "--profile-data",
        path.join(temporaryDirectory, "profiles"),
      ], environment);
      const authorizationUrl = await login.authorizationUrl();
      // A browser on another machine cannot reach this loopback listener, so
      // the person copies the redirect from the address bar instead.
      const authorization = await fetch(authorizationUrl, {redirect: "manual"});
      const redirect = authorization.headers.get("location");
      expect(redirect).toMatch(/^http:\/\/127\.0\.0\.1:45678\/oauth\/callback\?/u);
      login.writeLine(redirect ?? "");
      const result = await login.finished;
      expect(result.exitCode).toBe(0);
      expect(profileOutputSchema.parse(JSON.parse(result.stdout))).toMatchObject({
        authentication: "oauth",
        status: "authenticated",
      });
      expect(oauth.observations.pkceVerified).toBe(true);
      expect(result.stderr).not.toContain("Standard input closed");
    } finally {
      await oauth.stop();
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 30_000);

  // An agent runs the command with standard input closed; a person may still
  // sign in with a browser on this machine.
  test.each([
    {closeInput: false, input: "open"},
    {closeInput: true, input: "closed"},
  ])("completes headless login from the loopback callback with $input standard input", async ({closeInput}) => {
    const temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "artifact-server-cli-headless-loopback-"),
    );
    const environment = await credentialHelperEnvironment(
      path.join(temporaryDirectory, "credential-helper.mjs"),
      path.join(temporaryDirectory, "credential-helper.json"),
    );
    const oauth = await startOAuthFixture();
    try {
      const login = startCliSession([
        "auth",
        "login",
        oauth.origin,
        "--headless",
        "--profile-data",
        path.join(temporaryDirectory, "profiles"),
      ], environment);
      if (closeInput) login.closeInput();
      const authorizationUrl = await login.authorizationUrl();
      const browser = await fetch(authorizationUrl, {redirect: "follow"});
      expect(browser.ok).toBe(true);
      expect(browser.headers.get("content-security-policy")).toBe(
        "default-src 'none'; style-src 'unsafe-inline'",
      );
      expect(await browser.text()).toContain("Houston Artifacts is connected.");
      const result = await login.finished;
      expect(result.exitCode).toBe(0);
      expect(profileOutputSchema.parse(JSON.parse(result.stdout))).toMatchObject({
        authentication: "oauth",
        status: "authenticated",
      });
      expect(result.stderr.includes("Standard input closed")).toBe(closeInput);
    } finally {
      await oauth.stop();
      await rm(temporaryDirectory, {force: true, recursive: true});
    }
  }, 30_000);
});

interface CliSession {
  readonly finished: Promise<ProcessResult>;
  authorizationUrl(): Promise<string>;
  closeInput(): void;
  writeLine(line: string): void;
}

/** Run the CLI with standard input left open, like a person at a terminal. */
function startCliSession(
  argumentsToPass: readonly string[],
  environment: NodeJS.ProcessEnv,
): CliSession {
  const child = spawn(cliExecutable, [cliEntrypoint, ...argumentsToPass], {
    cwd: repositoryRoot,
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  const stderrListeners = new Set<() => void>();
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
    for (const listener of stderrListeners) listener();
  });
  const finished = new Promise<ProcessResult>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => {
      for (const listener of stderrListeners) listener();
      resolve({exitCode: code ?? -1, stderr, stdout});
    });
  });
  return {
    finished,
    authorizationUrl: () => new Promise((resolve, reject) => {
      const check = () => {
        const match = /https?:\/\/\S+\/authorize\?\S+/u.exec(stderr);
        if (match !== null) {
          stderrListeners.delete(check);
          resolve(match[0]);
        } else if (child.exitCode !== null) {
          stderrListeners.delete(check);
          reject(new Error(`CLI exited before printing an authorization URL: ${stderr}`));
        }
      };
      stderrListeners.add(check);
      check();
    }),
    closeInput: () => {
      child.stdin.end();
    },
    writeLine: (line) => {
      child.stdin.write(`${line}\n`, "utf8");
    },
  };
}

interface ProcessResult {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}

interface LostCommitResponseProxy {
  readonly origin: string;
  droppedResponses(): number;
  errors(): readonly string[];
  stop(): Promise<void>;
}

interface OrganizationAddressProxy {
  readonly origin: string;
  paths(): readonly string[];
  stop(): Promise<void>;
}

async function startOrganizationAddressProxy(
  backendOrigin: string,
): Promise<OrganizationAddressProxy> {
  let origin = "";
  const observedPaths: string[] = [];
  const server = createHttpServer(async (request, response) => {
    try {
      const requestUrl = new URL(request.url ?? "/", "http://localhost");
      observedPaths.push(requestUrl.pathname);
      if (requestUrl.pathname === "/api/v1/installation") {
        response.writeHead(308, {Location: "/o/orvex/api/v1/installation"}).end();
        return;
      }
      if (!requestUrl.pathname.startsWith("/o/orvex/api/")) {
        response.writeHead(404).end();
        return;
      }
      const upstreamPath = requestUrl.pathname.slice("/o/orvex".length);
      const target = new URL(`${upstreamPath}${requestUrl.search}`, backendOrigin);
      const body = await readTextBody(request);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        if (value === undefined || ["host", "connection", "content-length", "transfer-encoding"].includes(name)) continue;
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
      const init: RequestInit = body.length === 0
        ? {headers, method: request.method ?? "GET", redirect: "manual"}
        : {body, headers, method: request.method ?? "GET", redirect: "manual"};
      const upstream = await fetch(target, init);
      const responseBody = await upstream.text();
      let renderedBody = responseBody;
      if (request.method === "POST" && upstreamPath === "/api/v1/uploads" && upstream.ok) {
        const upload = z.object({
          commitUrl: z.url(),
          files: z.array(z.object({uploadUrl: z.url()}).passthrough()),
        }).passthrough().parse(JSON.parse(responseBody));
        const prefix = (value: string): string => {
          const url = new URL(value);
          return `${origin}/o/orvex${url.pathname}${url.search}`;
        };
        renderedBody = JSON.stringify({
          ...upload,
          commitUrl: prefix(upload.commitUrl),
          files: upload.files.map((file) => Object.assign({}, file, {
            uploadUrl: prefix(file.uploadUrl),
          })),
        });
      }
      response.writeHead(upstream.status, {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
      });
      response.end(renderedBody);
    } catch (cause) {
      response.writeHead(502, {"content-type": "text/plain"});
      response.end(cause instanceof Error ? cause.message : "Organization proxy failed.");
    }
  });
  await listenHttp(server);
  const address = assignedAddressSchema.parse(server.address());
  origin = `http://127.0.0.1:${address.port}`;
  return {
    origin,
    paths: () => [...observedPaths],
    stop: () => closeHttp(server),
  };
}

async function startLostCommitResponseProxy(
  upstreamOrigin: string,
): Promise<LostCommitResponseProxy> {
  let origin = "";
  let droppedResponses = 0;
  const errors: string[] = [];
  const server = createHttpServer(async (request, response) => {
    try {
      const target = new URL(request.url ?? "/", upstreamOrigin);
      const requestBody = await readTextBody(request);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        if (
          value === undefined
          || name === "host"
          || name === "connection"
          || name === "content-length"
          || name === "transfer-encoding"
        ) continue;
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
      const requestInit: RequestInit = requestBody.length === 0
        ? {headers, method: request.method ?? "GET"}
        : {body: requestBody, headers, method: request.method ?? "GET"};
      const upstream = await fetch(target, requestInit);
      const body = await upstream.text();
      if (
        request.method === "POST"
        && target.pathname.endsWith("/commit")
        && droppedResponses === 0
      ) {
        droppedResponses += 1;
        response.destroy();
        return;
      }
      let responseBody = body;
      if (request.method === "POST" && target.pathname === "/api/v1/uploads") {
        const decoded = z.object({
          commitUrl: z.url(),
          files: z.array(z.object({uploadUrl: z.url()}).passthrough()),
        }).passthrough().parse(JSON.parse(body));
        responseBody = JSON.stringify({
          ...decoded,
          commitUrl: replaceOrigin(decoded.commitUrl, origin),
          files: decoded.files.map((file) => Object.assign({}, file, {
            uploadUrl: replaceOrigin(file.uploadUrl, origin),
          })),
        });
      }
      response.writeHead(upstream.status, {"Content-Type": "application/json"});
      response.end(responseBody);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : "Proxy failure");
      response.writeHead(502, {"Content-Type": "text/plain"});
      response.end(error instanceof Error ? error.message : "Proxy failure");
    }
  });
  await listenHttp(server);
  const address = assignedAddressSchema.parse(server.address());
  origin = `http://127.0.0.1:${address.port}`;
  return {
    droppedResponses: () => droppedResponses,
    errors: () => errors,
    origin,
    stop: () => closeHttp(server),
  };
}

function replaceOrigin(value: string, origin: string): string {
  const url = new URL(value);
  const replacement = new URL(origin);
  url.protocol = replacement.protocol;
  url.host = replacement.host;
  return url.toString();
}

function runCli(
  argumentsToPass: readonly string[],
  environment: NodeJS.ProcessEnv,
  standardInput = "",
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(cliExecutable, [cliEntrypoint, ...argumentsToPass], {
      cwd: repositoryRoot,
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => resolve({
      exitCode: code ?? -1,
      stderr: Buffer.concat(stderr).toString("utf8"),
      stdout: Buffer.concat(stdout).toString("utf8"),
    }));
    child.stdin.end(standardInput, "utf8");
  });
}

function startServer(
  dataDirectory: string,
  port: number,
): ChildProcessWithoutNullStreams {
  const child = spawn(cliExecutable, [
    cliEntrypoint,
    "start",
    "--data",
    dataDirectory,
    "--port",
    String(port),
  ], {cwd: repositoryRoot, stdio: ["pipe", "pipe", "pipe"]});
  runningProcesses.add(child);
  return child;
}

async function waitForReady(
  child: ChildProcessWithoutNullStreams,
  port: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let output = "";
    const expected = `Houston Artifacts: http://localhost:${port}`;
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Houston Artifacts did not become ready."));
    }, 30_000);
    const receive = (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (!output.includes(expected)) return;
      cleanup();
      resolve();
    };
    const exit = () => {
      cleanup();
      reject(new Error("Houston Artifacts exited before becoming ready."));
    };
    const cleanup = () => {
      clearTimeout(timeout);
      child.stdout.off("data", receive);
      child.stderr.off("data", receive);
      child.off("exit", exit);
    };
    child.stdout.on("data", receive);
    child.stderr.on("data", receive);
    child.once("exit", exit);
  });
}

async function stopProcess(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (!runningProcesses.delete(child) || child.exitCode !== null) return;
  const exited = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", () => resolve());
  });
  child.kill("SIGTERM");
  await exited;
}

async function credentialHelperEnvironment(
  helper: string,
  statePath: string,
): Promise<NodeJS.ProcessEnv> {
  await writeFile(helper, `#!/usr/bin/env node
import {existsSync, readFileSync, writeFileSync} from "node:fs";
const input = JSON.parse(readFileSync(0, "utf8"));
const statePath = process.env.CREDENTIAL_HELPER_STATE;
if (statePath === undefined) process.exit(3);
const state = existsSync(statePath)
  ? JSON.parse(readFileSync(statePath, "utf8"))
  : {};
const operation = process.argv[2];
if (operation === "read") {
  if (!(input.account in state)) process.exit(2);
  process.stdout.write(state[input.account]);
} else if (operation === "write") {
  state[input.account] = input.secret;
  writeFileSync(statePath, JSON.stringify(state));
} else if (operation === "delete") {
  if (!(input.account in state)) process.exit(2);
  delete state[input.account];
  writeFileSync(statePath, JSON.stringify(state));
} else {
  process.exit(3);
}
`, {mode: 0o700});
  await chmod(helper, 0o700);
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    ARTIFACT_SERVER_CREDENTIAL_HELPER: helper,
    CREDENTIAL_HELPER_STATE: statePath,
  };
  delete environment["ARTIFACT_SERVER_CREDENTIAL_STORE"];
  return environment;
}

async function writeBrowserHelper(target: string): Promise<void> {
  await writeFile(target, `#!/usr/bin/env node
const target = process.argv[2];
if (target === undefined) process.exit(2);
const response = await fetch(target, {redirect: "follow"});
if (!response.ok) process.exit(3);
`, {mode: 0o700});
  await chmod(target, 0o700);
}

interface OAuthFixtureObservations {
  authorizationCount: number;
  codeExchangeCount: number;
  lastSessionBearer: string | null;
  lastClientId: string | null;
  lastRedirectUri: string | null;
  pkceVerified: boolean;
  refreshCount: number;
  registrationCount: number;
  revocationCount: number;
  revokedToken: string | null;
  sessionCount: number;
}

interface OAuthFixture {
  readonly observations: OAuthFixtureObservations;
  readonly origin: string;
  advertiseWrongResource(): void;
  stop(): Promise<void>;
}

async function startOAuthFixture(organizations = [
  {displayName: "Orvex", role: "administrator", slug: "orvex"},
]): Promise<OAuthFixture> {
  const observations: OAuthFixtureObservations = {
    authorizationCount: 0,
    codeExchangeCount: 0,
    lastSessionBearer: null,
    lastClientId: null,
    lastRedirectUri: null,
    pkceVerified: false,
    refreshCount: 0,
    registrationCount: 0,
    revocationCount: 0,
    revokedToken: null,
    sessionCount: 0,
  };
  let wrongResource = false;
  let codeChallenge: string | null = null;
  let expectedRedirect: string | null = null;
  let origin = "";
  const server = createHttpServer(async (request, response) => {
    const target = new URL(request.url ?? "/", origin);
    const metadataSlug = /^\/\.well-known\/oauth-protected-resource\/o\/([^/]+)\/api$/u.exec(target.pathname)?.[1];
    if (
      target.pathname === "/.well-known/oauth-protected-resource/api"
      || metadataSlug !== undefined
    ) {
      sendJson(response, 200, {
        authorization_servers: [origin],
        bearer_methods_supported: ["header"],
        resource: wrongResource ? `${origin}/wrong` : metadataSlug === undefined
          ? `${origin}/api`
          : `${origin}/o/${metadataSlug}/api`,
        scopes_supported: ["artifactserver"],
      });
      return;
    }
    if (/^(?:\/o\/[a-z0-9-]+)?\/api\/v1\/installation$/u.test(target.pathname)) {
      const slug = /^\/o\/([^/]+)\//u.exec(target.pathname)?.[1];
      response.writeHead(401, {
        "WWW-Authenticate": `Bearer resource_metadata="${origin}${slug === undefined || slug === "orvex" ? "/.well-known/oauth-protected-resource/api" : `/.well-known/oauth-protected-resource/o/${slug}/api`}" scope="artifactserver"`,
      }).end();
      return;
    }
    if (target.pathname === "/api/v1/platform/me/orgs" && request.method === "GET") {
      if (request.headers.authorization !== "Bearer oauth-access-one") {
        sendJson(response, 401, {error: "Authentication required."});
        return;
      }
      sendJson(response, 200, organizations);
      return;
    }
    if (
      target.pathname === "/.well-known/oauth-authorization-server"
      || target.pathname === "/.well-known/openid-configuration"
    ) {
      sendJson(response, 200, {
        authorization_endpoint: `${origin}/authorize`,
        code_challenge_methods_supported: ["S256"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        issuer: origin,
        jwks_uri: `${origin}/jwks`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ["code"],
        revocation_endpoint: `${origin}/revoke`,
        token_endpoint: `${origin}/token`,
        token_endpoint_auth_methods_supported: ["none"],
      });
      return;
    }
    if (target.pathname === "/register" && request.method === "POST") {
      observations.registrationCount += 1;
      const registration = z.object({
        redirect_uris: z.array(z.url()).min(1),
      }).passthrough().parse(JSON.parse(await readTextBody(request)));
      observations.lastRedirectUri = registration.redirect_uris[0] ?? null;
      sendJson(response, 201, {
        client_id: "artifactserver-cli-test-client",
        redirect_uris: registration.redirect_uris,
        token_endpoint_auth_method: "none",
      });
      return;
    }
    if (target.pathname === "/authorize" && request.method === "GET") {
      observations.authorizationCount += 1;
      codeChallenge = target.searchParams.get("code_challenge");
      expectedRedirect = target.searchParams.get("redirect_uri");
      observations.lastRedirectUri = expectedRedirect;
      observations.lastClientId = target.searchParams.get("client_id");
      const state = target.searchParams.get("state");
      if (
        codeChallenge === null
        || target.searchParams.get("code_challenge_method") !== "S256"
        || expectedRedirect === null
        || state === null
      ) {
        response.writeHead(400).end();
        return;
      }
      const redirect = new URL(expectedRedirect);
      redirect.searchParams.set("code", "authorization-code-one");
      redirect.searchParams.set("iss", origin);
      redirect.searchParams.set("state", state);
      response.writeHead(302, {Location: redirect.toString()}).end();
      return;
    }
    if (target.pathname === "/token" && request.method === "POST") {
      const body = new URLSearchParams(await readTextBody(request));
      const grantType = body.get("grant_type");
      if (grantType === "authorization_code") {
        observations.codeExchangeCount += 1;
        const verifier = body.get("code_verifier");
        const redirect = body.get("redirect_uri");
        observations.pkceVerified = verifier !== null
          && codeChallenge === createHash("sha256")
            .update(verifier)
            .digest("base64url")
          && redirect === expectedRedirect;
        if (!observations.pkceVerified) {
          sendJson(response, 400, {error: "invalid_grant"});
          return;
        }
        const requestedResource = body.get("resource");
        sendJson(response, 200, {
          access_token: requestedResource?.endsWith("/o/acme/api") === true
            ? "oauth-access-acme"
            : "oauth-access-one",
          expires_in: 30,
          refresh_token: "oauth-refresh-one",
          scope: "artifactserver offline_access",
          token_type: "Bearer",
        });
        return;
      }
      if (grantType === "refresh_token") {
        observations.refreshCount += 1;
        if (body.get("refresh_token") !== "oauth-refresh-one") {
          sendJson(response, 400, {error: "invalid_grant"});
          return;
        }
        sendJson(response, 200, {
          access_token: "oauth-access-two",
          expires_in: 3_600,
          refresh_token: "oauth-refresh-two",
          scope: "artifactserver offline_access",
          token_type: "Bearer",
        });
        return;
      }
    }
    if (/^(?:\/o\/[a-z0-9-]+)?\/api\/v1\/session$/u.test(target.pathname) && request.method === "GET") {
      const authorization = request.headers.authorization;
      const bearer = authorization?.startsWith("Bearer ") === true
        ? authorization.slice("Bearer ".length)
        : null;
      const slug = /^\/o\/([^/]+)\//u.exec(target.pathname)?.[1];
      observations.lastSessionBearer = bearer;
      observations.sessionCount += 1;
      const accepted = slug === "acme"
        ? bearer === "oauth-access-acme"
        : bearer === "oauth-access-two"
          || bearer === "oauth-access-one";
      if (!accepted) {
        sendJson(response, 401, {error: {code: "AUTHENTICATION_REQUIRED"}});
        return;
      }
      sendJson(response, 200, {
        authenticationMethod: "bearer",
        principal: {
          authorizedByPrincipalId: null,
          capabilities: [
            "artifact:create",
            "artifact:publish:any",
            "artifact:read",
          ],
          id: "usr_oauth_test",
          installationId: "ins_oauth_test",
          kind: "human",
          membershipRole: "member",
        },
      });
      return;
    }
    if (target.pathname === "/revoke" && request.method === "POST") {
      observations.revocationCount += 1;
      observations.revokedToken = new URLSearchParams(
        await readTextBody(request),
      ).get("token");
      response.writeHead(200).end();
      return;
    }
    if (target.pathname === "/jwks") {
      sendJson(response, 200, {keys: []});
      return;
    }
    response.writeHead(404).end();
  });
  await listenHttp(server);
  const address = assignedAddressSchema.parse(server.address());
  origin = `http://127.0.0.1:${address.port}`;
  return {
    advertiseWrongResource: () => {
      wrongResource = true;
    },
    observations,
    origin,
    stop: () => closeHttp(server),
  };
}

function readTextBody(
  request: IncomingMessage,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.once("error", reject);
    request.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function sendJson(
  response: ServerResponse,
  status: number,
  value: JsonValue,
): void {
  response.writeHead(status, {"Content-Type": "application/json"});
  response.end(JSON.stringify(value));
}

function listenHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function closeHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}

function availablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = assignedAddressSchema.safeParse(server.address());
      if (!address.success) {
        server.close();
        reject(new Error("The operating system did not assign a TCP port."));
        return;
      }
      server.close((error) => {
        if (error === undefined) resolve(address.data.port);
        else reject(error);
      });
    });
  });
}

import {spawn} from "node:child_process";
import path from "node:path";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {Effect, Redacted} from "effect";
import type {BearerCredentialVerifier} from "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {createTestInstallation, openProjectToMembers, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const cliTestTimeoutMilliseconds = 60_000;
const viewerToken = "public-link-test-viewer";
const administratorToken = "public-link-test-administrator";
const viewerVerifier: BearerCredentialVerifier = {verify: (credential) =>
  Redacted.value(credential) === viewerToken
    ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Test viewer", id: "test-viewer", installationId: "local", kind: "service", membershipRole: "member"})
    : Redacted.value(credential) === administratorToken
      ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Test administrator", id: "test-administrator", installationId: "local", kind: "human", membershipRole: "administrator"})
      : Effect.fail(new AuthenticationRequired({message: "The test credential is invalid."}))};

describe("artifactserver public-link", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation, {externalApiBearerVerifier: viewerVerifier});
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("manages public-link settings and sessions through the authenticated CLI", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link cli fixture",
      idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const common = ["--server", server.baseUrl];

    const created = await runCli(["public-link", "create", artifactId, "--permission", "comment", ...common]);
    expect(created.exitCode).toBe(0);
    const createdOutput = z.object({permission: z.string(), url: z.url()}).parse(JSON.parse(created.stdout));
    expect(createdOutput.permission).toBe("comment");
    expect(createdOutput.url).toContain("#link=");

    const status = await runCli(["public-link", "get", artifactId, ...common]);
    expect(JSON.parse(status.stdout)).toMatchObject({enabled: true, permission: "comment", copyAvailable: false, url: null});
    const sessions = await runCli(["public-link", "sessions", artifactId, ...common]);
    expect(sessions.exitCode).toBe(0);
    expect(JSON.parse(sessions.stdout)).toEqual({sessions: []});

    const duplicate = await runCli(["public-link", "create", artifactId, ...common]);
    expect(duplicate.exitCode).toBe(1);
    expect(duplicate.stderr).toContain("PUBLIC_LINK_EXISTS");

    const changed = await runCli(["public-link", "set", artifactId, "--permission", "view", ...common]);
    expect(JSON.parse(changed.stdout)).toEqual({permission: "view"});

    const reset = await runCli(["public-link", "reset", artifactId, "--permission", "comment", ...common]);
    const resetOutput = z.object({permission: z.string(), url: z.url()}).parse(JSON.parse(reset.stdout));
    expect(resetOutput.permission).toBe("comment");
    expect(resetOutput.url).not.toBe(createdOutput.url);

    const missingSession = await runCli(["public-link", "revoke-session", artifactId, crypto.randomUUID(), ...common]);
    expect(missingSession.exitCode).toBe(1);
    expect(missingSession.stderr).toContain("ARTIFACT_NOT_FOUND");

    const revoked = await runCli(["public-link", "revoke", artifactId, ...common]);
    expect(JSON.parse(revoked.stdout)).toEqual({revoked: true});
    const finalStatus = await runCli(["public-link", "get", artifactId, ...common]);
    expect(JSON.parse(finalStatus.stdout)).toMatchObject({enabled: false, url: null});
  }, cliTestTimeoutMilliseconds);

  test("surfaces disabled policy, legacy permission, authorization denial, and missing-artifact codes", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link cli errors", idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const common = ["--server", server.baseUrl];

    await openProjectToMembers(server, installation, published.body.artifact.projectId);
    const issuedKey = await fetch(`${server.baseUrl}/api/v1/api-keys`, {
      method: "POST",
      headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"},
      body: JSON.stringify({capabilities: ["artifact:read"], expiresAt: "2099-01-01T00:00:00.000Z", name: "Public link read-only test key"}),
    });
    expect(issuedKey.status).toBe(201);
    const readOnlyToken = z.object({token: z.string().startsWith("as_key_")}).parse(await issuedKey.json()).token;
    const denied = await runCli(["public-link", "create", artifactId, "--project", published.body.artifact.projectId, ...common], readOnlyToken);
    expect(denied.exitCode).toBe(1);
    expect(denied.stderr).toContain("AUTHORIZATION_DENIED");

    const policy = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: false}),
    });
    expect(policy.status).toBe(200);
    const disabled = await runCli(["public-link", "create", artifactId, ...common]);
    expect(disabled.exitCode).toBe(1);
    expect(disabled.stderr).toContain("PUBLIC_LINKS_DISABLED");

    const reenabled = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: true}),
    });
    expect(reenabled.status).toBe(200);
    const legacy = await publishNew(server, installation, {
      accessSetting: "public_link", content: "legacy public link", idempotencyKey: crypto.randomUUID(),
    });
    const legacyPermission = await runCli(["public-link", "set", legacy.body.artifact.id, "--permission", "comment", ...common]);
    expect(legacyPermission.exitCode).toBe(1);
    expect(legacyPermission.stderr).toContain("PUBLIC_LINK_LEGACY");

    const missing = await runCli(["public-link", "get", crypto.randomUUID(), ...common]);
    expect(missing.exitCode).toBe(1);
    expect(missing.stderr).toContain("ARTIFACT_NOT_FOUND");
  }, cliTestTimeoutMilliseconds);

  async function runCli(args: string[], token = installation.apiToken): Promise<{exitCode: number; stderr: string; stdout: string}> {
    const child = spawn(path.join(repositoryRoot, "node_modules/.bin/tsx"), [path.join(repositoryRoot, "src/cli/main.ts"), ...args], {
      cwd: repositoryRoot,
      env: {...process.env, ARTIFACT_SERVER_API_TOKEN: token},
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      collect(child.stdout), collect(child.stderr), new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      }),
    ]);
    return {exitCode, stderr, stdout};
  }
});

async function collect(stream: NodeJS.ReadableStream): Promise<string> {
  let value = "";
  for await (const chunk of stream) value += String(chunk);
  return value;
}

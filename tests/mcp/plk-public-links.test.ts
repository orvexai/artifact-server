import {spawn} from "node:child_process";
import path from "node:path";
import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {BearerCredentialVerifier} from "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {createTestInstallation, openProjectToMembers, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const protocolVersion = "2026-07-28";
const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const cliTestTimeoutMilliseconds = 60_000;
const viewerToken = "public-link-test-viewer-01234567890123456789";
const unprivilegedServiceToken = "public-link-test-service-no-capabilities";
const administratorToken = "public-link-test-administrator";
const humanToken = "public-link-test-human-member";
let humanMemberId: string | null = null;
const viewerVerifier: BearerCredentialVerifier = {verify: (credential) =>
  Redacted.value(credential) === viewerToken
    ? Effect.succeed({authorizedByPrincipalId: null, capabilities: ["artifact:manage:any", "project:manage"], displayName: "Test viewer", id: "test-viewer", installationId: "local", kind: "service", membershipRole: "member"})
    : Redacted.value(credential) === unprivilegedServiceToken
      ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Unprivileged test service", id: "test-unprivileged-service", installationId: "local", kind: "service", membershipRole: "member"})
    : Redacted.value(credential) === humanToken && humanMemberId !== null
      ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Test human member", id: humanMemberId, installationId: "local", kind: "human", membershipRole: "member"})
    : Redacted.value(credential) === administratorToken
      ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Test administrator", id: "test-administrator", installationId: "local", kind: "human", membershipRole: "administrator"})
      : Effect.fail(new AuthenticationRequired({message: "The test credential is invalid."}))};
const publicLinkResultSchema = z.object({activeSessionCount: z.number().int().optional(), copyAvailable: z.boolean().optional(), createdAt: z.string().nullable().optional(), enabled: z.boolean().optional(), legacy: z.boolean().optional(), limitHitRecently: z.boolean().optional(), permission: z.enum(["view", "comment"]).optional(), updatedAt: z.string().nullable().optional(), url: z.url().nullable().optional(), sessions: z.array(z.object({createdAt: z.string(), displayName: z.string(), guestId: z.string(), lastUsedAt: z.string()})).optional(), revoked: z.literal(true).optional()}).passthrough();
const toolResponseSchema = z.object({result: z.object({content: z.array(z.object({text: z.string()})), isError: z.boolean().optional(), structuredContent: z.unknown()})});
interface ToolArguments {
  readonly artifactId: string;
  readonly guestId?: string;
  readonly permission?: "view" | "comment";
  readonly projectId: string | null;
}

describe("public-link MCP tools", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation, {externalApiBearerVerifier: viewerVerifier, externalMcpBearerVerifier: viewerVerifier});
    const admitted = await fetch(`${server.baseUrl}/api/v1/members`, {
      method: "POST",
      headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"},
      body: JSON.stringify({displayName: "Public link human member", email: `public-link-${crypto.randomUUID()}@example.test`, role: "member"}),
    });
    if (admitted.status !== 201) throw new Error(`Could not admit the public-link human member (${admitted.status}).`);
    humanMemberId = z.object({member: z.object({id: z.string()})}).parse(await admitted.json()).member.id;
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("PLK-019-B: manages link settings and guest sessions through MCP", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link mcp fixture",
      idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const projectId = published.body.artifact.projectId;
    const args = {artifactId, projectId};

    const created = await callTool(server, humanToken, "artifact_public_link_create", {...args, permission: "view"});
    expect(created.isError).toBeFalsy();
    const createdOutput = contentJson(created);
    expect(createdOutput.permission).toBe("view");
    const createdUrl = createdOutput.url;
    if (createdUrl === undefined || createdUrl === null) throw new Error("create did not return a manager URL");
    expect(new URL(createdUrl).hash).toContain("#link=");
    const createdSecret = new URLSearchParams(new URL(createdUrl).hash.slice(1)).get("link");
    if (createdSecret === null) throw new Error("create URL did not contain a link secret");
    const exchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: "MCP-created link visitor", secret: createdSecret}),
      headers: {"Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin"},
      method: "POST",
    });
    expect(exchange.status).toBe(201);

    const status = contentJson(await callTool(server, humanToken, "artifact_public_link_get", args));
    expect(status).toMatchObject({enabled: true, permission: "view", copyAvailable: false});
    expect(status.url).toBeNull();

    const changed = await callTool(server, humanToken, "artifact_public_link_set_permission", {...args, permission: "comment"});
    expect(contentJson(changed)).toEqual({permission: "comment"});

    const legacy = contentJson(await callTool(server, humanToken, "artifact_enable_guest_invitation", args));
    expect(legacy.url).toContain("#invite=");
    const deprecatedStatus = await callTool(server, humanToken, "artifact_guest_invitation_status", args);
    expect(deprecatedStatus.isError).toBeFalsy();
    expect(JSON.stringify(deprecatedStatus.structuredContent)).not.toContain("linkSecret");
    expect(JSON.stringify(deprecatedStatus.structuredContent)).not.toContain("#");
    expect(deprecatedStatus.content.map((entry) => entry.text).join(" ")).not.toContain("#");
    expect(contentJson(await callTool(server, humanToken, "artifact_public_link_get", args))).toMatchObject({permission: "comment"});
    const sessions = contentJson(await callTool(server, humanToken, "artifact_public_link_sessions", args));
    expect(sessions.sessions).toEqual([]);
    expect((await callTool(server, humanToken, "artifact_public_link_revoke_session", {...args, guestId: crypto.randomUUID()})).isError).toBe(true);

    const reset = contentJson(await callTool(server, humanToken, "artifact_public_link_reset", {...args, permission: "view"}));
    expect(reset.permission).toBe("view");
    expect(reset.url).not.toBe(createdUrl);
    expect(contentJson(await callTool(server, humanToken, "artifact_public_link_revoke", args))).toEqual({revoked: true});
    expect(contentJson(await callTool(server, humanToken, "artifact_public_link_get", args))).toMatchObject({enabled: false, url: null});
  });

  test("maps disabled policy, legacy permissions, authorization denial, and missing artifacts through MCP", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link mcp errors", idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const projectId = published.body.artifact.projectId;
    const args = {artifactId, projectId};
    await openProjectToMembers(server, installation, projectId);
    const permissionDenied = await callTool(server, unprivilegedServiceToken, "artifact_public_link_create", {artifactId, permission: "view", projectId});
    expect(errorCode(permissionDenied)).toBe("AUTHORIZATION_DENIED");
    const denied = await callTool(server, viewerToken, "artifact_public_link_create", {artifactId, permission: "view", projectId});
    expect(errorCode(denied)).toBe("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(errorMessage(denied)).not.toContain("#");

    const policy = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: false}),
    });
    expect(policy.status).toBe(200);
    const disabled = await callTool(server, humanToken, "artifact_public_link_create", {...args, permission: "view"});
    expect(errorCode(disabled)).toBe("PUBLIC_LINKS_DISABLED");
    expect(errorMessage(disabled)).not.toContain("#");

    const reenabled = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: true}),
    });
    expect(reenabled.status).toBe(200);
    const legacy = await publishNew(server, installation, {
      accessSetting: "public_link", content: "legacy public link", idempotencyKey: crypto.randomUUID(),
    });
    const legacyPermission = await callTool(server, humanToken, "artifact_public_link_set_permission", {
      artifactId: legacy.body.artifact.id, permission: "comment", projectId: legacy.body.artifact.projectId,
    });
    expect(errorCode(legacyPermission)).toBe("PUBLIC_LINK_LEGACY");
    expect(errorMessage(legacyPermission)).not.toContain("#");

    const missing = await callTool(server, humanToken, "artifact_public_link_get", {artifactId: crypto.randomUUID(), projectId});
    expect(errorCode(missing)).toBe("ARTIFACT_NOT_FOUND");
  });

  test("PLK-019-F: service principals cannot create, reset, or enable links that they cannot exchange", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link creator fixture",
      idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const projectId = published.body.artifact.projectId;
    const projectQuery = `?projectId=${encodeURIComponent(projectId)}`;
    const headers = (token: string) => ({Authorization: `Bearer ${token}`, "Content-Type": "application/json"});
    await openProjectToMembers(server, installation, projectId);

    const serviceCreate = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/public-link${projectQuery}`, {
      method: "POST", headers: headers(viewerToken), body: JSON.stringify({permission: "view"}),
    });
    expect(serviceCreate.status).toBe(403);
    expect(serviceCreate.headers.get("cache-control")).toContain("no-store");
    const serviceCreateBody = await serviceCreate.text();
    expect(serviceCreateBody).toContain("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(serviceCreateBody).not.toContain("#link=");
    const absent = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/public-link${projectQuery}`, {headers: headers(humanToken)});
    expect(await absent.json()).toMatchObject({enabled: false, url: null});

    const mcpCreate = await callTool(server, viewerToken, "artifact_public_link_create", {artifactId, permission: "view", projectId});
    expect(errorCode(mcpCreate)).toBe("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(JSON.stringify(mcpCreate)).not.toContain("#link=");
    const cliCreate = await runCli(["public-link", "create", artifactId, "--project", projectId, "--server", server.baseUrl], viewerToken);
    expect(cliCreate.exitCode).toBe(1);
    expect(cliCreate.stderr).toContain("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(cliCreate.stdout).toBe("");
    expect(cliCreate.stderr).not.toContain("#link=");

    const humanCreate = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/public-link${projectQuery}`, {
      method: "POST", headers: headers(humanToken), body: JSON.stringify({permission: "view"}),
    });
    expect(humanCreate.status).toBe(201);
    const humanUrl = z.object({url: z.url()}).parse(await humanCreate.json()).url;
    const humanSecret = new URL(humanUrl).hash.slice("#link=".length);
    const exchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      method: "POST", headers: {"Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin"},
      body: JSON.stringify({secret: new URL(humanUrl).hash.slice("#link=".length)}),
    });
    expect(exchange.status).toBe(201);

    const serviceReset = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/public-link/reset${projectQuery}`, {
      method: "POST", headers: headers(viewerToken), body: JSON.stringify({permission: "comment"}),
    });
    expect(serviceReset.status).toBe(403);
    expect(serviceReset.headers.get("cache-control")).toContain("no-store");
    const resetBody = await serviceReset.text();
    expect(resetBody).toContain("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(resetBody).not.toContain("#link=");
    expect(resetBody).not.toContain(humanSecret);

    const serviceEnable = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/guest-invitation${projectQuery}`, {
      method: "POST", headers: headers(viewerToken),
    });
    expect(serviceEnable.status).toBe(403);
    expect(serviceEnable.headers.get("cache-control")).toContain("no-store");
    const enableBody = await serviceEnable.text();
    expect(enableBody).toContain("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(enableBody).not.toContain(humanSecret);

    const mcpReset = await callTool(server, viewerToken, "artifact_public_link_reset", {artifactId, permission: "view", projectId});
    expect(errorCode(mcpReset)).toBe("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(JSON.stringify(mcpReset)).not.toContain("#link=");
    expect(JSON.stringify(mcpReset)).not.toContain(humanSecret);
    const mcpEnable = await callTool(server, viewerToken, "artifact_enable_guest_invitation", {artifactId, projectId});
    expect(errorCode(mcpEnable)).toBe("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(JSON.stringify(mcpEnable)).not.toContain("#invite=");
    expect(JSON.stringify(mcpEnable)).not.toContain(humanSecret);

    const cliReset = await runCli(["public-link", "reset", artifactId, "--project", projectId, "--server", server.baseUrl], viewerToken);
    expect(cliReset.exitCode).toBe(1);
    expect(cliReset.stderr).toContain("PUBLIC_LINK_HUMAN_CREATOR_REQUIRED");
    expect(cliReset.stdout).toBe("");
    expect(cliReset.stderr).not.toContain("#link=");
    expect(cliReset.stderr).not.toContain(humanSecret);

    const unchanged = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/public-link${projectQuery}`, {headers: headers(humanToken)});
    expect(unchanged.status).toBe(200);
    expect(await unchanged.json()).toMatchObject({enabled: true, permission: "view"});
  }, cliTestTimeoutMilliseconds);

  async function runCli(args: string[], token: string): Promise<{exitCode: number; stderr: string; stdout: string}> {
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

async function callTool(server: RunningTestServer, token: string, name: string, args: ToolArguments) {
  const response = await fetch(`${server.baseUrl}/mcp`, {
    method: "POST",
    headers: {Accept: "application/json, text/event-stream", Authorization: `Bearer ${token}`, "Content-Type": "application/json", "MCP-Protocol-Version": protocolVersion, "Mcp-Method": "tools/call", "Mcp-Name": name},
    body: JSON.stringify({id: crypto.randomUUID(), jsonrpc: "2.0", method: "tools/call", params: {arguments: args, name, _meta: {"io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": {name: "artifact-server-test", version: "1"}, "io.modelcontextprotocol/protocolVersion": protocolVersion}}}),
  });
  expect(response.status).toBe(200);
  return toolResponseSchema.parse(await response.json()).result;
}

function contentJson(result: {structuredContent: unknown}) {
  return publicLinkResultSchema.parse(result.structuredContent);
}

function errorCode(result: {structuredContent: unknown}): string | undefined {
  return z.object({error: z.object({code: z.string()})}).safeParse(result.structuredContent).data?.error.code;
}

function errorMessage(result: {structuredContent: unknown}): string {
  return z.object({error: z.object({message: z.string()})}).parse(result.structuredContent).error.message;
}

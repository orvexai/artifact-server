import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {BearerCredentialVerifier} from "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {createTestInstallation, openProjectToMembers, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const protocolVersion = "2026-07-28";
const viewerToken = "public-link-test-viewer";
const administratorToken = "public-link-test-administrator";
const viewerVerifier: BearerCredentialVerifier = {verify: (credential) =>
  Redacted.value(credential) === viewerToken
    ? Effect.succeed({authorizedByPrincipalId: null, capabilities: [], displayName: "Test viewer", id: "test-viewer", installationId: "local", kind: "service", membershipRole: "member"})
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

    const created = await callTool(server, installation.apiToken, "artifact_public_link_create", {...args, permission: "view"});
    expect(created.isError).toBeFalsy();
    const createdOutput = contentJson(created);
    expect(createdOutput.permission).toBe("view");
    const createdUrl = createdOutput.url;
    if (createdUrl === undefined || createdUrl === null) throw new Error("create did not return a manager URL");
    expect(new URL(createdUrl).hash).toContain("#link=");

    const status = contentJson(await callTool(server, installation.apiToken, "artifact_public_link_get", args));
    expect(status).toMatchObject({enabled: true, permission: "view", copyAvailable: false});
    expect(status.url).toBeNull();

    const changed = await callTool(server, installation.apiToken, "artifact_public_link_set_permission", {...args, permission: "comment"});
    expect(contentJson(changed)).toEqual({permission: "comment"});

    const legacy = contentJson(await callTool(server, installation.apiToken, "artifact_enable_guest_invitation", args));
    expect(legacy.url).toContain("#invite=");
    const deprecatedStatus = await callTool(server, installation.apiToken, "artifact_guest_invitation_status", args);
    expect(deprecatedStatus.isError).toBeFalsy();
    expect(JSON.stringify(deprecatedStatus.structuredContent)).not.toContain("linkSecret");
    expect(JSON.stringify(deprecatedStatus.structuredContent)).not.toContain("#");
    expect(deprecatedStatus.content.map((entry) => entry.text).join(" ")).not.toContain("#");
    expect(contentJson(await callTool(server, installation.apiToken, "artifact_public_link_get", args))).toMatchObject({permission: "comment"});
    const sessions = contentJson(await callTool(server, installation.apiToken, "artifact_public_link_sessions", args));
    expect(sessions.sessions).toEqual([]);
    expect((await callTool(server, installation.apiToken, "artifact_public_link_revoke_session", {...args, guestId: crypto.randomUUID()})).isError).toBe(true);

    const reset = contentJson(await callTool(server, installation.apiToken, "artifact_public_link_reset", {...args, permission: "view"}));
    expect(reset.permission).toBe("view");
    expect(reset.url).not.toBe(createdUrl);
    expect(contentJson(await callTool(server, installation.apiToken, "artifact_public_link_revoke", args))).toEqual({revoked: true});
    expect(contentJson(await callTool(server, installation.apiToken, "artifact_public_link_get", args))).toMatchObject({enabled: false, url: null});
  });

  test("maps disabled policy, legacy permissions, authorization denial, and missing artifacts through MCP", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "public-link mcp errors", idempotencyKey: crypto.randomUUID(),
    });
    const artifactId = published.body.artifact.id;
    const projectId = published.body.artifact.projectId;
    const args = {artifactId, projectId};
    await openProjectToMembers(server, installation, projectId);
    const denied = await callTool(server, viewerToken, "artifact_public_link_create", {artifactId, permission: "view", projectId: null});
    expect(errorCode(denied)).toBe("AUTHORIZATION_DENIED");
    expect(errorMessage(denied)).not.toContain("#");

    const policy = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: false}),
    });
    expect(policy.status).toBe(200);
    const disabled = await callTool(server, installation.apiToken, "artifact_public_link_create", {...args, permission: "view"});
    expect(errorCode(disabled)).toBe("PUBLIC_LINKS_DISABLED");
    expect(errorMessage(disabled)).not.toContain("#");

    const reenabled = await fetch(`${server.baseUrl}/api/v1/administration/public-links/policy`, {
      method: "PATCH", headers: {Authorization: `Bearer ${administratorToken}`, "Content-Type": "application/json"}, body: JSON.stringify({enabled: true}),
    });
    expect(reenabled.status).toBe(200);
    const legacy = await publishNew(server, installation, {
      accessSetting: "public_link", content: "legacy public link", idempotencyKey: crypto.randomUUID(),
    });
    const legacyPermission = await callTool(server, installation.apiToken, "artifact_public_link_set_permission", {
      artifactId: legacy.body.artifact.id, permission: "comment", projectId: legacy.body.artifact.projectId,
    });
    expect(errorCode(legacyPermission)).toBe("PUBLIC_LINK_LEGACY");
    expect(errorMessage(legacyPermission)).not.toContain("#");

    const missing = await callTool(server, installation.apiToken, "artifact_public_link_get", {artifactId: crypto.randomUUID(), projectId});
    expect(errorCode(missing)).toBe("ARTIFACT_NOT_FOUND");
  });
});

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

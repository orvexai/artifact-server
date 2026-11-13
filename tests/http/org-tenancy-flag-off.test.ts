import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {groupRoleEditAllowed} from "../../src/core/group-role-policy.js";
import type {ArtifactResponseRecord} from "../../src/core/model.js";
import type {Principal} from "../../src/core/identity.js";
import {projectHttpTenantResponse} from "../../src/http/create-http-app.js";
import {ApiClient, signInAdministrator} from "../support/agent-dispatch.js";
import {
  createTestInstallation,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const mcpVersion = "2026-07-28";
const rpcSchema = z.object({result: z.object({structuredContent: z.unknown()}).passthrough()}).passthrough();

describe("organization tenancy flag-off compatibility", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation);
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("standalone permissions, projections, MCP emails, session, and API-key lifecycle retain their base contract", async () => {
    // The standalone harness does not compose the organization router or tenant visibility flag.
    expect(groupRoleEditAllowed("owner", true)).toBe(true);
    expect(groupRoleEditAllowed("administrator", true)).toBe(false);
    expect(groupRoleEditAllowed("owner", false)).toBe(false);

    const cookies = await signInAdministrator(server, installation);
    const sessionResponse = await fetch(`${server.baseUrl}/api/v1/session`, {headers: {Cookie: cookies.header}});
    expect(sessionResponse.status).toBe(200);
    const session = z.object({principal: z.record(z.string(), z.unknown())}).parse(await sessionResponse.json());
    const administratorId = z.string().parse(session.principal["id"]);
    expect(session.principal).not.toHaveProperty("staff");
    expect(session.principal).not.toHaveProperty("tenantStaffPrincipalIds");

    const keyResponse = await fetch(`${server.baseUrl}/api/v1/api-keys`, {
      body: JSON.stringify({capabilities: ["artifact:read", "artifact:responses:read"], expiresAt: "2099-01-01T00:00:00.000Z", memberId: administratorId, name: "flag-off-key"}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(keyResponse.status).toBe(201);
    const key = z.object({apiKey: z.object({id: z.string()}), token: z.string()}).parse(await keyResponse.json());
    const listed = await fetch(`${server.baseUrl}/api/v1/api-keys`, {headers: {Cookie: cookies.header}});
    expect((await listed.json()).apiKeys).toEqual(expect.arrayContaining([expect.objectContaining({id: key.apiKey.id})]));
    const rotatedResponse = await fetch(`${server.baseUrl}/api/v1/api-keys/${key.apiKey.id}/rotate`, {
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(rotatedResponse.status).toBe(201);
    const rotated = z.object({apiKey: z.object({id: z.string()}), token: z.string()}).parse(await rotatedResponse.json());

    const publication = await publishNew(server, installation, {accessSetting: "account_required", content: "<!doctype html><title>flag off</title>", idempotencyKey: "flag-off-publish"});
    const published = publication.body;
    const client = new ApiClient(server, installation.apiToken);
    const thread = await client.openThread(published, "Standalone comment", "flag-off-comment");
    const comments = await fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/comments?projectId=${published.artifact.projectId}`, {headers: {Cookie: cookies.header}});
    const commentPage = z.object({items: z.array(z.object({author: z.object({displayName: z.string(), principalId: z.string()}).passthrough()}).passthrough())}).parse(await comments.json());
    const commentAuthor = commentPage.items.find((entry) => entry["id"] === thread.id)?.author;
    expect(commentAuthor).toMatchObject({displayName: "Local", principalId: "local-api-token"});
    expect(commentAuthor).not.toHaveProperty("staff");

    const responsePath = `/api/v1/artifacts/${published.artifact.id}/responses?projectId=${published.artifact.projectId}`;
    const responseCreated = await fetch(`${server.baseUrl}${responsePath}`, {
      body: JSON.stringify({choice: "yes", questionId: "flag-off-q", versionId: published.version.id}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(responseCreated.status).toBe(201);
    const responseRecord = z.object({
      artifactId: z.string(), authorDisplayName: z.string(), authorEmail: z.string().nullable(), authorKind: z.enum(["guest", "member"]),
      authorSubject: z.string(), choice: z.string().nullable(), createdAt: z.string(), data: z.unknown().nullable(),
      externalQuestion: z.boolean(), guestSessionId: z.string().nullable(), id: z.string(), questionId: z.string(), versionId: z.string(),
    }).parse(await responseCreated.json());
    const guest: Principal = {authorizedByPrincipalId: null, capabilities: [], displayName: "Guest", id: "guest", installationId: "standalone", kind: "human", membershipRole: "guest"};
    // SAFETY: responseRecord supplies every required ArtifactResponseRecord field for this projection contract test.
    const guestProjection = projectHttpTenantResponse(responseRecord as ArtifactResponseRecord, guest);
    expect(guestProjection.authorEmail).toBeNull();
    expect(JSON.parse(JSON.stringify(guestProjection))).not.toHaveProperty("authorSubject");

    const mcp = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id: "flag-off-response-list", jsonrpc: "2.0", method: "tools/call", params: {
        _meta: {
          [CLIENT_CAPABILITIES_META_KEY]: {},
          [CLIENT_INFO_META_KEY]: {name: "flag-off-regression", version: "1"},
          [PROTOCOL_VERSION_META_KEY]: mcpVersion,
        },
        arguments: {artifactId: published.artifact.id, projectId: published.artifact.projectId, questionId: "flag-off-q"},
        name: "artifact_response_list",
      }}),
      headers: {Accept: "application/json, text/event-stream", Authorization: `Bearer ${rotated.token}`, "Content-Type": "application/json", "Mcp-Method": "tools/call", "Mcp-Name": "artifact_response_list", "MCP-Protocol-Version": mcpVersion},
      method: "POST",
    });
    expect(mcp.status).toBe(200);
    // SAFETY: artifact_response_list's structured content is the paged response with an items array.
    const mcpPayload = rpcSchema.parse(await mcp.json()).result.structuredContent as {items: Array<{authorEmail: string | null}>};
    expect(mcpPayload.items[0]?.authorEmail).toBe("administrator@example.test");
  });
});

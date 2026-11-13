import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {AuthenticationRequired} from "../../src/core/errors.js";
import type {Principal} from "../../src/core/identity.js";
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
const responseListContentSchema = z.object({items: z.array(z.object({authorEmail: z.string().nullable()}).passthrough())}).passthrough();
const rpcSchema = z.object({result: z.object({structuredContent: z.unknown()}).passthrough()}).passthrough();
const mcpPrincipals = new Map<string, Principal>();

describe("organization tenancy flag-off compatibility", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    mcpPrincipals.clear();
    server = await startTestServer(installation, {externalMcpBearerVerifier: {verify: (credential) => {
      const principal = mcpPrincipals.get(Redacted.value(credential));
      return principal === undefined
        ? Effect.fail(new AuthenticationRequired({message: "The test MCP principal was not configured."}))
        : Effect.succeed(principal);
    }}});
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("standalone permissions, projections, MCP emails, session, and API-key lifecycle retain their base contract", async () => {
    const cookies = await signInAdministrator(server, installation);
    const sessionResponse = await fetch(`${server.baseUrl}/api/v1/session`, {headers: {Cookie: cookies.header}});
    expect(sessionResponse.status).toBe(200);
    const session = z.object({principal: z.record(z.string(), z.unknown())}).parse(await sessionResponse.json());
    const administratorId = z.string().parse(session.principal["id"]);
    const installationId = z.string().parse(session.principal["installationId"]);
    const memberMutationHeaders = {
      Cookie: cookies.header,
      Origin: server.baseUrl,
      "Content-Type": "application/json",
      "Sec-Fetch-Site": "same-origin",
      "X-CSRF-Token": cookies.csrf,
    };
    const admittedResponse = await fetch(`${server.baseUrl}/api/v1/members`, {
      body: JSON.stringify({displayName: "Standalone member", email: "standalone-member@example.test", role: "member"}),
      headers: memberMutationHeaders,
      method: "POST",
    });
    expect(admittedResponse.status).toBe(201);
    const admitted = z.object({member: z.object({id: z.string(), status: z.string()}).passthrough()}).parse(await admittedResponse.json()).member;
    expect(admitted).not.toHaveProperty("staff");
    const deactivatedResponse = await fetch(`${server.baseUrl}/api/v1/members/${admitted.id}/deactivate`, {
      headers: memberMutationHeaders,
      method: "POST",
    });
    expect(deactivatedResponse.status).toBe(200);
    const deactivated = z.object({member: z.record(z.string(), z.unknown())}).parse(await deactivatedResponse.json()).member;
    expect(deactivated).not.toHaveProperty("staff");
    const viewerPrincipal: Principal = {
      authorizedByPrincipalId: null,
      capabilities: ["artifact:read", "artifact:responses:read"],
      displayName: "Flag off viewer",
      id: administratorId,
      installationId,
      kind: "human",
      membershipRole: "viewer",
    };
    const guestPrincipal: Principal = {...viewerPrincipal, displayName: "Flag off guest", membershipRole: "guest"};
    mcpPrincipals.set("flag-off-viewer", viewerPrincipal);
    mcpPrincipals.set("flag-off-guest", guestPrincipal);
    expect(session.principal).not.toHaveProperty("staff");
    expect(session.principal).not.toHaveProperty("tenantStaffPrincipalIds");

    const groupRoleHttp = await fetch(`${server.baseUrl}/api/v1/groups/not-a-real-group/role`, {
      body: JSON.stringify({role: "viewer"}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "PUT",
    });
    expect(groupRoleHttp.status).toBe(403);
    const groupRoleMcp = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id: "flag-off-group-role", jsonrpc: "2.0", method: "tools/call", params: {
        _meta: {[CLIENT_CAPABILITIES_META_KEY]: {}, [CLIENT_INFO_META_KEY]: {name: "flag-off-regression", version: "1"}, [PROTOCOL_VERSION_META_KEY]: mcpVersion},
        arguments: {groupId: "not-a-real-group", role: "viewer"}, name: "group_set_role",
      }}),
      headers: {Accept: "application/json, text/event-stream", Authorization: `Bearer ${installation.apiToken}`, "Content-Type": "application/json", "Mcp-Method": "tools/call", "Mcp-Name": "group_set_role", "MCP-Protocol-Version": mcpVersion},
      method: "POST",
    });
    expect(groupRoleMcp.status).toBe(200);
    expect((await groupRoleMcp.json()).result.isError).toBe(true);

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
    const replyResponse = await fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/comments/${thread.id}/replies?projectId=${published.artifact.projectId}`, {
      body: JSON.stringify({body: "Standalone reply"}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Idempotency-Key": "flag-off-reply-idempotency", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(replyResponse.status).toBe(201);
    const resolvedResponse = await fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/comments/${thread.id}?projectId=${published.artifact.projectId}`, {
      body: JSON.stringify({state: "resolved"}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Idempotency-Key": "flag-off-resolve", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "PATCH",
    });
    expect(resolvedResponse.status).toBe(200);
    const comments = await fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/comments?projectId=${published.artifact.projectId}`, {headers: {Cookie: cookies.header}});
    const commentPage = z.object({items: z.array(z.object({author: z.object({displayName: z.string(), principalId: z.string()}).passthrough()}).passthrough())}).parse(await comments.json());
    const commentAuthor = commentPage.items.find((entry) => entry["id"] === thread.id)?.author;
    expect(commentAuthor).toMatchObject({displayName: "Local", principalId: "local-api-token"});
    expect(commentAuthor).not.toHaveProperty("staff");
    expect(commentPage.items.find((entry) => entry["id"] === thread.id)?.["resolvedBy"]).toMatchObject({displayName: "Local administrator", principalId: administratorId});

    const identityReads = await Promise.all([
      fetch(`${server.baseUrl}/api/v1/members`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/groups`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/projects/${published.artifact.projectId}/audit`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/actions?projectId=${published.artifact.projectId}`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/versions`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/state?projectId=${published.artifact.projectId}`, {headers: {Cookie: cookies.header}}),
      fetch(`${server.baseUrl}/api/v1/agents`, {headers: {Cookie: cookies.header}}),
    ]);
    expect(identityReads.map(({status}) => status)).toEqual([200, 200, 200, 200, 200, 200, 200]);
    const [memberRead, groupRead, auditRead, actionRead, versionRead, stateRead, agentRead] = await Promise.all(identityReads.map((response) => response.json()));
    expect(memberRead).not.toHaveProperty("members.0.staff");
    for (const body of [memberRead, groupRead, auditRead, actionRead, versionRead, stateRead, agentRead]) {
      expect(JSON.stringify(body)).not.toContain("tenantStaffPrincipalIds");
      expect(JSON.stringify(body)).not.toContain('"staff":');
    }

    const responsePath = `/api/v1/artifacts/${published.artifact.id}/responses?projectId=${published.artifact.projectId}`;
    const responseCreated = await fetch(`${server.baseUrl}${responsePath}`, {
      body: JSON.stringify({choice: "yes", questionId: "flag-off-q", versionId: published.version.id}),
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(responseCreated.status).toBe(201);
    const invitationResponse = await fetch(`${server.baseUrl}/api/v1/artifacts/${published.artifact.id}/guest-invitation?projectId=${published.artifact.projectId}`, {
      body: "{}", headers: {Cookie: cookies.header, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf}, method: "POST",
    });
    expect(invitationResponse.status).toBe(201);
    const invitationUrl = new URL(z.object({url: z.string()}).parse(await invitationResponse.json()).url);
    const inviteSecret = new URLSearchParams(invitationUrl.hash.slice(1)).get("invite");
    expect(inviteSecret).toBeTruthy();
    const guestExchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${published.artifact.id}/guest-session`, {
      body: JSON.stringify({displayName: "Outside reviewer", secret: inviteSecret}),
      headers: {Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, method: "POST",
    });
    expect(guestExchange.status).toBe(201);
    const guestCookies = guestExchange.headers.getSetCookie();
    const guestSession = guestCookies.find((value) => value.startsWith("artifact_guest_session="))?.split(";", 1)[0];
    const guestCsrf = guestCookies.find((value) => value.startsWith("artifact_guest_csrf="))?.split(";", 1)[0]?.split("=", 2)[1];
    expect(guestSession).toBeDefined();
    expect(guestCsrf).toBeDefined();
    const publicGuestPost = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${published.artifact.id}/guest/responses`, {
      body: JSON.stringify({choice: "yes", questionId: "flag-off-public-q", versionId: published.version.id}),
      headers: {Cookie: `${guestSession}; artifact_guest_csrf=${guestCsrf}`, Origin: server.baseUrl, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": guestCsrf ?? ""},
      method: "POST",
    });
    expect(publicGuestPost.status).toBe(201);
    const publicGuestRecord = z.object({authorEmail: z.string().nullable(), authorSubject: z.string()}).passthrough().parse(await publicGuestPost.json());
    expect(publicGuestRecord.authorEmail).toBeNull();
    expect(publicGuestRecord.authorSubject).toBeTruthy();

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
    const mcpPayload = responseListContentSchema.parse(rpcSchema.parse(await mcp.json()).result.structuredContent);
    expect(mcpPayload.items[0]?.authorEmail).toBe("administrator@example.test");
    const readResponsesMcp = async (credential: string, id: string) => fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id, jsonrpc: "2.0", method: "tools/call", params: {
        _meta: {
          [CLIENT_CAPABILITIES_META_KEY]: {},
          [CLIENT_INFO_META_KEY]: {name: "flag-off-regression", version: "1"},
          [PROTOCOL_VERSION_META_KEY]: mcpVersion,
        },
        arguments: {artifactId: published.artifact.id, projectId: published.artifact.projectId, questionId: "flag-off-q"},
        name: "artifact_response_list",
      }}),
      headers: {Accept: "application/json, text/event-stream", Authorization: `Bearer ${credential}`, "Content-Type": "application/json", "Mcp-Method": "tools/call", "Mcp-Name": "artifact_response_list", "MCP-Protocol-Version": mcpVersion},
      method: "POST",
    });
    const viewerMcp = await readResponsesMcp("flag-off-viewer", "flag-off-viewer-response-list");
    expect(viewerMcp.status).toBe(200);
    const viewerMcpPayload = responseListContentSchema.parse(rpcSchema.parse(await viewerMcp.json()).result.structuredContent);
    expect(viewerMcpPayload.items[0]?.authorEmail).toBe("administrator@example.test");
    const guestMcp = await readResponsesMcp("flag-off-guest", "flag-off-guest-response-list");
    expect(guestMcp.status).toBe(200);
    const guestMcpBody = z.object({result: z.object({isError: z.boolean().optional()}).passthrough()}).passthrough().parse(await guestMcp.json());
    expect(guestMcpBody.result.isError).toBe(true);
    expect(JSON.stringify(guestMcpBody)).not.toContain("administrator@example.test");
    const serviceMcp = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id: "flag-off-service-response-list", jsonrpc: "2.0", method: "tools/call", params: {
        _meta: {
          [CLIENT_CAPABILITIES_META_KEY]: {},
          [CLIENT_INFO_META_KEY]: {name: "flag-off-regression", version: "1"},
          [PROTOCOL_VERSION_META_KEY]: mcpVersion,
        },
        arguments: {artifactId: published.artifact.id, projectId: published.artifact.projectId, questionId: "flag-off-q"},
        name: "artifact_response_list",
      }}),
      headers: {Accept: "application/json, text/event-stream", Authorization: `Bearer ${installation.apiToken}`, "Content-Type": "application/json", "Mcp-Method": "tools/call", "Mcp-Name": "artifact_response_list", "MCP-Protocol-Version": mcpVersion},
      method: "POST",
    });
    expect(serviceMcp.status).toBe(200);
    const serviceMcpPayload = responseListContentSchema.parse(rpcSchema.parse(await serviceMcp.json()).result.structuredContent);
    expect(serviceMcpPayload.items[0]?.authorEmail).toBeNull();
    const revokedResponse = await fetch(`${server.baseUrl}/api/v1/api-keys/${rotated.apiKey.id}/revoke`, {
      headers: {Cookie: cookies.header, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": cookies.csrf},
      method: "POST",
    });
    expect(revokedResponse.status).toBe(200);
  });
});

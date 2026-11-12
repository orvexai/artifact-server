import {Effect, Redacted} from "effect";
import {afterAll, beforeAll, describe, expect, test} from "vitest";
import {z} from "zod";

import {loadOidcConfiguration} from "../../src/cli/oidc-configuration.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {membershipRoles, principalCapabilities, principalKinds} from "../../src/core/identity.js";
import {provisionerToolNames} from "../../src/mcp/provisioner-tools.js";
import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

const provider = "oidc:https://idp.example.test/realms/main";
interface JsonObject {
  readonly [key: string]: JsonValue;
}
type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
const mcpResultSchema = z.object({
  content: z.array(z.object({text: z.string().optional()}).passthrough()).optional(),
  isError: z.boolean().optional(),
  structuredContent: z.unknown().optional(),
}).passthrough();
const mcpEnvelopeSchema = z.object({result: mcpResultSchema}).passthrough();
const provisioner = {
  authorizedByPrincipalId: null,
  capabilities: [principalCapabilities.readArtifactResponses, principalCapabilities.provisionProjects],
  directoryGroupIds: ["g-tenant-cli"],
  displayName: "tenant-cli",
  email: null,
  id: "oidc-service:test:tenant-cli",
  installationId: "local",
  kind: principalKinds.service,
  membershipRole: membershipRoles.member,
  serviceAccountSource: "oidc" as const,
};

describe("OIDC project provisioner MCP boundary", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeAll(async () => {
    installation = await createTestInstallation();
    const databasePath = `${installation.dataDirectory}/artifact-server.db`;
    server = await startTestServer(installation, {
      externalMcpBearerVerifier: {
        verify: (credential) => {
          const value = Redacted.value(credential);
          if (value === "oidc-tenant-cli") return Effect.succeed(provisioner);
          if (value === "oidc-other-service") {
            return Effect.succeed({
              ...provisioner,
              capabilities: [principalCapabilities.readArtifactResponses],
              id: "oidc-service:test:other-service",
            });
          }
          return Effect.fail(new AuthenticationRequired({message: "Unexpected test credential."}));
        },
      },
    });
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      await repository.applyDirectoryGroups("local", {
        groups: [
          {id: "g-tenant-cli", members: [{email: "cli@example.test", subject: "kc-cli"}], name: "CLI", path: "/Tenant/CLI"},
          {id: "g-tenant-support", members: [{email: "support@example.test", subject: "kc-support"}], name: "Support", path: "/Tenant/Support"},
        ],
        provider,
        syncedAt: "2026-11-12T00:00:00.000Z",
      });
    } finally {
      repository.close();
    }
  });

  afterAll(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("configuration requires provisioner clients to be service clients", async () => {
    const shared = {
      ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: "admin@example.test",
      ARTIFACT_SERVER_ORIGIN: "https://artifacts.example.test",
      ARTIFACT_SERVER_OIDC_CLIENT_ID: "browser",
      ARTIFACT_SERVER_OIDC_ISSUER: "https://auth.example.test",
    };
    const configured = await loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "tenant-cli,other-service",
    });
    expect(configured?.provisionerClients).toEqual(["tenant-cli"]);
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "other-service",
    })).rejects.toThrow("must also appear in ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS");
  });

  test("allows exactly five provisioner tools and creates a restricted two-group project", async () => {
    const names = await call("oidc-tenant-cli", "tools/list", {}).then((result) =>
      z.object({tools: z.array(z.object({name: z.string()}))})
        .parse(result)["tools"].map(({name}) => name).toSorted()
    );
    expect(names).toEqual([...provisionerToolNames].toSorted());

    const listed = await call("oidc-tenant-cli", "tools/call", {
      name: "project_list", arguments: {},
    });
    expect(listed["isError"]).not.toBe(true);

    const created = await call("oidc-tenant-cli", "tools/call", {
      name: "project_create",
      arguments: {
        name: "Tenant project",
        shareWith: [
          {group: "/Tenant/CLI", role: "manager"},
          {group: "/Tenant/Support", role: "viewer"},
        ],
      },
    });
    expect(created["isError"]).not.toBe(true);
    const sharing = z.object({
      sharing: z.object({
        accessMode: z.literal("restricted"),
        groups: z.array(z.object({path: z.string(), role: z.string()})),
        projectId: z.string(),
        yourRole: z.string().nullable(),
      }),
    }).parse(created["structuredContent"]).sharing;
    expect(sharing).toMatchObject({
      accessMode: "restricted",
      groups: [
        {path: "/Tenant/CLI", role: "manager"},
        {path: "/Tenant/Support", role: "viewer"},
      ],
      yourRole: "manager",
    });
    const bareGroup = await call("oidc-tenant-cli", "tools/call", {
      name: "project_share",
      arguments: {group: "Support", projectId: sharing.projectId, role: "editor"},
    });
    expect(bareGroup["isError"]).toBe(true);
    expect(bareGroup["content"]?.[0]?.text).toContain("Input validation error");

    const details = await call("oidc-tenant-cli", "tools/call", {
      name: "project_sharing", arguments: {projectId: sharing.projectId},
    });
    expect(details["isError"]).not.toBe(true);
    const changedShare = await call("oidc-tenant-cli", "tools/call", {
      name: "project_share",
      arguments: {group: "/Tenant/Support", projectId: sharing.projectId, role: "editor"},
    });
    expect(changedShare["isError"]).not.toBe(true);
    const restricted = await call("oidc-tenant-cli", "tools/call", {
      name: "project_set_access",
      arguments: {accessMode: "restricted", projectId: sharing.projectId},
    });
    expect(restricted["isError"]).not.toBe(true);

    for (const name of ["artifact_list", "group_list", "group_set_role", "comment_list"]) {
      // oxlint-disable-next-line eslint/no-await-in-loop
      const denied = await call("oidc-tenant-cli", "tools/call", {
        name, arguments: {},
      });
      expect(denied["isError"]).toBe(true);
      expect(denied["content"]?.[0]?.text).toContain("Permission denied");
    }

    const otherService = await mcpRequest("oidc-other-service", "tools/list", {});
    expect(otherService.status).toBe(403);
  });

  async function call(
    token: string,
    method: "tools/list" | "tools/call",
    params: JsonObject,
  ) {
    const response = await mcpRequest(token, method, params);
    const payload = await readJsonRpc(response);
    if (!response.ok) {
      throw new Error(`MCP request failed (${response.status}): ${JSON.stringify(payload)}`);
    }
    return payload.result;
  }

  async function mcpRequest(token: string, method: string, params: JsonObject) {
    return fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id: 1, jsonrpc: "2.0", method, params}),
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
        "Mcp-Method": method,
      },
      method: "POST",
    });
  }

});

async function readJsonRpc(response: Response): Promise<z.infer<typeof mcpEnvelopeSchema>> {
  const body = await response.text();
  const payload = body.split("\n").filter((line) => line.startsWith("data: "))
    .map((line) => line.slice(6)).at(-1) ?? body;
  const decoded: unknown = JSON.parse(payload);
  return mcpEnvelopeSchema.parse(decoded);
}

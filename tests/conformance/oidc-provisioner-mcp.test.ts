import {DatabaseSync} from "node:sqlite";
import {Effect, Redacted} from "effect";
import {afterAll, beforeAll, describe, expect, test} from "vitest";
import {z} from "zod";

import {loadOidcConfiguration} from "../../src/cli/oidc-configuration.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {SqliteArtifactRepository} from "../../src/storage/sqlite-artifact-repository.js";
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
  capabilities: [principalCapabilities.provisionProjects],
  directoryGroupIds: ["g-tenant-cli"],
  displayName: "tenant-cli",
  email: null,
  id: "oidc-service:test:tenant-cli",
  installationId: "local",
  kind: principalKinds.service,
  membershipRole: membershipRoles.member,
  serviceAccountSource: "oidc" as const,
  serviceAccountClientId: "tenant-cli",
  provisionerGroupPrefixes: ["/Tenant/"],
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
          {id: "g-admins", members: [], name: "Administrators", path: "/Administrators"},
          {id: "g-devs", members: [], name: "Developers", path: "/Developers"},
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
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: "Tenant=operator",
      ARTIFACT_SERVER_OIDC_ISSUER: "https://auth.example.test",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "/Tenant/",
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
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: "Tenant=operator",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "",
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "tenant-cli",
    })).rejects.toThrow("requires non-empty ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES");
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: undefined,
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "/Tenant/",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "tenant-cli",
    })).rejects.toThrow("requires an OIDC group-roles policy");
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: "Tenant=operator",
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "browser",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "/Tenant/",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "browser",
    })).rejects.toThrow("must not include the hosted-login or MCP OAuth client id");
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: "Tenant=operator",
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "/Tenant//",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "tenant-cli",
    })).rejects.toThrow("Every ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES entry");
    await expect(loadOidcConfiguration({
      ...shared,
      ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED: "Tenant=operator",
      ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES: "/Tenant/",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "tenant-cli",
      ARTIFACT_SERVER_OIDC_EMBED_BIND_CLIENTS: "tenant-cli",
    })).rejects.toThrow("must not overlap");
  });

  test("allows exactly five provisioner tools and creates a restricted two-group project", async () => {
    const projectSeedRepository = new SqliteArtifactRepository(`${installation.dataDirectory}/artifact-server.db`, "local");
    try {
      await projectSeedRepository.createProject({
        accessMode: "restricted",
        archivedAt: null,
        createdAt: "2026-11-12T00:00:00.000Z",
        createdByMemberId: null,
        createdByPrincipalId: "another-principal",
        id: "another-principal-project",
        installationId: "local",
        name: "Another principal project",
      });
    } finally {
      projectSeedRepository.close();
    }
    const names = await call("oidc-tenant-cli", "tools/list", {}).then((result) =>
      z.object({tools: z.array(z.object({name: z.string()}))})
        .parse(result)["tools"].map(({name}) => name).toSorted()
    );
    expect(names).toEqual([...provisionerToolNames].toSorted());

    const managerCreate = await call("oidc-tenant-cli", "tools/call", {
      name: "project_create",
      arguments: {name: "Rejected manager project", shareWith: [{group: "/Tenant/CLI", role: "manager"}]},
    });
    expect(managerCreate["isError"]).toBe(true);

    const listed = await call("oidc-tenant-cli", "tools/call", {
      name: "project_list", arguments: {},
    });
    expect(listed["isError"]).not.toBe(true);
    const initialProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(listed["structuredContent"]).projects;
    expect(initialProjects.some(({id}) => id === "default")).toBe(false);
    expect(initialProjects.some(({id}) => id === "another-principal-project")).toBe(false);

    const created = await call("oidc-tenant-cli", "tools/call", {
      name: "project_create",
      arguments: {
        name: "Tenant project",
        shareWith: [
          {group: "/Tenant/CLI", role: "editor"},
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
        {path: "/Tenant/CLI", role: "editor"},
        {path: "/Tenant/Support", role: "viewer"},
      ],
      yourRole: "manager",
    });
    const visibleProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse((await call("oidc-tenant-cli", "tools/call", {
        name: "project_list", arguments: {},
      }))["structuredContent"]).projects;
    expect(visibleProjects.map(({id}) => id)).toContain(sharing.projectId);
    expect(visibleProjects.some(({id}) => id === "default")).toBe(false);
    const bareGroup = await call("oidc-tenant-cli", "tools/call", {
      name: "project_share",
      arguments: {group: "Support", projectId: sharing.projectId, role: "editor"},
    });
    expect(bareGroup["isError"]).toBe(true);
    expect(bareGroup["content"]?.[0]?.text).toContain("full group path");

    const managerGrant = await call("oidc-tenant-cli", "tools/call", {
      name: "project_share",
      arguments: {group: "/Tenant/Support", projectId: sharing.projectId, role: "manager"},
    });
    expect(managerGrant["isError"]).toBe(true);
    const installationAccess = await call("oidc-tenant-cli", "tools/call", {
      name: "project_set_access",
      arguments: {accessMode: "installation", projectId: sharing.projectId},
    });
    expect(installationAccess["isError"]).toBe(true);

    for (const group of ["/Administrators", "/Developers"]) {
      // oxlint-disable-next-line eslint/no-await-in-loop
      const deniedInitialShare = await call("oidc-tenant-cli", "tools/call", {
        name: "project_create",
        arguments: {name: `Denied share to ${group}`, shareWith: [{group, role: "viewer"}]},
      });
      expect(deniedInitialShare["isError"]).toBe(true);
      expect(deniedInitialShare["content"]?.[0]?.text).toContain("configured group prefixes");
      // oxlint-disable-next-line eslint/no-await-in-loop
      const deniedGroupShare = await call("oidc-tenant-cli", "tools/call", {
        name: "project_share", arguments: {group, projectId: sharing.projectId, role: "editor"},
      });
      expect(deniedGroupShare["isError"]).toBe(true);
      expect(deniedGroupShare["content"]?.[0]?.text).toContain("configured group prefixes");
    }

    const otherOpenProjectShare = await call("oidc-tenant-cli", "tools/call", {
      name: "project_share", arguments: {group: "/Tenant/Support", projectId: "default", role: "editor"},
    });
    expect(otherOpenProjectShare["isError"]).toBe(true);
    const otherOpenProjectRestrict = await call("oidc-tenant-cli", "tools/call", {
      name: "project_set_access", arguments: {accessMode: "restricted", projectId: "default"},
    });
    expect(otherOpenProjectRestrict["isError"]).toBe(true);

    const details = await call("oidc-tenant-cli", "tools/call", {
      name: "project_sharing", arguments: {projectId: sharing.projectId},
    });
    expect(details["isError"]).not.toBe(true);
    const openProjectDetails = await call("oidc-tenant-cli", "tools/call", {
      name: "project_sharing", arguments: {projectId: "default"},
    });
    expect(openProjectDetails["isError"]).toBe(true);
    const unrelatedRestrictedProjectDetails = await call("oidc-tenant-cli", "tools/call", {
      name: "project_sharing", arguments: {projectId: "another-principal-project"},
    });
    expect(unrelatedRestrictedProjectDetails["isError"]).toBe(true);
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

    const resources = await call("oidc-tenant-cli", "tools/call", {
      name: "resources/list", arguments: {},
    });
    expect(resources["content"]?.[0]?.text).toContain("Permission denied");
    const prompts = await mcpRequest("oidc-tenant-cli", "prompts/list", {});
    expect((await prompts.text())).toContain("Permission denied");

    const batch = await mcpRequestRaw("oidc-tenant-cli", JSON.stringify([
      {id: 1, jsonrpc: "2.0", method: "tools/list", params: {}},
    ]));
    expect(batch.status).toBe(200);
    expect(await batch.text()).toContain("Permission denied");
    const malformed = await mcpRequestRaw("oidc-tenant-cli", "{");
    expect(malformed.status).toBe(200);
    expect(await malformed.text()).toContain("Permission denied");

    const repository = new SqliteArtifactRepository(`${installation.dataDirectory}/artifact-server.db`, "local");
    try {
      const audit = await repository.listProjectAuditEvents(sharing.projectId);
      expect(audit.filter(({action}) => action === "create" || action === "share" || action === "set_access")).toEqual(
        expect.arrayContaining([
          expect.objectContaining({action: "create", clientId: "tenant-cli", principalId: provisioner.id}),
          expect.objectContaining({action: "share", clientId: "tenant-cli", principalId: provisioner.id}),
          expect.objectContaining({action: "set_access", clientId: "tenant-cli", principalId: provisioner.id}),
        ]),
      );
    } finally {
      repository.close();
    }
  });

  test("provisioner completes the MCP initialize handshake before project creation over HTTP", async () => {
    const initialized = await mcpRequestRaw("oidc-tenant-cli", JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        capabilities: {},
        clientInfo: {name: "tenant-cli-test", version: "1.0.0"},
        protocolVersion: "2025-06-18",
      },
    }), "initialize");
    expect(initialized.status).toBe(200);
    expect(await readJsonRpc(initialized)).toMatchObject({
      result: {protocolVersion: "2025-06-18"},
    });

    const ping = await mcpRequest("oidc-tenant-cli", "ping", {});
    expect(ping.status).toBe(200);
    expect(await readJsonRpc(ping)).toMatchObject({result: {}});

    const notification = await mcpRequestRaw("oidc-tenant-cli", JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    }), "notifications/initialized");
    expect([200, 202, 204]).toContain(notification.status);

    const listed = await call("oidc-tenant-cli", "tools/list", {});
    expect(z.object({tools: z.array(z.object({name: z.string()}))})
      .parse(listed).tools.map(({name}) => name).toSorted())
      .toEqual([...provisionerToolNames].toSorted());

    const created = await call("oidc-tenant-cli", "tools/call", {
      name: "project_create",
      arguments: {name: "Handshake-created project", shareWith: []},
    });
    expect(created["isError"]).not.toBe(true);
    expect(z.object({sharing: z.object({accessMode: z.literal("restricted")})})
      .parse(created["structuredContent"]).sharing.accessMode).toBe("restricted");
  });

  test("create audit records only successful initial shares and audit outages do not fail creation", async () => {
    const database = new DatabaseSync(`${installation.dataDirectory}/artifact-server.db`);
    database.exec(`
      CREATE TRIGGER reject_initial_group_share
      BEFORE INSERT ON project_group_grants
      BEGIN SELECT RAISE(ABORT, 'injected sharing failure'); END;
    `);
    try {
      const created = await call("oidc-tenant-cli", "tools/call", {
        name: "project_create",
        arguments: {
          name: "Initial share failure project",
          shareWith: [{group: "/Tenant/CLI", role: "editor"}],
        },
      });
      expect(created["isError"]).not.toBe(true);
      const projectId = z.object({sharing: z.object({projectId: z.string()})})
        .parse(created["structuredContent"]).sharing.projectId;
      database.exec("DROP TRIGGER reject_initial_group_share;");
      const repository = new SqliteArtifactRepository(
        `${installation.dataDirectory}/artifact-server.db`,
        "local",
      );
      try {
        const audit = await repository.listProjectAuditEvents(projectId);
        expect(audit.map(({action}) => action)).toEqual(["create"]);
      } finally {
        repository.close();
      }

      database.exec(`
        CREATE TRIGGER reject_provisioner_audit
        BEFORE INSERT ON project_provisioner_audit_events
        BEGIN SELECT RAISE(ABORT, 'injected audit outage'); END;
      `);
      const auditOutageCreate = await call("oidc-tenant-cli", "tools/call", {
        name: "project_create",
        arguments: {name: "Audit outage project", shareWith: []},
      });
      expect(auditOutageCreate["isError"]).not.toBe(true);
      database.exec("DROP TRIGGER reject_provisioner_audit;");
    } finally {
      database.exec("DROP TRIGGER IF EXISTS reject_initial_group_share;");
      database.exec("DROP TRIGGER IF EXISTS reject_provisioner_audit;");
      database.close();
    }
  });

  async function call(
    token: string,
    method: "tools/list" | "tools/call",
    params: JsonObject,
  ) {
    const response = await mcpRequest(token, method, params);
    const raw = await response.clone().text();
    let payload: z.infer<typeof mcpEnvelopeSchema>;
    try {
      payload = await readJsonRpc(response);
    } catch (cause) {
      throw new Error(`MCP response ${response.status}: ${raw}`, {cause});
    }
    if (!response.ok) {
      throw new Error(`MCP request failed (${response.status}): ${JSON.stringify(payload)} ${raw}`);
    }
    return payload.result;
  }

  async function mcpRequest(token: string, method: string, params: JsonObject) {
    return mcpRequestRaw(token, JSON.stringify({id: 1, jsonrpc: "2.0", method, params}), method);
  }

  async function mcpRequestRaw(token: string, body: string, method = "tools/call") {
    return fetch(`${server.baseUrl}/mcp`, {
      body,
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

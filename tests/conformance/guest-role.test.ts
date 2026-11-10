import {Effect, Layer, ManagedRuntime, Redacted, Result} from "effect";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {DatabaseSync} from "node:sqlite";
import nodePath from "node:path";
import {z} from "zod";

import {AuthorizationService} from "../../src/application/authorization.js";
import type {BearerCredentialVerifier} from "../../src/application/authentication.js";
import {AuthenticationRequired, type AuthorizationDenied} from "../../src/core/errors.js";
import {groupMembershipRole} from "../../src/core/group-role-policy.js";
import {
  membershipRoles,
  type Principal,
} from "../../src/core/identity.js";
import {resolveProjectAccess, type ProjectAccessRecord} from "../../src/core/project-access.js";
import {createTestInstallation, issueLocalBrowserLogin, removeTestInstallation, startTestServer, storeTestGroupRoles, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const guestMcpResultSchema = z.union([
  z.object({groups: z.array(z.never())}).strict(),
  z.object({sharing: z.object({
    accessMode: z.literal("restricted"), groups: z.array(z.never()),
    projectId: z.string(), yourRole: z.null(),
  }).strict()}).strict(),
]);

describe("guest installation role", () => {
  let runtime: ManagedRuntime.ManagedRuntime<AuthorizationService, never>;
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    runtime = ManagedRuntime.make(Layer.mergeAll(
      AuthorizationService.layer({installationId: "installation-a"}),
    ));
    await runtime.context();
    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      externalApiBearerVerifier: conformanceBearerVerifier,
      externalMcpBearerVerifier: conformanceBearerVerifier,
    });
    await storeTestGroupRoles(server, installation, [
      {name: "Guests", role: membershipRoles.guest},
      {name: "Viewers", role: membershipRoles.viewer},
      {name: "Owners", role: membershipRoles.owner},
    ]);
  });

  afterEach(async () => {
    await runtime.dispose();
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("GUEST-001-B: a guest sees only explicitly shared restricted projects at viewer level", () => {
    const guest = humanPrincipal("guest", membershipRoles.guest);
    expect(resolveProjectAccess(guest, record("installation", ["manager"])))
      .toEqual({mode: "restricted", role: null});
    expect(resolveProjectAccess(guest, record("restricted", [])))
      .toEqual({mode: "restricted", role: null});
    expect(resolveProjectAccess(guest, record("restricted", ["manager"])))
      .toEqual({mode: "restricted", role: "viewer"});
  });

  test("GUEST-001-F: guest access cannot create or manage artifacts, while comments and reads remain allowed", async () => {
    expect.hasAssertions();
    const guest = humanPrincipal("guest", membershipRoles.guest);
    await expectDenied((authorization) => authorization.requireArtifactCreation(guest));
    await expectDenied((authorization) => authorization.requireArtifactManagement(guest));
    await expectDenied((authorization) => authorization.requireProjectManagement(guest));
    await expectAllowed((authorization) => authorization.requireArtifactRead(guest));
    await expectAllowed((authorization) => authorization.requireCommentRead(guest));
    await expectAllowed((authorization) => authorization.requireCommentWrite(guest));
  });

  test("GUEST-002-B: the strongest matching group role admits a guest", () => {
    expect.hasAssertions();
    expect(groupMembershipRole([
      assignment("group-guests", "guest"),
      assignment("group-viewers", "viewer"),
      assignment("group-operators", "member"),
    ], ["/Guests", "/Viewers", "/Operators"])).toBe("guest");
    expect(groupMembershipRole([
      assignment("group-guests", "guest"),
      assignment("group-admins", "administrator"),
    ], ["/Guests", "/Admins"])).toBe("administrator");
    expect(groupMembershipRole([
      assignment("group-guests", "guest"),
      assignment("group-owners", "owner"),
    ], ["/Guests", "/Owners"])).toBe("owner");
    expect(groupMembershipRole([assignment("group-guests", "guest")], ["/Guests"]))
      .toBe("guest");
  });

  test("GUEST-003-B: guests receive empty directory and sharing lists and cannot list members or create projects", async () => {
    expect.hasAssertions();
    const existingProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(await (await ownerFetch("/api/v1/projects")).json()).projects;
    expect(existingProjects).toHaveLength(1);
    const defaultProjectId = existingProjects[0]?.id;
    if (defaultProjectId === undefined) throw new Error("The test installation has no default project.");
    const createdProject = await ownerFetch("/api/v1/projects", {
      body: JSON.stringify({
        name: "Guest shared project",
        shareWith: [{group: "/Guests", role: "manager"}],
      }),
      method: "POST",
    });
    expect(createdProject.status).toBe(201);
    const projectId = z.object({project: z.object({id: z.string()})})
      .parse(await createdProject.json()).project.id;
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Guests'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'guest', 'active', ?, ?)`).run(
        "member_guest_conformance", installationId, "guest@example.test", "Guest", now, now,
      );
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?)`).run(
        installationId, "group-Guests", "guest-subject", "guest@example.test", "guest-role-conformance",
      );
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?)`).run(
        installationId, "group-Viewers", "guest-subject", "guest@example.test", "guest-role-conformance",
      );
    } finally {
      database.close();
    }
    const groups = await guestFetch("/api/v1/groups");
    expect(groups.status).toBe(200);
    expect(await groups.json()).toEqual({groups: []});
    const mcpGroups = await guestMcpTool("group_list", {});
    expect(mcpGroups).toEqual({groups: []});
    const mcpSharing = await guestMcpTool("project_sharing", {projectId: "unshared"});
    expect(mcpSharing).toEqual({sharing: {
      accessMode: "restricted", groups: [], projectId: "unshared", yourRole: null,
    }});
    const ownerGroups = z.object({groups: z.array(z.object({
      hasHigherRoleOverlap: z.boolean(), id: z.string(),
    }).passthrough())}).parse(await (await ownerFetch("/api/v1/groups")).json()).groups;
    expect(ownerGroups.find((group) => group.id === "group-Guests")?.hasHigherRoleOverlap).toBe(true);
    const sharing = await guestFetch("/api/v1/projects/unshared/sharing");
    expect(sharing.status).toBe(200);
    expect(await sharing.json()).toEqual({sharing: {
      accessMode: "restricted", groups: [], projectId: "unshared", yourRole: null,
    }});
    const visibleProjectsResponse = await guestFetch("/api/v1/projects");
    expect(await visibleProjectsResponse.clone().text()).not.toContain("@");
    const visibleProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(await visibleProjectsResponse.json()).projects;
    expect(visibleProjects.map(({id}) => id)).toEqual([projectId]);
    expect((await guestFetch("/api/v1/members")).status).toBe(403);
    const guestKey = await ownerFetch("/api/v1/api-keys", {
      body: JSON.stringify({
        capabilities: ["artifact:read"], expiresAt: "2099-01-01T00:00:00.000Z",
        memberId: "member_guest_conformance", name: "Guest key",
      }),
      method: "POST",
    });
    expect(guestKey.status).toBe(403);
    expect((await guestFetch("/api/v1/agents")).status).toBe(403);
    expect((await guestFetch("/api/v1/agent-dispatches")).status).toBe(403);
    expect((await guestFetch("/api/v1/agent-dispatches/dispatch-private")).status).toBe(403);
    expect((await guestFetch("/api/v1/projects", {body: JSON.stringify({name: "Guest project"}), method: "POST"})).status).toBe(403);
    expect((await guestFetch("/api/v1/administration/public-links")).status).toBe(403);
    const artifact = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "private artifact for guest boundary",
      idempotencyKey: "guest-boundary-artifact",
      name: "Private artifact",
      projectId: defaultProjectId,
    });
    expect((await guestFetch(`/api/v1/artifacts/${artifact.body.artifact.id}`)).status).toBe(404);
    expect((await guestFetch(`/api/v1/embed/artifacts/${artifact.body.artifact.id}/bootstrap?path=index.html`)).status).toBe(404);
    expect([403, 404]).toContain((await guestFetch(`/api/v1/artifacts/${artifact.body.artifact.id}/guest-invitation`, {
      body: "{}", method: "POST",
    })).status);
  });

  test("GUEST-004-B GUEST-004-F: only owners edit group roles and the final owner group is retained", async () => {
    expect.hasAssertions();
    expect((await guestFetch("/api/v1/groups/group-Guests/role", {
      body: JSON.stringify({role: "viewer"}), method: "PUT",
    })).status).toBe(403);
    expect((await ownerFetch("/api/v1/groups/group-Owners/role", {
      body: JSON.stringify({role: null}), method: "PUT",
    })).status).toBe(409);
    expect((await ownerFetch("/api/v1/groups/group-Guests/role", {
      body: JSON.stringify({role: "viewer"}), method: "PUT",
    })).status).toBe(204);
    const groups = z.object({groups: z.array(z.object({id: z.string(), role: z.string().nullable()}))})
      .parse(await (await ownerFetch("/api/v1/groups")).json());
    expect(groups.groups.find((group) => group.id === "group-Guests")?.role).toBe("viewer");
  });

  test("GUEST-005-B: changing a viewer group to guest updates an existing browser session", async () => {
    expect.hasAssertions();
    const loginToken = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(`${server.baseUrl}/auth/local?token=${loginToken}`, {redirect: "manual"});
    const cookie = login.headers.getSetCookie()
      .filter((item) => /^artifact_(session|csrf)=/u.test(item))
      .map((item) => item.split(";", 1)[0]).join("; ");
    expect(cookie).not.toBe("");
    const currentSession = await fetch(`${server.baseUrl}/api/v1/session`, {headers: {Cookie: cookie}});
    const session = z.object({principal: z.object({email: z.string(), id: z.string()})})
      .parse(await currentSession.json()).principal;
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM installation_members WHERE id = ?").get(session.id)).installationId;
      const now = new Date().toISOString();
      database.prepare("UPDATE installation_members SET role = 'viewer' WHERE installation_id = ? AND id = ?")
        .run(installationId, session.id);
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?)`).run(
        installationId, "group-Viewers", "existing-session-subject", session.email, "guest-role-session-test",
      );
      database.prepare("UPDATE installation_members SET updated_at = ? WHERE id = ?").run(now, session.id);
    } finally {
      database.close();
    }
    expect((await ownerFetch("/api/v1/groups/group-Viewers/role", {
      body: JSON.stringify({role: "viewer"}), method: "PUT",
    })).status).toBe(204);
    const issuedViewerKey = z.object({token: z.string()}).parse(await (await ownerFetch("/api/v1/api-keys", {
      body: JSON.stringify({
        capabilities: ["artifact:read"], expiresAt: "2099-01-01T00:00:00.000Z",
        memberId: session.id, name: "Viewer member key",
      }),
      method: "POST",
    })).json()).token;
    const projectListPath = `${server.baseUrl}/api/v1/projects`;
    const viewerProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(await (await fetch(projectListPath, {headers: {Cookie: cookie}})).json()).projects;
    expect(viewerProjects.length).toBeGreaterThan(0);
    expect((await ownerFetch("/api/v1/groups/group-Viewers/role", {
      body: JSON.stringify({role: "guest"}), method: "PUT",
    })).status).toBe(204);
    const updatedSession = z.object({principal: z.object({membershipRole: z.string()})})
      .parse(await (await fetch(`${server.baseUrl}/api/v1/session`, {headers: {Cookie: cookie}})).json());
    expect(updatedSession.principal.membershipRole).toBe("guest");
    const guestProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(await (await fetch(projectListPath, {headers: {Cookie: cookie}})).json()).projects;
    expect(guestProjects).toEqual([]);
    const keyProjects = z.object({projects: z.array(z.object({id: z.string()}))})
      .parse(await (await fetch(projectListPath, {
        headers: {Authorization: `Bearer ${issuedViewerKey}`},
      })).json()).projects;
    expect(keyProjects).toEqual([]);
  });

  async function expectAllowed(
    operation: (authorization: AuthorizationService["Service"]) => Effect.Effect<void, AuthorizationDenied>,
  ): Promise<void> {
    expect(Result.isSuccess(await runtime.runPromise(Effect.result(AuthorizationService.use(operation)))))
      .toBe(true);
  }

  async function expectDenied(
    operation: (authorization: AuthorizationService["Service"]) => Effect.Effect<void, AuthorizationDenied>,
  ): Promise<void> {
    const result = await runtime.runPromise(Effect.result(AuthorizationService.use(operation)));
    expect(Result.match(result, {
      onFailure: (failure) => failure._tag,
      onSuccess: () => "UnexpectedSuccess",
    })).toBe("AuthorizationDenied");
  }

  async function guestFetch(path: string, init: RequestInit = {}): Promise<Response> {
    return authenticatedFetch(path, "guest-conformance", init);
  }

  async function ownerFetch(path: string, init: RequestInit = {}): Promise<Response> {
    return authenticatedFetch(path, "owner-conformance", init);
  }

  async function authenticatedFetch(path: string, token: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    return fetch(`${server.baseUrl}${path}`, {...init, headers});
  }

  async function guestMcpTool(
    name: "group_list" | "project_sharing",
    args: {readonly projectId?: string},
  ): Promise<z.infer<typeof guestMcpResultSchema>> {
    const response = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "guest-role-conformance", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
          },
          arguments: args,
          name,
        },
      }),
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer guest-conformance",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
      },
      method: "POST",
    });
    expect(response.status).toBe(200);
    const result = z.object({result: z.object({structuredContent: z.unknown()}).loose()}).parse(await response.json());
    return guestMcpResultSchema.parse(result.result.structuredContent);
  }
});

const conformanceBearerVerifier: BearerCredentialVerifier = {
  verify: (credential) => {
    const value = Redacted.value(credential);
    if (value === "guest-conformance") {
      return Effect.succeed({...humanPrincipal("member_guest_conformance", membershipRoles.guest), installationId: "local"});
    }
    if (value === "owner-conformance") {
      return Effect.succeed({...humanPrincipal("member_owner_conformance", membershipRoles.owner), installationId: "local"});
    }
    return Effect.fail(new AuthenticationRequired({message: "Unknown conformance token."}));
  },
};

function record(
  mode: ProjectAccessRecord["accessMode"],
  grantRoles: readonly ("viewer" | "editor" | "manager")[],
): ProjectAccessRecord {
  return {
    accessMode: mode,
    grantRoles,
    isCreator: true,
    member: {role: membershipRoles.guest, status: "active"},
  };
}

function humanPrincipal(id: string, membershipRole: Principal["membershipRole"]): Principal {
  return {
    authorizedByPrincipalId: null,
    capabilities: [],
    displayName: id,
    id,
    installationId: "installation-a",
    kind: "human",
    membershipRole,
  };
}

function assignment(groupId: string, role: Principal["membershipRole"]) {
  return {
    assignedAt: "",
    groupId,
    name: groupId,
    nameUnique: true,
    path: groupId === "group-guests" ? "/Guests"
      : groupId === "group-owners" ? "/Owners"
      : groupId === "group-admins" ? "/Admins"
      : "/Viewers",
    role,
  };
}

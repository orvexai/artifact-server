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
import type {InteractiveIdentityProvider} from "../../src/application/interactive-login.js";
import type {BearerCredentialVerifier} from "../../src/application/authentication.js";
import {AuthenticationRequired, IdentityProviderFailure, type AuthorizationDenied} from "../../src/core/errors.js";
import {browserLoginKinds, privateTeamBrowserAccess} from "../../src/core/browser-access.js";
import {groupMembershipRole, guestGroupPathMatches} from "../../src/core/group-role-policy.js";
import type {ExternalIdentity} from "../../src/core/installation-identity.js";
import {
  membershipRoles,
  principalCapabilities,
  type Principal,
} from "../../src/core/identity.js";
import {resolveProjectAccess, type ProjectAccessRecord} from "../../src/core/project-access.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {createTestInstallation, issueLocalBrowserLogin, loginHandshakeCookie, removeTestInstallation, startTestServer, storeTestGroupRoles, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const guestMcpResultSchema = z.union([
  z.object({groups: z.array(z.never())}).strict(),
  z.object({sharing: z.object({
    accessMode: z.literal("restricted"), groups: z.array(z.never()),
    projectId: z.string(), yourRole: z.null(),
  }).strict()}).strict(),
]);

function snapshotGroupsForGuestSync(guestMembership: boolean) {
  return [
    {id: "group-Guests", members: guestMembership
      ? [{email: "directory-sync@example.test", subject: "directory-sync-subject"}]
      : [], name: "Guests", path: "/Guests"},
    {id: "group-Viewers", members: guestMembership
      ? []
      : [{email: "directory-sync@example.test", subject: "directory-sync-subject"}],
      name: "Viewers", path: "/Viewers"},
    {id: "group-Owners", members: [], name: "Owners", path: "/Owners"},
  ];
}

function groupRoleAssignment(groupId: string, name: string, path: string, role: "guest" | "viewer" | "member" | "owner") {
  return {assignedAt: "now", groupId, name, nameUnique: true, path, role};
}

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

  test("GUEST-004-R: configured full-path prefixes assign guest while explicit roles retain precedence", () => {
    const groups = [
      {id: "acme", name: "acme", path: "/Guests/acme"},
      {id: "leads", name: "leads", path: "/Guests/acme/leads"},
      {id: "bare", name: "Guests", path: "/Guests"},
      {id: "lookalike", name: "a", path: "/GuestsX/a"},
    ];
    expect(groups.map(({path}) => guestGroupPathMatches(path, ["/Guests/"]))).toEqual([
      true, true, false, false,
    ]);
    expect(groupMembershipRole([groupRoleAssignment("acme", "acme", "/Guests/acme", "guest")], ["/Guests/acme"])).toBe("guest");
    expect(groupMembershipRole([
      groupRoleAssignment("acme", "acme", "/Guests/acme", "guest"),
      groupRoleAssignment("operators", "operators", "/Operators", "member"),
    ], ["/Guests/acme", "/Operators"])).toBe("guest");
    expect(groupMembershipRole([
      groupRoleAssignment("acme", "acme", "/Guests/acme", "guest"),
      groupRoleAssignment("owners", "owners", "/Owners", "owner"),
    ], ["/Guests/acme", "/Owners"])).toBe("owner");
    expect(groupMembershipRole([
      groupRoleAssignment("acme", "acme", "/Guests/acme", "viewer"),
    ], ["/Guests/acme"])).toBe("viewer");
    expect(groupMembershipRole([
      groupRoleAssignment("staff", "x-staff", "/TenantWorkspaces/x/x-staff", "member"),
    ], ["/TenantWorkspaces/x/x-staff"])).toBe("member");
    expect(guestGroupPathMatches("/TenantWorkspaces/x/x-staff", ["/Guests/"])).toBe(false);
    const sharedStaff = {
      authorizedByPrincipalId: null,
      capabilities: [principalCapabilities.readArtifacts],
      directoryGroupIds: ["staff"],
      displayName: "Staff service",
      id: "service:staff",
      installationId: "installation",
      kind: "service" as const,
      membershipRole: membershipRoles.member,
      serviceAccountSource: "oidc" as const,
    };
    expect(resolveProjectAccess(sharedStaff, record("restricted", ["editor"])))
      .toEqual({mode: "restricted", role: "editor"});
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
      ) VALUES (?, ?, ?, ?, 'owner', 'active', ?, ?)`).run(
        "member_owner_conformance", installationId, "owner@example.test", "owner@example.test", now, now,
      );
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
    const sharedArtifact = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "shared content for guest comment privacy",
      idempotencyKey: "guest-comment-privacy",
      projectId,
    });
    const createdComment = await ownerFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/versions/${sharedArtifact.body.version.id}/comments?projectId=${projectId}`,
      {body: JSON.stringify({body: "Staff note"}), headers: {"Idempotency-Key": "guest-comment-privacy"}, method: "POST"},
    );
    const createdCommentStatus = createdComment.status;
    expect(await createdComment.clone().text()).not.toContain("PROJECT_NOT_FOUND");
    expect(createdCommentStatus).toBe(201);
    const threadId = z.object({thread: z.object({id: z.string()})})
      .parse(await createdComment.json()).thread.id;
    const staffThread = await ownerFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/comments/${threadId}?projectId=${projectId}`,
    );
    expect(JSON.stringify(await staffThread.json())).toContain("owner@example.test");
    const guestThreadResponse = await guestFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/comments/${threadId}?projectId=${projectId}`,
    );
    expect(guestThreadResponse.status).toBe(200);
    const guestThreadBody = await guestThreadResponse.text();
    expect(guestThreadBody).not.toContain("owner@example.test");
    expect(guestThreadBody).not.toContain("principalId");
    expect(guestThreadBody).toContain("Team member");
    const staffResponse = await ownerFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/responses?projectId=${projectId}`,
      {body: JSON.stringify({choice: "yes", questionId: "privacy-question", versionId: sharedArtifact.body.version.id}), method: "POST"},
    );
    expect(staffResponse.status).toBe(201);
    const serviceResponse = await serviceFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/responses?projectId=${projectId}`,
    );
    expect(serviceResponse.status).toBe(200);
    expect(JSON.stringify(await serviceResponse.json())).not.toContain("authorEmail\":\"owner@example.test");
    const guestResponses = await guestFetch(
      `/api/v1/artifacts/${sharedArtifact.body.artifact.id}/responses?projectId=${projectId}`,
    );
    const guestResponseBody = await guestResponses.text();
    expect(guestResponseBody).not.toContain("owner@example.test");
    expect(guestResponseBody).not.toContain("authorSubject");
    expect(guestResponseBody).toContain("Team member");
    const guestHttpVersions = await guestFetch(`/api/v1/artifacts/${sharedArtifact.body.artifact.id}/versions?projectId=${projectId}`);
    expect((await guestHttpVersions.text())).not.toContain("publisherPrincipalId");
    const guestMcpVersions = await guestMcpCall("artifact_version_list", {artifactId: sharedArtifact.body.artifact.id, projectId});
    expect(JSON.stringify(await guestMcpVersions.json())).not.toContain("publisherPrincipalId");
    const mcpGuestResponses = await guestMcpCall("artifact_response_list", {
      after: null, artifactId: sharedArtifact.body.artifact.id, limit: 10,
      projectId, questionId: null, versionId: null,
    });
    const mcpResponsePayload = z.object({result: z.object({structuredContent: z.unknown()}).loose()})
      .parse(await mcpGuestResponses.json()).result.structuredContent;
    expect(JSON.stringify(mcpResponsePayload)).not.toContain("authorSubject");
    expect(JSON.stringify(mcpResponsePayload)).not.toContain("owner@example.test");
    expect((await ownerFetch(`/api/v1/artifacts/${sharedArtifact.body.artifact.id}/state/staff-key?projectId=${projectId}`, {
      body: JSON.stringify({value: "staff value"}), method: "PUT",
    })).status).toBe(200);
    const guestState = await guestFetch(`/api/v1/artifacts/${sharedArtifact.body.artifact.id}/state?projectId=${projectId}`);
    const guestStateBody = await guestState.text();
    expect(guestStateBody).not.toContain("owner@example.test");
    expect(guestStateBody).toContain("Team member");
    const mcpGuestState = await guestMcpCall("artifact_state_list", {artifactId: sharedArtifact.body.artifact.id, projectId});
    const mcpStatePayload = z.object({result: z.object({structuredContent: z.unknown()}).loose()})
      .parse(await mcpGuestState.json()).result.structuredContent;
    expect(JSON.stringify(mcpStatePayload)).not.toContain("owner@example.test");
    expect((await guestFetch(`/api/v1/artifacts/${sharedArtifact.body.artifact.id}/state/guest-key?projectId=${projectId}`, {
      body: JSON.stringify({value: "guest write"}), method: "PUT",
    })).status).toBe(403);
    expect((await guestFetch(`/api/v1/artifacts/${sharedArtifact.body.artifact.id}/state/guest-key?projectId=${projectId}`, {
      method: "DELETE",
    })).status).toBe(403);
    expect((await guestFetch(`/api/v1/projects/${projectId}/git-history`)).status).toBe(403);
    expect((await guestFetch(`/api/v1/projects/${projectId}/git-history/estimate`, {
      method: "POST",
    })).status).toBe(403);
    expect((await guestFetch(`/api/v1/projects/${projectId}/artifacts/${sharedArtifact.body.artifact.id}/history/clone-token`, {
      body: "{}", method: "POST",
    })).status).toBe(403);
    const protectedMcpCalls = await Promise.all(([
      ["artifact_state_set", {artifactId: sharedArtifact.body.artifact.id, key: "guest-key", projectId, value: "guest write"}],
      ["artifact_state_delete", {artifactId: sharedArtifact.body.artifact.id, key: "guest-key", projectId}],
      ["comment_clear", {artifactId: sharedArtifact.body.artifact.id, projectId, state: "resolved", versionId: null}],
      ["project_git_history_status", {projectId}],
      ["project_git_history_estimate", {projectId}],
      ["artifact_history_clone_token", {artifactId: sharedArtifact.body.artifact.id, projectId}],
    ] as const).map(([name, args]) => guestMcpCall(name, args)));
    const mcpErrors = await Promise.all(protectedMcpCalls.map(async (response) =>
      z.object({result: z.object({isError: z.literal(true)}).passthrough()})
        .parse(await response.json()).result.isError,
    ));
    expect(mcpErrors).toEqual([true, true, true, true, true, true]);
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
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Owners'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'owner', 'active', ?, ?)`).run(
        "member_final_owner", installationId, "owner@example.test", "Owner", now, now,
      );
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?)`).run(
        installationId, "group-Owners", "final-owner-subject", "owner@example.test", "guest-role-owner-test",
      );
      database.prepare(`UPDATE directory_group_roles SET role = 'owner', assigned_at = ?,
        assigned_by_principal_id = 'test' WHERE installation_id = ? AND group_id = ?`)
        .run(now, installationId, "group-Viewers");
    } finally {
      database.close();
    }
    const lastOwnerResponse = await ownerFetch("/api/v1/groups/group-Owners/role", {
      body: JSON.stringify({role: null}), method: "PUT",
    });
    expect(lastOwnerResponse.status).toBe(409);
    expect(await lastOwnerResponse.text()).toMatch(/last active owner/u);
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
    expect((await fetch(projectListPath, {
      headers: {Authorization: `Bearer ${issuedViewerKey}`},
    })).status).toBe(401);
  });

  test("GUEST-006-B: a second seeded directory sync demotes a moved member to guest", async () => {
    const databasePath = nodePath.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Guests'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'viewer', 'active', ?, ?)`).run(
        "member_directory_sync_guest", installationId, "directory-sync@example.test", "Sync Guest", now, now,
      );
      const provider = "guest-role-sync-test";
      expect(database.prepare("SELECT 1 FROM directory_group_role_seeds WHERE installation_id = ?")
        .get(installationId)).toBeDefined();
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(false), {
          id: "group-Acme", name: "acme", path: "/Guests/acme", members: [],
        }, {
          id: "group-MovedIn", name: "movedin", path: "/Outside/movedin", members: [],
        }, {
          id: "group-OwnerAcme", name: "owner-acme", path: "/Guests/owner-acme", members: [],
        }], provider, syncedAt: now,
      });
      await repository.setGroupRole(
        installationId, "group-OwnerAcme", "owner", now, "owner",
      );
      expect(database.prepare("SELECT role FROM installation_members WHERE id = ?")
        .get("member_directory_sync_guest")).toEqual({role: "viewer"});
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(true), {
          id: "group-Acme", name: "acme", path: "/Guests/acme",
          members: [{email: "tenant@example.test", subject: "tenant-subject"}],
        }, {
          id: "group-MovedIn", name: "movedin", path: "/Guests/movedin", members: [],
        }, {
          id: "group-OwnerAcme", name: "owner-acme", path: "/Guests/owner-acme", members: [],
        }],
        guestGroupPrefixes: ["/Guests/"], provider, syncedAt: new Date(Date.now() + 1).toISOString(),
      });
      expect(await repository.listGroupRoles(installationId)).toContainEqual(expect.objectContaining({
        groupId: "group-Acme", role: "guest", source: "rule",
      }));
      expect(await repository.listGroupRoles(installationId)).toContainEqual(expect.objectContaining({
        groupId: "group-OwnerAcme", role: "owner",
      }));
      expect(await repository.listGroupRoles(installationId)).not.toContainEqual(
        expect.objectContaining({groupId: "group-MovedIn"}),
      );
      expect(database.prepare("SELECT role FROM installation_members WHERE id = ?")
        .get("member_directory_sync_guest")).toEqual({role: "guest"});
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'viewer', 'active', ?, ?)`).run(
        "member_prefix_guest", installationId, "tenant@example.test", "Tenant Guest", now, now,
      );
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(true), {
          id: "group-Acme", name: "acme", path: "/Guests/acme",
          members: [{email: "tenant@example.test", subject: "tenant-subject"}],
        }, {
          id: "group-MovedIn", name: "movedin", path: "/Guests/movedin", members: [],
        }, {
          id: "group-OwnerAcme", name: "owner-acme", path: "/Guests/owner-acme", members: [],
        }],
        guestGroupPrefixes: ["/Guests/"], provider, syncedAt: new Date(Date.now() + 2).toISOString(),
      });
      expect(database.prepare("SELECT role FROM installation_members WHERE id = ?")
        .get("member_prefix_guest")).toEqual({role: "guest"});
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(true), {
          id: "group-Acme", name: "acme", path: "/Outside/acme",
          members: [{email: "tenant@example.test", subject: "tenant-subject"}],
        }, {
          id: "group-MovedIn", name: "movedin", path: "/Guests/movedin", members: [],
        }, {
          id: "group-OwnerAcme", name: "owner-acme", path: "/Guests/owner-acme", members: [],
        }],
        guestGroupPrefixes: ["/Guests/"], provider, syncedAt: new Date(Date.now() + 3).toISOString(),
      });
      expect(await repository.listGroupRoles(installationId)).toContainEqual(expect.objectContaining({
        groupId: "group-Acme", role: "guest", source: "rule",
      }));
      await repository.setGroupRole(
        installationId, "group-Acme", null, new Date(Date.now() + 4).toISOString(), "owner",
      );
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(true), {
          id: "group-Acme", name: "acme", path: "/Outside/acme",
          members: [{email: "tenant@example.test", subject: "tenant-subject"}],
        }, {
          id: "group-MovedIn", name: "movedin", path: "/Guests/movedin", members: [],
        }, {
          id: "group-OwnerAcme", name: "owner-acme", path: "/Guests/owner-acme", members: [],
        }],
        guestGroupPrefixes: ["/Guests/"], provider, syncedAt: new Date(Date.now() + 5).toISOString(),
      });
      expect(await repository.listGroupRoles(installationId)).not.toContainEqual(expect.objectContaining({groupId: "group-Acme"}));
      expect(database.prepare("SELECT status FROM installation_members WHERE id = ?")
        .get("member_prefix_guest")).toEqual({status: "inactive"});
    } finally {
      repository.close();
      database.close();
    }
  });

  test("GUEST-006-G: the first guest-rule pass preserves member status when recompute is disabled", async () => {
    const databasePath = nodePath.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Guests'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'viewer', 'active', ?, ?)`).run(
        "member_preseed_pass", installationId, "preseed@example.test", "Preseed Member", now, now,
      );
      await repository.applyDirectoryGroups(installationId, {
        groups: [...snapshotGroupsForGuestSync(false), {
          id: "group-NoRole", name: "no-role", path: "/NoRole", members: [
            {email: "preseed@example.test", subject: "preseed-subject"},
          ],
        }, {
          id: "group-Acme", name: "acme", path: "/Guests/acme", members: [
            {email: "tenant@example.test", subject: "tenant-subject"},
          ],
        }],
        guestGroupPrefixes: ["/Guests/"],
        provider: "guest-rule-first-pass-test",
        recomputeRoles: false,
        syncedAt: now,
      });
      expect(await repository.listGroupRoles(installationId)).toContainEqual(expect.objectContaining({
        groupId: "group-Acme", role: "guest", source: "rule",
      }));
      expect(database.prepare("SELECT role, status FROM installation_members WHERE id = ?")
        .get("member_preseed_pass")).toEqual({role: "viewer", status: "active"});
    } finally {
      repository.close();
      database.close();
    }
  });

  test("GUEST-006-F: sign-in denies a member whose group role is missing from the stored mirror", async () => {
    await server.stop();
    const identity: ExternalIdentity = {
      displayName: "Stale role member",
      email: "stale-role-signin@example.test",
      emailVerified: true,
      groups: ["/Viewers"],
      provider: "guest-role-signin-test",
      subject: "stale-role-signin-subject",
    };
    const provider: InteractiveIdentityProvider = {
      name: identity.provider,
      start: () => Effect.succeed({
        authorizationUrl: "https://identity.example/authorize",
        codeVerifier: "test-code-verifier-with-sufficient-entropy",
        nonce: null,
        state: "guest-role-signin-state-with-sufficient-entropy",
      }),
      complete: (code) => code === "guest-role-signin-code"
        ? Effect.succeed(identity)
        : Effect.fail(new IdentityProviderFailure({message: "Invalid code."})),
    };
    server = await startTestServer(installation, {
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      externalApiBearerVerifier: conformanceBearerVerifier,
      externalMcpBearerVerifier: conformanceBearerVerifier,
      groupRolePolicy: {seed: [
        {role: membershipRoles.guest, selector: "/Guests"},
        {role: membershipRoles.viewer, selector: "/Viewers"},
        {role: membershipRoles.owner, selector: "/Owners"},
      ]},
      interactiveIdentityProvider: provider,
    });

    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Viewers'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'administrator', 'active', ?, ?)`).run(
        "member_stale_role_signin", installationId, identity.email, identity.displayName, now, now,
      );
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'administrator', 'active', ?, ?)`).run(
        "member_stale_role_keeper", installationId, "stale-role-keeper@example.test", "Role keeper", now, now,
      );
    } finally {
      database.close();
    }

    const login = await fetch(`${server.baseUrl}/auth/login`, {redirect: "manual"});
    expect(login.status).toBe(302);
    const callback = new URL("/auth/callback", server.baseUrl);
    callback.searchParams.set("code", "guest-role-signin-code");
    callback.searchParams.set("state", "guest-role-signin-state-with-sufficient-entropy");
    const response = await fetch(callback, {
      headers: {Cookie: loginHandshakeCookie(login)},
      redirect: "manual",
    });
    expect(response.status).toBe(403);

    const verifyDatabase = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      expect(verifyDatabase.prepare("SELECT role, status FROM installation_members WHERE id = ?")
        .get("member_stale_role_signin")).toEqual({role: "administrator", status: "active"});
      expect(verifyDatabase.prepare("SELECT COUNT(*) AS count FROM application_sessions WHERE member_id = ?")
        .get("member_stale_role_signin")).toEqual({count: 0});
    } finally {
      verifyDatabase.close();
    }
  });

  test("GUEST-006-E: a sole owner can sign in when the stored mirror misses their owner group", async () => {
    await server.stop();
    const identity: ExternalIdentity = {
      displayName: "Sole owner",
      email: "sole-owner-stale-mirror@example.test",
      emailVerified: true,
      groups: ["/Owners"],
      provider: "guest-role-last-owner-test",
      subject: "guest-role-last-owner-subject",
    };
    const provider: InteractiveIdentityProvider = {
      name: identity.provider,
      start: () => Effect.succeed({
        authorizationUrl: "https://identity.example/authorize",
        codeVerifier: "test-code-verifier-with-sufficient-entropy",
        nonce: null,
        state: "guest-role-last-owner-state-with-sufficient-entropy",
      }),
      complete: (code) => code === "guest-role-last-owner-code"
        ? Effect.succeed(identity)
        : Effect.fail(new IdentityProviderFailure({message: "Invalid code."})),
    };
    server = await startTestServer(installation, {
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      groupRolePolicy: {seed: [
        {role: membershipRoles.guest, selector: "/Guests"},
        {role: membershipRoles.viewer, selector: "/Viewers"},
        {role: membershipRoles.owner, selector: "/Owners"},
      ]},
      interactiveIdentityProvider: provider,
    });

    const originalUpdatedAt = "2026-11-10T10:00:00.000Z";
    const databasePath = nodePath.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Owners'").get()).installationId;
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'owner', 'active', ?, ?)`).run(
        "member_sole_stale_owner", installationId, identity.email, identity.displayName,
        originalUpdatedAt, originalUpdatedAt,
      );
      expect(database.prepare("SELECT COUNT(*) AS count FROM directory_group_members WHERE email = ?")
        .get(identity.email)).toEqual({count: 0});
    } finally {
      database.close();
    }

    const login = await fetch(`${server.baseUrl}/auth/login`, {redirect: "manual"});
    expect(login.status).toBe(302);
    const callback = new URL("/auth/callback", server.baseUrl);
    callback.searchParams.set("code", "guest-role-last-owner-code");
    callback.searchParams.set("state", "guest-role-last-owner-state-with-sufficient-entropy");
    const response = await fetch(callback, {
      headers: {Cookie: loginHandshakeCookie(login)},
      redirect: "manual",
    });
    expect(response.status).toBe(303);
    const sessionCookie = response.headers.getSetCookie()
      .filter((cookie) => cookie.startsWith("artifact_session="))
      .map((cookie) => cookie.split(";", 1)[0]).join("; ");
    const session = z.object({principal: z.object({
      id: z.literal("member_sole_stale_owner"),
      membershipRole: z.literal("owner"),
    })}).parse(await (await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Cookie: sessionCookie},
    })).json());
    expect(session.principal.membershipRole).toBe("owner");

    const verifyDatabase = new DatabaseSync(databasePath);
    try {
      expect(verifyDatabase.prepare("SELECT role, status, updated_at AS updatedAt FROM installation_members WHERE id = ?")
        .get("member_sole_stale_owner")).toEqual({
        role: "owner", status: "active", updatedAt: originalUpdatedAt,
      });
    } finally {
      verifyDatabase.close();
    }
  });

  test("GUEST-006-C: an empty directory snapshot leaves members active", async () => {
    const databasePath = nodePath.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Guests'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'guest', 'active', ?, ?)`).run(
        "member_empty_snapshot", installationId, "empty-snapshot@example.test", "Empty Snapshot", now, now,
      );
      await expect(repository.applyDirectoryGroups(installationId, {
        groups: [], provider: "guest-role-empty-snapshot", syncedAt: now,
      })).rejects.toThrow(/empty|memberless/u);
      expect(database.prepare("SELECT status FROM installation_members WHERE id = ?")
        .get("member_empty_snapshot")).toEqual({status: "active"});
    } finally {
      repository.close();
      database.close();
    }
  });

  test("GUEST-006-D: removing a member's last role deactivates it and revokes sessions and keys", async () => {
    const databasePath = nodePath.join(installation.dataDirectory, "artifact-server.db");
    const database = new DatabaseSync(databasePath);
    const repository = new SqliteIdentityRepository(databasePath);
    try {
      const installationId = z.object({installationId: z.string()})
        .parse(database.prepare("SELECT installation_id AS installationId FROM directory_groups WHERE id = 'group-Guests'").get()).installationId;
      const now = new Date().toISOString();
      database.prepare(`INSERT INTO installation_members (
        id, installation_id, email, display_name, role, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'guest', 'active', ?, ?)`).run(
        "member_removed_role", installationId, "removed-role@example.test", "Removed Role", now, now,
      );
      database.prepare(`INSERT INTO directory_group_members (
        installation_id, group_id, subject, email, provider
      ) VALUES (?, ?, ?, ?, ?)`).run(
        installationId, "group-Guests", "removed-role-subject", "removed-role@example.test", "guest-role-remove-test",
      );
      database.prepare(`INSERT INTO application_sessions (
        installation_id, id, member_id, token_digest, csrf_digest, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
        installationId, "session_removed_role", "member_removed_role", "token-digest", "csrf-digest", now, "2099-01-01T00:00:00.000Z",
      );
      database.prepare(`INSERT INTO managed_api_keys (
        installation_id, id, name, prefix, secret_digest, principal_id, principal_kind,
        capabilities_json, authorized_by_principal_id, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'human', '[]', ?, ?, ?)`).run(
        installationId, "key_removed_role", "test key", "test-prefix", "key-digest", "member_removed_role", "owner", now, "2099-01-01T00:00:00.000Z",
      );
      await repository.setGroupRole(installationId, "group-Guests", null, now, "owner");
      expect(database.prepare("SELECT status FROM installation_members WHERE id = ?")
        .get("member_removed_role")).toEqual({status: "inactive"});
      expect(database.prepare("SELECT revoked_at FROM application_sessions WHERE id = ?")
        .get("session_removed_role")).toEqual({revoked_at: now});
      expect(database.prepare("SELECT revoked_at FROM managed_api_keys WHERE id = ?")
        .get("key_removed_role")).toEqual({revoked_at: now});
    } finally {
      repository.close();
      database.close();
    }
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

  async function serviceFetch(path: string, init: RequestInit = {}): Promise<Response> {
    return authenticatedFetch(path, "service-conformance", init);
  }

  async function authenticatedFetch(path: string, token: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    return fetch(`${server.baseUrl}${path}`, {...init, headers});
  }

  async function guestMcpTool(
    name: "group_list" | "project_sharing",
    args: Readonly<Record<string, string | number | boolean | null | undefined>>,
  ): Promise<z.infer<typeof guestMcpResultSchema>> {
    const result = z.object({result: z.object({structuredContent: z.unknown()}).loose()})
      .parse(await (await guestMcpCall(name, args)).json());
    return guestMcpResultSchema.parse(result.result.structuredContent);
  }

  async function guestMcpCall(
    name: string,
    args: Readonly<Record<string, string | number | boolean | null | undefined>>,
  ): Promise<Response> {
    return fetch(`${server.baseUrl}/mcp`, {
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
    }).then((response) => {
      expect(response.status).toBe(200);
      return response;
    });
  }
});

const conformanceBearerVerifier: BearerCredentialVerifier = {
  verify: (credential) => {
    const value = Redacted.value(credential);
    if (value === "guest-conformance") {
      return Effect.succeed({...humanPrincipal("member_guest_conformance", membershipRoles.guest), installationId: "local"});
    }
    if (value === "owner-conformance") {
      return Effect.succeed({...humanPrincipal("member_owner_conformance", membershipRoles.owner), displayName: "owner@example.test", installationId: "local"});
    }
    if (value === "service-conformance") {
      return Effect.succeed({
        authorizedByPrincipalId: null,
        capabilities: [principalCapabilities.readArtifacts, principalCapabilities.readArtifactResponses],
        directoryGroupIds: ["group-Guests"],
        displayName: "Conformance service",
        id: "service:guest-role-conformance",
        installationId: "local",
        kind: "service",
        membershipRole: membershipRoles.member,
        serviceAccountSource: "oidc",
      });
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

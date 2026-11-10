import {Effect, Layer, ManagedRuntime, Redacted, Result} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
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
import {createTestInstallation, removeTestInstallation, startTestServer, storeTestGroupRoles, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

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
    server = await startTestServer(installation, {externalApiBearerVerifier: conformanceBearerVerifier});
    await storeTestGroupRoles(server, installation, [
      {name: "Guests", role: membershipRoles.guest},
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
    ], ["/Guests", "/Viewers"])).toBe("viewer");
    expect(groupMembershipRole([assignment("group-guests", "guest")], ["/Guests"]))
      .toBe("guest");
  });

  test("GUEST-003-B: guests receive empty directory and sharing lists and cannot list members or create projects", async () => {
    expect.hasAssertions();
    const groups = await guestFetch("/api/v1/groups");
    expect(groups.status).toBe(200);
    expect(await groups.json()).toEqual({groups: []});
    const sharing = await guestFetch("/api/v1/projects/unshared/sharing");
    expect(sharing.status).toBe(200);
    expect(await sharing.json()).toEqual({sharing: {
      accessMode: "restricted", groups: [], projectId: "unshared", yourRole: null,
    }});
    expect((await guestFetch("/api/v1/members")).status).toBe(403);
    expect((await guestFetch("/api/v1/projects", {body: JSON.stringify({name: "Guest project"}), method: "POST"})).status).toBe(403);
    expect((await guestFetch("/api/v1/administration/public-links")).status).toBe(403);
    const artifact = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "private artifact for guest boundary",
      idempotencyKey: "guest-boundary-artifact",
      name: "Private artifact",
    });
    expect((await guestFetch(`/api/v1/artifacts/${artifact.body.artifact.id}`)).status).toBe(404);
    expect([403, 404]).toContain((await guestFetch(`/api/v1/artifacts/${artifact.body.artifact.id}/content-sessions`, {
      body: "{}", method: "POST",
    })).status);
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
    path: groupId === "group-guests" ? "/Guests" : "/Viewers",
    role,
  };
}

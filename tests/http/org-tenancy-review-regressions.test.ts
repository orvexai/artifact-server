import {createServer} from "node:http";

import {Effect, Redacted} from "effect";
import {describe, expect, test} from "vitest";

import {api} from "../../apps/web/src/api/client.js";
import {readOrganizationDirectorySnapshot} from "../../src/application/directory-sync.js";
import {membershipRoles, principalKinds, type Principal} from "../../src/core/identity.js";
import type {InstallationMember} from "../../src/core/installation-identity.js";
import type {RegisteredAgentRecord} from "../../src/core/model.js";
import {
  organizationRuntimeAdmissionPolicy,
  organizationStaffSelectors,
} from "../../src/external-storage/create-external-storage-runtime.js";
import {prefixOrganizationRedirect} from "../../src/external-storage/create-organization-router.js";
import {
  createKeycloakOrganizationMembershipResolver,
  createOrvexAdmissionRole,
} from "../../src/external-storage/organization-memberships.js";
import type {OrganizationRecord} from "../../src/external-storage/organization-registry.js";
import {
  maskedTenantStaffMember,
  platformRootRedirectHeader,
  registeredAgentResponse,
  tenantMemberMutationResponse,
} from "../../src/http/create-http-app.js";
import {
  KeycloakDirectory,
  type DirectoryOrganization,
  type DirectoryOrganizationMember,
  type OrganizationDirectory,
} from "../../src/identity/keycloak-directory.js";

const origin = "https://artifacts.example.test";

const platformRedirect = () => new Response(null, {
  headers: {Location: "/", [platformRootRedirectHeader]: "1"},
  status: 303,
});

const record = (slug: string, keycloakId: string | null): OrganizationRecord => ({
  admissionPolicy: null, displayName: slug.toUpperCase(), embedOrigins: [], id: `${slug}-id`, keycloakId,
  registryVersion: "1", routeId: "route123", slug, status: "active",
});
const withServer = async (routes: ReadonlyMap<string, object>, run: () => Promise<void>) => {
  const server = createServer((request, response) => {
    const body = routes.get(`${request.method} ${request.url}`);
    if (body === undefined) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {"Content-Type": "application/json"}).end(JSON.stringify(body));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!(address instanceof Object) || !("port" in address)) throw new Error("The test server did not bind.");
  const originalFetch = globalThis.fetch;
  const originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", {configurable: true, value: {cookie: "artifact_csrf=test-csrf", querySelector: () => null}});
  globalThis.fetch = ((input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    return originalFetch(new URL(url, `http://127.0.0.1:${address.port}`), init);
  });
  try {
    await run();
  } finally {
    globalThis.fetch = originalFetch;
    if (originalDocument === undefined) Reflect.deleteProperty(globalThis, "document");
    else Object.defineProperty(globalThis, "document", originalDocument);
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error === undefined ? resolve() : reject(error));
    });
  }
};


describe("H1: org sync marks staff from the admission policy", () => {
  const organization: DirectoryOrganization = {alias: "acme", id: "11111111-1111-4111-8111-111111111111", name: "Acme"};
  const users: DirectoryOrganizationMember[] = [
    {email: "owner@acme.test", emailVerified: true, enabled: true, firstName: "Ann", id: "kc-owner", lastName: "Owner", role: "owner", username: "owner"},
    {email: "staff@orvex.test", emailVerified: true, enabled: true, firstName: "Private", id: "kc-staff", lastName: "Staffer", role: "editor", username: "staff"},
  ];
  const runSync = (directory: OrganizationDirectory, selectors: readonly string[]) =>
    Effect.runPromise(Effect.result(readOrganizationDirectorySnapshot(directory, organization, selectors)));

  test("the staff selector's group members reach the snapshot as staff", async () => {
    const lookups: string[] = [];
    const directory: OrganizationDirectory = {
      listGroupMemberIdsByPath: (path) => {
        lookups.push(path);
        return Effect.succeed(path === "/teams/acme/support" ? ["kc-staff"] : []);
      },
      listOrganizationMembers: () => Effect.succeed(users),
      listOrganizations: () => Effect.succeed([organization]),
    };
    const result = await runSync(directory, ["/teams/acme/support"]);
    expect(lookups).toEqual(["/teams/acme/support"]);
    expect(result).toMatchObject({_tag: "Success"});
    if (result._tag !== "Success" || result.success.kind === "emptied") throw new Error("The snapshot was not read.");
    expect(result.success.desired).toEqual(expect.arrayContaining([
      {displayName: "Ann Owner", email: "owner@acme.test", role: "owner"},
      {displayName: "Private Staffer", email: "staff@orvex.test", role: "member", staff: true},
    ]));
  });

  test("staff selectors with no way to read group members fail closed", async () => {
    const directory: OrganizationDirectory = {
      listOrganizationMembers: () => Effect.succeed(users),
      listOrganizations: () => Effect.succeed([organization]),
    };
    const result = await runSync(directory, ["/teams/acme/support"]);
    expect(result).toMatchObject({_tag: "Failure", failure: {message: expect.stringContaining("cannot read group members")}});
  });

  test("the sync runtime receives the registered admission policy's staff selectors", () => {
    const policy = organizationRuntimeAdmissionPolicy({
      groupRoots: ["/teams/acme/"],
      seed: [
        {role: "owner", selector: "/teams/acme/owners"},
        {role: "administrator", selector: "/teams/acme/support", staff: true},
      ],
    });
    expect(organizationStaffSelectors(policy)).toEqual(["/teams/acme/support"]);
    expect(organizationStaffSelectors(organizationRuntimeAdmissionPolicy(null))).toEqual([]);
  });

  test("the Keycloak directory resolves a staff selector by exact group path", async () => {
    const requested: string[] = [];
    const directory = new KeycloakDirectory({
      adminBaseUrl: "https://keycloak.example.test/admin/realms/test",
      clientId: "artifact-server",
      clientSecret: Redacted.make("secret"),
      fetch: async (input) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        requested.push(url.pathname);
        if (url.pathname.endsWith("/token")) return Response.json({access_token: "token"});
        if (url.pathname.endsWith("/group-by-path/teams/acme/support")) {
          return Response.json({id: "group-support", path: "/teams/acme/support"});
        }
        if (url.pathname.endsWith("/groups/group-support/members")) {
          return Response.json([{id: "kc-staff", username: "staff"}]);
        }
        return new Response(null, {status: 404});
      },
      issuer: "https://keycloak.example.test/realms/test",
      retryBaseDelayMilliseconds: 0,
      tokenEndpoint: "https://keycloak.example.test/realms/test/protocol/openid-connect/token",
    });
    expect(await Effect.runPromise(directory.listGroupMemberIdsByPath("/teams/acme/support"))).toEqual(["kc-staff"]);
    expect(requested).toContain("/admin/realms/test/group-by-path/teams/acme/support");
    await expect(Effect.runPromise(directory.listGroupMemberIdsByPath("/teams/acme/missing"))).rejects.toThrow("HTTP 404");
  });
});

describe("M1: platform login lands on the root chooser", () => {
  test("the root callback keeps the platform redirect at / and strips the marker", () => {
    const response = prefixOrganizationRedirect(platformRedirect(), "orvex", origin, true);
    expect(response.headers.get("location")).toBe("/");
    expect(response.headers.has(platformRootRedirectHeader)).toBe(false);
  });

  test("an ordinary Orvex login through the root callback is still prefixed", () => {
    const response = prefixOrganizationRedirect(
      new Response(null, {headers: {Location: "/"}, status: 303}), "orvex", origin, true,
    );
    expect(response.headers.get("location")).toBe("/o/orvex/");
  });

  test("the marker is ignored and stripped on an organization-prefixed path", () => {
    const response = prefixOrganizationRedirect(platformRedirect(), "acme", origin, false);
    expect(response.headers.get("location")).toBe("/o/acme/");
    expect(response.headers.has(platformRootRedirectHeader)).toBe(false);
  });
});

describe("M2: the chooser lists every org the user is admitted to", () => {
  const organizations = new Map([
    ["orvex", record("orvex", null)],
    ["acme", record("acme", "11111111-1111-4111-8111-111111111111")],
    ["globex", record("globex", "22222222-2222-4222-8222-222222222222")],
  ]);
  const identity = {
    displayName: "Person", email: "person@example.test", emailVerified: true,
    groups: ["/orvex/staff"], provider: "oidc", subject: "subject",
    organizations: {
      acme: {groups: ["/editor"], id: "11111111-1111-4111-8111-111111111111"},
      globex: {groups: [], id: "22222222-2222-4222-8222-222222222222"},
    },
  };
  const orvexAdmission = createOrvexAdmissionRole({
    bootstrapAdministratorEmail: null,
    findActiveMemberByEmail: async () => null,
    findActiveMemberByExternalIdentity: async () => null,
    groupRolePolicy: {seed: [{role: "member", selector: "/orvex/staff"}]},
    hasMembers: async () => true,
    isGroupRoleSeedApplied: async () => false,
    listGroupRoles: async () => [],
  });

  test("Orvex and sync-discovered orgs with no admission policy are listed", async () => {
    const resolver = createKeycloakOrganizationMembershipResolver(
      async (slug) => organizations.get(slug) ?? null, undefined, orvexAdmission,
    );
    expect(await resolver.forIdentity(identity)).toEqual([
      {displayName: "ORVEX", role: "member", slug: "orvex"},
      {displayName: "ACME", role: "member", slug: "acme"},
      {displayName: "GLOBEX", role: "viewer", slug: "globex"},
    ]);
  });

  test("a mismatched Keycloak id, non-role groups or no Orvex group are not listed", async () => {
    const resolver = createKeycloakOrganizationMembershipResolver(
      async (slug) => organizations.get(slug) ?? null, undefined, orvexAdmission,
    );
    expect(await resolver.forIdentity({
      ...identity,
      groups: ["/elsewhere"],
      organizations: {
        acme: {groups: ["/editor"], id: "33333333-3333-4333-8333-333333333333"},
        globex: {groups: ["/teams/globex/reviewers"], id: "22222222-2222-4222-8222-222222222222"},
        orvex: {groups: ["/owner"], id: "44444444-4444-4444-8444-444444444444"},
      },
    })).toEqual([]);
  });
});

describe("M4: tenant Members and Agents pages accept masked staff rows", () => {
  const staffMember: InstallationMember = {
    createdAt: "2026-11-13T00:00:00.000Z", displayName: "Private Staffer", email: "staff@orvex.test",
    id: "staff-real-id", installationId: "tenant", role: "administrator", staff: true, status: "inactive",
    updatedAt: "2026-11-13T00:00:00.000Z",
  };
  const ordinaryMember: InstallationMember = {
    createdAt: "2026-11-13T00:00:00.000Z", displayName: "Ann Owner", email: "owner@acme.test",
    id: "owner-id", installationId: "tenant", role: "owner", status: "active",
    updatedAt: "2026-11-13T00:00:00.000Z",
  };
  const staffAgent: RegisteredAgentRecord = {
    activityAt: null, activityState: null, agentSessionId: "session", capabilities: {beacon: false, evidence: "mailbox"},
    connectionKey: "staff-connection", createdAt: "2026-11-13T00:00:00.000Z", displayName: "Staff agent",
    id: "agent-id", installationId: "tenant", kind: "pi", lastSeenAt: "2026-11-13T00:00:00.000Z",
    principalId: "staff-real-id", workingDirectory: "/home/staff/secret",
  };
  const viewer: Principal = {
    authorizedByPrincipalId: null, capabilities: [], displayName: "Owner", email: "owner@acme.test", id: "owner-id",
    installationId: "tenant", kind: principalKinds.human, membershipRole: membershipRoles.owner,
    tenantStaffPrincipalIds: ["staff-real-id"],
  };

  test("member list and member mutations parse without leaking staff data", async () => {
    const maskedRow = maskedTenantStaffMember({id: "staff_opaque", status: "active"});
    const mutation = tenantMemberMutationResponse({...staffMember, displayName: "Orvex Support", email: "", id: "staff_opaque"});
    for (const value of [maskedRow, mutation]) {
      const serialized = JSON.stringify(value);
      expect(serialized).not.toContain("Private Staffer");
      expect(serialized).not.toContain("staff@orvex.test");
      expect(serialized).not.toContain("staff-real-id");
    }
    await withServer(new Map<string, object>([
      ["GET /api/v1/members", {members: [ordinaryMember, maskedRow]}],
      ["POST /api/v1/members/staff_opaque/deactivate", {member: mutation}],
      ["POST /api/v1/members/owner-id/deactivate", {member: tenantMemberMutationResponse(ordinaryMember)}],
    ]), async () => {
      const members = await api.members();
      expect(members.at(1)).toEqual({displayName: "Orvex Support", id: "staff_opaque", staff: true, status: "active"});
      await expect(api.deactivateMember("staff_opaque")).resolves.toEqual({
        displayName: "Orvex Support", id: "staff_opaque", staff: true, status: "inactive",
      });
      await expect(api.deactivateMember("owner-id")).resolves.toEqual({displayName: "Ann Owner", id: "owner-id", status: "active"});
    });
  });

  test("a masked staff agent parses in both agent schemas", async () => {
    const agent = registeredAgentResponse(staffAgent, viewer);
    expect(agent.workingDirectory).toBeNull();
    expect(agent.connectionKey).toBeNull();
    expect(JSON.stringify(agent)).not.toContain("/home/staff/secret");
    await withServer(new Map<string, object>([["GET /api/v1/agents", {items: [{...agent, connected: false}]}]]), async () => {
      expect((await api.agents()).at(0)?.workingDirectory).toBeNull();
      expect((await api.agentPresence()).at(0)?.displayName).toBe("Orvex Support");
    });
  });
});

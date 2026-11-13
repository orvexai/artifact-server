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
  tenantStaffGroupPaths,
} from "../../src/external-storage/create-external-storage-runtime.js";
import {
  expandOrganizationStaffGroups,
  parseOrganizationStaffEmailDomains,
  parseOrganizationStaffGroups,
  requireOrganizationStaffGroups,
} from "../../src/external-storage/organization-staff-groups.js";
import {
  emailHasStaffDomain,
  staffPathCovers,
  tenantLoginIsStaff,
  type TenantLoginStaffInput,
} from "../../src/core/tenant-staff.js";
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

  test("the Keycloak directory resolves a staff path and every nested subgroup's members (M-A)", async () => {
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
        if (url.pathname.endsWith("/groups/group-support/children")) {
          return Response.json([{id: "group-oncall", name: "oncall", subGroupCount: 1}]);
        }
        if (url.pathname.endsWith("/groups/group-oncall/children")) {
          return Response.json([{id: "group-nights", name: "nights", subGroupCount: 0}]);
        }
        if (url.pathname.endsWith("/groups/group-oncall/members")) return Response.json([]);
        if (url.pathname.endsWith("/groups/group-nights/members")) {
          return Response.json([{id: "kc-nested", username: "nested"}, {id: "kc-staff", username: "staff"}]);
        }
        return new Response(null, {status: 404});
      },
      issuer: "https://keycloak.example.test/realms/test",
      retryBaseDelayMilliseconds: 0,
      tokenEndpoint: "https://keycloak.example.test/realms/test/protocol/openid-connect/token",
    });
    expect(await Effect.runPromise(directory.listGroupMemberIdsByPath("/teams/acme/support"))).toEqual(["kc-staff", "kc-nested"]);
    expect(requested).toContain("/admin/realms/test/group-by-path/teams/acme/support");
    await expect(Effect.runPromise(directory.listGroupMemberIdsByPath("/teams/acme/missing"))).rejects.toThrow("HTTP 404");
  });
});

describe("H1: platform-wide staff groups (ARTIFACT_SERVER_ORG_STAFF_GROUPS)", () => {
  const organization: DirectoryOrganization = {alias: "synced", id: "55555555-5555-4555-8555-555555555555", name: "Synced"};

  test("a sync-created org with no policy masks a member of /Developers", async () => {
    const staffGroups = tenantStaffGroupPaths(parseOrganizationStaffGroups("/Administrators, /Developers"), organizationRuntimeAdmissionPolicy(null), "synced");
    expect(staffGroups).toEqual(["/Administrators", "/Developers"]);
    const directory: OrganizationDirectory = {
      listGroupMemberIdsByPath: (path) => Effect.succeed(path === "/Developers" ? ["kc-dev"] : []),
      listOrganizationMembers: () => Effect.succeed([
        {email: "dev@orvex.test", emailVerified: true, enabled: true, firstName: "Private", id: "kc-dev", lastName: "Developer", role: "viewer", username: "dev"},
        {email: "client@synced.test", emailVerified: true, enabled: true, firstName: "Cara", id: "kc-client", lastName: "Client", role: "owner", username: "client"},
      ]),
      listOrganizations: () => Effect.succeed([organization]),
    };
    const result = await Effect.runPromise(Effect.result(readOrganizationDirectorySnapshot(directory, organization, staffGroups)));
    if (result._tag !== "Success" || result.success.kind === "emptied") throw new Error("The snapshot was not read.");
    expect(result.success.desired).toEqual(expect.arrayContaining([
      {displayName: "Private Developer", email: "dev@orvex.test", role: "viewer", staff: true},
      {displayName: "Cara Client", email: "client@synced.test", role: "owner"},
    ]));
  });

  test("platform groups are united with an org's own staff selectors", () => {
    expect(tenantStaffGroupPaths(["/Developers"], organizationRuntimeAdmissionPolicy({
      groupRoots: ["/teams/acme/"],
      seed: [{role: "administrator", selector: "/teams/acme/support", staff: true}],
    }), "acme")).toEqual(["/Developers", "/teams/acme/support"]);
  });

  test("{slug} expands to each org's slug at login and sync, and must stay an exact path", async () => {
    const platform = parseOrganizationStaffGroups("/TenantWorkspaces/{slug}/{slug}-staff");
    const staffGroups = tenantStaffGroupPaths(platform, organizationRuntimeAdmissionPolicy(null), "acme");
    expect(staffGroups).toEqual(["/TenantWorkspaces/acme/acme-staff"]);
    expect(tenantStaffGroupPaths(platform, null, "globex")).toEqual(["/TenantWorkspaces/globex/globex-staff"]);
    const lookups: string[] = [];
    const directory: OrganizationDirectory = {
      listGroupMemberIdsByPath: (path) => {
        lookups.push(path);
        return Effect.succeed(["kc-staff"]);
      },
      listOrganizationMembers: () => Effect.succeed([
        {email: "staff@orvex.test", emailVerified: true, enabled: true, firstName: null, id: "kc-staff", lastName: null, role: "viewer", username: "staff"},
      ]),
      listOrganizations: () => Effect.succeed([organization]),
    };
    const result = await Effect.runPromise(Effect.result(readOrganizationDirectorySnapshot(directory, organization, staffGroups)));
    expect(lookups).toEqual(["/TenantWorkspaces/acme/acme-staff"]);
    if (result._tag !== "Success" || result.success.kind === "emptied") throw new Error("The snapshot was not read.");
    expect(result.success.desired.at(0)?.staff).toBe(true);
    expect(() => parseOrganizationStaffGroups("/Tenant/{org}")).toThrow("exact group paths");
    expect(() => parseOrganizationStaffGroups("/Tenant/{slug")).toThrow("exact group paths");
    expect(() => expandOrganizationStaffGroups(["/Tenant/{slug}"], "bad slug")).toThrow("not an exact group path");
  });
});

describe("H1: staff email domains (ARTIFACT_SERVER_ORG_STAFF_EMAIL_DOMAINS)", () => {
  const organization: DirectoryOrganization = {alias: "acme", id: "66666666-6666-4666-8666-666666666666", name: "Acme"};

  test("only a verified email on an exact staff domain marks staff", () => {
    const domains = parseOrganizationStaffEmailDomains(" Orvex.AI ");
    expect(domains).toEqual(["orvex.ai"]);
    expect(emailHasStaffDomain("Person@ORVEX.ai", true, domains)).toBe(true);
    expect(emailHasStaffDomain("person@orvex.ai", false, domains)).toBe(false);
    expect(emailHasStaffDomain("person@eu.orvex.ai", true, domains)).toBe(false);
    expect(emailHasStaffDomain("person@notorvex.ai", true, domains)).toBe(false);
    expect(emailHasStaffDomain("orvex.ai@example.test", true, domains)).toBe(false);
    expect(() => parseOrganizationStaffEmailDomains("@orvex.ai")).toThrow("bare domains");
  });

  test("org sync marks Keycloak-verified staff-domain members and nobody else", async () => {
    const directory: OrganizationDirectory = {
      listOrganizationMembers: () => Effect.succeed([
        {email: "staff@orvex.ai", emailVerified: true, enabled: true, firstName: null, id: "kc-staff", lastName: null, role: "viewer", username: "staff"},
        {email: "sub@eu.orvex.ai", emailVerified: true, enabled: true, firstName: null, id: "kc-sub", lastName: null, role: "viewer", username: "sub"},
        {email: "client@acme.test", emailVerified: true, enabled: true, firstName: null, id: "kc-client", lastName: null, role: "owner", username: "client"},
      ]),
      listOrganizations: () => Effect.succeed([organization]),
    };
    const result = await Effect.runPromise(Effect.result(
      readOrganizationDirectorySnapshot(directory, organization, [], ["orvex.ai"]),
    ));
    if (result._tag !== "Success" || result.success.kind === "emptied") throw new Error("The snapshot was not read.");
    expect(result.success.desired.filter(({staff}) => staff === true).map(({email}) => email)).toEqual(["staff@orvex.ai"]);
  });
});

describe("tenant login staff decision", () => {
  const base: TenantLoginStaffInput = {
    email: "person@example.test", emailVerified: true, groups: [],
    seed: [], staffEmailDomains: ["orvex.ai"], staffGroups: ["/TenantWorkspaces/acme/acme-staff", "/Developers"],
  };

  test("a verified staff-domain email marks staff; an unverified one never does", () => {
    expect(tenantLoginIsStaff({...base, email: "dev@Orvex.AI"})).toBe(true);
    expect(tenantLoginIsStaff({...base, email: "dev@orvex.ai", emailVerified: false})).toBe(false);
    expect(tenantLoginIsStaff({...base, email: "dev@eu.orvex.ai"})).toBe(false);
  });

  test("a staff group covers its subgroups, including {slug}-expanded paths (M-A)", () => {
    expect(tenantLoginIsStaff({...base, groups: ["/Developers"]})).toBe(true);
    expect(tenantLoginIsStaff({...base, groups: ["/Developers/backend/oncall"]})).toBe(true);
    expect(tenantLoginIsStaff({...base, groups: ["/TenantWorkspaces/acme/acme-staff/support"]})).toBe(true);
    expect(tenantLoginIsStaff({...base, groups: ["/DevelopersGuild"]})).toBe(false);
    expect(tenantLoginIsStaff({...base, groups: ["/TenantWorkspaces/acme/acme-staffing"]})).toBe(false);
    expect(tenantLoginIsStaff({...base, groups: ["Developers"]})).toBe(false);
    expect(tenantLoginIsStaff({
      ...base, groups: ["/teams/acme/support/tier2"], staffGroups: [],
      seed: [{role: "administrator", selector: "/teams/acme/support", staff: true}],
    })).toBe(true);
    expect(staffPathCovers("/Developers", "/Developers/x")).toBe(true);
  });

  test("tenancy without a staff definition fails closed, and entries must be exact paths", () => {
    expect(parseOrganizationStaffGroups(undefined)).toEqual([]);
    expect(() => requireOrganizationStaffGroups(parseOrganizationStaffGroups(" , "))).toThrow("ARTIFACT_SERVER_ORG_STAFF_GROUPS");
    expect(() => parseOrganizationStaffGroups("Developers")).toThrow("exact group paths");
    expect(() => parseOrganizationStaffGroups("/Developers/")).toThrow("exact group paths");
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

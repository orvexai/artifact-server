import {describe, expect, test} from "vitest";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";

import {isReservedTenantIdentityName, tenantIdentityPresentation, tenantVersionRecord, tenantVisiblePrincipalId, type Principal} from "../../src/core/identity.js";
import {agentDispatchResponse, projectHttpTenantResponse, projectTenantMembers} from "../../src/http/create-http-app.js";
import type {AgentDispatchRecord, ArtifactResponseRecord} from "../../src/core/model.js";
import {createKeycloakOrganizationMembershipResolver} from "../../src/external-storage/organization-memberships.js";
import {artifactResponseProjection} from "../../src/mcp/artifact-mcp-server.js";
import {gitHistoryMetadataFiles, gitHistoryVersionMetadata} from "../../src/git-history/git-history-mirror.js";
import {unicodeConfusablesVersion} from "../../src/core/confusables.js";
import {staffMemberOpaqueId} from "../../src/application/installation-access.js";

describe("tenant identity projection", () => {
  const principal: Principal = {
    authorizedByPrincipalId: null,
    capabilities: [],
    displayName: "Tenant viewer",
    email: "viewer@example.test",
    id: "viewer-id",
    installationId: "tenant-installation",
    kind: "human",
    membershipRole: "viewer",
    tenantStaffPrincipalIds: ["staff-id"],
  };

  test("staff identity is masked by principal id and leaves same-name non-staff untouched", () => {
    expect(tenantIdentityPresentation(principal, {
      displayName: "Private staff name", email: "staff@example.test", principalId: "staff-id",
    })).toEqual({displayName: "Orvex Support", email: null, isStaff: true, subject: null});
    expect(tenantIdentityPresentation(principal, {
      displayName: "Private staff name", email: "member@example.test", principalId: "member-id",
    })).toEqual({displayName: "Private staff name", email: "member@example.test", isStaff: false, subject: "member-id"});
    expect(tenantIdentityPresentation(principal, {
      displayName: "  ORVEX   SUPPORT ", email: "member@example.test", principalId: "member-id",
    })).toEqual({displayName: "Orvex Support (member)", email: "member@example.test", isStaff: false, subject: "member-id"});
  });

  test("reserved tenant identity folding catches invisible characters and common confusables", () => {
    for (const value of [
      "Orvex\u200d Support",
      "Orvex\u00ad Support",
      "0rvex Support",
      "օrvex սupport",
      "ᴏʀᴠᴇx ѕᴜᴘᴘᴏʀᴛ",
      "orѵex-support",
      "Orvex\u0307.Support",
      "or\u2c9fvexsupport",
      "orvex ꜱupport",
      "orvexꜱupport",
      "orʋexsupport",
      "orvexҽupport",
      "orvҽxsupport",
      "orvex suppo\u2ca3t",
      "orvex \ua731upport",
      "or\u04bdex support",
      "or\u028bex support",
      "оrvexsupport",
    ]) {
      expect(isReservedTenantIdentityName(value), `reserved identity: ${value}`).toBe(true);
      expect(tenantIdentityPresentation(principal, {displayName: value, principalId: "member-id"}).displayName)
        .toBe("Orvex Support (member)");
    }
    for (const value of ["Orvex 5upport", "Orv3x", "0rv3x 5upp0r7", "or\u2c9fvexsupport", "orvex suppo\u2ca3t"]) {
      expect(isReservedTenantIdentityName(value), `reserved identity: ${value}`).toBe(true);
    }
    for (const value of ["田中 Taro", "Иван Ivanov"]) {
      expect(isReservedTenantIdentityName(value), `ordinary name: ${value}`).toBe(false);
    }
  });

  test("reserved-name folding catches variants without reserving unrelated names", () => {
    for (const name of [
      "Orvéx Support Team", "Orʋex", "OrvexSupport Team", "Orvexsupport staff",
      "Orvex™ Support Desk", "Orvex℠ Support Desk", "Orvex\u00adSupport", "Orvex\u200bSupport",
      "Orvex 5upport", "Orv3x", "0rv3x 5upp0r7", "or\u2c9fvexsupport",
      "orvex suppo\u2ca3t", "Orv€x",
    ]) {
      expect(isReservedTenantIdentityName(name), `reserved identity: ${name}`).toBe(true);
    }
    for (const name of [
      "Orvexa Smith", "Lorvex Jones", "Torvex", "Sorvex Ltd", "Marvex", "Irvex",
      "Orvel", "Orvexian Club", "Oliver Vex", "Cortex", "Convex", "Vortex", "Forex",
      "OrvexHelp", "田中 Taro", "Иван Ivanov",
    ]) {
      expect(isReservedTenantIdentityName(name)).toBe(false);
    }
  });

  test("vendors the pinned Unicode 17 UTS #39 confusables table", () => {
    const bytes = readFileSync(new URL("../../src/core/unicode/confusables.txt", import.meta.url));
    expect(unicodeConfusablesVersion).toBe("17.0.0");
    expect(createHash("sha256").update(bytes).digest("hex"))
      .toBe("091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a");
    const generated = readFileSync(new URL("../../src/core/unicode/confusables-data.json", import.meta.url));
    expect(createHash("sha256").update(generated).digest("hex"))
      .toBe("c5172e647efd550afb93b49d9e4d7afdabef59794be136cc921010674fc41383");
  });

  test("staff handles use installation-scoped HKDF/HMAC keys, which rotate with the server token", () => {
    const handle = staffMemberOpaqueId("install-a", "server-key", "member-1");
    expect(handle).toMatch(/^staff_[A-Za-z0-9_-]{22}$/u);
    expect(staffMemberOpaqueId("install-a", "server-key", "member-1")).toBe(handle);
    expect(staffMemberOpaqueId("install-b", "server-key", "member-1")).not.toBe(handle);
    expect(staffMemberOpaqueId("install-a", "rotated-server-token", "member-1")).not.toBe(handle);
  });

  test("tenant attribution projection masks staff ids while preserving other principals", () => {
    expect(["principalId", "authorizedByPrincipalId", "publisherPrincipalId", "updatedByPrincipalId"]
      .map(() => tenantVisiblePrincipalId(principal, "staff-id"))).toEqual([null, null, null, null]);
    expect(tenantVisiblePrincipalId(principal, "member-id")).toBe("member-id");
    const version = {id: "v1", publisherPrincipalId: "staff-id"};
    expect(tenantVersionRecord(principal, version).publisherPrincipalId).toBeNull();
    expect(tenantVersionRecord(undefined, version).publisherPrincipalId).toBeNull();
    expect(tenantVersionRecord(principal, {...version, publisherPrincipalId: "member-id"}).publisherPrincipalId).toBe("member-id");
  });

  test("tenant Git history commits omit the publisher identity from metadata files", () => {
    const version = {
      artifactId: "art_test", createdAt: "2026-11-12T00:00:00.000Z", entryPath: "index.html",
      id: "ver_test", manifestDigest: "sha256:test", number: 1, projectId: "prj_test",
      publisherPrincipalId: "staff-id",
    };
    const metadata = gitHistoryVersionMetadata(version, "tenant-installation", false);
    expect(metadata).not.toHaveProperty("publisherPrincipalId");
    const metadataFile = gitHistoryMetadataFiles({
      coordinates: {
        artifactId: version.artifactId, defaultBranch: "main", projectId: version.projectId,
        provider: "cloudflare-artifacts", remoteUrl: "https://git.example.test/repo",
        repositoryName: "repo", status: "provisioned",
      },
      files: [], metadata, pointers: [],
    }).find(({path}) => path === ".artifactserver/version.json");
    if (metadataFile === undefined) throw new Error("The Git history version metadata file was not written.");
    expect(JSON.parse(new TextDecoder().decode(metadataFile.bytes))).not.toHaveProperty("publisherPrincipalId");
    expect(gitHistoryVersionMetadata(version, "orvex-installation", true).publisherPrincipalId).toBe("staff-id");
  });

  test("platform memberships require the claim organization id to match the registry", async () => {
    const organization = {
      admissionPolicy: {groupRoots: ["/teams/acme/"], seed: [{role: "viewer" as const, selector: "/teams/acme/reviewers"}]},
      displayName: "Acme", embedOrigins: [], id: "installation-id", keycloakId: "keycloak-org-id",
      registryVersion: "1", routeId: "route1234", slug: "acme", status: "active" as const,
    };
    const resolver = createKeycloakOrganizationMembershipResolver(async () => organization);
    const identity = {
      displayName: "member", email: null, emailVerified: false, groups: null, provider: "oidc", subject: "member-subject",
      organizations: {acme: {id: "wrong-id", groups: ["/teams/acme/reviewers"]}},
    };
    expect(await resolver.forIdentity(identity)).toEqual([]);
    // The chooser role follows tenant admission: Keycloak org /viewer, /editor, /owner groups.
    expect(await resolver.forIdentity({...identity, organizations: {acme: {id: "keycloak-org-id", groups: ["/teams/acme/reviewers"]}}}))
      .toEqual([]);
    expect(await resolver.forIdentity({...identity, organizations: {acme: {id: "keycloak-org-id", groups: ["/viewer"]}}}))
      .toEqual([{displayName: "Acme", role: "viewer", slug: "acme"}]);
  });

  test("tenant directory projection hides staff and applies role visibility", () => {
    const members = [{
      createdAt: "2026-11-12T00:00:00.000Z", displayName: "Tenant member", email: "member@example.test",
      id: "member-id", installationId: "tenant-installation", role: "viewer" as const, staff: false,
      status: "active" as const, updatedAt: "2026-11-12T00:00:00.000Z",
    }, {
      createdAt: "2026-11-12T00:00:00.000Z", displayName: "Support", email: "support@example.test",
      id: "staff-id", installationId: "tenant-installation", role: "member" as const, staff: true,
      status: "active" as const, updatedAt: "2026-11-12T00:00:00.000Z",
    }];
    const expectedDirectoryEntry = {displayName: "Tenant member", id: "member-id", role: "viewer"};
    expect(projectTenantMembers(members, "viewer")).toEqual([expectedDirectoryEntry]);
    expect(projectTenantMembers(members, "member")).toEqual([expectedDirectoryEntry]);
    expect(projectTenantMembers(members, "administrator")[0]).toMatchObject({
      createdAt: "2026-11-12T00:00:00.000Z",
      email: "member@example.test",
      id: "member-id",
      role: "viewer",
      status: "active",
      updatedAt: "2026-11-12T00:00:00.000Z",
    });
    expect(projectTenantMembers(members, "owner")[0]).toMatchObject({
      email: "member@example.test",
      id: "member-id",
      role: "viewer",
      status: "active",
    });
    expect(projectTenantMembers(members, "guest")).toEqual([]);
  });

  test("tenant artifact responses expose other members' email only to owners and administrators", () => {
    const response: ArtifactResponseRecord = {
      artifactId: "art_test", authorDisplayName: "Support Person", authorEmail: "support@example.test",
      authorKind: "member", authorSubject: "staff-id", choice: null, createdAt: "2026-11-12T00:00:00.000Z",
      data: {answer: "unchanged"}, externalQuestion: false, guestSessionId: null, id: "response-id",
      questionId: "question-id", versionId: "version-id",
    };
    const staffViewer = {...principal, id: "viewer-id", membershipRole: "viewer" as const, tenantStaffPrincipalIds: ["staff-id"]};
    for (const role of ["viewer", "member"] as const) {
      const reader = {...staffViewer, membershipRole: role};
      const httpResponse = projectHttpTenantResponse({...response, authorSubject: "ordinary-member"}, reader);
      expect(httpResponse).toMatchObject({authorDisplayName: "Support Person", authorEmail: null, data: {answer: "unchanged"}});
      expect(JSON.parse(JSON.stringify(httpResponse))).not.toHaveProperty("authorSubject");
      const mcpResponse = artifactResponseProjection({...response, authorSubject: "ordinary-member"}, false, reader, true);
      expect(mcpResponse).toMatchObject({authorDisplayName: "Support Person", authorEmail: null, authorSubject: null});
    }
    for (const role of ["administrator", "owner"] as const) {
      const reader = {...staffViewer, membershipRole: role};
      const otherMemberResponse = {...response, authorSubject: "ordinary-member"};
      expect(projectHttpTenantResponse(otherMemberResponse, reader).authorEmail).toBe("support@example.test");
      expect(artifactResponseProjection(otherMemberResponse, false, reader, true).authorEmail).toBe("support@example.test");
    }
    const viewerResponse = projectHttpTenantResponse(response, staffViewer);
    expect(viewerResponse).toMatchObject({authorDisplayName: "Orvex Support", authorEmail: null, data: {answer: "unchanged"}});
    expect(JSON.parse(JSON.stringify(viewerResponse))).not.toHaveProperty("authorSubject");
    expect(projectHttpTenantResponse(response, {...principal, tenantStaffPrincipalIds: undefined})).toEqual(response);
    const guest = {...staffViewer, membershipRole: "guest" as const};
    const guestTenantResponse = projectHttpTenantResponse(response, guest);
    expect(guestTenantResponse).toMatchObject({authorDisplayName: "Orvex Support", authorEmail: null});
    expect(JSON.parse(JSON.stringify(guestTenantResponse))).not.toHaveProperty("authorSubject");
  });

  test("tenant dispatch sender emails are limited to owners and administrators", () => {
    const dispatch: AgentDispatchRecord = {
      addressedAt: null, agentDisplayName: "Review agent", agentId: "agent-id", canceledAt: null,
      claimedAt: null, createdAt: "2026-11-12T00:00:00.000Z", deliveredAt: null, failedAt: null,
      failureReason: null, id: "dispatch-id", idempotencyKey: "dispatch-key", installationId: "tenant-installation",
      leaseExpiresAt: null, note: null, projectId: "project-id",
      sender: Object.assign(
        {authorizedByPrincipalId: null, displayName: "Other member", principalId: "other-member", principalKind: "human" as const},
        {email: "other@example.test"},
      ),
      state: "queued", threadIds: [], updatedAt: "2026-11-12T00:00:00.000Z",
    };
    for (const role of ["viewer", "member"] as const) {
      const result = agentDispatchResponse(dispatch, {...principal, membershipRole: role});
      expect(result.sender).toMatchObject({displayName: "Other member", email: null, principalId: "other-member"});
    }
    for (const role of ["administrator", "owner"] as const) {
      const result = agentDispatchResponse(dispatch, {...principal, membershipRole: role});
      expect(result.sender).toMatchObject({email: "other@example.test"});
    }
  });
});

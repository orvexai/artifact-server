import {describe, expect, test} from "vitest";

import {tenantIdentityPresentation, type Principal} from "../../src/core/identity.js";
import {projectHttpTenantResponse, projectTenantMembers} from "../../src/http/create-http-app.js";
import type {ArtifactResponseRecord} from "../../src/core/model.js";

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
    const viewer = projectTenantMembers(members, "viewer");
    expect(viewer).toHaveLength(1);
    expect(viewer[0]).not.toHaveProperty("email");
    expect(projectTenantMembers(members, "member")[0]).toHaveProperty("email", "member@example.test");
    expect(projectTenantMembers(members, "guest")).toEqual([]);
  });

  test("response identities follow tenant roles and preserve the Orvex projection", () => {
    const response: ArtifactResponseRecord = {
      artifactId: "art_test", authorDisplayName: "Support Person", authorEmail: "support@example.test",
      authorKind: "member", authorSubject: "staff-id", choice: null, createdAt: "2026-11-12T00:00:00.000Z",
      data: {answer: "unchanged"}, externalQuestion: false, guestSessionId: null, id: "response-id",
      questionId: "question-id", versionId: "version-id",
    };
    const staffViewer = {...principal, id: "viewer-id", membershipRole: "viewer" as const, tenantStaffPrincipalIds: ["staff-id"]};
    const staffEditor = {...staffViewer, membershipRole: "member" as const};
    const viewerResponse = projectHttpTenantResponse(response, staffViewer);
    expect(viewerResponse).toMatchObject({authorDisplayName: "Orvex Support", authorEmail: null, data: {answer: "unchanged"}});
    expect(JSON.parse(JSON.stringify(viewerResponse))).not.toHaveProperty("authorSubject");
    const editorResponse = projectHttpTenantResponse({...response, authorSubject: "ordinary-member"}, staffEditor);
    expect(editorResponse).toMatchObject({authorDisplayName: "Support Person", authorEmail: "support@example.test", data: {answer: "unchanged"}});
    expect(JSON.parse(JSON.stringify(editorResponse))).not.toHaveProperty("authorSubject");
    expect(projectHttpTenantResponse(response, {...principal, tenantStaffPrincipalIds: undefined})).toEqual(response);
  });
});

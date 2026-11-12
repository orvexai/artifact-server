import {describe, expect, test} from "vitest";

import {maskTenantStaffAuthorPayload, projectTenantMembers} from "../../src/http/create-http-app.js";

describe("tenant staff author masking", () => {
  test("replaces visible names and preserves principal ids for audit", () => {
    const result = maskTenantStaffAuthorPayload({items: [
      {author: {displayName: "Private staff name", principalId: "member-staff"}},
      {author: {displayName: "Tenant author", principalId: "member-tenant"}},
    ]}, ["member-staff"]);

    expect(result).toEqual({items: [
      {author: {displayName: "Orvex Support", principalId: "member-staff"}},
      {author: {displayName: "Tenant author", principalId: "member-tenant"}},
    ]});
  });

  test("projects directory fields for viewers, editors, and guests", () => {
    const members = [{
      createdAt: "2026-11-12T00:00:00.000Z",
      displayName: "Tenant member",
      email: "member@example.test",
      id: "member-id",
      installationId: "tenant-installation",
      role: "viewer" as const,
      status: "active" as const,
      updatedAt: "2026-11-12T00:00:00.000Z",
    }];

    expect(projectTenantMembers(members, "viewer")[0]).not.toHaveProperty("email");
    expect(projectTenantMembers(members, "viewer")[0]).not.toHaveProperty("role");
    expect(projectTenantMembers(members, "member")[0]).toHaveProperty("email", "member@example.test");
    expect(projectTenantMembers(members, "member")[0]).not.toHaveProperty("role");
    expect(projectTenantMembers(members, "guest")).toEqual([]);
    expect(projectTenantMembers(members, "administrator")[0]).not.toHaveProperty("email");
    expect(projectTenantMembers(members, "administrator")[0]).toHaveProperty("role", "viewer");
    expect(projectTenantMembers(members, "owner")[0]).toHaveProperty("role", "viewer");
  });

});

import {describe, expect, test} from "vitest";

import {projectTenantMembers, projectTenantVisibility} from "../../src/http/create-http-app.js";
import {projectTenantMcpResult} from "../../src/mcp/artifact-mcp-server.js";

describe("tenant staff author masking", () => {
  test("replaces visible names and preserves principal ids for audit", () => {
    const projectionInput = {items: [
      {author: {displayName: "Private staff name", principalId: "member-staff"}},
      {author: {displayName: "Tenant author", principalId: "member-tenant"}},
      {authorDisplayName: "Private staff name", authorEmail: "staff@example.test", authorSubject: "member-staff"},
      {principalId: "member-staff", actorDisplayName: "Private staff name"},
    ]};
    const result = projectTenantVisibility(projectionInput, new Set(["member-staff", "Private staff name"]), "viewer");

    expect(result).toEqual({items: [
      {author: {displayName: "Orvex Support", principalId: "member-staff"}},
      {author: {displayName: "Tenant author", principalId: "member-tenant"}},
      {authorDisplayName: "Orvex Support"},
      {principalId: "member-staff", actorDisplayName: "Orvex Support"},
    ]});
    const editorResult = projectTenantVisibility(projectionInput, new Set(["member-staff", "Private staff name"]), "member");
    expect(editorResult.items[2]).toEqual({authorDisplayName: "Orvex Support"});
    const regularEditor = projectTenantVisibility({authorDisplayName: "Tenant author", authorEmail: "tenant@example.test", authorSubject: "member-tenant"}, new Set(["member-staff"]), "member");
    expect(regularEditor).toEqual({authorDisplayName: "Tenant author", authorEmail: "tenant@example.test"});
  });

  test("projects directory fields for viewers, editors, and guests", () => {
    const members = [{
      createdAt: "2026-11-12T00:00:00.000Z",
      displayName: "Tenant member",
      email: "member@example.test",
      id: "member-id",
      installationId: "tenant-installation",
      role: "viewer" as const,
      staff: false,
      status: "active" as const,
      updatedAt: "2026-11-12T00:00:00.000Z",
    }, {
      createdAt: "2026-11-12T00:00:00.000Z",
      displayName: "Orvex Support",
      email: "support@example.test",
      id: "staff-id",
      installationId: "tenant-installation",
      role: "member" as const,
      staff: true,
      status: "active" as const,
      updatedAt: "2026-11-12T00:00:00.000Z",
    }];

    expect(projectTenantMembers(members, "viewer")).toHaveLength(1);
    expect(projectTenantMembers(members, "viewer")[0]).not.toHaveProperty("email");
    expect(projectTenantMembers(members, "viewer")[0]).not.toHaveProperty("role");
    expect(projectTenantMembers(members, "member")[0]).toHaveProperty("email", "member@example.test");
    expect(projectTenantMembers(members, "member")[0]).not.toHaveProperty("role");
    expect(projectTenantMembers(members, "guest")).toEqual([]);
    expect(projectTenantMembers(members, "administrator")[0]).not.toHaveProperty("email");
    expect(projectTenantMembers(members, "administrator")[0]).toHaveProperty("role", "viewer");
    expect(projectTenantMembers(members, "owner")[0]).toHaveProperty("role", "viewer");
  });

  test("projects structured MCP output and text content for tenant viewers", async () => {
    const result = await projectTenantMcpResult({
      content: [{type: "text", text: "Private staff name staff@example.test"}],
      structuredContent: {items: [{authorDisplayName: "Private staff name", authorEmail: "staff@example.test", authorSubject: "member-staff"}]},
    }, [{displayName: "Private staff name", email: "staff@example.test", id: "member-staff"}], "viewer");

    expect(result.content).toEqual([{type: "text", text: "Orvex Support Orvex Support"}]);
    expect(result.structuredContent).toEqual({items: [{authorDisplayName: "Orvex Support"}]});
  });

  test("a projection failure returns a safe payload instead of throwing", () => {
    const hostileValue = new Proxy({}, {get: (_target, property) => {
      if (property === Symbol.toStringTag) throw new Error("unreadable value");
      return undefined;
    }});

    expect(projectTenantVisibility(hostileValue, new Set())).toEqual({});
  });

});

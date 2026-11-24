import {afterEach, describe, expect, test, vi} from "vitest";

import {
  api,
  adminPublicLinkRevokeFeedback,
  buildPublicLinkRevokeItem,
  mapPublicLinkInventoryRow,
  organizationLoginHref,
  organizationPath,
} from "./client";

describe("tenant-masked version client payload", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("prefixes sign-in and return URLs on an organization page", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/isotest-b"})});
    const returnTo = organizationPath("/review?artifact=example");
    const signInHref = organizationLoginHref(returnTo);
    expect(signInHref.startsWith("/o/isotest-b/auth/login?returnTo=")).toBe(true);
    expect(new URLSearchParams(new URL(signInHref, "https://artifact.example.test").search).get("returnTo"))
      .toBe("/o/isotest-b/review?artifact=example");
  });

  test("prefixes same-origin absolute navigation and preserves content-host URLs", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/isotest-b"})});
    vi.stubGlobal("window", {location: {origin: "https://app.example.test"}});

    expect(organizationPath("https://app.example.test/auth/local-owner"))
      .toBe("https://app.example.test/o/isotest-b/auth/local-owner");
    expect(organizationPath("https://content.example.test/artifacts/a1"))
      .toBe("https://content.example.test/artifacts/a1");
  });

  test("rejects unsafe navigation paths and encoded path separators", () => {
    vi.stubGlobal("document", {querySelector: () => ({content: "/o/acme"})});

    for (const path of [
      "//evil.example/x",
      "/\\evil.example",
      "/review%2f..%2fadmin",
      "/review%5c..%5cadmin",
    ]) {
      expect(organizationPath(path)).toBe("/o/acme/review");
    }
  });

  test("parses a version whose staff publisher id is masked", async () => {
    vi.stubGlobal("document", {querySelector: () => null});
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      links: {review: "https://artifacts.example.test/review", version: "https://artifacts.example.test/version"},
      manifest: {digest: "digest", entries: [], entryPath: "index.html", routingMode: "static"},
      version: {
        artifactId: "artifact", contentToken: "content", createdAt: "2026-11-13T00:00:00.000Z",
        entryPath: "index.html", id: "version", manifestDigest: "digest", number: 1,
        projectId: "project", publisherPrincipalId: null, routingMode: "static",
      },
    }), {headers: {"Content-Type": "application/json"}, status: 200})));

    const result = await api.version("project", "artifact", "version");
    expect(result.version.publisherPrincipalId).toBeNull();
  });

  test("maps r3 secret inventory metadata into the generation-guarded revoke command", () => {
    const row = mapPublicLinkInventoryRow({
      artifact: {
        accessSetting: "account_required", createdAt: "2026-11-24T00:00:00.000Z",
        currentVersionId: "version", deletedAt: null, id: "artifact", name: "Review",
        projectId: "project", tags: [],
      },
      currentVersion: {
        artifactId: "artifact", contentToken: "content", createdAt: "2026-11-24T00:00:00.000Z",
        entryPath: "index.html", id: "version", manifestDigest: "digest", number: 1,
        projectId: "project", publisherPrincipalId: null, routingMode: "static",
      },
      kind: "secret",
      links: {public: "https://artifacts.example.test/artifact"},
      project: {
        archivedAt: null, createdAt: "2026-11-24T00:00:00.000Z", id: "project",
        installationId: "installation", name: "Project",
      },
      secretLink: {
        createdAt: "2026-11-24T00:00:00.000Z", generation: 7, invitationId: "invitation",
        permission: "comment", updatedAt: "2026-11-24T00:01:00.000Z",
      },
    });

    expect(buildPublicLinkRevokeItem(row)).toEqual({
      artifactId: "artifact", generation: 7, kind: "secret", projectId: "project",
    });
    expect(adminPublicLinkRevokeFeedback("stale_generation", "Review")).toEqual({
      kind: "warning",
      message: "This link was reset after the list loaded and is still active. Review it and revoke again.",
    });
    expect(adminPublicLinkRevokeFeedback("revoked", "Review").kind).toBe("success");
    expect(adminPublicLinkRevokeFeedback("made_private", "Review").kind).toBe("success");
  });

  test("keeps visitor permission, paused, and name-required signals from guest/current", async () => {
    vi.stubGlobal("document", {querySelector: () => null});
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      artifactName: "Review", bootstrapUrl: "https://content.example.test/bootstrap",
      createdAt: "2026-11-24T00:00:00.000Z", displayName: "", nameRequired: true,
      number: 1, paused: false, permission: "comment", versionId: "version",
    }), {headers: {"Content-Type": "application/json"}, status: 201})));

    const visitor = await api.publicVisitor("artifact");
    expect(visitor).toMatchObject({nameRequired: true, paused: false, permission: "comment"});
  });
});

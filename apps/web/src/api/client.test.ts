import {afterEach, describe, expect, test, vi} from "vitest";

import {api, organizationLoginHref, organizationPath} from "./client";

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
});

import {afterEach, describe, expect, test, vi} from "vitest";

import {api} from "./client";

describe("tenant-masked version client payload", () => {
  afterEach(() => vi.unstubAllGlobals());

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

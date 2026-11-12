import {describe, expect, test} from "vitest";

import {applicationPathUrl, artifactReviewUrl} from
  "../../src/http/artifact-http-links.js";
import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
} from "../support/runtime-harness.js";
import {createStagedUpload} from "../support/publishing.js";

describe("organization application base paths", () => {
  test("keeps generated API and review links inside the selected organization", () => {
    const origin = new URL("https://artifacts.example.com/o/org-b");

    expect(applicationPathUrl(origin, "/api/v1/projects?cursor=next").toString())
      .toBe("https://artifacts.example.com/o/org-b/api/v1/projects?cursor=next");
    expect(artifactReviewUrl(origin, "prj_1", "art_1", "ver_1"))
      .toContain("https://artifacts.example.com/o/org-b/review?");
  });

  test.each([
    ["local mode", undefined, ""],
    ["a mismatched host with an org base path", "https://trusted.example.test/o/org-b", "/o/org-b"],
  ])("upload links preserve request-origin behavior in %s", async (_label, applicationOrigin, expectedBasePath) => {
    const installation = await createTestInstallation();
    const server = await startTestServer(installation, applicationOrigin === undefined
      ? {}
      : {applicationOrigin});
    try {
      const upload = await createStagedUpload(server, installation, "index.html", [{
        bytes: new TextEncoder().encode("<title>link base</title>"),
        mediaType: "text/html",
        path: "index.html",
      }]);
      expect(upload.response.status).toBe(201);
      for (const link of [upload.body.commitUrl, ...upload.body.files.map(({uploadUrl}) => uploadUrl)]) {
        const url = new URL(link);
        expect(url.origin).toBe(new URL(server.baseUrl).origin);
        expect(url.pathname).toMatch(new RegExp(`^${expectedBasePath}/api/v1/uploads/upl_[^/]+/`, "u"));
        expect(url.pathname).not.toContain("/api/v1/uploads/api/v1/uploads/");
      }
    } finally {
      await server.stop();
      await removeTestInstallation(installation);
    }
  });
});

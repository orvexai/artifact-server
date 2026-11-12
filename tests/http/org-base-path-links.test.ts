import {describe, expect, test} from "vitest";

import {applicationPathUrl, artifactReviewUrl} from
  "../../src/http/artifact-http-links.js";

describe("organization application base paths", () => {
  test("keeps generated API and review links inside the selected organization", () => {
    const origin = new URL("https://artifacts.example.com/o/org-b");

    expect(applicationPathUrl(origin, "/api/v1/projects?cursor=next").toString())
      .toBe("https://artifacts.example.com/o/org-b/api/v1/projects?cursor=next");
    expect(artifactReviewUrl(origin, "prj_1", "art_1", "ver_1"))
      .toContain("https://artifacts.example.com/o/org-b/review?");
  });
});

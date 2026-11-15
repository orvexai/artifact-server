import {afterEach, describe, expect, test, vi} from "vitest";

import {isSettingsPath, parseSettingsRoute} from "./review-routes.ts";

describe("organization-mounted review routes", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("rejects a path that only shares the organization base prefix", () => {
    vi.stubGlobal("document", {
      querySelector: () => ({content: "/o/acme"}),
    });

    expect(isSettingsPath("/o/acme-evil/review/settings/members")).toBe(false);
    expect(parseSettingsRoute("/o/acme-evil/review")).toEqual({kind: "notFound"});
  });

  test("parses tenant settings paths after removing the organization base", () => {
    vi.stubGlobal("document", {
      querySelector: () => ({content: "/o/acme"}),
    });

    expect(isSettingsPath("/o/acme/review/settings/projects")).toBe(true);
    expect(parseSettingsRoute("/o/acme/review/settings/projects")).toEqual({kind: "projects"});
  });
});

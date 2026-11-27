import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {afterEach, describe, expect, test, vi} from "vitest";

import {api} from "@/api/client";
import {ProjectSharingSection, loadProjectSharing} from "./settings-project-sharing.tsx";

describe("project group sharing capability", () => {
  afterEach(() => vi.restoreAllMocks());

  test("does not request groups or render the picker when directory groups are unavailable", async () => {
    const groups = vi.spyOn(api, "groups").mockResolvedValue([]);
    vi.spyOn(api, "projectSharing").mockResolvedValue({
      accessMode: "installation",
      groups: [],
      projectId: "project-1",
      yourRole: "administrator",
    });

    await loadProjectSharing("project-1", false);
    const html = renderToStaticMarkup(createElement(ProjectSharingSection, {
      administrator: true,
      directoryGroups: false,
      projectId: "project-1",
    }));

    expect(groups).not.toHaveBeenCalled();
    expect(html).toContain("Project sharing with groups is managed by your identity provider.");
    expect(html).not.toContain("project-share-group");
  });

  test("requests groups when the capability is available", async () => {
    const groups = vi.spyOn(api, "groups").mockResolvedValue([]);
    vi.spyOn(api, "projectSharing").mockResolvedValue({
      accessMode: "installation",
      groups: [],
      projectId: "project-1",
      yourRole: "administrator",
    });

    await loadProjectSharing("project-1", true);

    expect(groups).toHaveBeenCalledOnce();
  });
});

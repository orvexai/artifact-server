import {createElement} from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe, expect, test} from "vitest";

import {OrganizationSwitcherView} from "./product";

describe("organization switcher", () => {
  test("is absent for one membership and renders choices for multiple", () => {
    const single = renderToStaticMarkup(createElement(OrganizationSwitcherView, {
      organizations: [{displayName: "Org One", role: "viewer", slug: "org-one"}],
      pathname: "/o/org-one/",
    }));
    const multiple = renderToStaticMarkup(createElement(OrganizationSwitcherView, {
      organizations: [
        {displayName: "Org One", role: "viewer", slug: "org-one"},
        {displayName: "Org Two", role: "editor", slug: "org-two"},
      ],
      pathname: "/o/org-one/",
    }));

    expect(single).toBe("");
    expect(multiple).toContain("aria-label=\"Organization\"");
    expect(multiple).toContain("Org One");
    expect(multiple).toContain("Org Two");
  });
});

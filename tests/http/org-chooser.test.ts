import {describe, expect, test} from "vitest";

import {
  organizationRootRedirect,
  renderNoOrganizationPage,
  renderOrganizationChooser,
} from "../../src/external-storage/create-organization-router.js";

describe("organization chooser", () => {
  test("renders escaped organization names and the platform sign-out action", () => {
    const html = renderOrganizationChooser([
      {displayName: `R&D <Partners> "One"`, slug: "research"},
    ]);

    expect(html).toContain("R&amp;D &lt;Partners&gt; &quot;One&quot;");
    expect(html).toContain(`action="/api/v1/platform/session/logout"`);
    expect(html).toContain(`method="post"`);
    expect(html).toContain(`class="avatar"`);
    expect(html).toContain("prefers-color-scheme:dark");
  });

  test("renders a styled no-organization page with sign-out", () => {
    const html = renderNoOrganizationPage();
    expect(html).toContain("<title>Houston Artifacts — No organization</title>");
    expect(html).toContain("Houston Artifacts");
    expect(html).toContain("You don't belong to any organization yet.");
    expect(html).toContain('action="/api/v1/platform/session/logout"');
    expect(html).toContain("prefers-color-scheme:dark");
  });

  test("renders Houston branding and the self-hosted font URLs", () => {
    const html = renderOrganizationChooser([
      {displayName: "Research", slug: "research"},
    ]);
    expect(html).toContain("<title>Houston Artifacts — Choose an organization</title>");
    expect(html).toContain("Houston Artifacts");
    expect(html).toContain("<svg class=\"mark\"");
    expect(html).toContain("/assets/fonts/houston/inter-latin-wght-normal.woff2");
    expect(html).toContain("/assets/fonts/houston/space-grotesk-latin-wght-normal.woff2");
  });

  test("redirects the sole active organization regardless of stale lastOrg", () => {
    expect(organizationRootRedirect([{slug: "only-org"}], "removed-org"))
      .toBe("/o/only-org/");
    expect(organizationRootRedirect([{slug: "only-org"}], null))
      .toBe("/o/only-org/");
    expect(organizationRootRedirect([{slug: "one"}, {slug: "two"}], "removed-org"))
      .toBeNull();
  });
});

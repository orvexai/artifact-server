import {describe, expect, test} from "vitest";
import {renderIdentityAdmissionDeniedPage} from "../../src/http/create-http-app.js";

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
      .toBe("/o/only-org/auth/login?returnTo=%2Fo%2Fonly-org%2F");
    expect(organizationRootRedirect([{slug: "only-org"}], null))
      .toBe("/o/only-org/auth/login?returnTo=%2Fo%2Fonly-org%2F");
    expect(organizationRootRedirect([{slug: "one"}, {slug: "two"}], "removed-org"))
      .toBeNull();
  });

  test("AUTH-030-B: single-org redirect and multi-org chooser continue through organization login", () => {
    const slug = "tenant-one";
    const loginTarget = "/o/tenant-one/auth/login?returnTo=%2Fo%2Ftenant-one%2F";
    expect(organizationRootRedirect([{slug}], null)).toBe(loginTarget);

    const html = renderOrganizationChooser([
      {displayName: "Tenant One", slug: "tenant-one"},
      {displayName: "Tenant Two", slug: "tenant-two"},
    ]);
    expect(html).toContain(`href="${loginTarget}"`);
    expect(html).toContain('href="/o/tenant-two/auth/login?returnTo=%2Fo%2Ftenant-two%2F"');
    expect(html).not.toContain('href="/o/tenant-one/"');
    expect(html).not.toContain('href="/o/tenant-two/"');
  });

  test("AUTH-030-F: organization continuation never targets the bare organization root", () => {
    const single = organizationRootRedirect([{slug: "tenant"}], null);
    const lastOrg = organizationRootRedirect([{slug: "tenant"}, {slug: "other"}], "tenant");
    expect(single).toBe("/o/tenant/auth/login?returnTo=%2Fo%2Ftenant%2F");
    expect(lastOrg).toBe("/o/tenant/auth/login?returnTo=%2Fo%2Ftenant%2F");
    expect(single).not.toBe("/o/tenant/");
    expect(lastOrg).not.toBe("/o/tenant/");
    const deniedPage = renderIdentityAdmissionDeniedPage("/o/tenant/assets/fonts/houston/");
    expect(deniedPage).toContain("Sign-in unavailable");
    expect(deniedPage).toContain("Your account does not have access to this organization.");
    expect(deniedPage).toContain("Houston Artifacts");
  });
});

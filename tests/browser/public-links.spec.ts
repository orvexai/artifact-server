import {AxeBuilder} from "@axe-core/playwright";
import {expect, test} from "@playwright/test";
import {z} from "zod";

import {apiHeaders} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";
import {createPublicLinkAsHuman, localLogin, startBrowserFixture, stopBrowserFixture} from "./browser-fixture.js";

const publicLinkIssueSchema = z.object({url: z.url()});

async function issuePublicLink(fixture: Awaited<ReturnType<typeof startBrowserFixture>>, artifactId: string, permission: "view" | "comment" = "view"): Promise<string> {
  const response = await createPublicLinkAsHuman(fixture, artifactId, permission);
  expect(response.status()).toBe(201);
  return publicLinkIssueSchema.parse(await response.json()).url;
}

test("PLK-001-B Public links open at root and under an organization prefix", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    // This route simulates the /o/orvex prefix in the test harness; it is not hosted proof of organization routing.
    await fixture.page.route("**/o/orvex/**", async (route) => {
      const requested = new URL(route.request().url());
      const upstreamUrl = new URL(`${requested.pathname.replace(/^\/o\/orvex/u, "")}${requested.search}`, fixture.server.baseUrl);
      const response = await route.fetch({url: upstreamUrl.toString()});
      const body = (await response.text()).replace(
        "</head>",
        '<meta name="as-organization-base" content="/o/orvex"></head>',
      );
      await route.fulfill({response, body});
    });
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id, "comment");
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    const organizationLink = new URL(link);
    organizationLink.pathname = "/o/orvex/review";
    await fixture.page.goto(organizationLink.toString());
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.getByRole("button", {name: /sign in/i})).toHaveCount(0);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-001-F Public link browsing stays on the installation without identity-provider requests", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id, "comment");
    const applicationUrl = new URL(fixture.server.baseUrl);
    const publishedVersionUrl = new URL(published.body.links.version);
    const contentDomainPrefix = `${published.body.version.contentToken}.`;
    expect(publishedVersionUrl.hostname.startsWith(contentDomainPrefix)).toBe(true);
    const contentDomain = publishedVersionUrl.hostname.slice(contentDomainPrefix.length);
    const externalRequests: string[] = [];
    fixture.page.on("request", (request) => {
      const requestUrl = new URL(request.url());
      const isContentSubdomain =
        requestUrl.protocol === applicationUrl.protocol &&
        requestUrl.port === applicationUrl.port &&
        requestUrl.hostname.endsWith(`.${contentDomain}`);
      if (requestUrl.origin !== applicationUrl.origin && !isContentSubdomain) {
        externalRequests.push(request.url());
      }
    });
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.getByRole("heading", {name: "Comments"})).toBeVisible();
    await fixture.page.context().clearCookies();
    await fixture.page.reload();
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.getByRole("heading", {name: "Comments"})).toBeVisible();
    expect(externalRequests).toEqual([]);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-002-B Valid public-link pages render without a Sign in control", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    await fixture.page.goto(await issuePublicLink(fixture, published.body.artifact.id));
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.getByRole("link", {name: /sign in/i})).toHaveCount(0);
    await expect(fixture.page.getByRole("button", {name: /sign in/i})).toHaveCount(0);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("Unknown public links show a neutral failure without sign-in controls", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id);
    const revoke = await fetch(
      `${fixture.server.baseUrl}/api/v1/artifacts/${encodeURIComponent(published.body.artifact.id)}/public-link?projectId=prj_default`,
      {
        headers: apiHeaders(fixture.installation, `revoke-public-link-${crypto.randomUUID()}`),
        method: "DELETE",
      },
    );
    expect(revoke.status).toBe(204);
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Link unavailable"})).toBeVisible();
    await expect(fixture.page.getByRole("link", {name: /sign in/i})).toHaveCount(0);
    const unavailableMessage = fixture.page.getByText("This shared artifact is unavailable.", {exact: true});
    await expect(unavailableMessage).toHaveCount(1);
    await expect(unavailableMessage).toBeVisible();
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-003-F Public link fragments survive reload and the invite alias remains supported", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id);
    const parsed = new URL(link);
    expect(parsed.hash.startsWith("#link=")).toBe(true);
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    expect(new URL(fixture.page.url()).hash).toBe(parsed.hash);
    await fixture.page.reload();
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    expect(new URL(fixture.page.url()).hash).toBe(parsed.hash);

    const legacyAlias = new URL(link);
    legacyAlias.hash = `#invite=${parsed.hash.slice("#link=".length)}`;
    await fixture.page.goto(legacyAlias.toString());
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    expect(new URL(fixture.page.url()).hash).toBe(legacyAlias.hash);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-003-B A link fragment remains available for exchange after visitor-session expiry", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id, "comment");
    const fragment = new URL(link).hash;
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Comments"})).toBeVisible();
    await fixture.page.context().clearCookies();
    await fixture.page.reload();
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.getByRole("heading", {name: "Comments"})).toBeVisible();
    expect(new URL(fixture.page.url()).hash).toBe(fragment);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("A public link fragment takes the public path for a signed-in browser", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Public preview</title><h1>Public preview</h1>",
      idempotencyKey: `public-link-fixture-${crypto.randomUUID()}`,
      name: "Public preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id);
    await localLogin(fixture);
    await fixture.page.goto(`${fixture.server.baseUrl}/review`);
    await expect(fixture.page.getByRole("link", {name: "Houston Artifacts"})).toBeVisible();
    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Public preview"})).toBeVisible();
    await expect(fixture.page.locator(".as-organization-switcher")).toHaveCount(0);
    await expect(fixture.page.getByRole("button", {name: "Log out"})).toHaveCount(0);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-022-B Share and public pages pass accessibility checks in both themes and viewport sizes", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><html lang=\"en\"><title>Accessible preview</title><main><h1>Accessible preview</h1><p>Review content</p></main></html>",
      idempotencyKey: `public-link-accessibility-${crypto.randomUUID()}`,
      name: "Accessible preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id);
    await localLogin(fixture);
    const reviewUrl = `${fixture.server.baseUrl}/review?${new URLSearchParams({
      artifact: published.body.artifact.id,
      project: "prj_default",
      version: published.body.version.id,
    })}`;

    const verifySurface = async (width: number, theme: "light" | "dark"): Promise<void> => {
      await fixture.page.setViewportSize({height: 844, width});
      await fixture.page.goto(reviewUrl);
      const toggleName = theme === "dark" ? "Use dark theme" : "Use light theme";
      if (!await fixture.page.getByRole("button", {name: toggleName}).isVisible()) {
        await fixture.page.getByRole("button", {name: "Open artifact catalog"}).click();
      }
      await expect(fixture.page.getByRole("button", {name: toggleName})).toBeVisible();
      await fixture.page.getByRole("button", {name: toggleName}).click();
      await expect(fixture.page.getByRole("button", {
        name: theme === "dark" ? "Use light theme" : "Use dark theme",
      })).toBeVisible();
      if (width === 390) {
        await fixture.page.getByRole("button", {name: "Collapse artifact catalog"}).click();
      }
      await expect(fixture.page.getByRole("heading", {name: "Accessible preview"})).toBeVisible();
      const shareAccessibility = await new AxeBuilder({page: fixture.page})
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();
      expect(shareAccessibility.violations).toEqual([]);

      const shareButton = fixture.page.getByRole("button", {name: "Share"});
      await shareButton.focus();
      await fixture.page.keyboard.press("Enter");
      await expect(fixture.page.getByRole("dialog", {name: "Share artifact"})).toBeVisible();
      await expect(fixture.page.getByRole("region", {name: "General access"})).toBeVisible();
      const overviewAccessibility = await new AxeBuilder({page: fixture.page})
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();
      expect(overviewAccessibility.violations).toEqual([]);
      await fixture.page.getByRole("button", {name: "Manage access"}).click();
      await expect(fixture.page.getByRole("heading", {name: "Artifact access"})).toBeVisible();
      const accessAccessibility = await new AxeBuilder({page: fixture.page})
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();
      expect(accessAccessibility.violations).toEqual([]);
      await fixture.page.keyboard.press("Escape");

      await fixture.page.goto(link);
      await expect(fixture.page.getByRole("heading", {name: "Accessible preview"})).toBeVisible();
      const publicAccessibility = await new AxeBuilder({page: fixture.page})
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();
      expect(publicAccessibility.violations).toEqual([]);
      expect(await fixture.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
    };
    await verifySurface(1280, "dark");
    await verifySurface(1280, "light");
    await verifySurface(390, "dark");
    await verifySurface(390, "light");
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-022-F Keyboard access and responsive layout are checked on public sharing surfaces", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><html lang=\"en\"><title>Keyboard preview</title><main><h1>Keyboard preview</h1></main></html>",
      idempotencyKey: `public-link-keyboard-${crypto.randomUUID()}`,
      name: "Keyboard preview",
    });
    const link = await issuePublicLink(fixture, published.body.artifact.id);
    await localLogin(fixture);
    await fixture.page.setViewportSize({height: 844, width: 390});
    await fixture.page.goto(`${fixture.server.baseUrl}/review?${new URLSearchParams({
      artifact: published.body.artifact.id,
      project: "prj_default",
      version: published.body.version.id,
    })}`);
    await expect(fixture.page.getByRole("heading", {name: "Keyboard preview"})).toBeVisible();
    const share = fixture.page.getByRole("button", {name: "Share"});
    await share.focus();
    await fixture.page.keyboard.press("Enter");
    await expect(fixture.page.getByRole("dialog", {name: "Share artifact"})).toBeVisible();
    await fixture.page.keyboard.press("Escape");
    await expect(fixture.page.getByRole("dialog", {name: "Share artifact"})).toHaveCount(0);

    await fixture.page.goto(link);
    await expect(fixture.page.getByRole("heading", {name: "Keyboard preview"})).toBeVisible();
    expect(await fixture.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
    const publicAccessibility = await new AxeBuilder({page: fixture.page})
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();
    expect(publicAccessibility.violations).toEqual([]);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

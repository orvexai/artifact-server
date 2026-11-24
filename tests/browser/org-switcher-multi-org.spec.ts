import {AxeBuilder} from "@axe-core/playwright";
import {expect, test} from "@playwright/test";
import {z} from "zod";

import {publishNew} from "../support/publishing.js";
import {createPublicLinkAsHuman, localLogin, startBrowserFixture, stopBrowserFixture} from "./browser-fixture.js";

const linkResponseSchema = z.object({url: z.url()});

test("PLK-020-B The organization switcher appears in catalog and settings and stays off public pages", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.route(/\/api\/v1\/platform\/me\/orgs$/u, async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: [
          {displayName: "Orvex", role: "Owner", slug: "orvex"},
          {displayName: "Research", role: "Member", slug: "research"},
        ],
        status: 200,
      });
    });
    const artifact = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Switching fixture</title><h1>Switching fixture</h1>",
      idempotencyKey: `org-switcher-fixture-${crypto.randomUUID()}`,
      name: "Switching fixture",
    });
    const issued = await createPublicLinkAsHuman(fixture, artifact.body.artifact.id);
    expect(issued.status()).toBe(201);
    const publicLink = linkResponseSchema.parse(await issued.json()).url;

    await localLogin(fixture);
    await fixture.page.goto(`${fixture.server.baseUrl}/review`);
    const switcher = fixture.page.locator(".as-organization-switcher");
    await expect(switcher).toBeVisible();
    await expect(switcher.locator("xpath=..")).toHaveClass(/as-catalog__header-actions/u);

    await fixture.page.goto(`${fixture.server.baseUrl}/review/settings`);
    await expect(fixture.page.locator(".as-settings__nav .as-organization-switcher")).toBeVisible();

    await fixture.page.goto(publicLink);
    await expect(fixture.page.getByRole("heading", {name: "Switching fixture"})).toBeVisible();
    await expect(fixture.page.locator(".as-organization-switcher")).toHaveCount(0);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PLK-020-F Multi-organization navigation stays accessible and fits both viewport sizes", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.route(/\/api\/v1\/platform\/me\/orgs$/u, async (route) => {
      await route.fulfill({
        contentType: "application/json",
        json: [
          {displayName: "Orvex", role: "Owner", slug: "orvex"},
          {displayName: "Research", role: "Member", slug: "research"},
        ],
        status: 200,
      });
    });
    await localLogin(fixture);
    const switcher = fixture.page.locator(".as-organization-switcher");
    await expect(switcher.getByRole("combobox", {name: "Organization"})).toHaveValue("orvex");
    await expect(switcher.getByText("Owner", {exact: true})).toBeVisible();

    const checkViewport = async (width: number): Promise<void> => {
      await fixture.page.setViewportSize({height: 800, width});
      const darkTheme = fixture.page.getByRole("button", {name: "Use dark theme"});
      await expect(darkTheme).toBeVisible();
      await darkTheme.click();
      await expect(fixture.page.getByRole("button", {name: "Use light theme"})).toBeVisible();
      await expect(fixture.page.locator(".as-organization-switcher__avatar")).toBeVisible();
      expect(await fixture.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
      const lightTheme = fixture.page.getByRole("button", {name: "Use light theme"});
      await lightTheme.click();
      await expect(fixture.page.getByRole("button", {name: "Use dark theme"})).toBeVisible();
      expect(await fixture.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
      const accessibility = await new AxeBuilder({page: fixture.page})
        .withTags(["wcag2a", "wcag2aa"])
        .analyze();
      expect(accessibility.violations).toEqual([]);
    };
    await checkViewport(1024);
    await checkViewport(390);

    await switcher.getByRole("combobox", {name: "Organization"}).selectOption("research");
    await expect(fixture.page).toHaveURL(/\/o\/research\//u);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

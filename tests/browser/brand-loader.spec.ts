import {expect, test, type Page} from "@playwright/test";

import {localLogin, startBrowserFixture, stopBrowserFixture} from "./browser-fixture.js";

test("BRD-004-F mark stays visible in the catalog and settings headers in both themes", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await localLogin(fixture);
    await checkTheme(fixture.page, fixture.server.baseUrl, "dawn", "rgb(8, 145, 178)", "rgb(15, 23, 42)");
    await checkTheme(fixture.page, fixture.server.baseUrl, "moon", "rgb(35, 181, 209)", "rgb(241, 245, 249)");
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("BRD-005-F visible loaders stay named, status-bearing, reduced-motion safe, and CSP-compatible", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  let releaseCatalog: () => void = () => undefined;
  let catalogRequestStarted: () => void = () => undefined;
  const catalogHeld = new Promise<void>((resolve) => { releaseCatalog = resolve; });
  const catalogStarted = new Promise<void>((resolve) => { catalogRequestStarted = resolve; });
  try {
    await fixture.page.emulateMedia({reducedMotion: "reduce"});
    await fixture.page.addInitScript(() => {
      document.documentElement.dataset["cspViolationCount"] = "0";
      window.addEventListener("securitypolicyviolation", () => {
        const current = Number(document.documentElement.dataset["cspViolationCount"] ?? "0");
        document.documentElement.dataset["cspViolationCount"] = String(current + 1);
      });
    });
    await fixture.page.route(/\/api\/v1\/artifacts\?.*/u, async (route) => {
      catalogRequestStarted();
      await catalogHeld;
      await route.continue();
    });
    await localLogin(fixture, false);
    await catalogStarted;
    await expect(fixture.page.locator(".as-catalog__header")).toBeVisible();

    const loaders = await fixture.page.locator("houston-loader").evaluateAll((elements) =>
      elements.filter((loader) => {
        const style = getComputedStyle(loader);
        return style.display !== "none" && style.visibility !== "hidden" && loader.getClientRects().length > 0;
      }).map((loader) => {
        const spin = loader.shadowRoot?.querySelector(".spin");
        return {
          ariaLabel: loader.getAttribute("aria-label"),
          animationName: spin === null || spin === undefined ? null : getComputedStyle(spin).animationName,
          role: loader.getAttribute("role"),
        };
      })
    );
    expect(loaders.length).toBeGreaterThan(0);
    for (const loader of loaders) {
      expect(["status", "progressbar"]).toContain(loader.role);
      expect(loader.ariaLabel?.trim().length ?? 0).toBeGreaterThan(0);
      expect(loader.animationName).toBe("rest");
    }
    const violationCounts = await Promise.all(fixture.page.frames().map(async (frame) =>
      frame.locator("html").getAttribute("data-csp-violation-count")
    ));
    expect(violationCounts.length).toBeGreaterThan(0);
    expect(violationCounts.every((count) => count === "0")).toBe(true);
  } finally {
    releaseCatalog();
    await stopBrowserFixture(fixture);
  }
});

async function checkTheme(
  page: Page,
  baseUrl: string,
  theme: "dawn" | "moon",
  expectedAccent: string,
  expectedText: string,
): Promise<void> {
  await page.evaluate((value) => {
    window.localStorage.setItem("artifact-review-theme", value);
  }, theme);
  await page.goto(`${baseUrl}/review?project=prj_default`);
  await expect(page.locator(".as-catalog__header")).toBeVisible();
  await expectMarkVisible(page, ".as-catalog__brand-mark", expectedAccent, expectedText);

  await page.goto(`${baseUrl}/review/settings/groups`);
  await expect(page.locator(".as-settings__header")).toBeVisible();
  await expectMarkVisible(page, ".as-settings__mark", expectedAccent, expectedText);
}

async function expectMarkVisible(
  page: Page,
  markSelector: string,
  expectedAccent: string,
  expectedText: string,
): Promise<void> {
  const colors = await page.locator(markSelector).evaluate((mark) => {
    const dot = mark.querySelector("circle:last-child");
    const ring = mark.querySelector("circle:not(:last-child)");
    const frame = mark.querySelector("rect");
    if (!(dot instanceof SVGCircleElement) || !(ring instanceof SVGCircleElement) || !(frame instanceof SVGRectElement)) return null;
    let effectiveBackground: string | null = null;
    let ancestor = mark.parentElement;
    while (ancestor !== null && effectiveBackground === null) {
      const background = getComputedStyle(ancestor).backgroundColor;
      if (background !== "transparent" && background !== "rgba(0, 0, 0, 0)") {
        effectiveBackground = background;
      }
      ancestor = ancestor.parentElement;
    }
    if (effectiveBackground === null) {
      effectiveBackground = getComputedStyle(document.body).backgroundColor;
    }
    return {
      dotFill: getComputedStyle(dot).fill,
      effectiveBackground,
      frameStroke: getComputedStyle(frame).stroke,
      height: mark.getBoundingClientRect().height,
      ringStroke: getComputedStyle(ring).stroke,
      textColor: getComputedStyle(mark).color,
      width: mark.getBoundingClientRect().width,
    };
  });
  expect(colors).not.toBeNull();
  if (colors === null) throw new Error("Mark D geometry is missing.");
  expect(colors.dotFill).toBe(expectedAccent);
  expect(colors.textColor).toBe(expectedText);
  expect(colors.frameStroke).toBe(expectedText);
  expect(colors.ringStroke).toBe(expectedText);
  expect(colors.frameStroke).not.toBe(expectedAccent);
  expect(colors.ringStroke).not.toBe(expectedAccent);
  expect(colors.width).toBeGreaterThanOrEqual(16);
  expect(colors.height).toBeGreaterThanOrEqual(16);
  expect(colors.effectiveBackground).not.toBe("rgba(0, 0, 0, 0)");
  expect(colors.dotFill).not.toBe(colors.effectiveBackground);
}

import {expect, test, type Locator, type Page} from "@playwright/test";

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

test("review frame loader keeps contrasting ink and Houston teal in both themes", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.goto(`${fixture.server.baseUrl}/review-frame`);
    const loader = fixture.page.locator("houston-loader");
    await expect(loader).toHaveAttribute("aria-label", "Waiting for the artifact to load");

    await checkFrameLoaderTheme(fixture.page, loader, false, "rgb(35, 181, 209)");
    await checkFrameLoaderTheme(fixture.page, loader, true, "rgb(8, 145, 178)");
  } finally {
    await stopBrowserFixture(fixture);
  }
});

async function checkFrameLoaderTheme(
  page: Page,
  loader: Locator,
  light: boolean,
  expectedAccent: string,
): Promise<void> {
  await page.locator("html").evaluate((root, useLightTheme) => {
    root.classList.toggle("light", useLightTheme);
  }, light);
  const colors = await loader.evaluate((element) => {
    const shadow = element.shadowRoot;
    const dot = shadow?.querySelector(".dot");
    const ink = shadow?.querySelector(".ink");
    if (!(dot instanceof SVGCircleElement) || !(ink instanceof SVGElement)) {
      throw new Error("Review frame loader geometry is missing.");
    }
    return {
      accent: getComputedStyle(dot).fill,
      background: getComputedStyle(document.body).backgroundColor,
      ink: getComputedStyle(ink).stroke,
    };
  });
  expect(colors.ink).not.toBe(colors.background);
  expect(colors.accent).toBe(expectedAccent);
}

test("BRD-005-F visible loaders stay named, status-bearing, reduced-motion safe, and CSP-compatible", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  let releaseSession: () => void = () => undefined;
  let sessionRequestStarted: () => void = () => undefined;
  const sessionHeld = new Promise<void>((resolve) => { releaseSession = resolve; });
  const sessionStarted = new Promise<void>((resolve) => { sessionRequestStarted = resolve; });
  let releaseCatalog: () => void = () => undefined;
  let catalogRequestStarted: () => void = () => undefined;
  const catalogHeld = new Promise<void>((resolve) => { releaseCatalog = resolve; });
  const catalogStarted = new Promise<void>((resolve) => { catalogRequestStarted = resolve; });
  let releaseSettings: () => void = () => undefined;
  let settingsRequestStarted: () => void = () => undefined;
  const settingsHeld = new Promise<void>((resolve) => { releaseSettings = resolve; });
  const settingsStarted = new Promise<void>((resolve) => { settingsRequestStarted = resolve; });
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
    await fixture.page.route(/\/api\/v1\/session$/u, async (route) => {
      sessionRequestStarted();
      await sessionHeld;
      await route.continue();
    });
    await localLogin(fixture, false);
    await sessionStarted;
    await expectVisibleLoaders(fixture.page);
    releaseSession();
    await catalogStarted;
    await expect(fixture.page.locator(".as-catalog__header")).toBeVisible();
    await expectVisibleLoaders(fixture.page);

    await fixture.page.locator(".as-catalog__brand").click();
    await expect(fixture.page.locator(".as-home-overlay")).toBeVisible();
    await expectVisibleLoaders(fixture.page);
    await expect(fixture.page.locator(".as-home-overlay__animation")).toHaveAttribute("variant", "arrival");
    await fixture.page.getByRole("button", {name: "Close Houston Artifacts home"}).click();

    await fixture.page.evaluate(() => {
      const frame = document.createElement("iframe");
      frame.dataset["loaderProbe"] = "true";
      frame.src = "/review-frame";
      document.body.append(frame);
    });
    const reviewFrameLoader = fixture.page.frameLocator('iframe[data-loader-probe="true"]').locator("houston-loader");
    await expect(reviewFrameLoader).toBeVisible();
    await expect(reviewFrameLoader).toHaveAttribute("role", "status");
    await expect(reviewFrameLoader).toHaveAttribute("aria-label", "Waiting for the artifact to load");
    const frameAnimation = await reviewFrameLoader.evaluate((loader) => {
      const spin = loader.shadowRoot?.querySelector(".spin");
      return spin === null || spin === undefined ? null : getComputedStyle(spin).animationName;
    });
    expect(frameAnimation).toBe("rest");

    await fixture.page.evaluate(async () => {
      await customElements.whenDefined("houston-loader");
      const loader = document.createElement("houston-loader");
      loader.setAttribute("label", "Upload progress");
      loader.setAttribute("value", "42");
      document.body.append(loader);
    });
    const progressLoader = fixture.page.locator("houston-loader").last();
    await expect(progressLoader).toHaveAttribute("role", "progressbar");
    await expect(progressLoader).toHaveAttribute("aria-valuemin", "0");
    await expect(progressLoader).toHaveAttribute("aria-valuemax", "100");
    await expect(progressLoader).toHaveAttribute("aria-valuenow", "42");
    await progressLoader.evaluate((loader) => loader.setAttribute("value", "80"));
    await expect(progressLoader).toHaveAttribute("aria-valuenow", "80");
    const progressAnimation = await progressLoader.evaluate((loader) => {
      const spin = loader.shadowRoot?.querySelector(".spin");
      return spin === null || spin === undefined ? null : getComputedStyle(spin).animationName;
    });
    expect(["none", "rest"]).toContain(progressAnimation);

    const violationCounts = await Promise.all(fixture.page.frames().map(async (frame) =>
      frame.locator("html").getAttribute("data-csp-violation-count")
    ));
    expect(violationCounts.length).toBeGreaterThan(0);
    expect(violationCounts.every((count) => count === "0")).toBe(true);

    releaseCatalog();
    await fixture.page.route(/\/api\/v1\/administration\/public-links\?/u, async (route) => {
      settingsRequestStarted();
      await settingsHeld;
      await route.continue();
    });
    await fixture.page.goto(`${fixture.server.baseUrl}/review/settings/public-links`);
    await settingsStarted;
    await expectVisibleLoaders(fixture.page);
  } finally {
    releaseSession();
    releaseCatalog();
    releaseSettings();
    await stopBrowserFixture(fixture);
  }
});

async function expectVisibleLoaders(page: Page): Promise<void> {
  const loaders = await page.locator("houston-loader").evaluateAll((elements) =>
    elements.filter((loader) => {
      const style = getComputedStyle(loader);
      return style.display !== "none" && style.visibility !== "hidden" && loader.getClientRects().length > 0;
    }).map((loader) => {
      const spin = loader.shadowRoot?.querySelector(".spin");
      return {
        animationName: spin === null || spin === undefined ? null : getComputedStyle(spin).animationName,
        ariaLabel: loader.getAttribute("aria-label"),
        ariaValueMax: loader.getAttribute("aria-valuemax"),
        ariaValueMin: loader.getAttribute("aria-valuemin"),
        ariaValueNow: loader.getAttribute("aria-valuenow"),
        role: loader.getAttribute("role"),
        variant: loader.getAttribute("variant"),
      };
    })
  );
  expect(loaders.length).toBeGreaterThan(0);
  for (const loader of loaders) {
    expect(["status", "progressbar"]).toContain(loader.role);
    expect(loader.ariaLabel?.trim().length ?? 0).toBeGreaterThan(0);
    if (loader.role === "progressbar") {
      expect(Number.isFinite(Number(loader.ariaValueNow))).toBe(true);
      expect(loader.ariaValueMin).toBe("0");
      expect(loader.ariaValueMax).toBe("100");
      expect(["none", "rest"]).toContain(loader.animationName);
    } else if (loader.variant === "arrival") {
      expect(["none", "rest"]).toContain(loader.animationName);
    } else if (loader.variant === "orbit" || loader.variant === "comet") {
      expect(loader.animationName).toBe("rest");
    } else {
      expect(loader.animationName).toBe("rest");
    }
  }
}

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

function relativeLuminance(color: string): number {
  const values = color.match(/[\d.]+/gu)?.slice(0, 3).map(Number);
  if (values?.length !== 3) throw new Error(`Unsupported computed color: ${color}`);
  const [red, green, blue] = values.map((value) => {
    const channel = value / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * (red ?? 0) + 0.7152 * (green ?? 0) + 0.0722 * (blue ?? 0);
}

function wcagContrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = relativeLuminance(foreground);
  const backgroundLuminance = relativeLuminance(background);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05)
    / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
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
  expect(wcagContrastRatio(colors.dotFill, colors.effectiveBackground)).toBeGreaterThanOrEqual(3);
}

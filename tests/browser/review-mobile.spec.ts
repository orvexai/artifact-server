import {expect, test, type Locator} from "@playwright/test";

import {publishNew} from "../support/publishing.js";
import {
  localLogin,
  startBrowserFixture,
  stopBrowserFixture,
} from "./browser-fixture.js";

async function clickWithin(locator: Locator): Promise<boolean> {
  try {
    await locator.click({timeout: 1_200});
    return true;
  } catch {
    return false;
  }
}

test("artifact-server-7gk: review workspace and Projects stay usable at 390px", async ({browser}) => {
  const started = await startBrowserFixture(browser);
  await started.context.close();
  const context = await browser.newContext({
    hasTouch: true,
    isMobile: true,
    viewport: {width: 390, height: 844},
  });
  const fixture = {...started, context, page: await context.newPage()};
  fixture.page.setDefaultTimeout(1_200);
  fixture.page.setDefaultNavigationTimeout(5_000);

  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><html lang=\"en\"><title>Mobile review fixture</title><main><h1>Mobile preview</h1></main></html>",
      idempotencyKey: "artifact-server-7gk-mobile-review",
      name: "Mobile review fixture",
    });

    await localLogin(fixture, false);
    await fixture.page.setViewportSize({width: 390, height: 844});
    const reviewUrl = `${fixture.server.baseUrl}/review?${new URLSearchParams({
      project: "prj_default",
      artifact: published.body.artifact.id,
    })}`;
    await fixture.page.goto(reviewUrl, {timeout: 5_000, waitUntil: "domcontentloaded"});

    const pageOverflow = () => fixture.page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect.soft(await pageOverflow(), "step b: page has no horizontal overflow").toBe(0);

    const previewHit = await fixture.page.evaluate(() => {
      const element = document.elementFromPoint(195, 400);
      return Boolean(element?.closest(".as-preview-panel"));
    });
    expect.soft(previewHit, "step c: preview is visible at the center of the compact viewport")
      .toBe(true);

    const catalog = fixture.page.getByRole("complementary", {name: "Artifact catalog"});
    const openCatalog = fixture.page.getByRole("button", {name: "Open artifact catalog"});
    if (!(await catalog.isVisible())) {
      expect.soft(await clickWithin(openCatalog), "step d: open the artifact catalog").toBe(true);
    }
    await expect.soft(catalog, "step d: artifact catalog is available").toBeVisible({timeout: 1_200});
    const catalogBox = await catalog.boundingBox();
    expect.soft(catalogBox?.x, "step d: catalog begins at the left viewport edge").toBe(0);
    expect.soft(catalogBox?.width, "step d: catalog fills the compact viewport").toBe(390);

    const artifactRow = catalog.getByRole("button", {name: /Mobile review fixture/u});
    expect.soft(await clickWithin(artifactRow), "step d: select the published artifact")
      .toBe(true);

    const catalogStillOpen = await catalog.isVisible();
    if (catalogStillOpen) {
      const collapseCatalog = catalog.getByRole("button", {
        name: "Collapse artifact catalog",
      });
      expect.soft(await clickWithin(collapseCatalog), "close the catalog to expose the preview")
        .toBe(true);
    }

    const fullScreenButton = fixture.page.getByRole("button", {name: "Full screen"});
    expect.soft(await clickWithin(fullScreenButton), "step e: enter full-screen review").toBe(true);

    const toolbar = fixture.page.getByRole("toolbar", {name: "Artifact viewer controls"});
    await expect.soft(toolbar, "step e: full-screen controls toolbar is present")
      .toBeVisible({timeout: 1_200});
    const toolbarButtons = toolbar.getByRole("button");
    const buttonCount = await toolbarButtons.count();
    const toolbarBoxes = await Promise.all(
      Array.from({length: buttonCount}, (_, index) => toolbarButtons.nth(index).boundingBox()),
    );
    toolbarBoxes.forEach((box, index) => {
      expect.soft(
        box !== null && box.x >= 0 && box.x + box.width <= 390 && box.y >= 0 &&
          box.y + box.height <= 844 && box.height >= 44,
        `step e: toolbar button ${index} stays in the viewport and is at least 44px tall`,
      ).toBe(true);
    });

    const commentsButton = toolbar.getByRole("button", {name: /Comments/u});
    expect.soft(await clickWithin(commentsButton), "step e: open Comments").toBe(true);
    const toolbarBoxWithComments = await toolbar.boundingBox();
    expect.soft(
      toolbarBoxWithComments !== null && toolbarBoxWithComments.x >= 0 &&
        toolbarBoxWithComments.x + toolbarBoxWithComments.width <= 390,
      "step e: toolbar remains in the viewport while Comments is open",
    ).toBe(true);

    const hideControls = fixture.page.getByRole("button", {name: "Hide viewer controls"});
    expect.soft(await clickWithin(hideControls), "step e: collapse viewer controls").toBe(true);
    const restoreButton = fixture.page.getByRole("button", {name: "Show viewer controls"});
    const restoreBox = await restoreButton.boundingBox();
    expect.soft(
      restoreBox !== null && restoreBox.x >= 0 && restoreBox.x + restoreBox.width <= 390 &&
        restoreBox.y >= 0 && restoreBox.y + restoreBox.height <= 844 &&
        restoreBox.width >= 44 && restoreBox.height >= 44,
      "step e: collapsed controls can be restored with an in-viewport 44px target",
    ).toBe(true);

    await fixture.page.goto(
      `${fixture.server.baseUrl}/review/settings/projects`,
      {timeout: 5_000, waitUntil: "domcontentloaded"},
    );
    expect.soft(await pageOverflow(), "step f: page has no horizontal overflow").toBe(0);
    const projectContainer = fixture.page.locator("#settings-project-table");
    const table = projectContainer.locator("table");
    const internalOverflow = await projectContainer.evaluate(
      (element) => element.scrollWidth - element.clientWidth,
    );
    expect.soft(internalOverflow, "step f: Projects inventory has no horizontal overflow")
      .toBe(0);

    const projectRow = table.getByRole("row").filter({hasText: "prj_default"});
    const createdCell = projectRow.getByRole("cell").nth(2);
    expect.soft(await createdCell.isVisible(), "step f: default project's Created value is visible")
      .toBe(true);
    const createdBox = await createdCell.boundingBox();
    expect.soft(
      createdBox !== null && createdBox.x + createdBox.width <= 390,
      "step f: default project's Created value fits within 390px",
    ).toBe(true);
    expect.soft(await table.getAttribute("aria-label"), "Projects table has an accessible name")
      .toBe("Projects");

    await fixture.page.setViewportSize({width: 1280, height: 800});
    const wideColumnHeaders = await Promise.all(
      ["Project", "State", "Created", "Actions"].map(async (column) => ({
        column,
        visible: await fixture.page.getByRole("columnheader", {name: column}).isVisible(),
      })),
    );
    wideColumnHeaders.forEach(({column, visible}) => {
      expect.soft(
        visible,
        `wide Projects table displays the ${column} header`,
      ).toBe(true);
    });

    await fixture.page.setViewportSize({width: 390, height: 844});
    await fixture.page.emulateMedia({colorScheme: "dark"});
    await fixture.page.goto(reviewUrl, {timeout: 5_000, waitUntil: "domcontentloaded"});
    expect.soft(await pageOverflow(), "step g: dark mode page has no horizontal overflow").toBe(0);
    const darkPreviewHit = await fixture.page.evaluate(() => {
      const element = document.elementFromPoint(195, 400);
      return Boolean(element?.closest(".as-preview-panel"));
    });
    expect.soft(darkPreviewHit, "step g: dark mode leaves the preview visible").toBe(true);

    await fixture.page.goto(
      `${fixture.server.baseUrl}/review/settings/projects`,
      {timeout: 5_000, waitUntil: "domcontentloaded"},
    );
    expect.soft(await pageOverflow(), "step g: dark mode page has no horizontal overflow").toBe(0);
    const darkContainer = fixture.page.locator("#settings-project-table");
    expect.soft(
      await darkContainer.evaluate((element) => element.scrollWidth - element.clientWidth),
      "step g: dark mode Projects inventory has no horizontal overflow",
    ).toBe(0);
    const darkCreated = darkContainer.locator("table").getByRole("row")
      .filter({hasText: "prj_default"}).getByRole("cell").nth(2);
    expect.soft(await darkCreated.isVisible(), "step g: dark mode Created value is visible")
      .toBe(true);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("artifact-server-7gk: resizing across 720px keeps one sheet in compact and restores the wide layout", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  fixture.page.setDefaultTimeout(1_200);
  fixture.page.setDefaultNavigationTimeout(5_000);

  try {
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><html lang=\"en\"><title>Resize review fixture</title><main><h1>Resize preview</h1></main></html>",
      idempotencyKey: "artifact-server-7gk-compact-resize",
      name: "Resize review fixture",
    });

    await localLogin(fixture, false);
    await fixture.page.setViewportSize({width: 1280, height: 800});
    const reviewUrl = `${fixture.server.baseUrl}/review?${new URLSearchParams({
      project: "prj_default",
      artifact: published.body.artifact.id,
    })}`;
    await fixture.page.goto(reviewUrl, {timeout: 5_000, waitUntil: "domcontentloaded"});

    const catalog = fixture.page.getByRole("complementary", {name: "Artifact catalog"});
    const inspector = fixture.page.getByRole("complementary", {name: "Artifact inspector"});
    const openCatalog = fixture.page.getByRole("button", {name: "Open artifact catalog"});
    const openInspector = fixture.page.getByRole("button", {name: "Open inspector"});
    const closeInspector = fixture.page.getByRole("button", {name: "Close inspector"});

    if (!(await catalog.isVisible())) await openCatalog.click();
    if (!(await inspector.isVisible())) await openInspector.click();
    await expect(catalog).toBeVisible();
    await expect(closeInspector).toBeVisible();

    await fixture.page.setViewportSize({width: 680, height: 720});
    await expect(catalog).toBeVisible();
    await expect(closeInspector).toHaveCount(0);
    await expect(openInspector).toBeVisible();

    await fixture.page.setViewportSize({width: 1280, height: 800});
    await expect(catalog).toBeVisible();
    await expect(closeInspector).toBeVisible();

    await fixture.page.setViewportSize({width: 680, height: 720});
    await expect(openInspector).toBeVisible();
    await fixture.page.evaluate(() => {
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
    await fixture.page.keyboard.press("]");
    await expect(inspector).toBeVisible();
    await expect(catalog).toBeHidden();

    await fixture.page.setViewportSize({width: 1280, height: 800});
    await expect(inspector).toBeVisible();
    await expect(catalog).toBeHidden();

    await fixture.page.setViewportSize({width: 680, height: 720});
    await closeInspector.click();
    await expect(inspector).toBeHidden();

    await fixture.page.setViewportSize({width: 1280, height: 800});
    await expect(inspector).toBeHidden();
    await expect(openInspector).toBeVisible();
    await expect(catalog).toBeHidden();
  } finally {
    await stopBrowserFixture(fixture);
  }
});

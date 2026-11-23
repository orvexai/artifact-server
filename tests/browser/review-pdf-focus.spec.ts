import {expect, test, type Locator} from "@playwright/test";

import {multiPagePdf} from "../support/pdf-fixture.js";
import {
  commitStagedUpload,
  createStagedUpload,
  publishNew,
  type TestSiteFile,
  uploadEveryStagedFile,
} from "../support/publishing.js";
import {
  localLogin,
  startBrowserFixture,
  stopBrowserFixture,
  type BrowserFixture,
} from "./browser-fixture.js";

test.use({channel: "chromium"});

async function publishPdf(fixture: BrowserFixture, key: string) {
  const pdf = multiPagePdf([["Focus layout"], ["Toolbar remains reachable"]]);
  const files: readonly TestSiteFile[] = [{
    bytes: pdf,
    mediaType: "application/pdf",
    path: "focus.pdf",
  }];
  const upload = await createStagedUpload(
    fixture.server,
    fixture.installation,
    "focus.pdf",
    files,
  );
  await uploadEveryStagedFile(fixture.installation, upload.body, files);
  const published = await commitStagedUpload(
    fixture.installation,
    upload.body,
    key,
    {
      accessSetting: "account_required",
      kind: "new_artifact",
      name: "Focus layout PDF",
    },
  );
  return published.body;
}

interface Box {
  readonly bottom: number;
  readonly height: number;
  readonly top: number;
}

async function settledBox(locator: Locator): Promise<Box> {
  let previous = "";
  let stableSamples = 0;
  await expect.poll(async () => {
    const box = await locator.boundingBox();
    if (box === null) {
      previous = "";
      stableSamples = 0;
      return stableSamples;
    }
    const current = JSON.stringify({
      bottom: box.y + box.height,
      height: box.height,
      top: box.y,
    });
    if (current === previous) {
      stableSamples += 1;
    } else {
      stableSamples = 0;
      previous = current;
    }
    return stableSamples;
  }, {intervals: [50, 100, 150, 200]}).toBeGreaterThanOrEqual(2);

  const box = await locator.boundingBox();
  if (box === null) throw new Error("Expected a rendered layout box.");
  return {bottom: box.y + box.height, height: box.height, top: box.y};
}

test("artifact-server-50e: wide PDF focus dock and hover zone stay above the viewer frame", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.setViewportSize({height: 800, width: 1280});
    await fixture.page.emulateMedia({reducedMotion: "reduce"});
    const published = await publishPdf(fixture, "artifact-server-50e-wide-pdf");
    await localLogin(fixture);
    await fixture.page.goto(published.links.review);

    const preview = fixture.page.locator(".as-pdf-preview");
    const frame = fixture.page.locator(".as-pdf-preview__frame");
    const dock = fixture.page.locator(".as-focus-controls-dock");
    await expect(fixture.page.getByRole("button", {name: "Exit full screen"}))
      .toBeVisible();
    await expect(preview).toHaveAttribute("data-status", "ready");
    await expect(frame).toBeVisible();
    const expandedDock = await settledBox(dock);
    const expandedFrame = await settledBox(frame);
    console.log("artifact-server-50e expanded PDF boxes", {
      dock: expandedDock,
      frame: expandedFrame,
    });
    expect(expandedDock.bottom).toBeLessThanOrEqual(expandedFrame.top);

    const controls = fixture.page.getByRole("toolbar", {
      name: "Artifact viewer controls",
    });
    await controls.hover();
    await fixture.page.getByRole("button", {name: "Hide viewer controls"}).click();
    await expect(dock).toHaveAttribute("data-collapsed", "true");
    await expect(dock).toHaveAttribute("data-hover-armed", "false");
    const hoverZone = dock.locator(".as-focus-controls__hover-zone");
    await expect(hoverZone).toBeVisible();
    const collapsedDock = await settledBox(dock);
    const collapsedHoverZone = await settledBox(hoverZone);
    const collapsedFrame = await settledBox(frame);
    console.log("artifact-server-50e collapsed PDF boxes", {
      dock: collapsedDock,
      frame: collapsedFrame,
      hoverZone: collapsedHoverZone,
    });
    expect(collapsedDock.bottom).toBeLessThanOrEqual(collapsedFrame.top);
    expect(collapsedHoverZone.bottom).toBeLessThanOrEqual(collapsedFrame.top);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("artifact-server-50e: HTML focus mode keeps preview body padding at zero", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.setViewportSize({height: 800, width: 1280});
    await fixture.page.emulateMedia({reducedMotion: "reduce"});
    const published = await publishNew(fixture.server, fixture.installation, {
      accessSetting: "account_required",
      content: "<!doctype html><html lang=\"en\"><title>Focus HTML</title><h1>Focus HTML</h1></html>",
      idempotencyKey: "artifact-server-50e-html-focus",
      mediaType: "text/html",
      name: "Focus HTML",
      path: "index.html",
    });
    await localLogin(fixture);
    await fixture.page.goto(published.body.links.review);

    const body = fixture.page.locator(".as-preview-panel__body[data-preview-kind=\"html\"]");
    await expect(fixture.page.getByRole("button", {name: "Exit full screen"}))
      .toBeVisible();
    await expect(body).toBeVisible();
    await expect.poll(() => body.evaluate((node) =>
      getComputedStyle(node).paddingTop
    )).toBe("0px");
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("artifact-server-50e: compact PDF keeps the bottom toolbar and frame top", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    await fixture.page.setViewportSize({height: 844, width: 390});
    await fixture.page.emulateMedia({reducedMotion: "reduce"});
    const published = await publishPdf(fixture, "artifact-server-50e-compact-pdf");
    await localLogin(fixture);

    await fixture.page.goto(published.links.review);
    const preview = fixture.page.locator(".as-pdf-preview");
    const body = fixture.page.locator(".as-preview-panel__body[data-preview-kind='pdf']");
    const frame = fixture.page.locator(".as-pdf-preview__frame");
    const dock = fixture.page.locator(".as-focus-controls-dock");
    const controls = fixture.page.getByRole("toolbar", {
      name: "Artifact viewer controls",
    });
    await expect(fixture.page.getByRole("button", {name: "Exit full screen"}))
      .toBeVisible();
    await expect(dock).toBeVisible();
    await expect(controls).toBeVisible();
    await expect(preview).toHaveAttribute("data-status", "ready");
    await expect(frame).toBeVisible();
    await expect.poll(() => body.evaluate((node) =>
      getComputedStyle(node).paddingTop
    )).toBe("0px");

    const focusFrame = await settledBox(frame);
    console.log("artifact-server-50e compact focus PDF frame", focusFrame);
    // Base 189f679 measured the compact focus frame at y=0..844; the band is off here.
    expect(Math.abs(focusFrame.top - 0)).toBeLessThanOrEqual(1);
    expect(Math.abs(focusFrame.bottom - 844)).toBeLessThanOrEqual(1);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

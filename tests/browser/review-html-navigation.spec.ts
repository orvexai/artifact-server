import {expect, test, type FrameLocator, type Page} from "@playwright/test";

import {
  commitStagedUpload,
  createStagedUpload,
  type TestSiteFile,
  uploadEveryStagedFile,
} from "../support/publishing.js";
import {
  localLogin,
  startBrowserFixture,
  stopBrowserFixture,
  type BrowserFixture,
} from "./browser-fixture.js";

const pngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z7aEAAAAASUVORK5CYII=";

/**
 * An ordinary multi-file guide with no knowledge of Review: a fixed menu of
 * fragment links, a module picker that records itself in the URL with the
 * History API, page-owned link handling, and relative assets.
 */
const guideHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Navigation guide</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<nav>
  <a id="to-architecture" href="#architecture">Architecture</a>
  <a id="to-services" href="index.html#services">Services</a>
  <svg width="120" height="24" role="img" aria-label="Journeys menu"><a id="to-journeys" href="#journeys"><text x="0" y="15">Journeys</text></a></svg>
  <a id="to-top" href="#">Top</a>
  <a id="to-handled" href="#journeys" data-handled>Handled by the page</a>
  <a id="to-window-handled" href="#services" data-window-handled>Handled by a window listener</a>
  <a id="to-other" href="other.html#elsewhere">Another file</a>
  <button id="choose-module" type="button">Choose a module</button>
</nav>
<section id="overview"><h1>Overview</h1><img id="dot" src="images/dot.png" alt="Status dot"></section>
<section id="architecture"><h2>Architecture</h2></section>
<section id="services"><h2>Services</h2></section>
<section id="journeys"><h2>Journeys</h2></section>
<ol id="guide-log" hidden></ol>
<script>
  function note(entry) {
    var item = document.createElement("li");
    item.textContent = entry;
    document.getElementById("guide-log").append(item);
  }
  window.addEventListener("hashchange", function () { note("hashchange:" + location.hash); });
  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-handled]") === null) return;
    event.preventDefault();
    note("handled");
  });
  window.addEventListener("click", function (event) {
    if (event.target.closest("[data-window-handled]") === null) return;
    event.preventDefault();
    note("window-handled");
  });
  window.addEventListener("click", function (event) {
    if (event.target.closest("#to-other") === null) return;
    note("other-prevented:" + event.defaultPrevented);
    event.preventDefault();
  });
  document.getElementById("choose-module").addEventListener("click", function () {
    try {
      history.replaceState({module: "ai"}, "", "#module-ai");
      history.pushState({module: "ai", detail: true}, "", "index.html#module-ai-detail");
      note("history:" + location.hash + ":" + JSON.stringify(history.state));
    } catch (error) {
      note("history-error:" + error.name);
    }
  });
</script>
</body>
</html>
`;

const guideCss = `html { scroll-behavior: auto; }
body { margin: 0; padding-left: 16rem; }
nav { background: white; display: flex; flex-direction: column; gap: 1rem; inset: 0 auto auto 0; position: fixed; width: 15rem; z-index: 1; }
section { min-height: 150vh; }
#overview h1 { color: rgb(1, 2, 3); }
`;

function text(path: string, mediaType: string, content: string): TestSiteFile {
  return {bytes: new TextEncoder().encode(content), mediaType, path};
}

async function publishGuide(fixture: BrowserFixture, key: string): Promise<{
  readonly artifactId: string;
  readonly versionId: string;
}> {
  const files: readonly TestSiteFile[] = [
    text("guide/index.html", "text/html; charset=utf-8", guideHtml),
    text("guide/style.css", "text/css; charset=utf-8", guideCss),
    text("guide/other.html", "text/html; charset=utf-8", "<!doctype html><title>Other</title>"),
    {bytes: Buffer.from(pngBase64, "base64"), mediaType: "image/png", path: "guide/images/dot.png"},
  ];
  const upload = await createStagedUpload(fixture.server, fixture.installation, "guide/index.html", files);
  await uploadEveryStagedFile(fixture.installation, upload.body, files);
  const committed = await commitStagedUpload(fixture.installation, upload.body, key, {
    accessSetting: "account_required",
    kind: "new_artifact",
    name: "Navigation guide",
  });
  return {artifactId: committed.body.artifact.id, versionId: committed.body.version.id};
}

function guideSandbox(page: Page): FrameLocator {
  return page.frameLocator(".as-artifact-frame").frameLocator("iframe");
}

/** Leave annotate mode so links and controls behave as they do in a tab. */
async function useInteractMode(page: Page): Promise<void> {
  const annotate = page.getByRole("button", {name: /^Annotate mode/u});
  if (await annotate.isVisible()) await annotate.click();
  await expect(page.getByRole("button", {name: /^Interact mode/u})).toBeVisible();
}

function guideState(sandbox: FrameLocator) {
  return sandbox.locator("body").evaluate(() => {
    // `+ 0` folds the -0 a section scrolled exactly to the top can report.
    const [architectureTop, servicesTop, journeysTop] = ["architecture", "services", "journeys"]
      .map((id) => Math.round(document.getElementById(id)?.getBoundingClientRect().top ?? Number.NaN) + 0);
    return {
      architectureTop,
      href: window.location.href,
      journeysTop,
      log: [...document.querySelectorAll("#guide-log li")].map((item) => item.textContent),
      scrollY: Math.round(window.scrollY),
      servicesTop,
    };
  });
}

/** Follow every kind of same-document link and History update in one Review view. */
async function navigateGuide(page: Page, reviewUrl: string): Promise<void> {
  await page.goto(reviewUrl);
  const sandbox = guideSandbox(page);
  await expect(sandbox.locator("#overview h1")).toHaveText("Overview");
  await useInteractMode(page);

  await sandbox.locator("#to-architecture").click();
  await expect.poll(() => guideState(sandbox)).toMatchObject({
    architectureTop: 0,
    href: "about:srcdoc#architecture",
  });

  // Following the current fragment again still scrolls back to it.
  await sandbox.locator("body").evaluate(() => window.scrollTo(0, 0));
  await sandbox.locator("#to-architecture").click();
  await expect.poll(() => guideState(sandbox)).toMatchObject({
    architectureTop: 0,
    href: "about:srcdoc#architecture",
  });

  // A link naming the entry file itself is the same document.
  await sandbox.locator("#to-services").click();
  await expect.poll(() => guideState(sandbox)).toMatchObject({
    href: "about:srcdoc#services",
    servicesTop: 0,
  });

  await sandbox.locator("#to-journeys text").click();
  await expect.poll(() => guideState(sandbox)).toMatchObject({
    href: "about:srcdoc#journeys",
    journeysTop: 0,
  });

  await sandbox.locator("#to-top").click();
  await expect.poll(() => guideState(sandbox)).toMatchObject({
    href: "about:srcdoc#",
    scrollY: 0,
  });

  // The page's own link handling still wins over Review's, whether it
  // listens on the document or on the window.
  await sandbox.locator("#to-handled").click();
  await expect.poll(async () => (await guideState(sandbox)).log).toContain("handled");
  await sandbox.locator("#to-window-handled").click();
  await expect.poll(async () => (await guideState(sandbox)).log).toContain("window-handled");
  expect((await guideState(sandbox)).href).toBe("about:srcdoc#");

  await sandbox.locator("#choose-module").click();
  await expect.poll(async () => (await guideState(sandbox)).log).toContain(
    'history:#module-ai-detail:{"module":"ai","detail":true}',
  );
  expect((await guideState(sandbox)).log).toEqual(expect.arrayContaining([
    "hashchange:#architecture",
    "hashchange:#services",
    "hashchange:#journeys",
    "hashchange:",
  ]));
  expect((await guideState(sandbox)).log.filter((entry) => entry.startsWith("history-error"))).toEqual([]);
}

test.describe("Review HTML navigation", () => {
  test("CMT-022-B: HTML fragment menus and History API module selection stay inside the reviewed document in standard and focus Review", async ({browser}) => {
    const fixture = await startBrowserFixture(browser);
    const policyViolations: string[] = [];
    fixture.page.on("console", (message) => {
      if (message.text().includes("Content Security Policy")) policyViolations.push(message.text());
    });
    try {
      const guide = await publishGuide(fixture, "cmt-022-navigation-guide");
      await localLogin(fixture);
      const reviewUrl = `${fixture.server.baseUrl}/review?project=prj_default&artifact=${guide.artifactId}&version=${guide.versionId}`;
      await navigateGuide(fixture.page, reviewUrl);
      await navigateGuide(fixture.page, `${reviewUrl}&view=focus`);
      expect(policyViolations).toEqual([]);
    } finally {
      await stopBrowserFixture(fixture);
    }
  });

  test("CMT-022-F: same-document navigation keeps the opaque sandbox, content-host assets, and other-document links unchanged", async ({browser}) => {
    const fixture = await startBrowserFixture(browser);
    try {
      const guide = await publishGuide(fixture, "cmt-022-navigation-boundary");
      await localLogin(fixture);
      await fixture.page.goto(
        `${fixture.server.baseUrl}/review?project=prj_default&artifact=${guide.artifactId}&version=${guide.versionId}`,
      );
      const sandbox = guideSandbox(fixture.page);
      await expect(sandbox.locator("#overview h1")).toHaveText("Overview");
      await useInteractMode(fixture.page);

      const sandboxElement = fixture.page.frameLocator(".as-artifact-frame").locator("iframe");
      await expect(sandboxElement).toHaveAttribute("sandbox", "allow-scripts");

      // Relative assets still come from the version's content host.
      const image = sandbox.getByRole("img", {name: "Status dot"});
      await expect.poll(() => image.evaluate((node) =>
        node instanceof HTMLImageElement ? node.naturalWidth : 0
      )).toBeGreaterThan(0);
      const applicationOrigin = new URL(fixture.server.baseUrl).origin;
      const assets = await sandbox.locator("body").evaluate(() => {
        const dot = document.getElementById("dot");
        const stylesheet = document.querySelector('link[rel="stylesheet"]');
        return {
          heading: getComputedStyle(document.querySelector("#overview h1") ?? document.body).color,
          image: dot instanceof HTMLImageElement ? dot.currentSrc : "",
          origin: window.origin,
          stylesheet: stylesheet instanceof HTMLLinkElement ? stylesheet.href : "",
        };
      });
      expect(assets.heading).toBe("rgb(1, 2, 3)");
      expect(assets.origin).toBe("null");
      expect(new URL(assets.image).origin).not.toBe(applicationOrigin);
      expect(new URL(assets.stylesheet).origin).not.toBe(applicationOrigin);
      expect(new URL(assets.stylesheet).pathname).toMatch(/\/guide\/style\.css$/u);

      // A link to another file is not mistaken for this document.
      await sandbox.locator("#to-other").click();
      await expect.poll(async () => (await guideState(sandbox)).log).toContain("other-prevented:false");
      expect((await guideState(sandbox)).href).toBe("about:srcdoc");

      // History may name only this document: another file stays refused, and
      // nothing reaches the application frame or its origin.
      expect(await sandbox.locator("body").evaluate(() => {
        try {
          history.replaceState(null, "", "other.html");
          return window.location.href;
        } catch (error) {
          return error instanceof Error ? error.name : "unknown";
        }
      })).toBe("SecurityError");
      await expect(fixture.page.frameLocator(".as-artifact-frame").locator("iframe")).toHaveAttribute("sandbox", "allow-scripts");
      expect(fixture.page.url()).toContain(`/review?project=prj_default&artifact=${guide.artifactId}`);
    } finally {
      await stopBrowserFixture(fixture);
    }
  });
});

import {expect, test, type FrameLocator, type Page} from "@playwright/test";

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
import {listThreadsOverApi} from "./comment-api.js";

const pngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z7aEAAAAASUVORK5CYII=";

/** A Plannotator-style plan: GFM features, a relative image, and hostile raw HTML. */
const planMarkdown = `# Plan overview

Reviewers read **this plan** in Review and see [the details](#rollout-details).

- [x] Draft the plan
- [ ] Ship the plan

| Phase | Owner |
|:------|------:|
| Build | Web |
| Verify | QA |

\`\`\`ts
const answer: number = 42;
\`\`\`

![Status dot](images/dot.png)

${"A paragraph that gives the reader enough length to scroll.\n\n".repeat(40)}
## Rollout details

Autolinked https://example.com and a [sibling file](notes/plain.md).

<script>window.__markdownScript = true</script>
<img src="images/dot.png" alt="hostile image" onerror="window.__markdownHandler = true">
<iframe src="https://example.com/frame"></iframe>
<object data="images/dot.png"></object>
<form action="https://example.com/steal"><input name="secret" value="x"><button>Send</button></form>
<style>body { display: none !important; }</style>
<a href="javascript:window.__markdownJavascriptLink = true">javascript link</a>
<p onclick="window.__markdownClick = true" id="hostile-paragraph">Click target</p>
`;

function text(path: string, mediaType: string, content: string): TestSiteFile {
  return {bytes: new TextEncoder().encode(content), mediaType, path};
}

async function publishPlan(fixture: BrowserFixture): Promise<{
  readonly artifactId: string;
  readonly versionId: string;
}> {
  const files: readonly TestSiteFile[] = [
    text("review.md", "text/markdown; charset=utf-8", planMarkdown),
    {bytes: Buffer.from(pngBase64, "base64"), mediaType: "image/png", path: "images/dot.png"},
    text("notes/plain.md", "text/plain; charset=utf-8", "# Plain label\n\nRendered as Markdown.\n"),
    text("notes/readme.txt", "text/plain; charset=utf-8", "# Not Markdown\n"),
    text("notes/legacy.markdown", "text/x-markdown", "## Legacy label\n"),
  ];
  const upload = await createStagedUpload(fixture.server, fixture.installation, "review.md", files);
  await uploadEveryStagedFile(fixture.installation, upload.body, files);
  const committed = await commitStagedUpload(fixture.installation, upload.body, "prv-006-markdown-plan", {
    accessSetting: "account_required",
    kind: "new_artifact",
    name: "Markdown plan",
  });
  return {artifactId: committed.body.artifact.id, versionId: committed.body.version.id};
}

function markdownSandbox(page: Page): FrameLocator {
  return page.frameLocator(".as-artifact-frame").frameLocator("iframe");
}

test.describe("Review Markdown preview", () => {
  test("PRV-006-B PRV-006-F: Markdown entries render as sanitized, theme-following, annotatable reader documents", async ({browser}) => {
    const fixture = await startBrowserFixture(browser);
    try {
      const plan = await publishPlan(fixture);
      await localLogin(fixture);
      await fixture.page.evaluate(() => window.localStorage.setItem("artifact-review-theme", "moon"));
      await fixture.page.goto(
        `${fixture.server.baseUrl}/review?project=prj_default&artifact=${plan.artifactId}&version=${plan.versionId}`,
      );

      const sandbox = markdownSandbox(fixture.page);
      const article = sandbox.locator("article.markdown-body");
      await expect(article.locator("h1#plan-overview")).toHaveText("Plan overview");
      await expect(article.locator("h2#rollout-details")).toHaveText("Rollout details");
      await expect(article.locator("table th")).toHaveText(["Phase", "Owner"]);
      await expect(article.locator("table td")).toHaveText(["Build", "Web", "Verify", "QA"]);
      await expect(article.locator('.task-list-item-checkbox[role="checkbox"]'))
        .toHaveCount(2);
      await expect(article.locator('.task-list-item-checkbox[aria-checked="true"]'))
        .toHaveCount(1);
      await expect(article.locator('pre[data-language="ts"] code'))
        .toHaveText("const answer: number = 42;");
      await expect(article.getByRole("link", {name: "https://example.com"}))
        .toHaveAttribute("href", "https://example.com");

      // Relative images resolve against the version's content host, never
      // against the application origin that renders Review.
      const image = article.getByRole("img", {name: "Status dot"});
      await expect.poll(() => image.evaluate((node) =>
        node instanceof HTMLImageElement ? node.naturalWidth : 0
      )).toBeGreaterThan(0);
      const imageUrl = new URL(await image.getAttribute("src") ?? "", "http://invalid");
      expect(imageUrl.origin).not.toBe(new URL(fixture.server.baseUrl).origin);
      expect(imageUrl.pathname).toMatch(/\/images\/dot\.png$/u);

      // The reader follows the Review palette and switches with it.
      const readerColors = () => sandbox.locator("body").evaluate(() => ({
        background: getComputedStyle(document.body).backgroundColor,
        light: document.documentElement.classList.contains("light"),
      }));
      const reviewBackground = () => fixture.page.evaluate(() =>
        getComputedStyle(document.body).backgroundColor
      );
      const darkReader = await readerColors();
      expect(darkReader.light).toBe(false);
      expect(darkReader.background).toBe(await reviewBackground());
      await fixture.page.getByRole("button", {name: "Use light theme"}).click();
      await expect.poll(readerColors).toMatchObject({light: true});
      expect((await readerColors()).background).toBe(await reviewBackground());
      expect((await readerColors()).background).not.toBe(darkReader.background);

      // In-page fragment links stay on the reader document.
      await fixture.page.keyboard.press("Escape");
      await article.getByRole("link", {name: "the details"}).click();
      await expect.poll(() => sandbox.locator("body").evaluate(() => ({
        href: window.location.href,
        scrolled: window.scrollY > 0,
      }))).toEqual({href: "about:srcdoc", scrolled: true});

      // Annotate mode works exactly as it does for HTML, and the comment is
      // stored against the Markdown file's manifest path.
      const header = fixture.page.locator(".as-preview-header__actions");
      await header.getByRole("button", {name: /^Interact mode:/u}).click();
      await expect(header.getByRole("button", {name: /^Annotate mode:/u})).toBeVisible();
      await article.locator("table td").filter({hasText: "Verify"}).click();
      const reviewFrame = fixture.page.frameLocator(".as-artifact-frame");
      const composer = reviewFrame.getByPlaceholder("Add a comment...");
      await expect(composer).toBeVisible();
      await composer.fill("Who signs off the verify phase?");
      await reviewFrame.getByRole("button", {name: "Save"}).click();
      await expect(async () => {
        const threads = await listThreadsOverApi(fixture, plan.artifactId);
        expect(threads).toHaveLength(1);
        expect(threads[0]?.body).toBe("Who signs off the verify phase?");
        expect(threads[0]?.path).toBe("review.md");
        expect(threads[0]?.versionId).toBe(plan.versionId);
        expect(JSON.stringify(threads[0]?.anchor)).toContain("Verify");
      }).toPass();

      // PRV-006-F: authored raw HTML cannot execute, frame, submit, or restyle.
      await expect(article.locator("#hostile-paragraph")).toHaveText("Click target");
      expect(await sandbox.locator("body").evaluate(() => ({
        forms: document.querySelectorAll("form, input, button, select, textarea").length,
        frames: document.querySelectorAll("iframe, object, embed, frame").length,
        handlerAttributes: [...document.querySelectorAll("*")].filter((node) =>
          [...node.attributes].some((attribute) => attribute.name.startsWith("on"))
        ).length,
        hidden: getComputedStyle(document.body).display === "none",
        javascriptLinks: [...document.querySelectorAll("a[href]")].filter((node) =>
          (node.getAttribute("href") ?? "").trim().toLowerCase().startsWith("javascript:")
        ).length,
        ranScript: "__markdownScript" in window,
        ranHandler: "__markdownHandler" in window || "__markdownClick" in window,
        scripts: document.querySelectorAll("article script").length,
        styles: document.querySelectorAll("article style").length,
      }))).toEqual({
        forms: 0,
        frames: 0,
        handlerAttributes: 0,
        hidden: false,
        javascriptLinks: 0,
        ranHandler: false,
        ranScript: false,
        scripts: 0,
        styles: 0,
      });

      // text/x-markdown and a `.md` path labelled text/plain use the reader;
      // other text/plain stays an honest unsupported fallback.
      await fixture.page.getByRole("tab", {name: /Files/u}).click();
      await fixture.page.locator(".as-file-list button").filter({hasText: "notes/plain.md"}).click();
      await expect(article.locator("h1#plain-label")).toHaveText("Plain label");
      await fixture.page.locator(".as-file-list button").filter({hasText: "notes/legacy.markdown"}).click();
      await expect(article.locator("h2#legacy-label")).toHaveText("Legacy label");
      await fixture.page.locator(".as-file-list button").filter({hasText: "notes/readme.txt"}).click();
      await expect(fixture.page.getByRole("heading", {name: "Preview not supported"})).toBeVisible();
      await expect(fixture.page.locator(".as-artifact-frame")).toHaveCount(0);

      // An oversized Markdown file settles into the typed fallback without
      // being fetched or rendered, and keeps the open and download actions.
      const large = await publishNew(fixture.server, fixture.installation, {
        accessSetting: "account_required",
        content: `# Large\n\n${"Long plan line.\n".repeat(150_000)}`,
        idempotencyKey: "prv-006-large-markdown",
        mediaType: "text/markdown; charset=utf-8",
        name: "Large Markdown",
        path: "large.md",
      });
      const versionFileRequests: string[] = [];
      fixture.page.on("request", (request) => {
        if (request.url().includes("/versions/") && request.url().includes("/file?")) {
          versionFileRequests.push(request.url());
        }
      });
      await fixture.page.goto(
        `${fixture.server.baseUrl}/review?project=prj_default&artifact=${large.body.artifact.id}&version=${large.body.version.id}`,
      );
      const fallback = fixture.page.locator(".as-preview-state--terminal");
      await expect(fallback.getByRole("heading", {name: "Preview not supported"})).toBeVisible();
      await expect(fallback).toContainText("larger than the 2 MiB inline preview limit");
      await expect(fallback.getByText("large.md", {exact: true})).toBeVisible();
      await expect(fallback.getByRole("button", {name: "Open raw artifact"})).toBeVisible();
      await expect(fallback.getByRole("link", {name: "Download file"})).toBeVisible();
      await expect(fixture.page.locator(".as-artifact-frame")).toHaveCount(0);
      await expect(fixture.page.locator(".as-preview-header__actions")
        .getByRole("button", {name: /^(?:Annotate|Interact) mode:/u})).toHaveCount(0);
      expect(versionFileRequests).toEqual([]);
    } finally {
      await stopBrowserFixture(fixture);
    }
  });
});

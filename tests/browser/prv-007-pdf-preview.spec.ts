import {expect, test, type Response} from "@playwright/test";

import {multiPagePdf} from "../support/pdf-fixture.js";
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

const reportBytes = multiPagePdf([
  ["Quarterly report", "Revenue grew in every region."],
  ["Appendix", "Methodology and sources."],
  ["Sign-off", "Approved for distribution."],
]);

const expectedShellPolicy = [
  "default-src 'self'",
  "base-uri 'none'",
  "connect-src 'self'",
  "font-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "frame-src 'self' http://*.localhost:* https://*.localhost",
  "img-src 'self' data:",
  "object-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
].join("; ");

async function publishReport(fixture: BrowserFixture): Promise<{
  readonly artifactId: string;
  readonly versionId: string;
}> {
  const files: readonly TestSiteFile[] = [
    {bytes: reportBytes, mediaType: "application/pdf", path: "reports/q3 report.pdf"},
    // Labelled as opaque bytes: the `.pdf` extension must not promote it.
    {bytes: reportBytes, mediaType: "application/octet-stream", path: "reports/unlabelled.pdf"},
  ];
  const upload = await createStagedUpload(
    fixture.server,
    fixture.installation,
    "reports/q3 report.pdf",
    files,
  );
  await uploadEveryStagedFile(fixture.installation, upload.body, files);
  const committed = await commitStagedUpload(fixture.installation, upload.body, "prv-007-pdf-report", {
    accessSetting: "account_required",
    kind: "new_artifact",
    name: "PDF report",
  });
  return {artifactId: committed.body.artifact.id, versionId: committed.body.version.id};
}

function isContentHostPdf(url: URL, applicationOrigin: string): boolean {
  return url.origin !== applicationOrigin
    && url.hostname.startsWith("review-")
    && url.pathname === "/reports/q3%20report.pdf";
}

// The full Chromium build in new headless mode ships the browser's own PDF
// viewer; the default headless shell has none and downloads framed PDFs.
test.use({channel: "chromium"});

test.describe("Review PDF preview", () => {
  test("PRV-007-B PRV-007-F: PDF entries open in the browser's PDF viewer from the version's isolated content host", async ({browser}) => {
    const fixture = await startBrowserFixture(browser);
    try {
      const report = await publishReport(fixture);
      const applicationOrigin = new URL(fixture.server.baseUrl).origin;
      const policyViolations: string[] = [];
      fixture.page.on("console", (message) => {
        if (/Content Security Policy|Refused to frame/iu.test(message.text())) {
          policyViolations.push(message.text());
        }
      });
      const pdfResponses: Response[] = [];
      fixture.page.on("response", (response) => {
        if (isContentHostPdf(new URL(response.url()), applicationOrigin)) {
          pdfResponses.push(response);
        }
      });
      await localLogin(fixture);

      const reviewUrl = `${fixture.server.baseUrl}/review?project=prj_default&artifact=${report.artifactId}&version=${report.versionId}`;
      const shell = await fixture.page.goto(reviewUrl);
      expect(shell?.status()).toBe(200);
      expect(shell?.headers()["content-security-policy"]).toBe(expectedShellPolicy);

      // An unsandboxed frame on the exact version's lease host, never on the
      // application origin.
      const frame = fixture.page.locator("iframe.as-pdf-preview__frame");
      await expect(frame).toHaveAttribute("title", "PDF report — reports/q3 report.pdf");
      expect(await frame.getAttribute("sandbox")).toBeNull();
      const frameSource = await frame.getAttribute("src") ?? "";
      const frameUrl = new URL(frameSource);
      expect(frameUrl.origin).not.toBe(applicationOrigin);
      expect(frameUrl.hostname).toMatch(/^review-[a-z0-9]+\.localhost$/u);
      expect(frameUrl.pathname).toBe("/reports/q3%20report.pdf");

      // The browser's PDF viewer loads inside that frame.
      await expect(fixture.page.locator(".as-pdf-preview")).toHaveAttribute("data-status", "ready");
      await expect.poll(() => fixture.page.frames().some((candidate) =>
        candidate.url().startsWith("chrome-extension://")
        && candidate.parentFrame()?.url() === frameSource
      )).toBe(true);

      // The framed navigation carried no cookie and received the declared
      // type inline, with nothing that refuses framing by the application.
      const delivered = pdfResponses.find((response) => response.url() === frameSource);
      if (delivered === undefined) throw new Error("The PDF frame's response was not observed.");
      expect(delivered.status()).toBe(200);
      expect(delivered.headers()["content-type"]).toBe("application/pdf");
      expect(delivered.headers()["content-disposition"]).toBe("inline");
      expect(delivered.headers()["content-length"]).toBe(String(reportBytes.byteLength));
      expect(delivered.headers()["x-content-type-options"]).toBe("nosniff");
      expect(delivered.headers()["x-frame-options"]).toBeUndefined();
      expect(delivered.headers()["content-security-policy"]).toBeUndefined();
      expect(delivered.request().resourceType()).toBe("document");
      expect(delivered.request().frame().parentFrame()).toBe(fixture.page.mainFrame());
      expect((await delivered.request().allHeaders())["cookie"]).toBeUndefined();
      const bytes = await fixture.page.request.get(frameSource);
      expect(Buffer.from(await bytes.body())).toEqual(Buffer.from(reportBytes));
      expect(policyViolations).toEqual([]);

      // Comments stay whole-file: there is nothing to annotate in place.
      await expect(fixture.page.locator(".as-preview-header__actions")
        .getByRole("button", {name: /^(?:Annotate|Interact) mode:/u})).toHaveCount(0);
      await expect(fixture.page.locator(".as-artifact-frame")).toHaveCount(0);

      // PRV-007-F: the same-origin media route still refuses PDF bytes.
      const media = await fixture.page.request.get(
        `${fixture.server.baseUrl}/api/v1/artifacts/${report.artifactId}/versions/${report.versionId}/media?${new URLSearchParams({path: "reports/q3 report.pdf", projectId: "prj_default"})}`,
      );
      expect(media.status()).toBe(415);

      // PRV-007-F: an extension never promotes opaque bytes into the viewer.
      await fixture.page.getByRole("tab", {name: /Files/u}).click();
      await fixture.page.locator(".as-file-list button").filter({hasText: "reports/unlabelled.pdf"}).click();
      await expect(fixture.page.getByRole("heading", {name: "Preview not supported"})).toBeVisible();
      await expect(frame).toHaveCount(0);

      // PRV-007-F: a lease that cannot be issued settles into the typed
      // fallback with retry, open, and download, and retry recovers.
      await fixture.page.route("**/preview-leases?**", (route) => route.fulfill({
        body: JSON.stringify({error: {code: "INTERNAL", message: "Preview lease unavailable."}}),
        contentType: "application/json",
        status: 503,
      }));
      await fixture.page.goto(reviewUrl);
      const fallback = fixture.page.locator(".as-preview-state--terminal");
      await expect(fallback.getByRole("heading", {name: "PDF preview unavailable"})).toBeVisible();
      await expect(fallback.getByRole("button", {name: "Open raw artifact"})).toBeVisible();
      await expect(fallback.getByRole("link", {name: "Download file"})).toBeVisible();
      await expect(frame).toHaveCount(0);
      await fixture.page.unroute("**/preview-leases?**");
      await fallback.getByRole("button", {name: "Retry preview"}).click();
      await expect(fixture.page.locator(".as-pdf-preview")).toHaveAttribute("data-status", "ready");
      expect(new URL(await frame.getAttribute("src") ?? "").hostname)
        .not.toBe(frameUrl.hostname);

      // PRV-007-F: a frame the browser never displays (here, a PDF that never
      // arrives) still settles, keeping the open and download actions.
      await fixture.page.clock.install();
      await fixture.page.route(
        (url) => isContentHostPdf(url, applicationOrigin),
        () => undefined,
      );
      await fixture.page.goto(reviewUrl);
      await expect(frame).toHaveCount(1);
      await expect(fixture.page.locator(".as-pdf-preview")).toHaveAttribute("data-status", "loading");
      await fixture.page.clock.fastForward(16_000);
      const stalled = fixture.page.locator(".as-pdf-preview__stalled");
      await expect(stalled).toContainText("The PDF has not appeared yet");
      await expect(stalled.getByRole("button", {name: "Open raw artifact"})).toBeVisible();
      await expect(stalled.getByRole("link", {name: "Download file"})).toBeVisible();
      await expect(stalled.getByRole("button", {name: "Retry preview"})).toBeVisible();
      await fixture.page.unrouteAll({behavior: "ignoreErrors"});
      expect(policyViolations).toEqual([]);
    } finally {
      await stopBrowserFixture(fixture);
    }
  });
});

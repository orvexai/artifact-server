import {expect, test} from "@playwright/test";

import {publishNew, publishVersion} from "../support/publishing.js";
import {
  localLogin,
  startBrowserFixture,
  stopBrowserFixture,
} from "./browser-fixture.js";

test.describe("Review Compare", () => {
  test("a changed small text file shows its added and removed line regions", async ({browser}) => {
    const fixture = await startBrowserFixture(browser);
    try {
      const first = await publishNew(fixture.server, fixture.installation, {
        accessSetting: "account_required",
        content: "alpha\nbravo\ncharlie\ndelta\necho\n",
        idempotencyKey: "review-compare-first",
        mediaType: "text/plain; charset=utf-8",
        name: "Compare fixture",
        path: "notes.txt",
      });
      await publishVersion(fixture.server, fixture.installation, {
        artifactId: first.body.artifact.id,
        content: "alpha\nBRAVO\ncharlie\necho\nfoxtrot\n",
        expectedCurrentVersionId: first.body.version.id,
        idempotencyKey: "review-compare-second",
        mediaType: "text/plain; charset=utf-8",
        path: "notes.txt",
      });

      await localLogin(fixture);
      await fixture.page.goto(
        `${fixture.server.baseUrl}/review?project=prj_default&artifact=${first.body.artifact.id}`,
      );
      await expect(fixture.page.getByRole("heading", {name: "Compare fixture"})).toBeVisible();
      await fixture.page.getByRole("tab", {name: "Versions"}).click();
      await fixture.page.getByRole("button", {name: "Compare", exact: true}).click();

      const panel = fixture.page.getByRole("tabpanel", {name: "Compare"});
      await expect(panel.getByRole("heading", {name: "Changed files"})).toBeVisible();
      await expect(panel.getByText("Comparison unavailable")).toHaveCount(0);
      await expect(panel.getByText("notes.txt", {exact: true})).toBeVisible();

      const lines = panel.getByRole("group", {name: "Line changes in notes.txt"});
      await expect(lines).toBeVisible();
      await expect(lines.locator(".as-diff__stats [data-kind=added]")).toHaveText("+2");
      await expect(lines.locator(".as-diff__stats [data-kind=removed]")).toHaveText("−2");
      await expect(lines.locator(".as-diff__line[data-kind=removed] code"))
        .toHaveText(["bravo", "delta"]);
      await expect(lines.locator(".as-diff__line[data-kind=added] code"))
        .toHaveText(["BRAVO", "foxtrot"]);
      await expect(lines.locator(".as-diff__header").first()).toHaveText("@@ −2,1 +2,1 @@");
    } finally {
      await stopBrowserFixture(fixture);
    }
  });
});

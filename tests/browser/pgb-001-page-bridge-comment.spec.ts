import {expect, test} from "@playwright/test";

import {publishNew} from "../support/publishing.js";
import {localLogin, startBrowserFixture, stopBrowserFixture} from "./browser-fixture.js";
import {listThreadsOverApi} from "./comment-api.js";

const commentBody = "Triage: ship the release notes";

async function publishPage(
  fixture: Awaited<ReturnType<typeof startBrowserFixture>>,
  name: string,
  html: string,
  idempotencyKey: string,
) {
  return (await publishNew(fixture.server, fixture.installation, {
    accessSetting: "account_required",
    content: html,
    idempotencyKey,
    mediaType: "text/html; charset=utf-8",
    name,
    path: "index.html",
  })).body;
}

async function openExactReview(
  fixture: Awaited<ReturnType<typeof startBrowserFixture>>,
  artifactId: string,
  versionId: string,
): Promise<void> {
  await fixture.page.goto(
    `${fixture.server.baseUrl}/review?project=prj_default&artifact=${artifactId}&version=${versionId}`,
  );
  await expect(fixture.page.locator(".as-artifact-frame")).toBeVisible();
}

test("PGB-001-B: a page posts a comment thread as the viewer after the viewer confirms", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const pageHtml = `<!doctype html><html lang="en"><head><title>Comment bridge</title></head><body><script>
      window.addEventListener("load", () => {
        window.artifactServer.comments.create(${JSON.stringify(commentBody)}, {path: "index.html"})
          .then(({threadId}) => { document.body.dataset.result = threadId; })
          .catch((error) => { document.body.dataset.error = error.message; });
      });
    </script></body></html>`;
    const published = await publishPage(
      fixture,
      "Page bridge comment",
      pageHtml,
      "pgb-001-behavior",
    );

    const dialogMessages: string[] = [];
    fixture.page.on("dialog", async (dialog) => {
      dialogMessages.push(dialog.message());
      await dialog.accept();
    });
    await localLogin(fixture);
    await openExactReview(fixture, published.artifact.id, published.version.id);

    const pageBody = fixture.page.frameLocator(".as-artifact-frame")
      .frameLocator("iframe").locator("body");
    await expect(pageBody).toHaveAttribute("data-result", /^cmt_/u);
    expect(dialogMessages).toHaveLength(1);
    expect(dialogMessages[0]).toContain(commentBody);

    await expect(async () => {
      const threads = await listThreadsOverApi(fixture, published.artifact.id);
      expect(threads).toHaveLength(1);
      expect(threads[0]).toMatchObject({
        body: commentBody,
        id: await pageBody.getAttribute("data-result"),
        path: "index.html",
        versionId: published.version.id,
      });
    }).toPass();
  } finally {
    await stopBrowserFixture(fixture);
  }
});

test("PGB-001-F: declined, unknown, and over-limit page posts create no thread", async ({browser}) => {
  const fixture = await startBrowserFixture(browser);
  try {
    const longBody = "x".repeat(600);
    const declined = await publishPage(
      fixture,
      "Declined page bridge comment",
      `<!doctype html><html lang="en"><body><script>
        window.addEventListener("load", () => {
          window.artifactServer.comments.create(${JSON.stringify(longBody)}, {path: "index.html"})
            .then(({threadId}) => { document.body.dataset.result = threadId; })
            .catch((error) => { document.body.dataset.error = error.message; });
        });
      </script></body></html>`,
      "pgb-001-declined",
    );
    const unknown = await publishPage(
      fixture,
      "Unknown page bridge operation",
      `<!doctype html><html lang="en"><body><script>
        window.addEventListener("load", () => {
          window.parent.postMessage({
            type: "as-artifact-bridge-request",
            v: 1,
            id: "page-unknown-operation-0001",
            operation: "comment_delete",
            body: "x"
          }, "*");
          window.artifactServer.state.list().then(() => {
            document.body.dataset.done = "true";
          });
        });
      </script></body></html>`,
      "pgb-001-unknown01",
    );
    const overLimit = await publishPage(
      fixture,
      "Over-limit page bridge comment",
      `<!doctype html><html lang="en"><body><script>
        window.addEventListener("load", () => {
          Promise.all(Array.from({length: 30}, () => window.artifactServer.state.list()))
            .then(() => window.artifactServer.comments.create("over limit"))
            .then(({threadId}) => { document.body.dataset.result = threadId; })
            .catch((error) => { document.body.dataset.error = error.message; });
        });
      </script></body></html>`,
      "pgb-001-over-limit",
    );

    const dialogMessages: string[] = [];
    fixture.page.on("dialog", async (dialog) => {
      dialogMessages.push(dialog.message());
      await dialog.dismiss();
    });
    await localLogin(fixture);

    await openExactReview(fixture, declined.artifact.id, declined.version.id);
    const frameBody = fixture.page.frameLocator(".as-artifact-frame")
      .frameLocator("iframe").locator("body");
    await expect(frameBody).toHaveAttribute("data-error", "The viewer declined the comment.");
    expect(dialogMessages).toHaveLength(1);
    expect(dialogMessages[0]).toContain("x".repeat(500));
    expect(dialogMessages[0]).toContain("(600 characters in total; only the first 500 are shown.)");
    expect(await listThreadsOverApi(fixture, declined.artifact.id)).toHaveLength(0);

    await openExactReview(fixture, unknown.artifact.id, unknown.version.id);
    const unknownBody = fixture.page.frameLocator(".as-artifact-frame")
      .frameLocator("iframe").locator("body");
    await expect(unknownBody).toHaveAttribute("data-done", "true");
    expect(dialogMessages).toHaveLength(1);
    expect(await listThreadsOverApi(fixture, unknown.artifact.id)).toHaveLength(0);

    await openExactReview(fixture, overLimit.artifact.id, overLimit.version.id);
    const overLimitBody = fixture.page.frameLocator(".as-artifact-frame")
      .frameLocator("iframe").locator("body");
    await expect(overLimitBody).toHaveAttribute(
      "data-error",
      "Artifact bridge request limit exceeded.",
    );
    expect(dialogMessages).toHaveLength(1);
    expect(await listThreadsOverApi(fixture, overLimit.artifact.id)).toHaveLength(0);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

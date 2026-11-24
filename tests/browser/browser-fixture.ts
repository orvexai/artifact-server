import {expect, type APIResponse, type Browser, type BrowserContext, type Page} from "@playwright/test";

import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

/** One browser test's own installation, server, and signed-in page. */
export interface BrowserFixture {
  readonly context: BrowserContext;
  readonly installation: TestInstallation;
  readonly page: Page;
  readonly server: RunningTestServer;
}

export async function startBrowserFixture(
  browser: Browser,
  options: {readonly timezoneId?: string} = {},
): Promise<BrowserFixture> {
  const installation = await createTestInstallation();
  const server = await startTestServer(installation);
  const context = await browser.newContext(options);
  const page = await context.newPage();
  return {context, installation, page, server};
}

export async function stopBrowserFixture(fixture: BrowserFixture): Promise<void> {
  await fixture.context.close();
  await fixture.server.stop();
  await removeTestInstallation(fixture.installation);
}

export async function localLogin(
  fixture: BrowserFixture,
  waitForApplication = true,
): Promise<void> {
  await fixture.page.goto(fixture.server.baseUrl);
  if (waitForApplication) {
    await expect(fixture.page.getByRole("link", {name: "Houston Artifacts"})).toBeVisible();
    await expect(fixture.page).toHaveURL(/\/review\?project=prj_default/u);
  }
}

/** Create a public link through the signed-in human browser session. */
export async function createPublicLinkAsHuman(
  fixture: BrowserFixture,
  artifactId: string,
  permission: "view" | "comment" = "view",
): Promise<APIResponse> {
  await localLogin(fixture);
  const csrf = (await fixture.context.cookies()).find(({name}) => name === "artifact_csrf")?.value;
  if (csrf === undefined) throw new Error("Signed-in browser did not receive its CSRF cookie.");
  return fixture.page.request.post(
    `${fixture.server.baseUrl}/api/v1/artifacts/${encodeURIComponent(artifactId)}/public-link?projectId=prj_default`,
    {
      data: {permission},
      headers: {
        Origin: fixture.server.baseUrl,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "X-CSRF-Token": csrf,
      },
    },
  );
}

export async function closeTopDialog(page: Page): Promise<void> {
  await page.keyboard.press("Escape");
}

/** Everything this application is forbidden to keep in the browser. */
export async function browserStorage(page: Page): Promise<{
  readonly indexedDatabaseNames: readonly string[];
  readonly localStorageKeys: readonly string[];
  readonly sessionStorageKeys: readonly string[];
}> {
  return page.evaluate(async () => ({
    indexedDatabaseNames: (await indexedDB.databases())
      .map((database) => database.name)
      .filter((name): name is string => name !== undefined),
    localStorageKeys: Object.keys(localStorage),
    sessionStorageKeys: Object.keys(sessionStorage),
  }));
}

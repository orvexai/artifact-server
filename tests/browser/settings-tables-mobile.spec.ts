import {expect, test, type Browser, type Page} from "@playwright/test";

import {publishNew} from "../support/publishing.js";
import {closeTopDialog, localLogin, startBrowserFixture, stopBrowserFixture} from "./browser-fixture.js";

const groupName = "Directory group with a deliberately descriptive name for wide table wrapping";

async function prepareSettingsFixture(
  browser: Browser,
  mobile: boolean,
) {
  const started = await startBrowserFixture(browser);
  if (!mobile) {
    await started.page.setViewportSize({width: 1280, height: 900});
  }
  const context = mobile
    ? await browser.newContext({
      hasTouch: true,
      isMobile: true,
      viewport: {width: 390, height: 844},
    })
    : started.context;
  if (mobile) await started.context.close();
  const page = mobile ? await context.newPage() : started.page;
  const fixture = {...started, context, page};

  await fixture.page.route("**/api/v1/groups", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        groups: [
          {
            hasHigherRoleOverlap: false,
            id: "group-long",
            memberCount: 12,
            name: groupName,
            path: "/Engineering/Artifact Server",
            role: "viewer",
            syncedAt: "2026-11-23T12:00:00.000Z",
          },
          {
            hasHigherRoleOverlap: false,
            id: "group-short",
            memberCount: 3,
            name: "Support",
            path: "/Support",
            role: "viewer",
            syncedAt: "2026-11-23T11:00:00.000Z",
          },
        ],
      }),
      contentType: "application/json",
      status: 200,
    });
  });

  await publishNew(fixture.server, fixture.installation, {
    accessSetting: "public_link",
    content: "<!doctype html><html lang=\"en\"><title>Mobile settings link</title></html>",
    idempotencyKey: "artifact-server-iun-settings-public-link",
    name: "Mobile public link",
  });

  await localLogin(fixture);
  await fixture.page.goto(fixture.server.baseUrl + "/review/settings/members");
  await expect(fixture.page.getByRole("heading", {name: "Members", exact: true})).toBeVisible();
  await expect(fixture.page.getByRole("table", {name: "Members"})).toBeVisible();
  await fixture.page.getByRole("button", {name: "Admit member"}).click();
  await fixture.page.getByLabel("Display name", {exact: true}).fill("Mobile settings member");
  await fixture.page.getByLabel("Email", {exact: true}).fill("mobile-settings-member@example.test");
  await expect(fixture.page.getByLabel("Display name", {exact: true}))
    .toHaveValue("Mobile settings member");
  await expect(fixture.page.getByLabel("Email", {exact: true}))
    .toHaveValue("mobile-settings-member@example.test");
  await fixture.page.getByRole("button", {name: "Admit member", exact: true}).last().click();
  await closeTopDialog(fixture.page);
  await expect(
    fixture.page.getByRole("row").filter({hasText: "Mobile settings member"}),
  ).toBeVisible();

  return fixture;
}

async function expectInventoryFits(
  page: Page,
  selector: string,
): Promise<void> {
  await expect.poll(async () => page.locator(selector).evaluate(
    (element) => element.scrollWidth - element.clientWidth,
  )).toBe(0);
}

async function expectLastColumnInside(
  page: Page,
  inventorySelector: string,
  lastCellSelector: string,
): Promise<void> {
  await expect.poll(async () => {
    const inventory = await page.locator(inventorySelector).boundingBox();
    const cell = await page.locator(lastCellSelector).first().boundingBox();
    return inventory !== null && cell !== null &&
      cell.x >= inventory.x && cell.x + cell.width <= inventory.x + inventory.width;
  }).toBe(true);
}

async function expectExplicitTableRoles(
  page: Page,
  tableName: string,
): Promise<void> {
  const table = page.getByRole("table", {name: tableName});
  await expect(table).toBeVisible();
  const allRolesExplicit = await table.evaluate((element) => {
    const hasRole = (selector: string, role: string) =>
      Array.from(element.querySelectorAll(selector))
        .every((child) => child.getAttribute("role") === role);
    return element.getAttribute("role") === "table" &&
      hasRole("tr", "row") &&
      hasRole("th", "columnheader") &&
      hasRole("td", "cell");
  });
  expect(allRolesExplicit).toBe(true);
}

test("artifact-server-iun: Members, Groups and Public links stay usable at 390px", async ({browser}) => {
  const fixture = await prepareSettingsFixture(browser, true);
  try {
    const pageOverflow = () => fixture.page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );

    await expectInventoryFits(fixture.page, "#settings-members-table");
    await expect.poll(pageOverflow).toBe(0);
    await expectExplicitTableRoles(fixture.page, "Members");
    const memberDeactivate = fixture.page.getByRole("button", {name: "Deactivate"}).first();
    await expect(memberDeactivate).toBeVisible();
    await expectLastColumnInside(
      fixture.page,
      "#settings-members-table",
      ".as-members-table__actions-cell",
    );

    await fixture.page.goto(fixture.server.baseUrl + "/review/settings/groups");
    await expect(fixture.page.getByRole("table", {name: "Groups"})).toBeVisible();
    await expectInventoryFits(fixture.page, "#settings-groups-table");
    await expect.poll(pageOverflow).toBe(0);
    await expectExplicitTableRoles(fixture.page, "Groups");
    const lastSynced = fixture.page.locator(".as-groups-table__synced").first();
    await expect(lastSynced).toContainText("Last synced");
    await expectLastColumnInside(
      fixture.page,
      "#settings-groups-table",
      ".as-groups-table__synced",
    );

    await fixture.page.goto(fixture.server.baseUrl + "/review/settings/public-links");
    await expect(fixture.page.getByRole("heading", {name: "Public links"})).toBeVisible();
    await expectExplicitTableRoles(fixture.page, "Public links inventory");
    await expectInventoryFits(fixture.page, ".as-public-links-inventory");
    await expect.poll(pageOverflow).toBe(0);
    const openLink = fixture.page.getByRole("link", {name: "Open"}).first();
    await expect(openLink).toBeVisible();
    await expectLastColumnInside(
      fixture.page,
      ".as-public-links-inventory",
      ".as-public-links-table__actions-cell",
    );
  } finally {
    await stopBrowserFixture(fixture);
  }
});

async function checkWideTables(
  fixture: Awaited<ReturnType<typeof prepareSettingsFixture>>,
  width: number,
  checkHeaders: boolean,
): Promise<void> {
  await fixture.page.setViewportSize({width, height: 900});
  await fixture.page.goto(fixture.server.baseUrl + "/review/settings/members");
  const membersTable = fixture.page.getByRole("table", {name: "Members"});
  await expect(membersTable).toBeVisible();
  await expectInventoryFits(fixture.page, "#settings-members-table");
  await expect(membersTable).toHaveCSS("table-layout", "auto");
  await expectLastColumnInside(
    fixture.page,
    "#settings-members-table",
    ".as-members-table__actions-cell",
  );
  await expect(fixture.page.getByRole("button", {name: "Deactivate"}).first()).toBeVisible();
  if (checkHeaders) {
    await Promise.all(
      ["Member", "Role", "Status", "Admitted", "Actions"].map((name) =>
        expect(membersTable.getByRole("columnheader", {name, exact: true})).toBeVisible()
      ),
    );
  }

  await fixture.page.goto(fixture.server.baseUrl + "/review/settings/groups");
  const groupsTable = fixture.page.getByRole("table", {name: "Groups"});
  await expect(groupsTable).toBeVisible();
  await expectInventoryFits(fixture.page, "#settings-groups-table");
  await expect(groupsTable).toHaveCSS("table-layout", "auto");
  await expectLastColumnInside(
    fixture.page,
    "#settings-groups-table",
    ".as-groups-table__synced",
  );
  await expect(fixture.page.locator(".as-groups-table__synced").first())
    .toContainText("Last synced");

  if (checkHeaders) {
    await Promise.all(
      ["Group", "Members", "Role", "Last synced"].map((name) =>
        expect(groupsTable.getByRole("columnheader", {name, exact: true})).toBeVisible()
      ),
    );
  }
}

test("artifact-server-iun: wide Members and Groups tables fit at 800 and 1024px without fixed layout", async ({browser}) => {
  const fixture = await prepareSettingsFixture(browser, false);
  try {
    await checkWideTables(fixture, 800, false);
    await checkWideTables(fixture, 1024, true);
  } finally {
    await stopBrowserFixture(fixture);
  }
});

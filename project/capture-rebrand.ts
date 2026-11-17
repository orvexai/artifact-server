/**
 * Manual, non-CI Houston Artifacts screenshot matrix.
 * Run from the repository root with: pnpm exec tsx project/capture-rebrand.ts
 */
/* oxlint-disable no-await-in-loop -- Captures are intentionally sequential to preserve output order. */
import {createHash} from "node:crypto";
import {mkdir, writeFile} from "node:fs/promises";
import path from "node:path";

import {AxeBuilder} from "@axe-core/playwright";
import {chromium, type Page} from "@playwright/test";

import {
  renderNoOrganizationPage,
  renderOrganizationChooser,
} from "../src/external-storage/create-organization-router.js";
import {renderIdentityAdmissionDeniedPage} from "../src/http/create-http-app.js";
import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
} from "../tests/support/runtime-harness.js";
import {publishNew} from "../tests/support/publishing.js";

const outputDirectory = path.resolve("project/evidence/rebrand");
const installation = await createTestInstallation();
const server = await startTestServer(installation);
const browser = await chromium.launch({headless: true});

try {
  await mkdir(outputDirectory, {recursive: true});
  const artifact = await publishNew(server, installation, {
    accessSetting: "account_required",
    content: "<!doctype html><title>Release dashboard</title><main><h1>Release dashboard</h1><p>Review-ready artifact content.</p></main>",
    idempotencyKey: "houston-rebrand-visual-matrix",
    name: "Release dashboard",
    tags: ["visual-review"],
  });

  for (const theme of ["light", "dark"] as const) {
    const context = await browser.newContext({
      colorScheme: theme,
      viewport: {height: 900, width: 1280},
    });
    await context.addInitScript((savedTheme) => {
      localStorage.setItem("artifact-review-theme", savedTheme);
    }, theme === "light" ? "dawn" : "moon");
    const page = await context.newPage();
    const pixelCheckPage = await context.newPage();

    try {
      await serveTemplate(page, server.baseUrl, "org-chooser", renderOrganizationChooser([
        {displayName: "Orvex", slug: "orvex"},
        {displayName: "Houston Research", slug: "research"},
      ]));
      await serveTemplate(page, server.baseUrl, "no-org", renderNoOrganizationPage());
      await serveTemplate(page, server.baseUrl, "sign-in-unavailable", renderIdentityAdmissionDeniedPage());
      for (const viewport of [
        {height: 900, width: 1280},
        {height: 844, width: 390},
      ]) {
        await page.setViewportSize(viewport);
        const size = String(viewport.width);

        await page.goto(`${server.baseUrl}/review?project=prj_default&artifact=${encodeURIComponent(artifact.body.artifact.id)}`);
        await page.getByRole("heading", {name: "Release dashboard"}).waitFor();
        await capture(page, pixelCheckPage, `review-artifact-${theme}-${size}.png`);

        await page.goto(`${server.baseUrl}/review/settings/projects`);
        await page.getByRole("heading", {name: "Projects"}).waitFor();
        await capture(page, pixelCheckPage, `settings-projects-${theme}-${size}.png`);

        await page.goto(`${server.baseUrl}/review/settings/mcp`);
        await page.locator("main").waitFor({state: "visible"});
        await capture(page, pixelCheckPage, `settings-mcp-${theme}-${size}.png`);

        await page.goto(`${server.baseUrl}/__rebrand/org-chooser`);
        await page.getByRole("heading", {name: "Choose an organization"}).waitFor();
        await capture(page, pixelCheckPage, `org-chooser-${theme}-${size}.png`);

        await page.goto(`${server.baseUrl}/__rebrand/no-org`);
        await page.getByRole("heading", {name: "No organization available"}).waitFor();
        await capture(page, pixelCheckPage, `no-org-${theme}-${size}.png`);

        await page.goto(`${server.baseUrl}/__rebrand/sign-in-unavailable`);
        await page.getByRole("heading", {name: /sign you in to Houston Artifacts/u}).waitFor();
        await capture(page, pixelCheckPage, `sign-in-unavailable-${theme}-${size}.png`);
      }
    } finally {
      await context.close();
    }
  }

  await writeContactSheet();
  process.stdout.write(`Captured 24 screenshots in ${outputDirectory}\n`);
} finally {
  await browser.close();
  await server.stop();
  await removeTestInstallation(installation);
}

async function writeContactSheet(): Promise<void> {
  const screens = [
    {id: "review-artifact", title: "Review page with an artifact"},
    {id: "settings-projects", title: "Settings: Projects"},
    {id: "settings-mcp", title: "Settings: MCP"},
    {id: "org-chooser", title: "Organization chooser"},
    {id: "no-org", title: "No organization"},
    {id: "sign-in-unavailable", title: "Sign-in unavailable"},
  ];
  const groups = [
    {title: "Desktop · light · 1280 × 900", theme: "light", width: "1280"},
    {title: "Desktop · dark · 1280 × 900", theme: "dark", width: "1280"},
    {title: "Mobile · light · 390 × 844", theme: "light", width: "390"},
    {title: "Mobile · dark · 390 × 844", theme: "dark", width: "390"},
  ];
  const sections = groups.map(({title, theme, width}) => {
    const figures = screens.map(({id, title: screenTitle}) => {
      const filename = `${id}-${theme}-${width}.png`;
      return `<figure><a href="./${filename}"><img loading="lazy" src="./${filename}" alt="${screenTitle}, ${theme} theme, ${width}px viewport"></a><figcaption>${screenTitle}</figcaption></figure>`;
    }).join("\n");
    return `<section><h2>${title}</h2><div class="grid">${figures}</div></section>`;
  }).join("\n");
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Houston Artifacts · R4 visual review</title>
  <style>
    :root { color-scheme: light dark; font: 16px/1.5 system-ui, sans-serif; }
    body { margin: 0; padding: 2rem; background: Canvas; color: CanvasText; }
    main { max-width: 1600px; margin: auto; }
    h1 { margin-top: 0; }
    section { margin-block: 3rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 1rem; }
    figure { margin: 0; }
    img { display: block; width: 100%; height: auto; border: 1px solid GrayText; }
    figcaption { padding-block: .4rem; font-size: .9rem; }
    @media (max-width: 600px) { body { padding: 1rem; } }
  </style>
</head>
<body>
  <main>
    <h1>Houston Artifacts · R4 visual review</h1>
    <p>24 screenshots across six screens, two color themes, and desktop and mobile widths. Each capture passed WCAG AA text-contrast checks and the visible-name and indigo/violet sanity checks.</p>
    ${sections}
  </main>
</body>
</html>
`;
  await writeFile(path.join(outputDirectory, "index.html"), html, "utf8");
}

async function serveTemplate(
  page: Page,
  baseUrl: string,
  name: string,
  html: string,
): Promise<void> {
  const route = `${baseUrl}/__rebrand/${name}`;
  const style = html.match(/<style>([\s\S]*?)<\/style>/u)?.[1];
  if (style === undefined) throw new Error(`The ${name} page has no inline style block.`);
  const styleHash = createHash("sha256").update(style).digest("base64");
  const isSignInUnavailable = name === "sign-in-unavailable";
  const contentSecurityPolicy = isSignInUnavailable
    ? "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'; font-src 'self'"
    : `default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; img-src 'self' data:; style-src 'self' 'sha256-${styleHash}'; font-src 'self'`;

  await page.route(route, (requestRoute) => requestRoute.fulfill({
    body: html,
    contentType: "text/html; charset=utf-8",
    headers: {"Content-Security-Policy": contentSecurityPolicy},
    status: 200,
  }));
}

async function capture(page: Page, pixelCheckPage: Page, filename: string): Promise<void> {
  const visibleText = await page.locator("body").innerText();
  if (/Artifact Server/iu.test(visibleText)) {
    throw new Error(`${filename} shows the retired visible product name.`);
  }

  await page.evaluate(() => document.fonts.ready.then(() => true));
  const screenshot = await page.screenshot({
    animations: "disabled",
    fullPage: true,
    path: path.join(outputDirectory, filename),
  });
  const contrast = await new AxeBuilder({page}).withRules(["color-contrast"]).analyze();
  if (contrast.violations.length > 0) {
    const details = await Promise.all(contrast.violations.map(async (violation) => {
      const nodes = await Promise.all(violation.nodes.map(async (node) => {
        const target = node.target[0];
        const selector = Array.isArray(target) ? target.at(-1) : target;
        const computed = await page.locator(selector ?? "body").evaluate((element) => {
          const style = getComputedStyle(element);
          const root = getComputedStyle(document.documentElement);
          return {
            background: style.backgroundColor,
            color: style.color,
            primaryForeground: root.getPropertyValue("--primary-foreground").trim(),
            oxOnAccent: root.getPropertyValue("--ox-color-on-accent").trim(),
            theme: document.documentElement.dataset["theme"],
            classes: element.className,
          };
        });
        return `${node.target.join(" ")} (${node.html}; ${JSON.stringify(computed)}; ${node.failureSummary ?? "no summary"})`;
      }));
      return `${violation.id}: ${nodes.join(", ")}`;
    })).then((lines) => lines.join("\n"));
    throw new Error(`${filename} has WCAG text-contrast violations:\n${details}`);
  }
  const indigoPixels = await pixelCheckPage.evaluate(async (base64Png) => {
    const image = new Image();
    image.src = `data:image/png;base64,${base64Png}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d");
    if (context === null) throw new Error("Could not inspect screenshot pixels.");
    context.drawImage(image, 0, 0);
    const {data} = context.getImageData(0, 0, canvas.width, canvas.height);
    let count = 0;
    for (let index = 0; index < data.length; index += 4) {
      const red = data[index] ?? 0;
      const green = data[index + 1] ?? 0;
      const blue = data[index + 2] ?? 0;
      const maximum = Math.max(red, green, blue);
      const minimum = Math.min(red, green, blue);
      if (maximum === minimum || maximum === 0) continue;
      const delta = maximum - minimum;
      const saturation = delta / maximum;
      let hue = 0;
      if (maximum === red) hue = 60 * (((green - blue) / delta) % 6);
      else if (maximum === green) hue = 60 * ((blue - red) / delta + 2);
      else hue = 60 * ((red - green) / delta + 4);
      if (hue < 0) hue += 360;
      // The Houston text token is intentionally deep navy (hue near 225).
      // Ignore that neutral text and dark antialiasing; flag saturated purple-blue.
      if (hue >= 235 && hue <= 315 && saturation >= 0.5 && maximum >= 144) count += 1;
    }
    return count;
  }, screenshot.toString("base64"));
  if (indigoPixels > 0) {
    throw new Error(`${filename} contains ${indigoPixels} blue-violet pixels.`);
  }
  process.stdout.write(`${filename}: contrast AA, no retired name, no blue-violet pixels\n`);
}

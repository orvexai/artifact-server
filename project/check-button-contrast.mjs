/**
 * Manual button contrast matrix against the built web CSS (not a CI test).
 * Run after `pnpm build` with `pnpm exec tsx project/check-button-contrast.mjs`.
 */
import {readdir, readFile} from "node:fs/promises";
import {join, resolve} from "node:path";

import {chromium} from "@playwright/test";

/* oxlint-disable no-await-in-loop -- The manual matrix intentionally records browser states sequentially. */
const assetsDir = resolve("dist/web/assets");
const stylesheetName = (await readdir(assetsDir)).find(
  (name) => /^review-[^.]+\.css$/.test(name) && !name.startsWith("review-frame-"),
);

if (stylesheetName === undefined) {
  throw new Error(`No built review stylesheet in ${assetsDir}; run pnpm build first.`);
}

const stylesheet = await readFile(join(assetsDir, stylesheetName), "utf8");
const variants = {
  default: "bg-primary text-primary-foreground hover:bg-primary/80",
  destructive:
    "bg-destructive/10 text-destructive hover:bg-destructive-hover active:bg-destructive-hover dark:bg-destructive/10 dark:hover:bg-destructive-hover dark:active:bg-destructive-hover",
  link: "text-accent-text-strong underline underline-offset-4 hover:underline",
  outline:
    "border-border bg-transparent hover:bg-muted hover:text-foreground dark:hover:bg-input/30",
  secondary:
    "bg-secondary text-secondary-foreground hover:bg-[color-mix(in_oklch,var(--secondary),var(--foreground)_5%)]",
  ghost: "hover:bg-muted hover:text-foreground dark:hover:bg-muted/50",
};
const baseClass =
  "inline-flex items-center justify-center rounded-none border border-transparent bg-clip-padding text-xs font-semibold transition-all outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30 active:not-aria-[haspopup]:translate-y-px";
const states = ["rest", "hover", "active", "focus"];
const surfaces = ["background", "card", "secondary"];
const measurements = [];

const browser = await chromium.launch({headless: true});
const browserPage = await browser.newPage({viewport: {width: 1280, height: 800}});

try {
  for (const theme of ["light", "dark"]) {
    for (const [variant, variantClass] of Object.entries(variants)) {
      const bySurface = [];
      for (const surface of surfaces) {
        await loadFixture(browserPage, stylesheet, theme, surface, variantClass);
        const button = browserPage.locator("#sample");
        const values = {};

        values.rest = await measure(button);
        await button.hover();
        values.hover = await measure(button);
        await browserPage.mouse.down();
        values.active = await measure(button);
        await browserPage.mouse.up();
        await browserPage.mouse.move(0, 0);
        await button.focus();
        values.focus = await measure(button);
        bySurface.push(values);
      }

      const values = Object.fromEntries(
        states.map((state) => [
          state,
          bySurface.slice(1).reduce(
            (worst, current) => (current[state].ratio < worst.ratio ? current[state] : worst),
            bySurface[0][state],
          ),
        ]),
      );
      measurements.push({variant, theme, values});
    }
  }
} finally {
  await browser.close();
}

console.log("| Variant | Theme | Rest (worst surface) | Hover | Active | Focus |");
console.log("| --- | --- | ---: | ---: | ---: | ---: |");
for (const {variant, theme, values} of measurements) {
  const cells = states.map((state) => {
    const {background, foreground, ratio} = values[state];
    return `${ratio.toFixed(2)}:1 (${foreground} on ${background})`;
  });
  console.log(`| ${variant} | ${theme} | ${cells.join(" | ")} |`);
}

const failures = measurements.flatMap(({variant, theme, values}) =>
  states.flatMap((state) =>
    values[state].ratio < 4.5 ? [`${theme} ${variant} ${state}: ${values[state].ratio.toFixed(2)}:1`] : [],
  ),
);
if (failures.length > 0) {
  throw new Error(`Text contrast below WCAG AA:\n${failures.join("\n")}`);
}

console.log(`All ${measurements.length * states.length * surfaces.length} button state/theme/surface combinations meet 4.5:1.`);

async function loadFixture(fixturePage, css, theme, surface, variantClass) {
  await fixturePage.setContent(
    `<html data-theme="${theme}"${theme === "dark" ? ' class="dark"' : ""}><body><main id="surface" style="--sample-surface:var(--${surface})"><button id="sample" class="${baseClass} ${variantClass}">Button</button></main></body></html>`,
  );
  await fixturePage.addStyleTag({content: css});
  await fixturePage.addStyleTag({
    content:
      "html,body{margin:0;min-height:100%;}#surface{min-height:100vh;padding:2rem;background:var(--sample-surface);color:var(--foreground);}#surface button{transition:none!important;}",
  });
  await fixturePage.locator("#sample").waitFor();
  await fixturePage.mouse.move(1279, 799);
}

async function measure(button) {
  return button.evaluate((element) => {
    const context = document.createElement("canvas").getContext("2d");
    if (context === null) throw new Error("Canvas 2D is unavailable");

    const buttonStyle = getComputedStyle(element);
    const surface = element.parentElement;
    if (surface === null) throw new Error("Missing button surface");
    const surfaceColor = getComputedStyle(surface).backgroundColor;
    context.canvas.width = 1;
    context.canvas.height = 1;
    context.clearRect(0, 0, 1, 1);
    context.fillStyle = surfaceColor;
    context.fillRect(0, 0, 1, 1);
    context.fillStyle = buttonStyle.backgroundColor;
    context.fillRect(0, 0, 1, 1);
    const backgroundData = context.getImageData(0, 0, 1, 1).data;
    const background = [backgroundData[0], backgroundData[1], backgroundData[2]];

    context.clearRect(0, 0, 1, 1);
    context.fillStyle = buttonStyle.color;
    context.fillRect(0, 0, 1, 1);
    const foregroundData = context.getImageData(0, 0, 1, 1).data;
    const foreground = [foregroundData[0], foregroundData[1], foregroundData[2]];

    const luminance = (rgb) => {
      const linear = rgb.map((channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    };
    const foregroundLuminance = luminance(foreground);
    const backgroundLuminance = luminance(background);
    const ratio =
      (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
      (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
    const toHex = (rgb) => `#${rgb.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;

    return {
      background: toHex(background),
      foreground: toHex(foreground),
      ratio,
    };
  });
}

import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {relative, resolve} from "node:path";

import {z} from "zod";
import {describe, expect, test} from "vitest";

import {houstonServerPageMark, houstonServerPageStyles} from "../../src/shared/houston-server-pages.js";

const root = process.cwd();
const read = (path: string) => readFileSync(resolve(root, path));
const text = (path: string) => read(path).toString("utf8");
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const designSystemSha256 = {
  "apps/web/public/apple-touch-icon-180.png": "5235cf97d50c72544dae5af87fb461b43e11e9d0582e826edb3e00ae943e9917",
  "apps/web/public/favicon.ico": "be56f91a83bce1c5bac0cb980a4fe3aee4dfd9d96476d9b2b1e6755a8e425dad",
  "apps/web/public/favicon.svg": "f48d281eaa40f2776e3a0576444c6cf2a1c60fd9a967807c39a93cde608e182b",
  "apps/web/public/icon-192.png": "c641aec6bd7666b66d8d4582931b1cfe9059f1f29272dfa942201d17b455347b",
  "apps/web/public/icon-512.png": "0e439547649e53d70499d5fdb450ce5fcd4f89771b36750e1417ba351a26cdca",
  "apps/web/public/maskable-512.png": "0e439547649e53d70499d5fdb450ce5fcd4f89771b36750e1417ba351a26cdca",
  "apps/web/src/brand/houston/contrast.json": "5db33a642d4e9f0e93e17e64868bc284314babd99c381b6cb29d116a5f90da1f",
  "apps/web/src/brand/houston/motion/houston-loader.js": "1d2e6d29a91835e87718b630927dd4955e7161ba41ea255389e7dd99e1decc71",
  "apps/web/src/brand/houston/variables.css": "d1de888920680e5bfc7a8b9b7863cb1a4a4ffa680cb749671736d98c6b599fb2",
  "apps/web/src/brand/houston/fonts/inter-latin-ext-wght-normal.woff2": "34b9c504cab7a73e37b746343a449132e56cf7b5481af2cb81dc74dcff25c956",
  "apps/web/src/brand/houston/fonts/inter-latin-wght-normal.woff2": "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62",
  "apps/web/src/brand/houston/fonts/space-grotesk-latin-ext-wght-normal.woff2": "952dddb45d2f96f71cbf3b7f510b24379afc3c89ea02fcf89d377b45d62c0166",
  "apps/web/src/brand/houston/fonts/space-grotesk-latin-wght-normal.woff2": "0640890476fc1198ab4de571fb658de443c4d85b66466ec09534a8737ab1ce9d",
} as const;
const contrastPairSchema = z.object({
  bg: z.string(),
  fg: z.string(),
  background: z.string(),
  foreground: z.string(),
  minimum: z.number(),
  ratio: z.number(),
  theme: z.enum(["dark", "light"]),
});
const contrastPackSchema = z.object({pairs: z.array(contrastPairSchema)});

type Oklch = {chroma: number; hue: number; lightness: number};

function linearize(channel: number): number {
  return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
}

function luminance(rgb: readonly number[]): number {
  const [red, green, blue] = rgb.map(linearize);
  return 0.2126 * (red ?? 0) + 0.7152 * (green ?? 0) + 0.0722 * (blue ?? 0);
}

function parseHex(value: string): readonly number[] {
  const expanded = value.length === 4
    ? `#${value[1]}${value[1]}${value[2]}${value[2]}${value[3]}${value[3]}`
    : value;
  const hex = expanded.slice(1);
  return [0, 2, 4].map((start) => Number.parseInt(hex.slice(start, start + 2), 16) / 255);
}

function cssDeclaration(css: string, selector: string, name: string): string {
  const source = css.replace(/\/\*[\s\S]*?\*\//gu, "");
  for (const match of source.matchAll(/([^{}]+)\{([^{}]*)\}/gu)) {
    const header = match[1];
    const body = match[2];
    if (header === undefined || body === undefined) continue;
    if (!header.split(",").some((entry) => entry.trim() === selector)) continue;
    const declaration = body.match(new RegExp(`(?:^|;)\\s*${name}:\\s*([^;]+);`, "u"))?.[1];
    if (declaration !== undefined) {
      return declaration.replace(/\s+/gu, " ").replace(/\( /gu, "(").replace(/ \)/gu, ")").trim();
    }
  }
  throw new Error(`Missing ${name} in ${selector}`);
}

function themeColor(name: string, theme: "dark" | "light"): readonly number[] {
  const source = name === "--destructive"
    ? text("apps/web/src/theme-tokens.css")
    : text("apps/web/src/brand/houston/variables.css");
  const selector = name === "--destructive"
    ? theme === "light" ? ":root" : ".dark"
    : `[data-theme="${theme}"]`;
  const value = cssDeclaration(source, selector, name);
  const reference = value.match(/^var\((--[\w-]+)\)$/u)?.[1];
  if (reference !== undefined) return themeColor(reference, theme);
  if (value.startsWith("#")) return parseHex(value);
  const oklch = value.match(/^oklch\(([\d.]+)\s+([\d.]+)\s+([\d.]+)\)$/u);
  if (oklch === null) throw new Error(`Unsupported CSS color for ${name}: ${value}`);
  return oklchToRgb(Number(oklch[1]), Number(oklch[2]), Number(oklch[3]));
}

function accentTextStrongColor(theme: "dark" | "light"): readonly number[] {
  const selector = theme === "light" ? ":root" : '[data-theme="dark"]';
  const value = cssDeclaration(
    text("apps/web/src/brand/houston/contrast.css"),
    selector,
    "--ox-color-accent-text-strong",
  );
  const reference = value.match(/^var\((--[\w-]+)\)$/u)?.[1];
  if (reference !== undefined) return themeColor(reference, theme);
  const mix = value.match(/^color-mix\(in oklch, var\((--[\w-]+)\) ([\d.]+)%, black\)$/u);
  if (mix === null) throw new Error(`Unsupported accent text mix: ${value}`);
  const base = rgbToOklch(themeColor(mix[1] ?? "", theme));
  const proportion = Number(mix[2]) / 100;
  return oklchToRgb(base.lightness * proportion, base.chroma * proportion, base.hue);
}

function composite(foreground: readonly number[], background: readonly number[], alpha: number): readonly number[] {
  return foreground.map((channel, index) =>
    channel * alpha + (background[index] ?? 0) * (1 - alpha));
}

function contrastRatio(foreground: readonly number[], background: readonly number[]): number {
  const foregroundLuminance = luminance(foreground);
  const backgroundLuminance = luminance(background);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05) /
    (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
}

function oklchToRgb(lightness: number, chroma: number, hue: number): readonly number[] {
  const angle = hue * Math.PI / 180;
  const a = chroma * Math.cos(angle);
  const b = chroma * Math.sin(angle);
  const l = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (lightness - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ].map((channel) => {
    const clamped = Math.max(0, Math.min(1, channel));
    return clamped <= 0.0031308
      ? 12.92 * clamped
      : 1.055 * clamped ** (1 / 2.4) - 0.055;
  });
}

function rgbToOklch(rgb: readonly number[]): Oklch {
  const [red, green, blue] = rgb.map(linearize);
  const redChannel = red ?? 0;
  const greenChannel = green ?? 0;
  const blueChannel = blue ?? 0;
  const l = (0.4122214708 * redChannel + 0.5363325363 * greenChannel + 0.0514459929 * blueChannel) ** (1 / 3);
  const m = (0.2119034982 * redChannel + 0.6806995451 * greenChannel + 0.1073969566 * blueChannel) ** (1 / 3);
  const s = (0.0883024619 * redChannel + 0.2817188376 * greenChannel + 0.6299787005 * blueChannel) ** (1 / 3);
  const lightness = 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s;
  const a = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
  const b = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
  return {
    chroma: Math.hypot(a, b),
    hue: (Math.atan2(b, a) * 180 / Math.PI + 360) % 360,
    lightness,
  };
}

function normalizeColor(value: string): string {
  return `#${parseHex(value).map((channel) => Math.round(channel * 255).toString(16).padStart(2, "0")).join("")}`;
}

function cssVar(css: string, name: string, selector: string): string {
  const block = css.match(new RegExp(`${selector}\\{([^}]*)\\}`, "u"))?.[1];
  const value = block?.match(new RegExp(`${name}:([^;]+)`, "u"))?.[1];
  if (value === undefined) throw new Error(`Missing ${name} in ${selector}`);
  return value;
}

describe("Houston Brand and Design System v0.4.0", () => {
  test("BRD-001-B vendored tokens, contrast data, fonts and copied files match commit 524b0137", () => {
    for (const [path, expectedHash] of Object.entries(designSystemSha256)) {
      expect(sha256(read(path))).toBe(expectedHash);
    }
  });

  test("BRD-002-B all pack contrast pairs and local text tokens meet their WCAG minimums", () => {
    const appIndexCss = text("apps/web/src/index.css");
    for (const importLine of [
      '@import "./brand/houston/variables.css";',
      '@import "./brand/houston/contrast.css";',
      '@import "./theme-tokens.css";',
    ]) {
      expect(appIndexCss).toContain(importLine);
    }
    expect(appIndexCss).toContain("--color-destructive-hover: var(--ox-color-danger-hover);");

    const pack = contrastPackSchema.parse(JSON.parse(text("apps/web/src/brand/houston/contrast.json")));
    expect(pack.pairs).toHaveLength(62);
    for (const pair of pack.pairs) {
      const actual = contrastRatio(parseHex(pair.fg), parseHex(pair.bg));
      expect(actual).toBeGreaterThanOrEqual(pair.minimum);
      expect(actual).toBeCloseTo(pair.ratio, 3);
    }

    const contrastCss = text("apps/web/src/brand/houston/contrast.css");
    const lightHover = cssDeclaration(contrastCss, ":root", "--ox-color-danger-hover");
    const darkHover = cssDeclaration(contrastCss, '[data-theme="dark"]', "--ox-color-danger-hover");
    expect(lightHover).toBe("color-mix(in srgb, var(--destructive) 20%, transparent)");
    expect(darkHover).toBe("color-mix(in srgb, var(--destructive) 14%, transparent)");

    for (const theme of ["light", "dark"] as const) {
      const background = themeColor("--ox-color-bg", theme);
      const surface = themeColor("--ox-color-surface-1", theme);
      const accentTextStrong = accentTextStrongColor(theme);
      const destructive = themeColor("--destructive", theme);
      expect(contrastRatio(accentTextStrong, background), `${theme} accent-text-strong`).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(destructive, background), `${theme} destructive`).toBeGreaterThanOrEqual(4.5);

      const hover = theme === "light" ? lightHover : darkHover;
      const opacity = Number(hover.match(/ ([\d.]+)%,/u)?.[1]) / 100;
      for (const [surfaceName, base] of [["background", background], ["surface", surface]] as const) {
        const hoverWash = composite(destructive, base, opacity);
        expect(
          contrastRatio(destructive, hoverWash),
          `${theme} destructive text over danger-hover on ${surfaceName}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  test("BRD-003-B Mark D geometry replaces the radar mark and public icons match the pack", () => {
    const component = text("apps/web/src/review/artifact-mark.tsx");
    const serverMark = houstonServerPageMark();
    const cliOAuthSource = text("src/cli/cli-oauth-client.ts");
    const favicon = text("apps/web/public/favicon.svg");
    const allMarks = `${component}\n${serverMark}\n${favicon}`;
    expect(allMarks).toContain('viewBox="-13 -13 74 74"');
    expect(allMarks).toContain('x="2.25"');
    expect(allMarks).toContain('width="43.5"');
    expect(allMarks).toContain('rx="10.75"');
    expect(allMarks).toContain('r="12.75"');
    expect(allMarks).toContain('cx="15" cy="33" r="6"');
    expect(allMarks).not.toContain('stroke-width="6.8"');
    expect(allMarks).not.toContain("M24 24 33.192 14.808");
    expect(component).toContain('stroke="var(--ox-color-text)"');
    expect(component).toContain('fill="var(--ox-color-accent)"');
    expect(serverMark).toContain("var(--page-text,var(--text))");
    expect(serverMark).toContain("var(--page-accent,var(--accent))");

    expect(cliOAuthSource).toContain('import {houstonServerPageMark} from "../shared/houston-server-pages.js";');
    const callbackHtmlStart = cliOAuthSource.indexOf("`<!doctype html>", cliOAuthSource.indexOf("async function createLoopbackCallback"));
    expect(callbackHtmlStart).toBeGreaterThanOrEqual(0);
    const callbackResponseStart = cliOAuthSource.lastIndexOf("response.end(", callbackHtmlStart);
    const callbackResponseEnd = cliOAuthSource.indexOf("\n    );", callbackHtmlStart);
    const callbackResponseSource = cliOAuthSource.slice(callbackResponseStart, callbackResponseEnd);
    expect(callbackResponseSource).toContain('${houstonServerPageMark()}');
    expect(callbackResponseSource).not.toContain('stroke-width="6.8"');
    expect(callbackResponseSource).not.toContain("M24 24 33.192 14.808");
    expect(serverMark).toContain('viewBox="-13 -13 74 74"');

    const manifest = z.object({
      background_color: z.string(),
      icons: z.array(z.object({src: z.string()})),
      short_name: z.string(),
      theme_color: z.string(),
    }).parse(JSON.parse(text("apps/web/public/site.webmanifest")));
    expect(manifest.short_name).toBe("Artifacts");
    expect(manifest.theme_color).toBe("#0c1017");
    expect(manifest.background_color).toBe("#0c1017");
    const publicDirectory = resolve(root, "apps/web/public");
    for (const icon of manifest.icons) {
      const iconPath = resolve(publicDirectory, icon.src);
      const relativeIconPath = relative(publicDirectory, iconPath);
      expect(relativeIconPath.startsWith("..") || relativeIconPath === "").toBe(false);
      expect(() => readFileSync(iconPath)).not.toThrow();
    }
    for (const pagePath of ["apps/web/review.html", "apps/web/review-frame.html", "apps/web/embed.html"]) {
      const page = text(pagePath);
      expect(page).toContain('href="./favicon.svg"');
      expect(page).toContain('href="./favicon.ico"');
      expect(page).toContain('href="./apple-touch-icon-180.png"');
      expect(page).toContain('href="./site.webmanifest"');
    }
  });

  test("BRD-004-B mark accent and server-page colour hex values track both theme token sets", () => {
    const tokens = text("apps/web/src/brand/houston/variables.css");
    const page = houstonServerPageStyles();
    const mappings = {
      "--page-bg": "--ox-color-bg",
      "--page-surface": "--ox-color-surface-1",
      "--page-raised": "--ox-color-surface-2",
      "--page-text": "--ox-color-text",
      "--page-secondary": "--ox-color-text-secondary",
      "--page-muted": "--ox-color-text-muted",
      "--page-border": "--ox-color-border",
      "--page-border-strong": "--ox-color-border-strong",
      "--page-accent": "--ox-color-accent",
      "--page-accent-hover": "--ox-color-accent-hover",
      "--page-accent-text": "--ox-color-accent-text",
      "--page-on-accent": "--ox-color-on-accent",
      "--page-focus": "--ox-color-focus",
    } as const;
    const themes = [
      {pageSelector: ":root", tokenSelector: ":root", name: "light"},
      {pageSelector: "@media\\(prefers-color-scheme:dark\\)", tokenSelector: '\\[data-theme="dark"\\]', name: "dark"},
    ];
    for (const theme of themes) {
      for (const [pageName, tokenName] of Object.entries(mappings)) {
        expect(
          normalizeColor(cssVar(page, pageName, theme.pageSelector)),
          `${theme.name} ${pageName}`,
        ).toBe(normalizeColor(cssVar(tokens, tokenName, theme.tokenSelector)));
      }
      expect(cssVar(page, "--page-mark", theme.pageSelector)).toBe(
        cssVar(page, "--page-text", theme.pageSelector),
      );
    }
  });
});

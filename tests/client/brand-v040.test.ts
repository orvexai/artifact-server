import {createHash} from "node:crypto";
import {readdirSync, readFileSync} from "node:fs";
import {join, relative, resolve} from "node:path";

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

function stripComments(source: string): string {
  const characters = source.split("");
  let quote: "'" | '"' | "`" | null = null;
  let escaped = false;
  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index];
    const next = characters[index + 1];
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character;
      continue;
    }
    if (character === "/" && next === "/") {
      while (index < characters.length && characters[index] !== "\n" && characters[index] !== "\r") {
        characters[index] = " ";
        index += 1;
      }
      index -= 1;
    } else if (character === "/" && next === "*") {
      characters[index] = " ";
      characters[index + 1] = " ";
      index += 2;
      while (index < characters.length && !(characters[index] === "*" && characters[index + 1] === "/")) {
        if (characters[index] !== "\n" && characters[index] !== "\r") characters[index] = " ";
        index += 1;
      }
      if (index < characters.length) {
        characters[index] = " ";
        characters[index + 1] = " ";
        index += 1;
      }
    }
  }
  return characters.join("");
}

function scanHoustonLoaderUsages(source: string): string[] {
  return [...stripComments(source).matchAll(/<houston-loader\b([^>]*)>/gu)]
    .map((match) => match[1] ?? "");
}

function isNumericLoaderExpression(expression: string): boolean {
  const tokenPattern = /\s*(?:(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|[A-Za-z_$][\w$]*|\?\.|\*\*|\+\+|--|[+*/%().,\x5b\x5d-])/uy;
  const tokens: string[] = [];
  let offset = 0;
  while (offset < expression.length) {
    if (expression.slice(offset).trim() === "") break;
    tokenPattern.lastIndex = offset;
    const match = tokenPattern.exec(expression);
    if (match === null) return false;
    tokens.push(match[0].trim());
    offset = tokenPattern.lastIndex;
  }

  let cursor = 0;
  const peek = (): string | undefined => tokens[cursor];
  const consume = (expected?: string): string | undefined => {
    const token = peek();
    if (token === undefined || (expected !== undefined && token !== expected)) return undefined;
    cursor += 1;
    return token;
  };

  // Accepted grammar: numeric literals; identifiers and dot/optional-dot members;
  // parentheses, unary +/- and + - * / % ** arithmetic; Number(...) and Math.*(...).
  // Calls accept only numeric expressions as arguments; strings, templates, booleans,
  // nullish values, empty expressions, and arbitrary calls are rejected.
  const parseExpression = (): boolean => {
    if (!parseProduct()) return false;
    while (peek() === "+" || peek() === "-") {
      consume();
      if (!parseProduct()) return false;
    }
    return true;
  };
  const parseProduct = (): boolean => {
    if (!parsePower()) return false;
    while (peek() === "*" || peek() === "/" || peek() === "%") {
      consume();
      if (!parsePower()) return false;
    }
    return true;
  };
  const parsePower = (): boolean => {
    if (!parseUnary()) return false;
    if (consume("**") !== undefined) return parsePower();
    return true;
  };
  const parseUnary = (): boolean => {
    if (peek() === "++" || peek() === "--") return false;
    if (peek() === "+" || peek() === "-") {
      consume();
      return parseUnary();
    }
    return parsePrimary();
  };
  const parsePrimary = (): boolean => {
    const token = peek();
    if (token === undefined) return false;
    if (/^(?:\d|\.\d)/u.test(token)) {
      consume();
      return true;
    }
    if (consume("(") !== undefined) {
      if (!parseExpression() || consume(")") === undefined) return false;
      return true;
    }
    if (!/^[A-Za-z_$][\w$]*$/u.test(token)) return false;
    if (["true", "false", "null", "undefined"].includes(token)) return false;
    const rootIdentifier = consume();
    if (rootIdentifier === undefined) return false;
    const members: Array<{computed: boolean; name: string}> = [];
    while (peek() === "." || peek() === "?." || peek() === "[") {
      const access = consume();
      if (access === "[") {
        if (!parseExpression() || consume("]") === undefined) return false;
        members.push({computed: true, name: ""});
        continue;
      }
      if (access === "?." && consume("[") !== undefined) {
        if (!parseExpression() || consume("]") === undefined) return false;
        members.push({computed: true, name: ""});
        continue;
      }
      const member = peek();
      if (member === undefined || !/^[A-Za-z_$][\w$]*$/u.test(member)) return false;
      members.push({computed: false, name: member});
      consume();
    }
    if (consume("(") === undefined) return true;
    const allowedCall = (rootIdentifier === "Number" && members.length === 0)
      || (rootIdentifier === "Math" && members.length === 1 && members[0]?.computed === false);
    if (!allowedCall) return false;
    if (consume(")") !== undefined) return true;
    if (!parseExpression()) return false;
    while (consume(",") !== undefined) {
      if (!parseExpression()) return false;
    }
    return consume(")") !== undefined;
  };

  return tokens.length > 0 && parseExpression() && cursor === tokens.length;
}

function isValidHoustonLoaderAttributes(attributes: string): boolean {
  const label = attributes.match(/(?:^|\s)label\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\})/u);
  if (label === null || (label[1] ?? label[2] ?? label[3] ?? "").trim() === "") return false;
  if (/(?:^|\s)(?:role|aria-valuenow|aria-valuemin|aria-valuemax)\s*=/u.test(attributes)) return false;

  if (!/(?:^|\s)value(?:\s|=|$)/u.test(attributes)) return true;
  const value = attributes.match(/(?:^|\s)value\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\})/u);
  if (value === null || value[1] !== undefined || value[2] !== undefined || value[3] === undefined) return false;
  return isNumericLoaderExpression(value[3]);
}

function webSourceFiles(directory: string): string[] {
  return readdirSync(directory, {withFileTypes: true}).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (path === resolve(root, "apps/web/src/brand/houston")) return [];
      return webSourceFiles(path);
    }
    return /\.(?:js|jsx|ts|tsx)$/u.test(entry.name) ? [path] : [];
  });
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
    const expectedGeometry = [
      'x="2.25"',
      'y="2.25"',
      'width="43.5"',
      'height="43.5"',
      'rx="10.75"',
      'r="12.75"',
      'cx="15" cy="33" r="6"',
    ];
    for (const [source, viewBox] of [
      [component, 'viewBox="0 0 48 48"'],
      [serverMark, 'viewBox="-13 -13 74 74"'],
      [favicon, 'viewBox="0 0 48.0000 48.0000"'],
    ] as const) {
      expect(source).toContain(viewBox);
      for (const geometry of expectedGeometry) expect(source).toContain(geometry);
      expect(source).not.toContain("M24 24 33.192 14.808");
    }
    expect(component).toContain('strokeWidth="4.5"');
    expect(component).not.toContain('strokeWidth="6.8"');
    expect(component).not.toContain('stroke-width="6.8"');
    expect(serverMark).toContain('stroke-width="4.5"');
    expect(serverMark).not.toContain('stroke-width="6.8"');
    expect(favicon).toContain('stroke-width="4.5"');
    expect(favicon).not.toContain('stroke-width="6.8"');
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

  test("BRD-005-B every Houston loader usage has component-owned accessible state", () => {
    const usages = webSourceFiles(resolve(root, "apps/web/src")).flatMap((path) => {
      const source = readFileSync(path, "utf8");
      return scanHoustonLoaderUsages(source).map((attributes) => ({
        attributes,
        path: relative(root, path),
      }));
    });
    expect(usages.length).toBeGreaterThan(0);
    for (const {attributes, path} of usages) {
      expect({path, valid: isValidHoustonLoaderAttributes(attributes)}).toEqual({path, valid: true});
    }

    const fixtures = [
      {source: '<houston-loader label="Upload" value={42} />', valid: true},
      {source: '<houston-loader label="Upload" value={progress.current + Number(offset)} />', valid: true},
      {source: '<houston-loader label="Upload" value={task?.progress} />', valid: true},
      {source: '<houston-loader label="Upload" value={progress[key]} />', valid: true},
      {source: '<houston-loader label="Upload" value={Math.max(progress, 1)} />', valid: true},
      {source: '<houston-loader label="Upload" value="42" />', valid: false},
      {source: '<houston-loader label="Upload" value={"not a number"} />', valid: false},
      {source: "<houston-loader label=\"Upload\" value={'not a number'} />", valid: false},
      {source: '<houston-loader label="Upload" value={`42`} />', valid: false},
      {source: '<houston-loader label="Upload" value={true} />', valid: false},
      {source: '<houston-loader label="Upload" value={false} />', valid: false},
      {source: '<houston-loader label="Upload" value={null} />', valid: false},
      {source: '<houston-loader label="Upload" value={undefined} />', valid: false},
      {source: '<houston-loader label="Upload" value={} />', valid: false},
      {source: '<houston-loader label="Upload" value={getProgress()} />', valid: false},
      {source: '<houston-loader aria-label="Upload" value={42} />', valid: false},
    ];
    for (const fixture of fixtures) {
      const [attributes] = scanHoustonLoaderUsages(fixture.source);
      expect(attributes !== undefined && isValidHoustonLoaderAttributes(attributes)).toBe(fixture.valid);
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

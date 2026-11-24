import {readdirSync, readFileSync} from "node:fs";
import {dirname, relative, resolve} from "node:path";

import {describe, expect, test} from "vitest";

const root = process.cwd();
const webRoot = resolve(root, "apps/web");
const zodCspPath = resolve(webRoot, "src/lib/zod-csp.ts");

function attribute(tag: string, name: string): string | undefined {
  return tag.match(new RegExp(`\\b${name}=["']([^"']+)["']`, "u"))?.[1];
}

function moduleEntries(): string[] {
  return readdirSync(webRoot, {withFileTypes: true})
    .filter((entry) => entry.isFile() && entry.name.endsWith(".html"))
    .flatMap((entry) => {
      const html = readFileSync(resolve(webRoot, entry.name), "utf8");
      return [...html.matchAll(/<script\b[^>]*>/gu)]
        .filter((match) => attribute(match[0], "type") === "module")
        .map((match) => attribute(match[0], "src"))
        .filter((src): src is string => src !== undefined && src.startsWith("/src/"))
        .map((src) => resolve(webRoot, src.slice(1)));
    });
}

function stripLeadingComments(source: string): string {
  return source.replace(/^(?:\s|\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)*/u, "");
}

describe("web entry CSP setup", () => {
  test("configures jitless before every HTML module entry imports other modules", () => {
    const entries = moduleEntries();
    expect(entries.length).toBeGreaterThan(0);

    for (const entry of entries) {
      const source = readFileSync(entry, "utf8");
      const firstImport = stripLeadingComments(source).match(/^import\b[^;]*;/u)?.[0];
      const specifier = relative(dirname(entry), zodCspPath).replaceAll("\\", "/");
      expect(firstImport).toBe(`import "${specifier.startsWith(".") ? specifier : `./${specifier}`}";`);
    }
  });

  test("sets Zod jitless mode for strict script-src policies", () => {
    const source = readFileSync(zodCspPath, "utf8");
    expect(source).toMatch(/\bz\.config\(\{\s*jitless:\s*true\s*\}\);/u);
  });
});

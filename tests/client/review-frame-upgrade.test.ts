import {readFile} from "node:fs/promises";
import path from "node:path";

import {describe, expect, it} from "vitest";
import {z} from "zod";

import {reviewAnchorFrom} from "../../apps/web/src/review-frame/protocol.ts";

const root = process.cwd();
const read = (relativePath: string) =>
  readFile(path.join(root, relativePath), "utf8");
const webPackageManifestSchema = z.object({
  dependencies: z.record(z.string(), z.string()),
});
const rootPackageManifestSchema = z.object({
  pnpm: z.object({
    patchedDependencies: z.record(z.string(), z.string()).optional(),
  }).optional(),
});
const installedViewerManifestSchema = z.object({version: z.string()});

describe("Review frame @plannotator/ui 0.64.0 boundary", () => {
  it("T1 installs the pinned registry package", async () => {
    const [appPackage, installedPackage] = await Promise.all([
      read("apps/web/package.json").then((source) =>
        webPackageManifestSchema.parse(JSON.parse(source))),
      read("apps/web/node_modules/@plannotator/ui/package.json").then((source) =>
        installedViewerManifestSchema.parse(JSON.parse(source))),
    ]);

    expect(appPackage.dependencies["@plannotator/ui"]).toBe("0.64.0");
    expect(installedPackage["version"]).toBe("0.64.0");
  });

  it("T2 pins the sandbox and keeps unreviewed viewer capabilities absent", async () => {
    const source = await read("apps/web/src/review-frame/review-frame.tsx");
    const viewer = source.match(/<HtmlViewer\b[\s\S]*?\/>/u)?.[0];
    expect(viewer).toBeDefined();
    expect(viewer).toContain('sandbox="allow-scripts"');
    expect(viewer).toContain("allowCommentImages={false}");

    for (const prop of [
      "src", "liveSandbox", "liveSession", "frameUrl", "bridgeScriptUrl",
      "hostNavigates", "onOpenLink", "onAskAI", "onHostDraft", "onSide",
      "selectionActions", "mentionSource", "onStep", "onPageEscape",
    ]) {
      expect(viewer).not.toMatch(new RegExp(`\\b${prop}\\s*=`));
    }
  });

  it("T3 retains the srcdoc sandbox shim and a single content iframe", async () => {
    const source = await read("apps/web/node_modules/@plannotator/ui/components/html-viewer/HtmlViewer.tsx");
    expect(
      source.includes("srcdocSandbox(sandbox, hostNavigates)")
        || /srcDoc:\s*srcdoc,\s*sandbox:\s*"allow-scripts"/u.test(source),
    ).toBe(true);
    expect(source.match(/<iframe\b/gu)).toHaveLength(1);
  });

  it("T4 keeps protocol anchor caps aligned with the viewer", async () => {
    const viewer = await read("apps/web/node_modules/@plannotator/ui/components/html-viewer/useHtmlAnnotation.ts");
    const cap = (name: string): number => {
      const value = viewer.match(new RegExp(`(?:const|let) ${name}\\s*=\\s*(\\d[\\d_]*)`, "u"))?.[1];
      if (value === undefined) throw new Error(`Could not read ${name} from installed viewer.`);
      return Number(value.replaceAll("_", ""));
    };
    const protocol = await import("../../apps/web/src/review-frame/protocol.ts");
    const caps = [
      ["MAX_ANCHOR_SELECTOR_LENGTH", "selector", "a", "anchor"],
      ["MAX_ANCHOR_TAG_LENGTH", "tagName", "A", "anchor"],
      ["MAX_ANCHOR_TEXT_LENGTH", "text", "x", "anchor"],
      ["MAX_TARGET_LABEL_LENGTH", "label", "L", "target"],
      ["MAX_SELECTION_TEXT_LENGTH", "originalText", "x", "root"],
    ] as const;

    for (const [name, field, character, location] of caps) {
      const anchor = {htmlAnchor: {selector: "a", tagName: "A"}, originalText: ""};
      const value = character.repeat(cap(name));
      const atCap = location === "root"
        ? {...anchor, originalText: value}
        : location === "anchor"
          ? {...anchor, htmlAnchor: {...anchor.htmlAnchor, [field]: value}}
          : {...anchor, htmlAdditionalTargets: [{text: "x", label: value}]};
      const overCap = location === "root"
        ? {...atCap, originalText: `${value}x`}
        : location === "anchor"
          ? {...atCap, htmlAnchor: {...atCap.htmlAnchor, [field]: `${value}x`}}
          : {...atCap, htmlAdditionalTargets: [{text: "x", label: `${value}x`}]};
      expect(protocol.reviewAnchorSchema.safeParse(atCap).success, `${name} at cap`).toBe(true);
      expect(protocol.reviewAnchorSchema.safeParse(overCap).success, `${name} over cap`).toBe(false);
    }

    const targetCap = cap("MAX_ADDITIONAL_TARGETS");
    const targets = Array.from({length: targetCap}, () => ({text: "x"}));
    expect(protocol.reviewAnchorSchema.safeParse({htmlAnchor: null, originalText: "", htmlAdditionalTargets: targets}).success).toBe(true);
    expect(protocol.reviewAnchorSchema.safeParse({htmlAnchor: null, originalText: "", htmlAdditionalTargets: [...targets, {text: "x"}]}).success).toBe(false);
  });

  it("T5 projects only the version-one stored anchor fields", () => {
    const anchorWithUntrustedField = {
      selector: "a", tagName: "A", point: {x: 0, y: 0}, extra: 1,
    };
    const targetWithUntrustedFields = {
      text: "x", label: "L", context: {tag: "a"},
      anchor: {selector: "b", tagName: "B", extra: 2},
    };
    expect(reviewAnchorFrom("t", anchorWithUntrustedField, [targetWithUntrustedFields])).toEqual({
      htmlAnchor: {selector: "a", tagName: "A", point: {x: 0, y: 0}},
      htmlAdditionalTargets: [{
        text: "x", label: "L", anchor: {selector: "b", tagName: "B"},
      }],
      originalText: "t",
    });
  });

  it("T6 patches only the Interact link guard and History sandbox shim", async () => {
    const rootPackage = rootPackageManifestSchema.parse(JSON.parse(await read("package.json")));
    const bridge = await read("apps/web/node_modules/@plannotator/ui/components/html-viewer/bridge-script.ts");
    const sandboxShim = await read("apps/web/node_modules/@plannotator/ui/components/html-viewer/sandboxShim.ts");

    expect(rootPackage.pnpm?.patchedDependencies?.["@plannotator/ui@0.64.0"]).toBe(
      "patches/@plannotator__ui@0.64.0.patch",
    );
    expect(bridge).toContain("if (!annotateModeActive) return; // Interact");
    expect(sandboxShim).not.toContain("var h = window.history");
    expect(sandboxShim).not.toContain("h[name] = shim");
    expect(sandboxShim).not.toContain("plannotatorSandboxShim = true");
    expect(sandboxShim).not.toMatch(/history\.(pushState|replaceState)\s*=/u);
    expect(sandboxShim).not.toMatch(/(?:h\[[^\]]+\]|history\.pushState)\s*=\s*shim/u);
    expect(sandboxShim).toContain("memoryStorage");
    expect(sandboxShim).toContain("History block removed by artifact-server patch");
  });
});

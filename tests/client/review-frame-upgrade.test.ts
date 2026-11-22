import {readFile} from "node:fs/promises";
import path from "node:path";

import {describe, expect, it} from "vitest";

import {reviewAnchorFrom, reviewAnchorSchema} from "../../apps/web/src/review-frame/protocol.ts";

const root = process.cwd();
const read = (relativePath: string) =>
  readFile(path.join(root, relativePath), "utf8");

describe("Review frame @plannotator/ui 0.63.0 boundary", () => {
  it("T1 installs the pinned registry package", async () => {
    const [appPackage, installedPackage] = await Promise.all([
      read("apps/web/package.json").then(JSON.parse) as Promise<{dependencies: Record<string, string>}>,
      read("apps/web/node_modules/@plannotator/ui/package.json").then(JSON.parse) as Promise<{version: string}>,
    ]);

    expect(appPackage.dependencies["@plannotator/ui"]).toBe("0.63.0");
    expect(installedPackage.version).toBe("0.63.0");
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
    expect(reviewAnchorFrom("t", {
      selector: "a", tagName: "A", point: {x: 0, y: 0}, extra: 1,
    } as never, [{
      text: "x", label: "L", context: {tag: "a"},
      anchor: {selector: "b", tagName: "B", extra: 2} as never,
    } as never])).toEqual({
      htmlAnchor: {selector: "a", tagName: "A", point: {x: 0, y: 0}},
      htmlAdditionalTargets: [{
        text: "x", label: "L", anchor: {selector: "b", tagName: "B"},
      }],
      originalText: "t",
    });
  });
});

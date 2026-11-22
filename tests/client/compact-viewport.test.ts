import {readFile} from "node:fs/promises";

import {describe, expect, test} from "vitest";

import {
  compactViewportMaxWidth,
  compactViewportQuery,
} from "../../apps/web/src/review/compact-viewport.js";

describe("compact viewport breakpoint", () => {
  test("keeps the JavaScript query and review CSS breakpoints aligned", async () => {
    const reviewCss = await readFile(
      new URL("../../apps/web/src/review/review.css", import.meta.url),
      "utf8",
    );

    expect(compactViewportMaxWidth).toBe(720);
    expect(compactViewportQuery).toBe("(max-width: 720px)");
    expect(reviewCss).toContain("@media (max-width: 720px)");

    const cssBreakpoints = [...reviewCss.matchAll(/@media\s*\(\s*max-width:\s*(\d+)px\s*\)/gu)]
      .map((match) => Number(match[1]));
    expect([...new Set(cssBreakpoints)].toSorted((left, right) => left - right))
      .toEqual([560, 720, 1180]);
  });
});

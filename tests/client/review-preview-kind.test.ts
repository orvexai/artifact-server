/**
 * Review picks one presenter per manifest entry from its declared media type
 * alone, and a PDF is framed only from the version's isolated content host
 * (PRV-007).
 */

import {describe, expect, test} from "vitest";

import {
  contentHostEntryUrl,
  documentBaseUrl,
} from "../../apps/web/src/review/content-host-url.js";
import {previewKindOf} from "../../apps/web/src/review/preview-kind.js";

const leaseBase = `http://review-${"a".repeat(56)}.localhost:4318/`;

describe("Review preview kind", () => {
  test("a declared application/pdf entry selects the PDF viewer, whatever its case or parameters", () => {
    expect.hasAssertions();
    for (const mediaType of [
      "application/pdf",
      "APPLICATION/PDF",
      "application/pdf; name=report.pdf",
      " application/pdf ;charset=binary",
    ]) {
      expect(previewKindOf({mediaType, path: "reports/q3.pdf"})).toBe("pdf");
    }
    expect(previewKindOf({mediaType: "application/pdf", path: "download"}))
      .toBe("pdf");
  });

  test("a .pdf extension never promotes another declared type into the PDF viewer", () => {
    expect.hasAssertions();
    for (const mediaType of [
      "application/octet-stream",
      "application/x-pdf",
      "text/plain",
      "application/pdfx",
    ]) {
      expect(previewKindOf({mediaType, path: "report.pdf"})).toBe("other");
    }
    expect(previewKindOf({mediaType: "text/html", path: "report.pdf"}))
      .toBe("html");
  });

  test("the existing presenters keep their classification", () => {
    expect.hasAssertions();
    expect(previewKindOf({mediaType: "text/html; charset=utf-8", path: "index.html"}))
      .toBe("html");
    expect(previewKindOf({mediaType: "text/markdown", path: "review.md"}))
      .toBe("markdown");
    expect(previewKindOf({mediaType: "text/plain", path: "notes.MD"}))
      .toBe("markdown");
    expect(previewKindOf({mediaType: "text/plain", path: "notes.txt"}))
      .toBe("other");
    expect(previewKindOf({mediaType: "image/svg+xml", path: "logo.svg"}))
      .toBe("image");
    expect(previewKindOf({mediaType: "video/webm", path: "clip.webm"}))
      .toBe("video");
    expect(previewKindOf({mediaType: "audio/mpeg", path: "clip.mp3"}))
      .toBe("other");
  });
});

describe("Review content-host URLs", () => {
  test("a PDF entry resolves on the lease's content host with every path segment encoded", () => {
    expect.hasAssertions();
    const url = new URL(contentHostEntryUrl(leaseBase, "reports/Q3 #1?.pdf"));
    expect(url.origin).toBe(new URL(leaseBase).origin);
    expect(url.pathname).toBe("/reports/Q3%20%231%3F.pdf");
    expect(url.search).toBe("");
    expect(url.hash).toBe("");
  });

  test("hostile paths cannot leave the lease's content host", () => {
    expect.hasAssertions();
    for (const path of [
      "//application.example/review.pdf",
      "https://application.example/report.pdf",
      "../../report.pdf",
      "\\\\application.example\\report.pdf",
    ]) {
      expect(new URL(contentHostEntryUrl(leaseBase, path)).origin)
        .toBe(new URL(leaseBase).origin);
    }
  });

  test("a document base is the entry's directory on the same content host", () => {
    expect.hasAssertions();
    expect(documentBaseUrl(leaseBase, "docs/guide/index.html"))
      .toBe(`${leaseBase}docs/guide/`);
    expect(documentBaseUrl(leaseBase, "index.html")).toBe(leaseBase);
  });
});

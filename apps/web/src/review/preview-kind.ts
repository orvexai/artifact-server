/** The presenter Review uses for one manifest entry in its preview surface. */
export type PreviewKind = "html" | "image" | "markdown" | "other" | "pdf" | "video";

/** The manifest facts the preview classification may consult. */
export interface PreviewEntryFacts {
  readonly mediaType: string;
  readonly path: string;
}

/**
 * Larger Markdown files are not rendered inline: parsing, sanitizing, and
 * annotating a multi-megabyte document in the tab would stall Review, so they
 * settle into the typed fallback with open and download actions instead.
 */
export const markdownPreviewByteLimit = 2 * 1_024 * 1_024;

/** The same limit in the binary unit people see in the fallback copy. */
export const markdownPreviewLimitLabel = "2 MiB";

const markdownMediaTypes: ReadonlySet<string> = new Set([
  "text/markdown",
  "text/x-markdown",
]);
const markdownPathSuffix = /\.(?:md|markdown)$/iu;

/** Lowercase essence of a declared media type, with parameters removed. */
export function mediaTypeEssence(mediaType: string): string {
  return mediaType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

/**
 * Classify one entry by its declared media type. The only use of the path is
 * the long-standing `text/plain` labelling of `.md` files by generic
 * publishers: that text is rendered through the same sanitized Markdown path,
 * never promoted into an active document. A PDF is recognised only by its
 * declared `application/pdf` type, never by a `.pdf` extension, so the browser
 * PDF viewer is offered exactly the bytes the publisher labelled as a PDF.
 */
export function previewKindOf(entry: PreviewEntryFacts): PreviewKind {
  const essence = mediaTypeEssence(entry.mediaType);
  if (essence === "text/html") return "html";
  if (markdownMediaTypes.has(essence)) return "markdown";
  if (essence === "text/plain" && markdownPathSuffix.test(entry.path)) {
    return "markdown";
  }
  if (essence === "application/pdf") return "pdf";
  if (essence.startsWith("image/")) return "image";
  if (essence.startsWith("video/")) return "video";
  return "other";
}

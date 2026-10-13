import monoRegular from "@fontsource/atkinson-hyperlegible-mono/files/atkinson-hyperlegible-mono-latin-400-normal.woff2?url&inline";
import sansBold from "@fontsource/atkinson-hyperlegible-next/files/atkinson-hyperlegible-next-latin-700-normal.woff2?url&inline";
import sansItalic from "@fontsource/atkinson-hyperlegible-next/files/atkinson-hyperlegible-next-latin-400-italic.woff2?url&inline";
import sansRegular from "@fontsource/atkinson-hyperlegible-next/files/atkinson-hyperlegible-next-latin-400-normal.woff2?url&inline";
import DOMPurify, {type Config} from "dompurify";
import {Marked, type Tokens} from "marked";

/**
 * Markdown entries (Plannotator's `review.md`, READMEs, plans) are rendered
 * into one self-contained reader document and then travel the exact path an
 * HTML entry takes: the credential-free review frame, the opaque-origin
 * annotation sandbox, element and text-selection comments, and theme sync.
 *
 * Markdown may embed raw HTML, so the rendered body is sanitized before it
 * leaves the application: no scripts, event handlers, frames, objects,
 * embeds, forms or form controls, styles, or document-level elements survive.
 * Relative links and images are kept as authored so the frame's `<base href>`
 * resolves them against the version's own content host.
 */

const sanitizeConfig: Config = {
  FORBID_ATTR: [
    "action",
    "autofocus",
    "formaction",
    "method",
    "ping",
    "srcdoc",
  ],
  FORBID_TAGS: [
    "base",
    "button",
    "datalist",
    "dialog",
    "embed",
    "fieldset",
    "form",
    "frame",
    "frameset",
    "iframe",
    "input",
    "link",
    "meta",
    "noscript",
    "object",
    "optgroup",
    "option",
    "output",
    "select",
    "style",
    "template",
    "textarea",
  ],
  USE_PROFILES: {html: true},
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

/** GitHub-compatible heading slug: lowercase words joined by hyphens. */
function headingSlug(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replaceAll(/[^\p{L}\p{M}\p{N}\p{Pc}\s-]/gu, "")
    .replaceAll(/\s/gu, "-");
}

function uniqueSlug(used: Map<string, number>, text: string): string {
  const base = headingSlug(text) || "section";
  const seen = used.get(base) ?? 0;
  used.set(base, seen + 1);
  return seen === 0 ? base : `${base}-${seen}`;
}

const taskCheckboxOpening = "<span aria-checked=\"";
const taskCheckboxClosing =
  "\" aria-disabled=\"true\" class=\"task-list-item-checkbox\" role=\"checkbox\"></span>";

/**
 * A loose task item renders its box ahead of the item's first paragraph,
 * which would strand it on a line of its own; move it into that paragraph.
 */
function attachStrandedTaskCheckboxes(html: string): string {
  let result = "";
  let cursor = 0;
  for (;;) {
    const start = html.indexOf(taskCheckboxOpening, cursor);
    if (start === -1) break;
    const closing = html.indexOf(taskCheckboxClosing, start);
    if (closing === -1) break;
    const state = html.slice(start + taskCheckboxOpening.length, closing);
    if (state !== "true" && state !== "false") {
      // Author-written markup that merely starts like a task box.
      result += html.slice(cursor, start + taskCheckboxOpening.length);
      cursor = start + taskCheckboxOpening.length;
      continue;
    }
    const end = closing + taskCheckboxClosing.length;
    const box = html.slice(start, end);
    result += html.slice(cursor, start);
    if (html.startsWith(" <p>", end)) {
      result += `<p>${box} `;
      cursor = end + " <p>".length;
    } else {
      result += box;
      cursor = end;
    }
  }
  return result + html.slice(cursor);
}

/** One GFM parser per document so heading-id de-duplication never leaks. */
function documentParser(): Marked {
  const usedSlugs = new Map<string, number>();
  const parser = new Marked({async: false, breaks: false, gfm: true});
  parser.use({
    renderer: {
      // Form controls are stripped wholesale; a task-list box is a styled,
      // read-only ARIA checkbox instead of an <input>.
      checkbox({checked}: Tokens.Checkbox): string {
        return `${taskCheckboxOpening}${checked ? "true" : "false"}${taskCheckboxClosing} `;
      },
      code({escaped, lang, text}: Tokens.Code): string {
        const language = /^\S+/u.exec(lang ?? "")?.[0] ?? "";
        const body = `${text.replace(/\n$/u, "")}\n`;
        const code = escaped === true ? body : escapeHtml(body);
        if (language === "") return `<pre><code>${code}</code></pre>\n`;
        const label = escapeHtml(language);
        return `<pre data-language="${label}"><code class="language-${label}">${code}</code></pre>\n`;
      },
      heading({depth, tokens}: Tokens.Heading): string {
        const content = this.parser.parseInline(tokens);
        const plain = this.parser.parseInline(tokens, this.parser.textRenderer);
        const id = uniqueSlug(usedSlugs, plain);
        return `<h${depth} id="${id}">${content}</h${depth}>\n`;
      },
    },
  });
  return parser;
}

/**
 * The generated document follows the Review palette. It opts in with the
 * viewer's `plannotator-theme` meta, so the sandbox receives the bare host
 * tokens (`--background`, `--foreground`, `--ring`, …), a `light` class, and
 * `color-scheme`; every token has a system-color fallback.
 *
 * The opaque-origin sandbox cannot fetch the application's font files, so
 * Review's own Atkinson Hyperlegible faces travel inside the document (about
 * 50 KB, latin subset) and the reader matches Review on every operating
 * system instead of depending on the local `system-ui` mapping.
 */
const readerFontFaces = [
  ["Atkinson Hyperlegible Next", "normal", 400, sansRegular],
  ["Atkinson Hyperlegible Next", "italic", 400, sansItalic],
  ["Atkinson Hyperlegible Next", "normal", 700, sansBold],
  ["Atkinson Hyperlegible Mono", "normal", 400, monoRegular],
] as const;

const readerFontStylesheet = readerFontFaces
  .map(([family, style, weight, source]) =>
    `@font-face { font-display: swap; font-family: "${family}"; font-style: ${style}; font-weight: ${weight}; src: url("${source}") format("woff2"); }`
  )
  .join("\n");

const readerStylesheet = String.raw`
:root {
  color-scheme: light dark;
  --md-bg: var(--background, Canvas);
  --md-fg: var(--foreground, CanvasText);
  --md-muted: var(--muted-foreground, color-mix(in oklab, var(--md-fg) 62%, var(--md-bg)));
  --md-accent: var(--ring, LinkText);
  --md-accent-soft: var(--focus-highlight, color-mix(in oklab, var(--md-accent) 16%, transparent));
  --md-rule: color-mix(in oklab, var(--md-fg) 14%, var(--md-bg));
  --md-faint: color-mix(in oklab, var(--md-fg) 4.5%, var(--md-bg));
  --md-surface: color-mix(in oklab, var(--md-fg) 8%, var(--md-bg));
  --md-radius: 0.5rem;
  --md-gutter: clamp(1.25rem, 5vw, 3rem);
  --md-font: "Atkinson Hyperlegible Next", ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, "Noto Sans", Helvetica, Arial, sans-serif;
  --md-mono: "Atkinson Hyperlegible Mono", ui-monospace, "SF Mono", SFMono-Regular, "Cascadia Code", "JetBrains Mono", Menlo, Consolas, "Liberation Mono", monospace;
  background: var(--md-bg);
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
}
*, *::before, *::after { box-sizing: border-box; }
body {
  background: var(--md-bg);
  color: var(--md-fg);
  font: 400 1.0625rem/1.7 var(--md-font);
  font-kerning: normal;
  margin: 0;
  overflow-wrap: break-word;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
}
.markdown-body {
  margin: 0 auto;
  max-width: calc(72ch + 2 * var(--md-gutter));
  padding: clamp(2rem, 7vh, 4.5rem) var(--md-gutter) 6rem;
}
.markdown-body > :first-child { margin-top: 0; }
.markdown-body > :last-child { margin-bottom: 0; }
h1, h2, h3, h4, h5, h6 {
  color: var(--md-fg);
  font-weight: 700;
  letter-spacing: -0.012em;
  line-height: 1.25;
  margin: 2em 0 0.7em;
  scroll-margin-top: 1.5rem;
  text-wrap: balance;
}
h1 { font-size: 2.15em; letter-spacing: -0.024em; margin-top: 0; }
h2 {
  border-bottom: 1px solid var(--md-rule);
  font-size: 1.5em;
  letter-spacing: -0.018em;
  margin-top: 2.1em;
  padding-bottom: 0.32em;
}
h3 { font-size: 1.22em; }
h4 { font-size: 1.05em; }
h5 { font-size: 0.95em; }
h6 { color: var(--md-muted); font-size: 0.8em; letter-spacing: 0.07em; text-transform: uppercase; }
h1 + h2 { margin-top: 1.2em; }
p, ul, ol, dl, blockquote, pre, table, details, figure { margin: 0 0 1.15em; }
p { text-wrap: pretty; }
a {
  color: var(--md-accent);
  text-decoration-color: color-mix(in oklab, var(--md-accent) 45%, transparent);
  text-decoration-line: underline;
  text-decoration-thickness: 0.07em;
  text-underline-offset: 0.18em;
}
a:hover { text-decoration-color: currentColor; }
a:not([href]) { color: inherit; text-decoration: none; }
a:focus-visible { border-radius: 2px; outline: 2px solid var(--md-accent); outline-offset: 2px; }
strong, b { font-weight: 700; }
del { color: var(--md-muted); }
mark { background: var(--md-accent-soft); border-radius: 0.2em; color: inherit; padding: 0 0.15em; }
small { color: var(--md-muted); }
hr { background: var(--md-rule); border: 0; height: 1px; margin: 2.4em 0; }
img, video { border-radius: 0.3rem; height: auto; max-width: 100%; }
ul, ol { padding-left: 1.6em; }
li { margin: 0.3em 0; }
li::marker { color: var(--md-muted); }
li > p { margin: 0.45em 0; }
li > ul, li > ol { margin: 0.3em 0 0; }
li:has(> .task-list-item-checkbox),
li:has(> p:first-child > .task-list-item-checkbox) { list-style: none; }
.task-list-item-checkbox {
  background: var(--md-bg);
  border: 1.5px solid color-mix(in oklab, var(--md-fg) 40%, var(--md-bg));
  border-radius: 0.28em;
  display: inline-block;
  height: 1em;
  margin: 0 0.3em 0 -1.5em;
  position: relative;
  vertical-align: -0.14em;
  width: 1em;
}
.task-list-item-checkbox[aria-checked="true"] { background: var(--md-accent); border-color: var(--md-accent); }
.task-list-item-checkbox[aria-checked="true"]::after {
  border: solid var(--md-bg);
  border-width: 0 0.14em 0.14em 0;
  content: "";
  height: 0.55em;
  left: 0.29em;
  position: absolute;
  top: 0.08em;
  transform: rotate(45deg);
  width: 0.28em;
}
blockquote {
  border-left: 3px solid color-mix(in oklab, var(--md-accent) 55%, var(--md-rule));
  color: var(--md-muted);
  margin-left: 0;
  margin-right: 0;
  padding: 0.1em 0 0.1em 1.15em;
}
blockquote > :last-child { margin-bottom: 0; }
code, kbd, samp, pre { font-family: var(--md-mono); }
:not(pre) > code {
  background: var(--md-faint);
  border: 1px solid color-mix(in oklab, var(--md-rule) 70%, transparent);
  border-radius: 0.35em;
  font-size: 0.86em;
  padding: 0.1em 0.36em;
}
pre {
  background: var(--md-faint);
  border: 1px solid var(--md-rule);
  border-radius: var(--md-radius);
  font-size: 0.84em;
  line-height: 1.6;
  overflow: auto;
  padding: 0.95rem 1.15rem;
  tab-size: 2;
}
pre code { background: none; border: 0; font-size: inherit; padding: 0; white-space: pre; }
pre[data-language]::before {
  color: var(--md-muted);
  content: attr(data-language);
  display: block;
  font: 700 0.66rem/1.2 var(--md-font);
  letter-spacing: 0.09em;
  margin: -0.15rem 0 0.6rem;
  text-transform: uppercase;
}
kbd {
  background: var(--md-surface);
  border: 1px solid var(--md-rule);
  border-bottom-width: 2px;
  border-radius: 0.3em;
  font-size: 0.8em;
  padding: 0.05em 0.4em;
}
table {
  border-collapse: collapse;
  border-spacing: 0;
  display: block;
  font-size: 0.93em;
  font-variant-numeric: tabular-nums;
  max-width: 100%;
  overflow: auto;
  width: max-content;
}
th, td { border: 1px solid var(--md-rule); padding: 0.5em 0.9em; text-align: left; vertical-align: top; }
th { background: var(--md-surface); font-weight: 700; }
tbody tr:nth-child(2n) { background: var(--md-faint); }
th[align="center"], td[align="center"] { text-align: center; }
th[align="right"], td[align="right"] { text-align: right; }
details { border: 1px solid var(--md-rule); border-radius: var(--md-radius); padding: 0.6em 1em; }
details[open] > summary { margin-bottom: 0.6em; }
summary { cursor: pointer; font-weight: 700; }
dt { font-weight: 700; }
dd { margin: 0 0 0.6em 1.25em; }
.markdown-empty { color: var(--md-muted); font-style: italic; }
`;

/**
 * The frame's `<base href>` points at the version's content host, which
 * would turn an in-page `#heading` link into a navigation away from the
 * review. This trusted script (never Markdown-authored; that is sanitized
 * away) keeps fragment links on the page.
 */
const fragmentNavigationScript = String.raw`
document.addEventListener("click", function (event) {
  if (event.defaultPrevented || event.button !== 0) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  var origin = event.target instanceof Element ? event.target : null;
  var link = origin === null ? null : origin.closest('a[href^="#"]');
  if (link === null) return;
  var id = "";
  try { id = decodeURIComponent(link.getAttribute("href").slice(1)); } catch (error) { return; }
  var destination = id === "" ? document.body : document.getElementById(id);
  if (destination === null) return;
  event.preventDefault();
  destination.scrollIntoView({block: "start"});
});
`;

let purifier: ReturnType<typeof DOMPurify> | null = null;

function sanitize(html: string): string {
  purifier ??= DOMPurify(window);
  return purifier.sanitize(html, sanitizeConfig);
}

/** Render Markdown source into the complete reader document Review annotates. */
export function renderMarkdownDocument(markdown: string, title: string): string {
  const rendered = attachStrandedTaskCheckboxes(
    documentParser().parse(markdown.replace(/^﻿/u, ""), {async: false}),
  );
  const body = sanitize(rendered).trim();
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="plannotator-theme" content="host">
<title>${escapeHtml(title)}</title>
<style>${readerFontStylesheet}${readerStylesheet}</style>
</head>
<body>
<article class="markdown-body">${body === "" ? "<p class=\"markdown-empty\">This Markdown file is empty.</p>" : body}</article>
<script>${fragmentNavigationScript}</script>
</body>
</html>
`;
}

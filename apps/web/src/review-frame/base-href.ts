/**
 * Multi-file artifacts reference their sub-resources relatively. The viewer
 * renders the entry document from a `srcdoc` sandbox, whose base URL is the
 * frame's own document, so those references would resolve against this
 * application. When the host knows a content-domain base for the version it
 * passes it here and the tag is spliced in as the first child of `<head>`,
 * where the first `<base>` in document order wins.
 *
 * That base also makes an in-page `#section` link or `history.replaceState`
 * URL name the entry on the content host instead of this `about:srcdoc`
 * document, so a trusted script spliced in right after it maps those
 * same-document URLs back before the artifact's own scripts run.
 */
const absoluteHttpUrl = /^https?:\/\/[^\s"'<>]+$/u;
const doctypeTag = /<!doctype\b[^>]*>/iu;
const resourceUrlAttributes = [
  ["[src]", "src"],
  ["link[href]", "href"],
  ["[poster]", "poster"],
  ["object[data]", "data"],
] as const;

/** Return `html` with a `<base href>` in place, or unchanged when it cannot be. */
export function withBaseHref(
  html: string,
  baseHref: string | null,
  entryPath: string,
): string {
  if (baseHref === null || !absoluteHttpUrl.test(baseHref)) return html;
  return withResolvedDocumentResources(html, baseHref, entryPath);
}

/**
 * Keep same-document navigation on the reviewed document. `documentUrls` are
 * the content-host spellings of this document: the base directory a bare
 * `#fragment` resolves to and the entry file itself. A link to one of them
 * becomes a fragment navigation of `about:srcdoc`, which the browser scrolls,
 * records, and announces with `hashchange` exactly as it would in a tab;
 * History API URLs for them are rewritten the same way. Every other URL is
 * left to the browser. The click listener joins the window only once the
 * page's own scripts have run, so a click the page handles anywhere it
 * listened while loading is left alone. `location` cannot be wrapped, so
 * `location.href = "#x"` still resolves against the base.
 */
function sameDocumentNavigationScript(documentUrls: readonly string[]): string {
  return String.raw`(function () {
  var documentUrls = ${JSON.stringify(documentUrls)};
  var documentUrl = location.href.split("#")[0];
  function sameDocumentUrl(value) {
    var url;
    try { url = new URL(String(value), document.baseURI).href; } catch (error) { return null; }
    var fragment = url.indexOf("#");
    if (documentUrls.indexOf(fragment === -1 ? url : url.slice(0, fragment)) === -1) return null;
    return documentUrl + (fragment === -1 ? "" : url.slice(fragment));
  }
  ["pushState", "replaceState"].forEach(function (name) {
    var update = History.prototype[name];
    History.prototype[name] = function (state, unused, url) {
      var local = url === undefined || url === null ? null : sameDocumentUrl(url);
      return local === null ? update.apply(this, arguments) : update.call(this, state, unused, local);
    };
  });
  function followSameDocumentLink(event) {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    var link = event.composedPath().find(function (node) {
      return node instanceof Element && node.matches("a[href], area[href], svg a[*|href]");
    });
    if (link === undefined || link.hasAttribute("download")) return;
    var target = link.getAttribute("target");
    if (target !== null && target !== "" && target.toLowerCase() !== "_self") return;
    var href = link.getAttribute("href");
    if (href === null) href = link.getAttributeNS("http://www.w3.org/1999/xlink", "href");
    var local = href === null ? null : sameDocumentUrl(href);
    if (local === null || local.indexOf("#") === -1) return;
    event.preventDefault();
    location.assign(local);
  }
  document.addEventListener("DOMContentLoaded", function () {
    window.addEventListener("click", followSameDocumentLink);
  });
})();`;
}

/** The content-host URLs that name the entry document, or null if unparseable. */
function sameDocumentUrls(
  baseHref: string,
  entryPath: string,
): readonly string[] | null {
  const entryName = entryPath.split("/").at(-1) ?? "";
  try {
    return [
      new URL(baseHref).toString(),
      new URL(`./${encodeURIComponent(entryName)}`, baseHref).toString(),
    ];
  } catch {
    return null;
  }
}

/**
 * Resolve parser-fetched resources before `srcdoc` navigation starts.
 *
 * Firefox can begin an image request against the frame document before a
 * dynamically supplied base URL settles, then retain the failed image even
 * after it retries the correct URL. Parsing here does not execute or fetch
 * anything. It makes eager resource attributes absolute up front, while the
 * base element still governs CSS, modules, runtime fetches, and navigation.
 */
function withResolvedDocumentResources(
  html: string,
  baseHref: string,
  entryPath: string,
): string {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  const base = parsed.createElement("base");
  base.href = baseHref;
  parsed.head.prepend(base);
  const documentUrls = sameDocumentUrls(baseHref, entryPath);
  if (documentUrls !== null) {
    const navigation = parsed.createElement("script");
    navigation.textContent = sameDocumentNavigationScript(documentUrls);
    base.after(navigation);
  }
  for (const [selector, attribute] of resourceUrlAttributes) {
    for (const element of parsed.querySelectorAll(selector)) {
      const value = element.getAttribute(attribute);
      if (value === null || value.trim() === "") continue;
      try {
        element.setAttribute(attribute, new URL(value, baseHref).toString());
      } catch {
        // Leave invalid authored URLs intact so the browser reports them in
        // the artifact instead of turning Review into an HTML validator.
      }
    }
  }
  const doctype = doctypeTag.exec(html)?.[0] ?? "";
  return `${doctype}${parsed.documentElement.outerHTML}`;
}

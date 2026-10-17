/**
 * URLs on one exact version's isolated content host. A preview lease's
 * `baseUrl` names that host (`<lease token>.<content domain>`), and every
 * manifest path resolves beneath it. Nothing here ever produces an
 * application-origin URL: the content host is the only place artifact bytes
 * are served as documents.
 */

/**
 * The content-host URL of one manifest entry, with each segment encoded. The
 * `./` prefix keeps the result path-relative even for a path that starts with
 * empty segments, so it can never resolve as a scheme-relative URL on another
 * host. (Manifest validation already rejects such paths.)
 */
export function contentHostEntryUrl(
  versionBaseUrl: string,
  entryPath: string,
): string {
  return new URL(
    `./${entryPath.split("/").map(encodeURIComponent).join("/")}`,
    versionBaseUrl,
  ).toString();
}

/** The directory URL an entry's relative references resolve against. */
export function documentBaseUrl(
  versionBaseUrl: string,
  entryPath: string,
): string {
  return new URL(".", contentHostEntryUrl(versionBaseUrl, entryPath)).toString();
}

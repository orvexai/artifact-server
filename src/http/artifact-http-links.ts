/** Build the stable browser URL for an artifact's current version. */
export function artifactBrowserUrl(
  applicationUrl: URL,
  artifactId: string,
): string {
  return applicationPathUrl(applicationUrl, `/artifacts/${artifactId}`).toString();
}

/** Build the authenticated, exact-version review URL used for review and comments. */
export function artifactReviewUrl(
  applicationUrl: URL,
  projectId: string,
  artifactId: string,
  versionId: string,
): string {
  const reviewUrl = applicationPathUrl(applicationUrl, "/review");
  reviewUrl.search = new URLSearchParams({
    artifact: artifactId,
    project: projectId,
    version: versionId,
    view: "focus",
  }).toString();
  return reviewUrl.toString();
}

/** Resolve an app-relative route while preserving an organization base path. */
export function applicationPathUrl(applicationUrl: URL, path: string): URL {
  const url = new URL(applicationUrl);
  const basePath = url.pathname.replace(/\/$/u, "");
  const route = new URL(path, "http://application.invalid");
  url.pathname = `${basePath}${route.pathname}`;
  url.search = route.search;
  url.hash = route.hash;
  return url;
}

/** Build the browser origin for one exact immutable version. */
export function versionBrowserUrl(
  applicationUrl: URL,
  contentDomain: string,
  contentToken: string,
): string {
  const versionUrl = new URL(applicationUrl);
  versionUrl.hostname = `${contentToken}.${contentDomain}`;
  versionUrl.pathname = "/";
  versionUrl.search = "";
  versionUrl.hash = "";
  return versionUrl.toString();
}

/** Build the browser URL for one file within an immutable version. */
export function versionFileBrowserUrl(
  applicationUrl: URL,
  contentDomain: string,
  contentToken: string,
  manifestPath: string,
): string {
  const fileUrl = new URL(
    versionBrowserUrl(applicationUrl, contentDomain, contentToken),
  );
  fileUrl.pathname = `/${manifestPath.split("/").map(encodeURIComponent).join("/")}`;
  return fileUrl.toString();
}

/** Build the one-time URL that establishes a private version browser session. */
export function contentBootstrapBrowserUrl(
  applicationUrl: URL,
  contentDomain: string,
  contentToken: string,
  bootstrapToken: string,
  destinationPath?: string,
): string {
  const bootstrapUrl = new URL(applicationUrl);
  bootstrapUrl.hostname = `${contentToken}.${contentDomain}`;
  bootstrapUrl.pathname = destinationPath === undefined
    ? "/"
    : `/${destinationPath.split("/").map(encodeURIComponent).join("/")}`;
  bootstrapUrl.search = new URLSearchParams({
    __artifact_bootstrap: bootstrapToken,
  }).toString();
  bootstrapUrl.hash = "";
  return bootstrapUrl.toString();
}

/** Build the content-host base URL for one short-lived embedded Review lease. */
export function previewLeaseBrowserUrl(
  applicationUrl: URL,
  contentDomain: string,
  leaseToken: string,
): string {
  return versionBrowserUrl(applicationUrl, contentDomain, leaseToken);
}

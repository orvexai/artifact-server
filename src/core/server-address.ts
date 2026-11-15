/** A validated Artifact Server origin and optional organization route prefix. */
export interface ArtifactServerAddress {
  readonly address: string;
  readonly basePath: string;
  readonly organizationSlug: string | null;
  readonly origin: string;
}

/** Parse an HTTP(S) server address with only an optional `/o/<slug>` path. */
export function parseArtifactServerAddress(candidate: string): ArtifactServerAddress {
  const url = new URL(candidate);
  if (
    (url.protocol !== "http:" && url.protocol !== "https:")
    || url.username.length > 0
    || url.password.length > 0
    || hasAuthorityCredentials(candidate)
    || candidate.includes("?")
    || candidate.includes("#")
  ) {
    throw new Error("invalid Artifact Server address");
  }

  let organizationSlug: string | null = null;
  if (url.pathname !== "" && url.pathname !== "/") {
    const match = /^\/o\/([a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)$/u.exec(url.pathname);
    if (match === null) throw new Error("invalid Artifact Server address");
    organizationSlug = match[1] ?? null;
  }

  const origin = url.origin;
  const basePath = organizationSlug === null ? "" : `/o/${organizationSlug}`;
  return {address: `${origin}${basePath}`, basePath, organizationSlug, origin};
}

function hasAuthorityCredentials(candidate: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/iu.test(candidate);
}

/** Join an API route to the address without allowing a leading slash to drop its tenant prefix. */
export function artifactServerRouteUrl(
  route: string,
  address: string | URL,
): URL {
  const parsed = parseArtifactServerAddress(String(address));
  const relativeRoute = route.replace(/^\/+/, "");
  return new URL(`${parsed.basePath}/${relativeRoute}`, parsed.origin);
}

/** RFC 9728 protected-resource metadata URL for one API or MCP resource. */
export function artifactServerProtectedResourceMetadataUrl(
  address: string | URL,
  resource: "api" | "mcp",
): URL {
  const parsed = parseArtifactServerAddress(String(address));
  const path = parsed.organizationSlug === null
    ? `/.well-known/oauth-protected-resource/${resource}`
    : `/.well-known/oauth-protected-resource/o/${encodeURIComponent(parsed.organizationSlug)}/${resource}`;
  return new URL(path, parsed.origin);
}

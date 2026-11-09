/** Refuse entries that are not exact, pathless browser origins. */
export function validateEmbedOrigins(origins: readonly string[]): void {
  for (const origin of origins) {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new Error(`Invalid ARTIFACT_SERVER_EMBED_ORIGINS entry: ${origin}`);
    }
    if (
      (url.protocol !== "https:" && url.protocol !== "http:")
      || url.origin !== origin
      || url.username !== ""
      || url.password !== ""
      || url.pathname !== "/"
      || url.search !== ""
      || url.hash !== ""
      || origin.includes("*")
      || origin.endsWith("/")
    ) {
      throw new Error(`Invalid ARTIFACT_SERVER_EMBED_ORIGINS entry: ${origin}`);
    }
  }
}

/** Parse the exact origins permitted to frame an embed document. */
export function loadEmbedOrigins(environment: NodeJS.ProcessEnv): readonly string[] {
  const configured = environment.ARTIFACT_SERVER_EMBED_ORIGINS ?? "";
  if (configured.trim() === "") return [];
  return configured.split(",").map((item) => {
    const origin = item.trim();
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
    return origin;
  });
}

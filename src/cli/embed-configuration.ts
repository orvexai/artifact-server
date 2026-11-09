import {validateEmbedOrigins} from "../http/embed-origins.js";

/** Parse the exact origins permitted to frame an embed document. */
export function loadEmbedOrigins(environment: NodeJS.ProcessEnv): readonly string[] {
  const configured = environment["ARTIFACT_SERVER_EMBED_ORIGINS"] ?? "";
  if (configured.trim() === "") return [];
  const origins = configured.split(",").map((item) => item.trim());
  validateEmbedOrigins(origins);
  return origins;
}

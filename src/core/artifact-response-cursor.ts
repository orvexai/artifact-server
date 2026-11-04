/** Stable polling cursor ordered by response timestamp and id. */
import {z} from "zod";

const cursorSchema = z.object({createdAt: z.iso.datetime(), id: z.string().min(1)}).strict();
export interface ArtifactResponseCursor { readonly createdAt: string; readonly id: string; }

export function encodeArtifactResponseCursor(cursor: ArtifactResponseCursor): string {
  return Buffer.from(JSON.stringify({createdAt: normalizeResponseTimestamp(cursor.createdAt), id: cursor.id}), "utf8").toString("base64url");
}

export function decodeArtifactResponseCursor(token: string | null): ArtifactResponseCursor | null {
  if (token === null) return null;
  try {
    const cursor = cursorSchema.parse(JSON.parse(Buffer.from(token, "base64url").toString("utf8")));
    return {createdAt: normalizeResponseTimestamp(cursor.createdAt), id: cursor.id};
  } catch { return null; }
}

export function normalizeResponseTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toISOString();
}

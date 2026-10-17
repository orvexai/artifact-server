import {Option, type Command} from "commander";
import {Redacted} from "effect";
import {z} from "zod";

import {
  resolveCliServerConnection,
  type CliServerConnectionOptions,
} from "./cli-server-connection.js";

interface CommentsListOptions extends CliServerConnectionOptions {
  readonly dispatched: "exclude" | "include" | "only";
  readonly includeReplies: boolean;
  readonly limit: string;
  readonly project?: string;
  readonly version?: string;
}

export interface CommentsCommandOptions {
  readonly defaultProfileDirectory: string;
}

const commentThreadSchema = z.object({
  artifactId: z.string(),
  author: z.object({displayName: z.string()}).passthrough(),
  body: z.string(),
  createdAt: z.string(),
  id: z.string(),
  path: z.string().nullable(),
  projectId: z.string(),
  replyCount: z.number(),
  state: z.enum(["open", "resolved"]),
  updatedAt: z.string(),
  versionId: z.string(),
}).passthrough();

const commentPageSchema = z.object({
  items: z.array(commentThreadSchema),
  nextCursor: z.string().nullable(),
}).passthrough();
const commentDetailsSchema = z.object({
  replies: z.array(z.object({
    author: z.object({displayName: z.string()}).passthrough(),
    body: z.string(),
    createdAt: z.string(),
    id: z.string(),
    threadId: z.string(),
    updatedAt: z.string(),
  }).passthrough()),
  thread: commentThreadSchema,
}).passthrough();

const failureSchema = z.object({
  error: z.object({code: z.string(), message: z.string()}).passthrough(),
}).passthrough();

/** Register read-only Artifact Server comment commands. */
export function configureCommentsCommand(
  program: Command,
  commandOptions: CommentsCommandOptions,
): void {
  program
    .command("comments")
    .description("Read comment threads from an Artifact Server artifact.")
    .command("list <artifact-id>")
    .description("List comment threads, including replies counts, across versions by default.")
    .addOption(new Option("--server <origin>", "Artifact Server origin").env("ARTIFACT_SERVER_URL"))
    .addOption(new Option("--profile <name>", "saved Artifact Server profile"))
    .addOption(
      new Option("--profile-data <directory>", "user-local CLI profile directory")
        .default(commandOptions.defaultProfileDirectory)
        .env("ARTIFACT_SERVER_HOME"),
    )
    .addOption(new Option("--data <directory>", "local Artifact Server data directory").default(".artifact-server"))
    .addOption(new Option("--token-file <path>", "file containing an Artifact Server API token"))
    .addOption(new Option("--project <id>", "project ID; optional when one active project exists"))
    .addOption(new Option("--version <id>", "restrict comments to one version"))
    .addOption(new Option("--include-replies", "include each thread's replies").default(false))
    .addOption(
      new Option("--dispatched <mode>", "include or filter threads held by an agent dispatch")
        .choices(["exclude", "include", "only"])
        .default("exclude"),
    )
    .addOption(new Option("--limit <count>", "maximum number of comment threads").default("500"))
    .action(async (artifactId: string, options: CommentsListOptions) => {
      const limit = parseLimit(options.limit);
      const connection = await resolveCliServerConnection(options, "comments");
      const queryOptions: CommentQueryOptions = {};
      if (options.project !== undefined) queryOptions.projectId = options.project;
      if (options.version !== undefined) queryOptions.versionId = options.version;
      const items = await listArtifactComments({
        artifactId,
        apiToken: Redacted.value(connection.apiToken),
        dispatched: options.dispatched,
        includeReplies: options.includeReplies,
        limit,
        origin: connection.origin,
        ...queryOptions,
      });
      console.log(JSON.stringify({items}, null, 2));
    });
}

interface CommentQueryOptions {
  projectId?: string;
  versionId?: string;
}

interface ListArtifactCommentsInput {
  readonly artifactId: string;
  readonly apiToken: string;
  readonly dispatched: "exclude" | "include" | "only";
  readonly fetchImpl?: typeof fetch;
  readonly includeReplies?: boolean;
  readonly limit: number;
  readonly origin: string;
  readonly projectId?: string;
  readonly versionId?: string;
}

/** Fetch all pages while keeping authentication inside the CLI process. */
export async function listArtifactComments({
  artifactId,
  apiToken,
  dispatched,
  fetchImpl = fetch,
  includeReplies = false,
  limit,
  origin,
  projectId,
  versionId,
}: ListArtifactCommentsInput): Promise<Array<z.infer<typeof commentThreadSchema> & {replies?: z.infer<typeof commentDetailsSchema>["replies"]}>> {
  if (!artifactId.trim()) throw new Error("Artifact ID is required.");
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000) {
    throw new Error("Comment limit must be a whole number from 1 to 5000.");
  }
  const loadPage = async (
    cursor: string | null,
    items: Array<z.infer<typeof commentThreadSchema> & {replies?: z.infer<typeof commentDetailsSchema>["replies"]}>,
  ): Promise<Array<z.infer<typeof commentThreadSchema> & {replies?: z.infer<typeof commentDetailsSchema>["replies"]}>> => {
    const query = new URLSearchParams({dispatched, limit: "100"});
    if (cursor !== null) query.set("cursor", cursor);
    if (projectId !== undefined) query.set("projectId", projectId);
    if (versionId !== undefined) query.set("versionId", versionId);
    const response = await fetchImpl(
      new URL(`/api/v1/artifacts/${encodeURIComponent(artifactId)}/comments?${query}`, origin),
      {
        headers: {Authorization: `Bearer ${apiToken}`, Accept: "application/json"},
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      },
    );
    if (!response.ok) throw await commentsFailure(response);
    const page = commentPageSchema.parse(await response.json());
    const remaining = limit - items.length;
    const pageItems = page.items.slice(0, remaining);
    if (includeReplies) {
      const detailedItems = await Promise.all(pageItems.map(async (thread) => {
        const resolvedProjectId = projectId ?? thread.projectId;
        const projectQuery = `?projectId=${encodeURIComponent(resolvedProjectId)}`;
        const detailsResponse = await fetchImpl(
          new URL(
            `/api/v1/artifacts/${encodeURIComponent(artifactId)}/comments/${encodeURIComponent(thread.id)}${projectQuery}`,
            origin,
          ),
          {
            headers: {Authorization: `Bearer ${apiToken}`, Accept: "application/json"},
            redirect: "error",
            signal: AbortSignal.timeout(30_000),
          },
        );
        if (!detailsResponse.ok) throw await commentsFailure(detailsResponse);
        const details = commentDetailsSchema.parse(await detailsResponse.json());
        return {
          ...thread,
          replies: details.replies,
        };
      }));
      items.push(...detailedItems);
    } else {
      items.push(...pageItems);
    }
    const nextCursor = items.length >= limit ? null : page.nextCursor;
    return nextCursor === null ? items : loadPage(nextCursor, items);
  };
  return loadPage(null, []);
}

function parseLimit(raw: string): number {
  const limit = Number(raw);
  if (!Number.isInteger(limit) || limit < 1 || limit > 5_000) {
    throw new Error("--limit must be a whole number from 1 to 5000.");
  }
  return limit;
}

async function commentsFailure(response: Response): Promise<Error> {
  try {
    const failure = failureSchema.parse(await response.json());
    return new Error(`${failure.error.code} (HTTP ${response.status}): ${failure.error.message}`);
  } catch {
    return new Error(`The comments request failed (HTTP ${response.status}).`);
  }
}

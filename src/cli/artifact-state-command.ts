import {Option, type Command} from "commander";
import {Redacted} from "effect";
import {z} from "zod";

import {
  resolveCliServerConnection,
  type CliServerConnectionOptions,
} from "./cli-server-connection.js";

interface ArtifactStateOptions extends CliServerConnectionOptions {
  readonly project?: string;
}

export interface ArtifactStateCommandOptions {
  readonly defaultProfileDirectory: string;
}

const entrySchema = z.object({
  artifactId: z.string(),
  key: z.string(),
  projectId: z.string(),
  updatedAt: z.string(),
  updatedBy: z.object({displayName: z.string(), principalId: z.string()}).strict(),
  value: z.unknown(),
}).strict();

/** Register remote CLI operations for state shared by an artifact's versions. */
export function configureArtifactStateCommand(
  program: Command,
  commandOptions: ArtifactStateCommandOptions,
): void {
  const state = program.command("artifact-state")
    .alias("state")
    .description("Read and write JSON state shared across an artifact's saved versions.");
  const connectionOptions = (command: Command): Command => command
    .addOption(new Option("--server <origin>", "Artifact Server origin").env("ARTIFACT_SERVER_URL"))
    .addOption(new Option("--profile <name>", "saved Artifact Server profile"))
    .addOption(new Option("--profile-data <directory>", "user-local CLI profile directory")
      .default(commandOptions.defaultProfileDirectory).env("ARTIFACT_SERVER_HOME"))
    .addOption(new Option("--data <directory>", "local Artifact Server data directory").default(".artifact-server"))
    .addOption(new Option("--token-file <path>", "file containing an Artifact Server API token"))
    .addOption(new Option("--project <id>", "project ID; optional when one active project exists"));

  connectionOptions(state.command("list <artifact-id>")
    .description("List the artifact's complete shared state.")
    .action(async (artifactId: string, options: ArtifactStateOptions) => {
      const result = await stateRequest(
        options,
        z.object({entries: z.array(entrySchema)}),
        artifactId,
        undefined,
      );
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("get <artifact-id> <key>")
    .description("Read one state value.")
    .action(async (artifactId: string, key: string, options: ArtifactStateOptions) => {
      const result = await stateRequest(
        options,
        z.object({entry: entrySchema.nullable()}),
        artifactId,
        key,
      );
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("set <artifact-id> <key> <json>")
    .description("Write one JSON state value.")
    .action(async (artifactId: string, key: string, value: string, options: ArtifactStateOptions) => {
      const parsed = z.json().safeParse(parseJsonText(value));
      if (!parsed.success) throw new Error("State value must be valid JSON.");
      const result = await stateRequest(
        options,
        z.object({entry: entrySchema}),
        artifactId,
        key,
        {jsonBody: JSON.stringify({value: parsed.data}), method: "PUT"},
      );
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("delete <artifact-id> <key>")
    .description("Delete one state value.")
    .action(async (artifactId: string, key: string, options: ArtifactStateOptions) => {
      await stateRequest(options, z.null(), artifactId, key, {method: "DELETE"});
      console.log(JSON.stringify({deleted: true}));
    }));
}

/** One state call: the HTTP method, and the JSON body for a write. */
interface StateRequest {
  readonly jsonBody?: string;
  readonly method: "DELETE" | "GET" | "PUT";
}

async function stateRequest<T>(
  options: ArtifactStateOptions,
  schema: z.ZodType<T>,
  artifactId: string,
  key: string | undefined,
  call: StateRequest = {method: "GET"},
): Promise<T> {
  if (artifactId.trim() === "") throw new Error("Artifact ID is required.");
  const connection = await resolveCliServerConnection(options, "state");
  const project = options.project === undefined
    ? ""
    : `?projectId=${encodeURIComponent(options.project)}`;
  const path = key === undefined
    ? `/api/v1/artifacts/${encodeURIComponent(artifactId)}/state${project}`
    : `/api/v1/artifacts/${encodeURIComponent(artifactId)}/state/${encodeURIComponent(key)}${project}`;
  const headers = new Headers({
    Accept: "application/json",
    Authorization: `Bearer ${Redacted.value(connection.apiToken)}`,
  });
  const init: RequestInit = {headers, method: call.method};
  if (call.jsonBody !== undefined) {
    headers.set("Content-Type", "application/json");
    init.body = call.jsonBody;
  }
  const response = await fetch(`${connection.origin}${path}`, init);
  const payload: unknown = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const failure = z.object({error: z.object({message: z.string()})}).safeParse(payload);
    throw new Error(failure.success ? failure.data.error.message : "Artifact state request failed.");
  }
  return schema.parse(payload);
}

function parseJsonText(text: string): z.core.util.JSONType | undefined {
  try {
    return z.json().parse(JSON.parse(text));
  } catch {
    return undefined;
  }
}

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
      const response = await stateRequest(options, artifactId);
      const result = z.object({entries: z.array(entrySchema)}).parse(response);
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("get <artifact-id> <key>")
    .description("Read one state value.")
    .action(async (artifactId: string, key: string, options: ArtifactStateOptions) => {
      const response = await stateRequest(options, artifactId, key);
      const result = z.object({entry: entrySchema.nullable()}).parse(response);
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("set <artifact-id> <key> <json>")
    .description("Write one JSON state value.")
    .action(async (artifactId: string, key: string, value: string, options: ArtifactStateOptions) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(value);
      } catch {
        throw new Error("State value must be valid JSON.");
      }
      const response = await stateRequest(options, artifactId, key, "PUT", {value: parsed});
      const result = z.object({entry: entrySchema}).parse(response);
      console.log(JSON.stringify(result, null, 2));
    }));

  connectionOptions(state.command("delete <artifact-id> <key>")
    .description("Delete one state value.")
    .action(async (artifactId: string, key: string, options: ArtifactStateOptions) => {
      await stateRequest(options, artifactId, key, "DELETE");
      console.log(JSON.stringify({deleted: true}));
    }));
}

async function stateRequest(
  options: ArtifactStateOptions,
  artifactId: string,
  key?: string,
  method = "GET",
  body?: unknown,
): Promise<unknown> {
  if (artifactId.trim() === "") throw new Error("Artifact ID is required.");
  const connection = await resolveCliServerConnection(options, "artifact state");
  const project = options.project === undefined
    ? ""
    : `?projectId=${encodeURIComponent(options.project)}`;
  const path = key === undefined
    ? `/api/v1/artifacts/${encodeURIComponent(artifactId)}/state${project}`
    : `/api/v1/artifacts/${encodeURIComponent(artifactId)}/state/${encodeURIComponent(key)}${project}`;
  const response = await fetch(`${connection.origin}${path}`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${Redacted.value(connection.apiToken)}`,
      ...(body === undefined ? {} : {"Content-Type": "application/json"}),
    },
    method,
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
  });
  const result: unknown = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    const failure = z.object({error: z.object({message: z.string()})}).safeParse(result);
    throw new Error(failure.success ? failure.data.error.message : "Artifact state request failed.");
  }
  return result;
}

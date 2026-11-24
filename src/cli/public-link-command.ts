import {Option, type Command} from "commander";
import {Redacted} from "effect";
import {z} from "zod";

import {artifactServerRouteUrl} from "../core/server-address.js";
import {resolveCliServerConnection, type CliServerConnectionOptions} from "./cli-server-connection.js";

interface PublicLinkOptions extends CliServerConnectionOptions {
  readonly permission?: "view" | "comment";
  readonly project?: string;
}

const failureSchema = z.object({error: z.object({code: z.string(), message: z.string()}).passthrough()}).passthrough();
const statusSchema = z.object({activeSessionCount: z.number().int(), copyAvailable: z.boolean(), createdAt: z.string().nullable(), enabled: z.boolean(), legacy: z.boolean(), limitHitRecently: z.boolean(), permission: z.enum(["view", "comment"]), updatedAt: z.string().nullable(), url: z.url().nullable()}).passthrough();
const issuedSchema = z.object({createdAt: z.string(), permission: z.enum(["view", "comment"]), url: z.url()}).passthrough();
const sessionsSchema = z.object({sessions: z.array(z.object({createdAt: z.string(), displayName: z.string(), guestId: z.string(), lastUsedAt: z.string()}))}).passthrough();

/** Register public-link manager commands. */
export function configurePublicLinkCommand(program: Command, options: {readonly defaultProfileDirectory: string}): void {
  const publicLink = program.command("public-link").description("Manage an artifact's public link.");
  for (const operation of ["get", "create", "set", "reset", "revoke"] as const) {
    const command = publicLink.command(`${operation} <artifact-id>`)
      .description(publicLinkDescription(operation))
      .addOption(new Option("--server <origin>", "Houston Artifacts origin").env("ARTIFACT_SERVER_URL"))
      .addOption(new Option("--profile <name>", "saved Houston Artifacts profile"))
      .addOption(new Option("--profile-data <directory>", "user-local CLI profile directory").default(options.defaultProfileDirectory).env("ARTIFACT_SERVER_HOME"))
      .addOption(new Option("--data <directory>", "local Houston Artifacts data directory").default(".artifact-server"))
      .addOption(new Option("--token-file <path>", "file containing a Houston Artifacts API token"))
      .addOption(new Option("--project <id>", "project ID; optional when one active project exists"));
    if (["create", "set", "reset"].includes(operation)) {
      command.addOption(new Option("--permission <permission>", "public-link permission").choices(["view", "comment"]));
    }
    command.action(async (artifactId: string, commandOptions: PublicLinkOptions) => {
      if (!artifactId.trim()) throw new Error("Artifact ID is required.");
      const connection = await resolveCliServerConnection(commandOptions, "state");
      const base = `/api/v1/artifacts/${encodeURIComponent(artifactId)}/public-link`;
      const project = commandOptions.project === undefined ? "" : `?projectId=${encodeURIComponent(commandOptions.project)}`;
      const headers = {Authorization: `Bearer ${Redacted.value(connection.apiToken)}`, Accept: "application/json"};
      const permission = commandOptions.permission ?? "view";
      let response: Response;
      switch (operation) {
        case "get":
          response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {headers, redirect: "error", signal: AbortSignal.timeout(30_000)});
          break;
        case "create":
          response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {method: "POST", headers: {...headers, "Content-Type": "application/json"}, body: JSON.stringify({permission}), redirect: "error", signal: AbortSignal.timeout(30_000)});
          break;
        case "set":
          response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {method: "PATCH", headers: {...headers, "Content-Type": "application/json"}, body: JSON.stringify({permission}), redirect: "error", signal: AbortSignal.timeout(30_000)});
          break;
        case "reset":
          response = await fetch(artifactServerRouteUrl(`${base}/reset${project}`, connection.origin), {method: "POST", headers: {...headers, "Content-Type": "application/json"}, body: JSON.stringify({permission}), redirect: "error", signal: AbortSignal.timeout(30_000)});
          break;
        case "revoke":
          response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {method: "DELETE", headers, redirect: "error", signal: AbortSignal.timeout(30_000)});
          break;
      }
      if (!response.ok) throw await requestFailure(response);
      if (operation === "revoke") {
        console.log(JSON.stringify({revoked: true}, null, 2));
      } else {
        const result = operation === "get" ? statusSchema.parse(await response.json()) : operation === "set"
          ? z.object({permission: z.enum(["view", "comment"])}).parse(await response.json())
          : issuedSchema.parse(await response.json());
        console.log(JSON.stringify(result, null, 2));
      }
    });
  }

  const sessions = publicLink.command("sessions <artifact-id>")
    .description("List active public-link sessions")
    .addOption(new Option("--server <origin>", "Houston Artifacts origin").env("ARTIFACT_SERVER_URL"))
    .addOption(new Option("--profile <name>", "saved Houston Artifacts profile"))
    .addOption(new Option("--profile-data <directory>", "user-local CLI profile directory").default(options.defaultProfileDirectory).env("ARTIFACT_SERVER_HOME"))
    .addOption(new Option("--data <directory>", "local Houston Artifacts data directory").default(".artifact-server"))
    .addOption(new Option("--token-file <path>", "file containing a Houston Artifacts API token"))
    .addOption(new Option("--project <id>", "project ID; optional when one active project exists"));
  sessions.action(async (artifactId: string, commandOptions: PublicLinkOptions) => {
    if (!artifactId.trim()) throw new Error("Artifact ID is required.");
    const connection = await resolveCliServerConnection(commandOptions, "state");
    const base = `/api/v1/artifacts/${encodeURIComponent(artifactId)}/public-link/sessions`;
    const project = commandOptions.project === undefined ? "" : `?projectId=${encodeURIComponent(commandOptions.project)}`;
    const headers = {Authorization: `Bearer ${Redacted.value(connection.apiToken)}`, Accept: "application/json"};
    const response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {headers, redirect: "error", signal: AbortSignal.timeout(30_000)});
    if (!response.ok) throw await requestFailure(response);
    console.log(JSON.stringify(sessionsSchema.parse(await response.json()), null, 2));
  });

  const revokeSession = publicLink.command("revoke-session <artifact-id> <guest-id>")
    .description("Revoke one active public-link session")
    .addOption(new Option("--server <origin>", "Houston Artifacts origin").env("ARTIFACT_SERVER_URL"))
    .addOption(new Option("--profile <name>", "saved Houston Artifacts profile"))
    .addOption(new Option("--profile-data <directory>", "user-local CLI profile directory").default(options.defaultProfileDirectory).env("ARTIFACT_SERVER_HOME"))
    .addOption(new Option("--data <directory>", "local Houston Artifacts data directory").default(".artifact-server"))
    .addOption(new Option("--token-file <path>", "file containing a Houston Artifacts API token"))
    .addOption(new Option("--project <id>", "project ID; optional when one active project exists"));
  revokeSession.action(async (artifactId: string, guestId: string, commandOptions: PublicLinkOptions) => {
    if (!artifactId.trim() || !guestId.trim()) throw new Error("Artifact ID and guest ID are required.");
    const connection = await resolveCliServerConnection(commandOptions, "state");
    const base = `/api/v1/artifacts/${encodeURIComponent(artifactId)}/public-link/sessions/${encodeURIComponent(guestId)}`;
    const project = commandOptions.project === undefined ? "" : `?projectId=${encodeURIComponent(commandOptions.project)}`;
    const headers = {Authorization: `Bearer ${Redacted.value(connection.apiToken)}`, Accept: "application/json"};
    const response = await fetch(artifactServerRouteUrl(`${base}${project}`, connection.origin), {method: "DELETE", headers, redirect: "error", signal: AbortSignal.timeout(30_000)});
    if (!response.ok) throw await requestFailure(response);
    console.log(JSON.stringify({revoked: true}, null, 2));
  });
}

function publicLinkDescription(operation: string): string {
  switch (operation) {
    case "get": return "Read public-link settings";
    case "create": return "Create a public link if none exists";
    case "set": return "Set public-link permission";
    case "reset": return "Rotate the public-link secret";
    case "revoke": return "Revoke a public link and its sessions";
    default: return operation;
  }
}

async function requestFailure(response: Response): Promise<Error> {
  try {
    const failure = failureSchema.parse(await response.json());
    return new Error(`${failure.error.code} (HTTP ${response.status}): ${failure.error.message}`);
  } catch {
    return new Error(`The public-link request failed (HTTP ${response.status}).`);
  }
}

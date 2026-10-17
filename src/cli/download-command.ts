import {createWriteStream} from "node:fs";
import {mkdir} from "node:fs/promises";
import {Readable} from "node:stream";
import {pipeline} from "node:stream/promises";
import path from "node:path";

import {Option, type Command} from "commander";
import {Redacted} from "effect";

import {resolveCliServerConnection} from "./cli-server-connection.js";

interface DownloadOptions {
  readonly data: string;
  readonly output?: string;
  readonly profile?: string;
  readonly profileData: string;
  readonly project?: string;
  readonly server?: string;
  readonly tokenFile?: string;
}

export function configureDownloadCommand(
  program: Command,
  commandOptions: {readonly defaultProfileDirectory: string},
): void {
  program
    .command("download")
    .description("Download an immutable artifact version source bundle as a ZIP.")
    .argument("<artifact-id>", "artifact ID")
    .argument("<version-id>", "exact version ID")
    .addOption(new Option("--project <id>", "project ID; optional when one active project exists"))
    .addOption(new Option("--output <file>", "ZIP file to create; defaults to the server filename"))
    .addOption(new Option("--server <origin>", "Artifact Server origin").env("ARTIFACT_SERVER_URL"))
    .addOption(new Option("--data <directory>", "local Artifact Server data directory").default(".artifact-server"))
    .addOption(new Option("--token-file <path>", "file containing an Artifact Server API token"))
    .addOption(new Option("--profile <name>", "saved Artifact Server profile"))
    .addOption(new Option("--profile-data <directory>", "user-local CLI profile directory")
      .default(commandOptions.defaultProfileDirectory).env("ARTIFACT_SERVER_HOME"))
    .action(async (artifactId: string, versionId: string, options: DownloadOptions) => {
      const connection = await resolveCliServerConnection(options, "history");
      const endpoint = new URL(
        `/api/v1/artifacts/${encodeURIComponent(artifactId)}/versions/${encodeURIComponent(versionId)}/archive`,
        connection.origin,
      );
      if (options.project !== undefined) endpoint.searchParams.set("projectId", options.project);
      const response = await fetch(endpoint, {
        headers: {Authorization: `Bearer ${Redacted.value(connection.apiToken)}`},
        redirect: "error",
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Artifact download failed (${response.status}): ${detail.slice(0, 1000)}`);
      }
      if (response.body === null) throw new Error("Artifact Server returned an empty download.");
      const disposition = response.headers.get("content-disposition") ?? "";
      const serverFilename = disposition.match(/filename\*=UTF-8''([^;]+)/iu)?.[1];
      const filename = serverFilename === undefined
        ? `artifact-${artifactId}-${versionId}.zip`
        : decodeURIComponent(serverFilename);
      const output = path.resolve(options.output ?? filename);
      await mkdir(path.dirname(output), {recursive: true});
      await pipeline(
        Readable.from(response.body),
        createWriteStream(output, {flags: "wx", mode: 0o600}),
      );
      console.log(JSON.stringify({artifactId, output, versionId}, null, 2));
    });
}

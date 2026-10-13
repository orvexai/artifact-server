import {spawnSync} from "node:child_process";
import {mkdtemp, readFile, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";

import {describe, expect, test} from "vitest";
import {z} from "zod";

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const cliExecutable = path.join(repositoryRoot, "node_modules/.bin/tsx");
const cliEntrypoint = path.join(repositoryRoot, "src/cli/main.ts");

function runCli(argumentsToPass: readonly string[], profileData: string) {
  const result = spawnSync(cliExecutable, [cliEntrypoint, ...argumentsToPass], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {...process.env, ARTIFACT_SERVER_HOME: profileData},
    timeout: 30_000,
  });
  return {exitCode: result.status, stderr: result.stderr, stdout: result.stdout};
}

describe("CLI option parsing", () => {
  test("keeps the root version flag while comments list owns its --version option", async () => {
    const profileData = await mkdtemp(path.join(tmpdir(), "artifact-server-cli-options-"));
    try {
      const packageMetadata = z.object({version: z.string()}).parse(JSON.parse(
        await readFile(path.join(repositoryRoot, "package.json"), "utf8"),
      ));

      const version = runCli(["--version"], profileData);
      expect(version.exitCode).toBe(0);
      expect(version.stdout.trim()).toBe(packageMetadata.version);

      // Plannotator's comment import passes --version <id>; it must reach the
      // command, not print the CLI version and exit successfully.
      const comments = runCli([
        "comments",
        "list",
        "artifact-id",
        "--server",
        "https://artifacts.example.test",
        "--version",
        "version-id",
      ], profileData);
      expect(comments.stdout.trim()).not.toBe(packageMetadata.version);
      expect(comments.exitCode).not.toBe(0);
      expect(comments.stderr).toContain(
        "No Artifact Server profile matches https://artifacts.example.test",
      );
    } finally {
      await rm(profileData, {force: true, recursive: true});
    }
  }, 60_000);
});

import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {Effect, Redacted} from "effect";
import {afterEach, describe, expect, it} from "vitest";

import {createSystemCredentialStore} from "../../src/cli/system-credential-store.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, {recursive: true, force: true})
  ));
});

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "artifact-cli-credentials-"));
  temporaryDirectories.push(directory);
  return directory;
}

describe("CLI credential file fallback", () => {
  it("uses the private file store when no keyring executable is available", async () => {
    const home = await temporaryDirectory();
    const store = createSystemCredentialStore({
      environment: {
        HOME: home,
        PATH: "",
        XDG_CONFIG_HOME: path.join(home, "config"),
      },
      platform: "linux",
    });

    await Effect.runPromise(store.write("profile-1", Redacted.make("secret-value")));
    const stored = await Effect.runPromise(store.read("profile-1"));
    const filePath = path.join(home, "config", "artifact-server", "credentials.json");

    expect(Redacted.value(stored)).toBe("secret-value");
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(filePath, "utf8"))).toEqual({
      "profile-1": "secret-value",
    });
  });

  it("uses the Linux keyring adapter when secret-tool is reachable", async () => {
    const home = await temporaryDirectory();
    const helperState = path.join(home, "keyring.json");
    const bin = path.join(home, "bin");
    const secretTool = path.join(bin, "secret-tool");
    await mkdir(bin, {mode: 0o700});
    await writeFile(secretTool, `#!${process.execPath}\n${[
      "import {readFile, writeFile} from 'node:fs/promises';",
      "let input = ''; for await (const chunk of process.stdin) input += chunk;",
      `const statePath = ${JSON.stringify(helperState)};`,
      "let state = {}; try { state = JSON.parse(await readFile(statePath, 'utf8')); } catch {}",
      "const account = process.argv.at(-1);",
      "if (process.argv[2] === 'store') { state[account] = input; await writeFile(statePath, JSON.stringify(state)); }",
      "else if (process.argv[2] === 'lookup') process.stdout.write(state[account] ?? '');",
      "else { delete state[account]; await writeFile(statePath, JSON.stringify(state)); }",
    ].join("\n")}\n`, {mode: 0o700});
    await chmod(secretTool, 0o700);
    const store = createSystemCredentialStore({
      environment: {
        HOME: home,
        PATH: bin,
        XDG_CONFIG_HOME: path.join(home, "config"),
      },
      platform: "linux",
    });

    await Effect.runPromise(store.write("profile-2", Redacted.make("keyring-secret")));
    const stored = await Effect.runPromise(store.read("profile-2"));

    expect(Redacted.value(stored)).toBe("keyring-secret");
    expect(JSON.parse(await readFile(helperState, "utf8"))).toEqual({
      "profile-2": "keyring-secret",
    });
    await expect(readFile(path.join(home, "config", "artifact-server", "credentials.json")))
      .rejects.toMatchObject({code: "ENOENT"});
  });

  it("refuses a file credential store readable by group or world", async () => {
    const home = await temporaryDirectory();
    const configHome = path.join(home, "config");
    const storePath = path.join(configHome, "artifact-server", "credentials.json");
    await mkdir(path.dirname(storePath), {recursive: true, mode: 0o700});
    await writeFile(storePath, JSON.stringify({"profile-3": "secret-value"}), {mode: 0o600});
    await chmod(storePath, 0o644);
    const store = createSystemCredentialStore({
      environment: {
        ARTIFACT_SERVER_CREDENTIAL_STORE: "file",
        HOME: home,
        XDG_CONFIG_HOME: configHome,
      },
      platform: "linux",
    });

    await expect(Effect.runPromise(store.read("profile-3")))
      .rejects.toThrow("unsafe permissions; set it to 0600");
  });
});

import {mkdtemp, readFile, rm, stat} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {Effect, Redacted} from "effect";
import {afterEach, describe, expect, test} from "vitest";

import {createSystemCredentialStore} from "../../src/cli/system-credential-store.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, {recursive: true, force: true})
  ));
});

describe("CLI credential store selection", () => {
  test("uses the configured private file store for headless profile credentials", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "artifact-cli-credentials-"));
    temporaryDirectories.push(home);
    const configHome = path.join(home, "config");
    const store = createSystemCredentialStore({
      environment: {
        ARTIFACT_SERVER_CREDENTIAL_STORE: "file",
        HOME: home,
        XDG_CONFIG_HOME: configHome,
      },
      platform: "linux",
    });

    await Effect.runPromise(store.write("profile-1", Redacted.make("secret-value")));
    const stored = await Effect.runPromise(store.read("profile-1"));
    const filePath = path.join(configHome, "artifact-server", "credentials.json");

    expect(Redacted.value(stored)).toBe("secret-value");
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(await readFile(filePath, "utf8"))).toEqual({
      "profile-1": "secret-value",
    });
  });
});

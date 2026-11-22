import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {
  createTestInstallation,
  fetchVersion,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {
  commitStagedUpload,
  createStagedUpload,
  type TestSiteFile,
  uploadEveryStagedFile,
} from "../support/publishing.js";

describe("partial publish behavior", () => {
  const publishBodySchema = z.object({
    artifact: z.object({id: z.string()}).loose(),
    links: z.object({version: z.url()}).loose(),
    version: z.object({entryPath: z.string(), id: z.string()}).loose(),
  }).loose();
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation);
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("P1-P3: complete uploads replace the file set; carry-forward is explicit and removable", async () => {
    const initial = [
      file("index.html", "text/html", "<script src=app.js></script>"),
      file("app.js", "text/javascript", "old app"),
      file("data.json", "application/json", "{\"v\":1}"),
    ];
    const first = await publishFiles("partial-publish-initial", initial, "index.html");

    const defaultVersion = await commitVersion(
      first.body.artifact.id,
      first.body.version.id,
      "partial-publish-default",
      [file("data.json", "application/json", "{\"v\":2}")],
      "data.json",
    );
    expect(defaultVersion.response.status).toBe(201);
    if (defaultVersion.body === null) throw new Error("Default publish did not return a version.");
    const defaultDiff = await difference(first.body.artifact.id, first.body.version.id, defaultVersion.body.version.id);
    expect(defaultDiff.removed.map((entry) => entry.path).toSorted()).toEqual(["app.js", "index.html"]);
    expect(defaultVersion.body.version.entryPath).toBe("data.json");

    const carryBase = await publishFiles("partial-publish-carry-base", initial, "index.html");
    const carry = await commitVersion(
      carryBase.body.artifact.id,
      carryBase.body.version.id,
      "partial-publish-carry",
      [file("data.json", "application/json", "{\"v\":3}")],
      "data.json",
      {carryForward: true},
    );
    expect(carry.response.status).toBe(201);
    if (carry.body === null) throw new Error("Carry-forward publish did not return a version.");
    const carryDiff = await difference(carryBase.body.artifact.id, carryBase.body.version.id, carry.body.version.id);
    expect(carryDiff.removed).toEqual([]);
    expect(carry.body.version.entryPath).toBe("index.html");

    const removed = await commitVersion(
      carryBase.body.artifact.id,
      carry.body.version.id,
      "partial-publish-remove",
      [file("data.json", "application/json", "{\"v\":4}")],
      "data.json",
      {carryForward: true, removePaths: ["app.js"]},
    );
    expect(removed.response.status).toBe(201);
    if (removed.body === null) throw new Error("Removal publish did not return a version.");
    const removeDiff = await difference(carryBase.body.artifact.id, carry.body.version.id, removed.body.version.id);
    expect(removeDiff.removed.map((entry) => entry.path)).toEqual(["app.js"]);
    const appResponse = await fetchVersion(server, `${removed.body.links.version}app.js`);
    expect(appResponse.status).toBe(404);
  });

  test("P4-P6: invalid removals refuse, missing bases conflict, and replay binds the removal set", async () => {
    const files = [
      file("index.html", "text/html", "index"),
      file("app.js", "text/javascript", "app"),
      file("data.json", "application/json", "data"),
      file("unused.txt", "text/plain", "unused"),
    ];
    const first = await publishFiles("partial-publish-p4-initial", files, "index.html");

    const refusals = await Promise.all([["index.html"], ["missing.txt"], ["data.json"]].map(async (removePaths) => {
      const uploadPath = removePaths[0] === "data.json" ? "data.json" : "app.js";
      const uploadFiles = uploadPath === "data.json"
        ? [file("data.json", "application/json", "changed")]
        : [file("app.js", "text/javascript", "changed")];
      const attempt = await commitVersion(
        first.body.artifact.id,
        first.body.version.id,
        `partial-publish-reject-${removePaths[0]}`,
        uploadFiles,
        uploadPath,
        {carryForward: true, removePaths},
      );
      return attempt;
    }));
    for (const refusal of refusals) {
      expect(refusal.response.status).toBeGreaterThanOrEqual(400);
      expect(refusal.response.status).toBeLessThan(500);
      expect(refusal.body).toBeNull();
    }
    const noCarry = await commitVersion(
      first.body.artifact.id,
      first.body.version.id,
      "partial-publish-reject-no-carry",
      [file("app.js", "text/javascript", "changed")],
      "app.js",
      {removePaths: ["data.json"]},
    );
    expect(noCarry.response.status).toBe(400);
    expect(noCarry.body).toBeNull();

    const missingBase = await commitVersion(
      first.body.artifact.id,
      "ver_missing_expected_base",
      "partial-publish-missing-base",
      [file("data.json", "application/json", "missing base")],
      "data.json",
      {carryForward: true},
    );
    expect(missingBase.response.status).toBe(409);
    expect(missingBase.body).toBeNull();

    const upload = await stagedFiles([file("app.js", "text/javascript", "replayed")], "app.js");
    const target = {
      artifactId: first.body.artifact.id,
      carryForward: true,
      expectedCurrentVersionId: first.body.version.id,
      kind: "new_version" as const,
      removePaths: ["data.json"],
    };
    const original = await commitRaw(upload, "partial-publish-replay", target);
    expect(original.response.status).toBe(201);
    if (original.body === null) throw new Error("Initial replay publish did not return a version.");
    const replay = await commitRaw(upload, "partial-publish-replay", target);
    expect(replay.response.status).toBe(200);
    if (replay.body === null) throw new Error("Replayed publish did not return a version.");
    expect(replay.body.version.id).toBe(original.body.version.id);
    const changedRemoval = await commitRaw(upload, "partial-publish-replay", {...target, removePaths: ["unused.txt"]});
    expect(changedRemoval.response.status).toBe(409);
  });

  async function publishFiles(key: string, files: readonly TestSiteFile[], entryPath: string) {
    const staged = await stagedFiles(files, entryPath);
    return commitStagedUpload(installation, staged, key, {
      accessSetting: "public_link",
      kind: "new_artifact",
      name: "Partial publish fixture",
    });
  }

  async function stagedFiles(files: readonly TestSiteFile[], entryPath: string) {
    const upload = await createStagedUpload(server, installation, entryPath, files);
    await uploadEveryStagedFile(installation, upload.body, files);
    return upload.body;
  }

  async function commitVersion(
    artifactId: string,
    expectedCurrentVersionId: string,
    key: string,
    files: readonly TestSiteFile[],
    entryPath: string,
    extra: {readonly carryForward?: boolean; readonly removePaths?: readonly string[]} = {},
  ) {
    const upload = await stagedFiles(files, entryPath);
    return commitRaw(upload, key, {artifactId, expectedCurrentVersionId, kind: "new_version", ...extra});
  }

  async function commitRaw(
    upload: Awaited<ReturnType<typeof stagedFiles>>,
    key: string,
    target: {
      readonly artifactId: string;
      readonly carryForward?: boolean;
      readonly expectedCurrentVersionId: string;
      readonly kind: "new_version";
      readonly removePaths?: readonly string[];
    },
  ) {
    const response = await fetch(upload.commitUrl, {
      body: JSON.stringify({target}),
      headers: {
        Authorization: `Bearer ${installation.apiToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": key,
      },
      method: "POST",
    });
    const value: unknown = await response.json();
    if (response.ok) {
      const body = publishBodySchema.parse(value);
      return {body, response};
    }
    return {body: null, response, value};
  }

  async function difference(artifactId: string, fromVersionId: string, toVersionId: string) {
    const response = await fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/comparisons?${new URLSearchParams({fromVersionId, toVersionId})}`, {
      headers: {Authorization: `Bearer ${installation.apiToken}`},
    });
    expect(response.status).toBe(200);
    return z.object({
      removed: z.array(z.object({path: z.string()}).loose()),
    }).loose().parse(await response.json());
  }
});

function file(path: string, mediaType: string, text: string): TestSiteFile {
  return {bytes: new TextEncoder().encode(text), mediaType, path};
}

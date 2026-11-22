import {DatabaseSync} from "node:sqlite";
import {readdir} from "node:fs/promises";
import nodePath from "node:path";

import {createHash} from "node:crypto";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
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
  const protocolVersion = "2026-07-28";
  const publishBodySchema = z.object({
    artifact: z.object({id: z.string()}).loose(),
    links: z.object({version: z.url()}).loose(),
    version: z.object({entryPath: z.string(), id: z.string()}).loose(),
  }).loose();
  const mcpToolResultSchema = z.object({
    result: z.object({
      content: z.array(z.object({text: z.string()}).loose()),
      isError: z.boolean().optional(),
      structuredContent: z.unknown().optional(),
    }).loose(),
  }).loose();
  const mcpUploadSchema = z.object({
    files: z.array(z.object({method: z.literal("PUT"), path: z.string(), uploadUrl: z.url()}).loose()).min(1),
    uploadId: z.string(),
  }).loose();
  const mcpPublicationSchema = z.object({
    artifact: z.object({id: z.string()}).loose(),
    version: z.object({id: z.string()}).loose(),
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
      await expectRefusalWithoutPublication(attempt, first.body.artifact.id);
      expectNoBlobWrite(attempt);
      return attempt;
    }));
    for (const attempt of refusals) {
      expect(attempt.response.status).toBeGreaterThanOrEqual(400);
      expect(attempt.response.status).toBeLessThan(500);
      expect(attempt.body).toBeNull();
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
    await expectRefusalWithoutPublication(noCarry, first.body.artifact.id);
    expectNoBlobWrite(noCarry);

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
    await expectRefusalWithoutPublication(missingBase, first.body.artifact.id);
    expectNoBlobWrite(missingBase);

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

  test("MCP artifact_commit_upload defaults to a complete file set and rejects removePaths without carryForward", async () => {
    const initial = await publishFiles(
      "partial-publish-mcp-initial",
      [file("index.html", "text/html", "index"), file("old.js", "text/javascript", "old")],
      "index.html",
    );
    const defaultFiles = [file("data.json", "application/json", "{\"mcp\":true}")];
    const defaultUpload = await createMcpUpload(defaultFiles, "data.json");
    const defaultResult = await callMcpTool("artifact_commit_upload", {
      idempotencyKey: "partial-publish-mcp-default",
      target: {
        artifactId: initial.body.artifact.id,
        expectedCurrentVersionId: initial.body.version.id,
        kind: "new_version",
      },
      uploadId: defaultUpload.uploadId,
    });
    expect(defaultResult.isError).not.toBe(true);
    const published = mcpPublicationSchema.parse(defaultResult.structuredContent);
    const defaultState = readArtifactSnapshot(initial.body.artifact.id);
    expect(defaultState.currentVersionId).toBe(published.version.id);
    expect(readVersionPaths(published.version.id)).toEqual(["data.json"]);

    const refusedUpload = await createMcpUpload(
      [file("data.json", "application/json", "{\"mcp\":false}")],
      "data.json",
    );
    const refused = await callMcpTool("artifact_commit_upload", {
      idempotencyKey: "partial-publish-mcp-remove-without-carry",
      target: {
        artifactId: initial.body.artifact.id,
        expectedCurrentVersionId: published.version.id,
        kind: "new_version",
        removePaths: ["old.js"],
      },
      uploadId: refusedUpload.uploadId,
    });
    expect(refused.isError).toBe(true);
    expect(refused.content[0]?.text).toMatch(/carryForward|removePaths/i);
    expect(readArtifactSnapshot(initial.body.artifact.id).currentVersionId).toBe(published.version.id);
    expect(readVersionPaths(published.version.id)).toEqual(["data.json"]);
  });

  test("F4: stale existing bases conflict in carry-forward and complete modes", async () => {
    const first = await publishFiles(
      "partial-publish-stale-base-initial",
      [file("index.html", "text/html", "v1"), file("app.js", "text/javascript", "v1 app")],
      "index.html",
    );
    const second = await commitVersion(
      first.body.artifact.id,
      first.body.version.id,
      "partial-publish-stale-base-current-v2",
      [file("index.html", "text/html", "v2")],
      "index.html",
    );
    expect(second.response.status).toBe(201);
    if (second.body === null) throw new Error("Second version did not return a version.");

    const staleCarry = await commitVersion(
      first.body.artifact.id,
      first.body.version.id,
      "partial-publish-stale-carry-forward",
      [file("carry.txt", "text/plain", "stale carry-forward")],
      "carry.txt",
      {carryForward: true},
    );
    expect(staleCarry.response.status).toBe(409);
    expect(staleCarry.body).toBeNull();
    await expectRefusalWithoutPublication(staleCarry, first.body.artifact.id);
    expect(staleCarry.stateBefore.currentVersionId).toBe(second.body.version.id);

    const staleComplete = await commitVersion(
      first.body.artifact.id,
      first.body.version.id,
      "partial-publish-stale-complete",
      [file("complete.txt", "text/plain", "stale complete")],
      "complete.txt",
    );
    expect(staleComplete.response.status).toBe(409);
    expect(staleComplete.body).toBeNull();
    await expectRefusalWithoutPublication(staleComplete, first.body.artifact.id);
    expect(staleComplete.stateBefore.currentVersionId).toBe(second.body.version.id);
    // Blobs are stored before commitVersion's optimistic check, so stale-base 409s may leave an unreferenced content-addressed blob, as on the base; no-blob assertions apply to validation refusals only.
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
    const stateBefore = readArtifactSnapshot(target.artifactId);
    const blobCountBefore = await countBlobFiles(nodePath.join(installation.dataDirectory, "blobs"));
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
    const blobCountAfter = await countBlobFiles(nodePath.join(installation.dataDirectory, "blobs"));
    if (response.ok) {
      const body = publishBodySchema.parse(value);
      return {body, blobCountAfter, blobCountBefore, response, stateBefore};
    }
    return {blobCountAfter, blobCountBefore, body: null, response, stateBefore, value};
  }

  async function expectRefusalWithoutPublication(
    attempt: {
      readonly blobCountAfter?: number;
      readonly blobCountBefore: number;
      readonly stateBefore: ReturnType<typeof readArtifactSnapshot>;
    },
    artifactId: string,
  ): Promise<void> {
    expect(attempt.stateBefore.currentVersionId).not.toBeNull();
    expect(readArtifactSnapshot(artifactId)).toEqual(attempt.stateBefore);
  }

  function expectNoBlobWrite(attempt: {readonly blobCountAfter?: number; readonly blobCountBefore: number}): void {
    expect(attempt.blobCountAfter).toBe(attempt.blobCountBefore);
  }

  function readArtifactSnapshot(artifactId: string) {
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"), {readOnly: true});
    try {
      const artifact = z.object({currentVersionId: z.string().nullable()}).parse(database.prepare(
        "SELECT current_version_id AS currentVersionId FROM artifacts WHERE id = ?",
      ).get(artifactId));
      const versions = z.object({count: z.number()}).parse(database.prepare(
        "SELECT COUNT(*) AS count FROM versions WHERE artifact_id = ?",
      ).get(artifactId));
      return {currentVersionId: artifact.currentVersionId, versionCount: versions.count};
    } finally {
      database.close();
    }
  }

  function readVersionPaths(versionId: string): string[] {
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"), {readOnly: true});
    try {
      return z.array(z.object({path: z.string()})).parse(database.prepare(
        "SELECT path FROM manifest_entries WHERE version_id = ? ORDER BY path",
      ).all(versionId)).map(({path: filePath}) => filePath);
    } finally {
      database.close();
    }
  }

  async function countBlobFiles(directory: string): Promise<number> {
    let entries;
    try {
      entries = await readdir(directory, {withFileTypes: true});
    } catch (error) {
      if (z.object({code: z.string().optional()}).safeParse(error).data?.code === "ENOENT") return 0;
      throw error;
    }
    const counts = await Promise.all(entries.map(async (entry) => entry.isDirectory()
      ? countBlobFiles(nodePath.join(directory, entry.name))
      : entry.isFile() ? 1 : 0));
    return counts.reduce((total, count) => total + count, 0);
  }

  async function createMcpUpload(files: readonly TestSiteFile[], entryPath: string) {
    const declaredFiles = files.map((item) => ({
      mediaType: item.mediaType,
      path: item.path,
      sha256: createHash("sha256").update(item.bytes).digest("hex"),
      size: item.bytes.byteLength,
    }));
    const created = await callMcpTool("artifact_create_upload", {entryPath, files: declaredFiles});
    expect(created.isError).not.toBe(true);
    const upload = mcpUploadSchema.parse(created.structuredContent);
    await Promise.all(upload.files.map(async (plan) => {
      const item = files.find(({path: manifestPath}) => manifestPath === plan.path);
      if (item === undefined) throw new Error(`Unexpected MCP upload path ${plan.path}.`);
      const response = await fetch(plan.uploadUrl, {body: Buffer.from(item.bytes), method: plan.method});
      expect(response.status).toBe(200);
    }));
    return upload;
  }

  async function callMcpTool(name: string, args: McpArguments) {
    const response = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          arguments: args,
          name,
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "artifact-server-partial-publish-test", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: protocolVersion,
          },
        },
      }),
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${installation.apiToken}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
      },
      method: "POST",
    });
    expect(response.status).toBe(200);
    return mcpToolResultSchema.parse(await response.json()).result;
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

type McpValue = boolean | number | string | null | readonly McpValue[] | McpArguments;

interface McpArguments {
  readonly [key: string]: McpValue;
}

function file(path: string, mediaType: string, text: string): TestSiteFile {
  return {bytes: new TextEncoder().encode(text), mediaType, path};
}

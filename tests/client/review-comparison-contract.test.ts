/**
 * Review's Compare tab validates every comparison response against the web
 * client's own schema. The server reports a changed bounded-text file as a
 * list of line regions (`detail.changes`); when the client still expected a
 * single nullable `detail.change`, every small text change made Compare fail
 * with "Artifact Server returned data that does not match the expected
 * contract." This test parses a response from a real server with the exact
 * schema the browser uses, so the two contracts cannot drift apart again.
 */

import {afterEach, beforeEach, describe, expect, test} from "vitest";

import {comparisonSchema} from "../../apps/web/src/api/client.js";
import {
  commitStagedUpload,
  createStagedUpload,
  type TestSiteFile,
  uploadEveryStagedFile,
} from "../support/publishing.js";
import {
  createTestInstallation,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

describe("Review comparison client contract", () => {
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

  test("the web client parses a server comparison of small text, binary, and oversized changes", async () => {
    const before: readonly TestSiteFile[] = [
      text("notes.txt", "text/plain; charset=utf-8", "alpha\nbravo\ncharlie\ndelta\necho\n"),
      text("review.md", "text/markdown; charset=utf-8", "# Plan\n\n- [ ] draft\n"),
      text("removed-lines.txt", "text/plain", "keep\ndrop one\ndrop two\nkeep too\n"),
      {bytes: new Uint8Array([0, 1, 2, 3]), mediaType: "application/octet-stream", path: "binary.dat"},
      text("large.txt", "text/plain", "a".repeat(256 * 1_024 + 1)),
    ];
    const after: readonly TestSiteFile[] = [
      text("notes.txt", "text/plain; charset=utf-8", "alpha\nBRAVO\ncharlie\ndelta\necho\nfoxtrot\n"),
      text("review.md", "text/markdown; charset=utf-8", "# Plan\n\n- [x] draft\n- [ ] ship\n"),
      text("removed-lines.txt", "text/plain", "keep\nkeep too\n"),
      {bytes: new Uint8Array([0, 1, 9, 3]), mediaType: "application/octet-stream", path: "binary.dat"},
      text("large.txt", "text/plain", "b".repeat(256 * 1_024 + 1)),
    ];

    const firstUpload = await createStagedUpload(server, installation, "notes.txt", before);
    await uploadEveryStagedFile(installation, firstUpload.body, before);
    const first = await commitStagedUpload(installation, firstUpload.body, "review-compare-first", {
      accessSetting: "account_required",
      kind: "new_artifact",
      name: "Review comparison contract",
    });
    const secondUpload = await createStagedUpload(server, installation, "notes.txt", after);
    await uploadEveryStagedFile(installation, secondUpload.body, after);
    const second = await commitStagedUpload(installation, secondUpload.body, "review-compare-second", {
      artifactId: first.body.artifact.id,
      expectedCurrentVersionId: first.body.version.id,
      kind: "new_version",
    });

    const response = await fetch(
      `${server.baseUrl}/api/v1/artifacts/${first.body.artifact.id}/comparisons?${new URLSearchParams({
        fromVersionId: first.body.version.id,
        projectId: first.body.artifact.projectId,
        toVersionId: second.body.version.id,
      })}`,
      {headers: {Authorization: `Bearer ${installation.apiToken}`}},
    );
    expect(response.status).toBe(200);
    const payload: unknown = await response.json();

    const parsed = comparisonSchema.safeParse(payload);
    expect(parsed.error?.issues ?? []).toEqual([]);
    if (!parsed.success) throw new Error("The comparison response did not parse.");
    const comparison = parsed.data;
    expect(comparison.from.id).toBe(first.body.version.id);
    expect(comparison.to.id).toBe(second.body.version.id);

    const detailFor = (path: string) =>
      comparison.changed.find((change) => change.after.path === path)?.detail;
    expect(detailFor("notes.txt")).toEqual({
      afterLineCount: 7,
      beforeLineCount: 6,
      changes: [
        {after: ["BRAVO"], afterStartLine: 2, before: ["bravo"], beforeStartLine: 2},
        {after: ["foxtrot"], afterStartLine: 6, before: [], beforeStartLine: 6},
      ],
      kind: "text",
    });
    expect(detailFor("review.md")).toEqual({
      afterLineCount: 5,
      beforeLineCount: 4,
      changes: [{
        after: ["- [x] draft", "- [ ] ship"],
        afterStartLine: 3,
        before: ["- [ ] draft"],
        beforeStartLine: 3,
      }],
      kind: "text",
    });
    expect(detailFor("removed-lines.txt")).toEqual({
      afterLineCount: 3,
      beforeLineCount: 5,
      changes: [{
        after: [],
        afterStartLine: 2,
        before: ["drop one", "drop two"],
        beforeStartLine: 2,
      }],
      kind: "text",
    });
    expect(detailFor("binary.dat")).toEqual({kind: "binary", reason: "binary_or_invalid_utf8"});
    expect(detailFor("large.txt")).toEqual({kind: "binary", reason: "text_limit_exceeded"});

    // The retired single-region field is not part of the contract any more:
    // a text detail without `changes` is rejected rather than half-rendered.
    const retired: unknown = JSON.parse(
      JSON.stringify(payload).replaceAll('"changes":', '"change":null,"retiredChanges":'),
    );
    expect(comparisonSchema.safeParse(retired).success).toBe(false);
  });
});

function text(path: string, mediaType: string, content: string): TestSiteFile {
  return {bytes: new TextEncoder().encode(content), mediaType, path};
}

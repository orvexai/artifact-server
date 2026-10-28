import {afterEach, beforeEach, describe, expect, test} from "vitest";

import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {publishNew, publishVersion} from "../support/publishing.js";

function readPublic(server: RunningTestServer, artifactId: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}`);
}

describe("read-only public Review page", () => {
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

  test("describe a public-link artifact's current version without a session", async () => {
    const first = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: "<!doctype html><title>One</title>",
      idempotencyKey: "public-review-page-one",
    });
    const second = await publishVersion(server, installation, {
      artifactId: first.body.artifact.id,
      content: "<!doctype html><title>Two</title>",
      expectedCurrentVersionId: first.body.version.id,
      idempotencyKey: "public-review-page-two",
    });
    expect(second.response.status).toBe(201);

    const response = await readPublic(server, first.body.artifact.id);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      artifact: {id: first.body.artifact.id, name: first.body.artifact.name},
      links: {version: second.body.links.version},
      version: {
        createdAt: second.body.version.createdAt,
        id: second.body.version.id,
        number: 2,
      },
    });
  });

  test("answer one identical 404 for a private or unknown artifact", async () => {
    const restricted = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Private</title>",
      idempotencyKey: "public-review-page-private",
    });
    expect(restricted.response.status).toBe(201);
    const responses = await Promise.all([
      readPublic(server, restricted.body.artifact.id),
      readPublic(server, "art_00000000-0000-4000-8000-000000000000"),
    ]);
    const bodies = await Promise.all(responses.map((response) => response.text()));
    expect(responses.map(({status}) => status)).toEqual([404, 404]);
    expect(bodies[0]).toBe(bodies[1]);
  });

  test("keep every other API route closed without a session", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: "<!doctype html><title>Public</title>",
      idempotencyKey: "public-review-page-closed",
    });
    const responses = await Promise.all([
      fetch(`${server.baseUrl}/api/v1/artifacts/${published.body.artifact.id}/versions`),
      fetch(`${server.baseUrl}/api/v1/session`),
    ]);
    expect(responses.map(({status}) => status)).toEqual([401, 401]);
    await Promise.all(responses.map((response) => response.arrayBuffer()));
  });
});

import {afterEach, beforeEach, describe, expect, test} from "vitest";

import {
  createTestInstallation,
  removeTestInstallation,
  startTestServer,
  type RunningTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {publishNew, publishVersion} from "../support/publishing.js";

function openReview(reviewUrl: string, cookie?: string): Promise<Response> {
  return fetch(reviewUrl, {
    headers: cookie === undefined ? {} : {Cookie: cookie},
    redirect: "manual",
  });
}

describe("Review links for public-link artifacts", () => {
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

  test("send a viewer without a session to the current version's public content", async () => {
    const html = "<!doctype html><title>Public</title><h1>Public</h1>";
    const published = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: html,
      idempotencyKey: "public-review-current",
    });
    expect(published.response.status).toBe(201);

    const responses = await Promise.all([
      published.body.links.review,
      `${server.baseUrl}/review?artifact=${published.body.artifact.id}`,
    ].map((reviewUrl) => openReview(reviewUrl)));
    for (const response of responses) {
      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toBe(published.body.links.version);
    }
  });

  test("keep the sign-in path for an old version, a private artifact, or an unknown one", async () => {
    const first = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: "<!doctype html><title>One</title>",
      idempotencyKey: "public-review-old-one",
    });
    const second = await publishVersion(server, installation, {
      artifactId: first.body.artifact.id,
      content: "<!doctype html><title>Two</title>",
      expectedCurrentVersionId: first.body.version.id,
      idempotencyKey: "public-review-old-two",
    });
    expect(second.response.status).toBe(201);
    const restricted = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Private</title>",
      idempotencyKey: "public-review-private",
    });
    expect(restricted.response.status).toBe(201);

    const responses = await Promise.all([
      first.body.links.review,
      `${server.baseUrl}/review?artifact=${first.body.artifact.id}&version=${restricted.body.version.id}`,
      restricted.body.links.review,
      `${server.baseUrl}/review?artifact=art_00000000-0000-4000-8000-000000000000`,
      `${server.baseUrl}/review`,
    ].map((reviewUrl) => openReview(reviewUrl)));
    expect(responses.map(({status}) => status)).not.toContain(302);
    await Promise.all(responses.map((response) => response.arrayBuffer()));
  });

  test("give a viewer with a session cookie the Review page, not a redirect", async () => {
    const published = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: "<!doctype html><title>Signed in</title>",
      idempotencyKey: "public-review-session",
    });
    const response = await openReview(
      published.body.links.review,
      "artifact_session=present; __Host-artifact_session=present",
    );
    expect(response.status).not.toBe(302);
    await response.arrayBuffer();
  });
});

import {createHmac} from "node:crypto";
import {mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {loadEmbedOrigins} from "../../src/cli/embed-configuration.js";
import {createTestInstallation, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

describe("artifact embeds", () => {
  type JsonValue = string | number | boolean | null | readonly JsonValue[] | {[key: string]: JsonValue};
  let installation: TestInstallation;
  let server: RunningTestServer;
  let webAssetsRoot: string;
  let artifactId: string;
  let projectId: string;
  let versionId: string;
  let sessionCookie: string;
  let csrf: string;

  beforeEach(async () => {
    installation = await createTestInstallation();
    webAssetsRoot = await mkdtemp(path.join(tmpdir(), "artifact-server-embed-"));
    await writeFile(path.join(webAssetsRoot, "embed.html"), "<!doctype html><html><head></head><body><div id=\"embed-root\"></div></body></html>");
    await writeFile(path.join(webAssetsRoot, "review.html"), "<!doctype html><title>Review</title>");
    await writeFile(path.join(webAssetsRoot, "review-frame.html"), "<!doctype html><title>Frame</title>");
    server = await startTestServer(installation, {
      embedOrigins: ["https://houston.example.test", "https://another.example.test"],
      webAssetsRoot,
    });
    const published = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Embedded</title>",
      idempotencyKey: "embed-conformance",
    });
    artifactId = published.body.artifact.id;
    projectId = published.body.artifact.projectId;
    versionId = published.body.version.id;
    const token = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(server.baseUrl + "/auth/local?token=" + token, {redirect: "manual"});
    const cookies = login.headers.getSetCookie();
    sessionCookie = cookies.filter((item) => /^artifact_(session|csrf)=/.test(item)).map((item) => item.split(";", 1)[0]).join("; ");
    csrf = cookies.find((item) => item.startsWith("artifact_csrf="))?.split(";", 1)[0]?.split("=", 2)[1] ?? "";
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
    await rm(webAssetsRoot, {force: true, recursive: true});
  });

  function memberRequest(method: string, route: string, body?: JsonValue): Promise<Response> {
    const headers = new Headers({
      Cookie: sessionCookie,
      Origin: server.baseUrl,
      "Sec-Fetch-Site": "same-origin",
      "X-CSRF-Token": csrf,
    });
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = JSON.stringify(body);
    return fetch(server.baseUrl + route, init);
  }

  test("is disabled with no configured embedding origins", async () => {
    const disabled = await startTestServer(installation, {webAssetsRoot});
    try {
      expect((await fetch(disabled.baseUrl + "/embed/artifacts/" + artifactId + "?path=index.html")).status).toBe(404);
    } finally {
      await disabled.stop();
    }
  });

  test("sets only the embed document's frame ancestor allowlist", async () => {
    const embed = await fetch(server.baseUrl + "/embed/artifacts/" + artifactId + "?path=index.html&parent=https%3A%2F%2Fhouston.example.test");
    expect(embed.status).toBe(200);
    expect(embed.headers.get("content-security-policy")).toContain("frame-ancestors https://houston.example.test https://another.example.test");
    expect(await embed.text()).toContain('name="as-embed-parent" content="https://houston.example.test"');
    const review = await fetch(server.baseUrl + "/review");
    expect(review.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  test("rejects malformed configured origins", () => {
    for (const value of [
      "https://houston.example.test/",
      "https://houston.example.test/path",
      "https://*.example.test",
      "https://user@houston.example.test",
      "https://houston.example.test?x=1",
    ]) {
      expect(() => loadEmbedOrigins({ARTIFACT_SERVER_EMBED_ORIGINS: value})).toThrow("Invalid ARTIFACT_SERVER_EMBED_ORIGINS entry");
    }
  });

  test("binds external responses to the server question despite a different submitted id", async () => {
    const bindingResponse = await memberRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?path=index.html", {
      mode: "respond", questionId: "bound-question", versionId,
    });
    expect(bindingResponse.status).toBe(200);
    const binding = z.object({binding: z.string()}).parse(await bindingResponse.json()).binding;
    const response = await memberRequest(
      "POST",
      "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId,
      {choice: "yes", embedBinding: binding, questionId: "caller-question", versionId},
    );
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({externalQuestion: true, questionId: "bound-question", versionId});
  });

  test("rejects forged and expired response bindings and refuses view-mode binding", async () => {
    const responsePath = "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId;
    const base = {questionId: "caller-question", versionId};
    const forged = await memberRequest("POST", responsePath, {...base, embedBinding: "forged.token"});
    expect(forged.status).toBe(403);

    const claims = Buffer.from(JSON.stringify({
      artifactId,
      expiresAt: Date.now() - 1,
      principalId: "local-owner",
      questionId: "expired",
      versionId,
    })).toString("base64url");
    const signature = createHmac("sha256", installation.apiToken)
      .update("artifact-embed-v1." + claims).digest("base64url");
    const expired = await memberRequest("POST", responsePath, {...base, embedBinding: claims + "." + signature});
    expect(expired.status).toBe(403);

    const view = await memberRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?path=index.html", {
      mode: "view", questionId: "external", versionId,
    });
    expect(view.status).toBe(422);
  });

  test("returns 404 for a manifest path outside the requested version", async () => {
    const response = await memberRequest("GET", "/api/v1/embed/artifacts/" + artifactId + "/bootstrap?path=missing.html&version=" + versionId);
    expect(response.status).toBe(404);
    const page = await memberRequest("GET", "/embed/artifacts/" + artifactId + "?path=missing.html&version=" + versionId);
    expect(page.status).toBe(404);
  });

  test("anonymous viewers require sign-in for private artifacts and can view public-link artifacts", async () => {
    const privateBootstrap = await fetch(server.baseUrl + "/api/v1/embed/artifacts/" + artifactId + "/bootstrap?path=index.html");
    expect(privateBootstrap.status).toBe(401);
    const publicPublish = await publishNew(server, installation, {
      accessSetting: "public_link",
      content: "<!doctype html><title>Public</title>",
      idempotencyKey: "embed-public-conformance",
    });
    const publicArtifactId = publicPublish.body.artifact.id;
    const publicVersionId = publicPublish.body.version.id;
    const publicView = await fetch(server.baseUrl + "/api/v1/public/embed/artifacts/" + publicArtifactId + "/bootstrap?path=index.html&version=" + publicVersionId);
    expect(publicView.status).toBe(200);
    expect(await publicView.json()).toMatchObject({artifact: {id: publicArtifactId}});
  });
});

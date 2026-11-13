import {createHmac} from "node:crypto";
import {mkdir, mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {loadEmbedOrigins} from "../../src/cli/embed-configuration.js";
import {validateEmbedOrigins} from "../../src/http/embed-origins.js";
import {loadOidcConfiguration} from "../../src/cli/oidc-configuration.js";
import {membershipRoles, principalCapabilities, principalKinds} from "../../src/core/identity.js";
import {createTestInstallation, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {commitStagedUpload, createStagedUpload, publishNew, uploadStagedFile} from "../support/publishing.js";

function signBinding(secret: string, claims: {
  readonly artifactId: string;
  readonly exp: number;
  readonly jti: string;
  readonly mode: "view" | "respond";
  readonly questionId: string;
  readonly versionId: string;
}): string {
  const payload = Buffer.from(JSON.stringify(claims))
    .toString("base64url");
  const signature = createHmac("sha256", secret)
    .update("artifact-embed-v1." + payload).digest("base64url");
  return payload + "." + signature;
}

describe("embed origin hostname validation", () => {
  test.each(["https://tenant.example,evil.test", "https://tenant.example;evil.test"])(
    "rejects URL host delimiters in %s",
    (origin) => expect(() => validateEmbedOrigins([origin])).toThrow(/Invalid/u),
  );

  test.each(["https://xn--bcher-kva.example", "http://[::1]"])(
    "accepts the supported hostname form %s",
    (origin) => expect(() => validateEmbedOrigins([origin])).not.toThrow(),
  );
});

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
  const bindingSecret = "dedicated-embed-binding-secret-with-32-bytes-minimum";
  const previousBindingSecret = "previous-embed-binding-secret-with-32-bytes-minimum";
  const servicePrincipal = {
    authorizedByPrincipalId: null,
    capabilities: [principalCapabilities.readArtifactResponses, principalCapabilities.bindArtifactEmbed],
    directoryGroupIds: [],
    displayName: "Houston V2",
    id: "oidc-service:test:houston-v2",
    installationId: "local",
    kind: principalKinds.service,
    membershipRole: membershipRoles.viewer,
    serviceAccountSource: "oidc" as const,
  };

  beforeEach(async () => {
    installation = await createTestInstallation();
    webAssetsRoot = await mkdtemp(path.join(tmpdir(), "artifact-server-embed-"));
    await mkdir(path.join(webAssetsRoot, "assets"));
    await writeFile(path.join(webAssetsRoot, "assets", "embed-signed-in.js"), "window.close();");
    await writeFile(path.join(webAssetsRoot, "embed.html"), "<!doctype html><html><head></head><body><div id=\"embed-root\"></div></body></html>");
    await writeFile(path.join(webAssetsRoot, "review.html"), "<!doctype html><title>Review</title>");
    await writeFile(path.join(webAssetsRoot, "review-frame.html"), "<!doctype html><title>Frame</title>");
    server = await startTestServer(installation, {
      embedBindingSecret: Redacted.make(bindingSecret),
      embedBindingPreviousSecret: Redacted.make(previousBindingSecret),
      embedOrigins: ["https://houston.example.test", "https://another.example.test"],
      externalApiBearerVerifier: {verify: (credential) => {
        if (Redacted.value(credential) === "test-houston-service-no-embed-bind") {
          return Effect.succeed({...servicePrincipal, capabilities: [principalCapabilities.readArtifactResponses]});
        }
        if (Redacted.value(credential) === "test-other-human") {
          return Effect.succeed({
            ...servicePrincipal,
            capabilities: [],
            id: "different-human",
            kind: principalKinds.human,
            membershipRole: membershipRoles.owner,
            serviceAccountSource: undefined,
          });
        }
        return Effect.succeed(servicePrincipal);
      }},
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

  function serviceRequest(method: string, route: string, body?: JsonValue): Promise<Response> {
    const headers = new Headers({Authorization: "Bearer test-houston-service"});
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = JSON.stringify(body);
    return fetch(server.baseUrl + route, init);
  }

  function otherHumanRequest(method: string, route: string, body: JsonValue): Promise<Response> {
    const headers = new Headers({Authorization: "Bearer test-other-human", "Content-Type": "application/json"});
    return fetch(server.baseUrl + route, {headers, method, body: JSON.stringify(body)});
  }

  test("keeps flag-off staged upload and commit working with no embed origins", async () => {
    const file = {
      bytes: new TextEncoder().encode("<!doctype html><title>Flag off upload</title>"),
      mediaType: "text/html; charset=utf-8",
      path: "index.html",
    };
    const upload = await createStagedUpload(server, installation, file.path, [file], projectId);
    expect(upload.response.status).toBe(201);
    const stagedFile = upload.body.files[0];
    if (stagedFile === undefined) throw new Error("The flag-off upload plan did not include its file.");
    const uploadUrl = new URL(stagedFile.uploadUrl);
    expect(uploadUrl.origin).toBe(server.baseUrl);
    expect(uploadUrl.pathname).toMatch(/^\/api\/v1\/uploads\/upl_[^/]+\/files\//u);
    expect(uploadUrl.pathname).not.toContain("/api/v1/uploads/api/v1/uploads/");
    const uploaded = await uploadStagedFile(installation, stagedFile, file.bytes);
    expect(uploaded.status).toBe(200);
    const committed = await commitStagedUpload(
      installation,
      upload.body,
      "embed-flag-off-staged-upload",
      {artifactId, expectedCurrentVersionId: versionId, kind: "new_version"},
    );
    expect(committed.response.status).toBe(201);
    expect(committed.body.version.contentToken).toMatch(/^[A-Za-z0-9_-]{16,100}$/u);

    const disabled = await startTestServer(installation, {webAssetsRoot});
    try {
      expect((await fetch(disabled.baseUrl + "/embed/artifacts/" + artifactId + "?path=index.html")).status).toBe(404);
    } finally {
      await disabled.stop();
    }
  });

  test("sets only the embed document's frame ancestor allowlist", async () => {
    const embed = await fetch(server.baseUrl + "/embed/artifacts/" + artifactId + "?path=index.html", {
      headers: {Referer: "https://houston.example.test/page"},
    });
    expect(embed.status).toBe(200);
    expect(embed.headers.get("content-security-policy")).toContain("frame-ancestors https://houston.example.test https://another.example.test");
    expect(await embed.text()).toContain('name="as-embed-parent" content="https://houston.example.test"');
    const review = await fetch(server.baseUrl + "/review");
    expect(review.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(embed.headers.get("x-artifact-embed-bootstrap")).toBeNull();
    expect(embed.headers.get("x-artifact-embed-mode")).toBeNull();
    expect(embed.headers.get("x-artifact-embed-question")).toBeNull();
    const plainFrame = await fetch(server.baseUrl + "/review-frame");
    expect(plainFrame.headers.get("content-security-policy")).toContain("frame-ancestors 'self'");
    expect(plainFrame.headers.get("content-security-policy")).not.toContain("https://houston.example.test");
    const embeddedFrame = await fetch(server.baseUrl + "/review-frame?embed=1");
    expect(embeddedFrame.headers.get("content-security-policy")).toContain("frame-ancestors 'self' https://houston.example.test https://another.example.test");
    expect(embeddedFrame.headers.get("cache-control")).toBe("no-store");
    const signedIn = await fetch(server.baseUrl + "/embed/signed-in");
    expect(signedIn.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(await signedIn.text()).toContain("/assets/embed-signed-in.js");
    expect((await fetch(server.baseUrl + "/assets/embed-signed-in.js")).status).toBe(200);
    expect(embed.headers.get("content-security-policy")).toContain("frame-src 'self' http://*.localhost:* https://*.localhost");
    expect(embed.headers.get("cache-control")).toBe("no-store");
  });

  test("rejects malformed configured origins", () => {
    for (const value of [
      "https://houston.example.test/",
      "https://houston.example.test/path",
      "https://*.example.test",
      "https://user@houston.example.test",
      "https://houston.example.test?x=1",
      "http://embed.example.test",
    ]) {
      expect(() => loadEmbedOrigins({ARTIFACT_SERVER_EMBED_ORIGINS: value})).toThrow("Invalid ARTIFACT_SERVER_EMBED_ORIGINS entry");
    }
    expect(loadEmbedOrigins({ARTIFACT_SERVER_EMBED_ORIGINS: "http://localhost:3000,http://127.0.0.1:8787,http://[::1]:5173"})).toEqual([
      "http://localhost:3000", "http://127.0.0.1:8787", "http://[::1]:5173",
    ]);
    expect(loadEmbedOrigins({ARTIFACT_SERVER_EMBED_ORIGINS: "https://houston.example.test,"})).toEqual(["https://houston.example.test"]);
  });

  test("limits embed binding to the configured subset of OIDC service clients", async () => {
    const oidc = await loadOidcConfiguration({
      ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: "admin@example.test",
      ARTIFACT_SERVER_ORIGIN: "https://artifacts.example.test",
      ARTIFACT_SERVER_OIDC_CLIENT_ID: "browser",
      ARTIFACT_SERVER_OIDC_EMBED_BIND_CLIENTS: "houston-v2",
      ARTIFACT_SERVER_OIDC_ISSUER: "https://auth.example.test",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "houston-v2,other-service",
    });
    expect(oidc?.embedBindingClients).toEqual(["houston-v2"]);
    await expect(loadOidcConfiguration({
      ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: "admin@example.test",
      ARTIFACT_SERVER_ORIGIN: "https://artifacts.example.test",
      ARTIFACT_SERVER_OIDC_CLIENT_ID: "browser",
      ARTIFACT_SERVER_OIDC_EMBED_BIND_CLIENTS: "not-a-service-client",
      ARTIFACT_SERVER_OIDC_ISSUER: "https://auth.example.test",
      ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS: "houston-v2",
    })).rejects.toThrow("must also appear in ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS");
  });

  test("binds external responses to the server question despite a different submitted id", async () => {
    const humanMint = await memberRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      mode: "respond", questionId: "bound-question", versionId,
    });
    expect(humanMint.status).toBe(403);
    const nonOptedService = await fetch(server.baseUrl + "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      headers: {Authorization: "Bearer test-houston-service-no-embed-bind", "Content-Type": "application/json"},
      method: "POST",
      body: JSON.stringify({mode: "respond", questionId: "bound-question", versionId}),
    });
    expect(nonOptedService.status).toBe(403);
    const bindingResponse = await serviceRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
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
    const firstRecord = z.object({
      id: z.string(), authorDisplayName: z.string(), authorEmail: z.string().nullable(),
      authorSubject: z.string(), choice: z.string().nullable(), externalQuestion: z.boolean(),
      questionId: z.string(), replayed: z.boolean(), versionId: z.string(),
    }).parse(await response.json());
    expect(firstRecord).toMatchObject({externalQuestion: true, questionId: "bound-question", replayed: false, versionId});

    const secondViewer = await otherHumanRequest(
      "POST",
      "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId,
      {choice: "no", embedBinding: binding, questionId: "attacker-question", versionId},
    );
    expect(secondViewer.status).toBe(409);
    const conflictBody = JSON.stringify(await secondViewer.json());
    expect(conflictBody).toContain('"code":"embed_binding_used"');
    expect(conflictBody).toContain("already been used by another viewer");
    const privateValues = [
      firstRecord.id,
      firstRecord.authorSubject,
      firstRecord.authorDisplayName,
      firstRecord.authorEmail,
      firstRecord.choice,
    ].filter((value): value is string => value !== null);
    expect(privateValues.every((privateValue) => !conflictBody.includes(privateValue))).toBe(true);
    const responsePath = "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId;
    const listed = z.object({items: z.array(z.unknown())}).parse(await (await memberRequest(
      "GET", responsePath + "&questionId=bound-question&versionId=" + versionId,
    )).json());
    expect(listed.items).toHaveLength(1);
  });

  test("rejects forged and expired response bindings and refuses view-mode binding", async () => {
    const responsePath = "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId;
    const base = {questionId: "caller-question", versionId};
    const forged = await memberRequest("POST", responsePath, {...base, embedBinding: "forged.token"});
    expect(forged.status).toBe(403);

    const claims = Buffer.from(JSON.stringify({
      artifactId,
      exp: Math.floor(Date.now() / 1_000) - 1,
      jti: "00000000-0000-4000-8000-000000000001",
      mode: "respond",
      questionId: "expired",
      versionId,
    })).toString("base64url");
    const signature = createHmac("sha256", bindingSecret)
      .update("artifact-embed-v1." + claims).digest("base64url");
    const expired = await memberRequest("POST", responsePath, {...base, embedBinding: claims + "." + signature});
    expect(expired.status).toBe(403);

    const view = await serviceRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      mode: "view", questionId: "external", versionId,
    });
    expect(view.status).toBe(200);
    const viewBinding = z.object({binding: z.string()}).parse(await view.json()).binding;
    const refused = await memberRequest("POST", responsePath, {...base, embedBinding: viewBinding});
    expect(refused.status).toBe(403);
  });

  test("treats a binding jti as single-use and returns the existing response on replay", async () => {
    const bindingResponse = await serviceRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      mode: "respond", questionId: "replay-question", versionId,
    });
    const binding = z.object({binding: z.string()}).parse(await bindingResponse.json()).binding;
    const responsePath = "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId;
    const first = await memberRequest("POST", responsePath, {
      choice: "first", embedBinding: binding, questionId: "ignored-a", versionId,
    });
    const firstBody = z.object({id: z.string(), choice: z.string().nullable(), externalQuestion: z.boolean(), questionId: z.string(), replayed: z.boolean()}).parse(await first.json());
    expect(firstBody.replayed).toBe(false);
    const replay = await memberRequest("POST", responsePath, {
      choice: "second", embedBinding: binding, questionId: "ignored-b", versionId,
    });
    expect(replay.status).toBe(201);
    const replayBody = z.object({id: z.string(), choice: z.string().nullable(), externalQuestion: z.boolean(), questionId: z.string(), replayed: z.boolean()}).parse(await replay.json());
    expect(replayBody).toMatchObject({...firstBody, replayed: true});
    const listed = await memberRequest("GET", responsePath + "&questionId=replay-question&versionId=" + versionId);
    const listedBody = await listed.json();
    expect(listedBody).toMatchObject({items: [{
      id: firstBody.id,
      choice: firstBody.choice,
      externalQuestion: firstBody.externalQuestion,
      questionId: firstBody.questionId,
    }]});
    expect(z.object({items: z.array(z.unknown())}).parse(listedBody).items).toHaveLength(1);
  });

  test("allows concurrent submissions for one viewer to return the one recorded response", async () => {
    const bindingResponse = await serviceRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      mode: "respond", questionId: "concurrent-question", versionId,
    });
    const binding = z.object({binding: z.string()}).parse(await bindingResponse.json()).binding;
    const responsePath = "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId;
    const submitted = await Promise.all(["first", "second"].map((choice) => memberRequest("POST", responsePath, {
      choice, embedBinding: binding, questionId: "ignored", versionId,
    })));
    expect(submitted.map((response) => response.status)).toEqual([201, 201]);
    const records = await Promise.all(submitted.map(async (response) => z.object({
      id: z.string(),
      choice: z.string().nullable(),
      externalQuestion: z.boolean(),
      questionId: z.string(),
      replayed: z.boolean(),
      versionId: z.string(),
    }).parse(await response.json())));
    expect(records.map((record) => record.replayed).toSorted((left, right) => Number(left) - Number(right))).toEqual([false, true]);
    expect(records[0]?.id).toBe(records[1]?.id);
    const listed = await memberRequest("GET", responsePath + "&questionId=concurrent-question&versionId=" + versionId);
    expect(z.object({items: z.array(z.unknown())}).parse(await listed.json()).items).toHaveLength(1);
  });

  test("accepts a response binding signed by the previous rotation key", async () => {
    const binding = signBinding(previousBindingSecret, {
      artifactId,
      exp: Math.floor(Date.now() / 1_000) + 300,
      jti: "00000000-0000-4000-8000-000000000099",
      mode: "respond",
      questionId: "rotated-question",
      versionId,
    });
    const response = await memberRequest("POST", "/api/v1/artifacts/" + artifactId + "/responses?projectId=" + projectId, {
      choice: "yes", embedBinding: binding, questionId: "ignored", versionId,
    });
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({externalQuestion: true, questionId: "rotated-question"});
  });

  test("rejects a binding version that belongs to another artifact", async () => {
    const other = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Other artifact</title>",
      idempotencyKey: "embed-other-artifact",
    });
    const response = await serviceRequest("POST", "/api/v1/embed/artifacts/" + artifactId + "/binding?projectId=" + projectId, {
      mode: "respond", questionId: "bound-question", versionId: other.body.version.id,
    });
    expect(response.status).toBe(404);
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

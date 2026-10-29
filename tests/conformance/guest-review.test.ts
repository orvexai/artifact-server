import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {createTestInstallation, fetchVersion, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

describe("invited guest review", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let artifactId: string;
  let otherArtifactId: string;
  let projectId: string;
  let ownerCookie: string;
  let ownerCsrf: string;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation);
    const published = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Private guest review</title>",
      idempotencyKey: "guest-review-private",
    });
    artifactId = published.body.artifact.id;
    projectId = published.body.artifact.projectId;
    const other = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Other private artifact</title>",
      idempotencyKey: "guest-review-other",
    });
    otherArtifactId = other.body.artifact.id;
    const token = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(`${server.baseUrl}/auth/local?token=${token}`, {redirect: "manual"});
    const cookies = login.headers.getSetCookie();
    ownerCookie = cookies.filter((item) => /^artifact_(session|csrf)=/.test(item)).map((item) => item.split(";", 1)[0]).join("; ");
    ownerCsrf = cookies.find((item) => item.startsWith("artifact_csrf="))?.split(";", 1)[0]?.split("=", 2)[1] ?? "";
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  async function owner(method: string, path: string, body?: string): Promise<Response> {
    const headers = new Headers({Cookie: ownerCookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": ownerCsrf});
    const init: RequestInit = {headers, method};
    if (body !== undefined) {
      headers.set("Content-Type", "application/json");
      init.body = body;
    }
    return fetch(`${server.baseUrl}${path}`, init);
  }

  async function enable(): Promise<{readonly guestCookie: string; readonly csrf: string; readonly secret: string; readonly url: string}> {
    const response = await owner("POST", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`, "{}");
    expect(response.status).toBe(201);
    const result = z.object({url: z.url(), enabled: z.boolean(), createdAt: z.string()}).parse(await response.json());
    expect(result.enabled).toBe(true);
    const url = new URL(result.url);
    expect(url.search).not.toContain("invite");
    const secret = new URLSearchParams(url.hash.slice(1)).get("invite");
    expect(secret).toBeTruthy();
    const exchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: " Guest Reviewer ", secret}), headers: {"Content-Type": "application/json"}, method: "POST",
    });
    expect(exchange.status).toBe(201);
    const cookieParts = exchange.headers.getSetCookie();
    const session = cookieParts.find((item) => item.startsWith("artifact_guest_session="));
    const csrfCookie = cookieParts.find((item) => item.startsWith("artifact_guest_csrf="));
    expect(session).toBeDefined();
    expect(csrfCookie).toBeDefined();
    const guestCookie = `${session?.split(";", 1)[0]}; ${csrfCookie?.split(";", 1)[0]}`;
    const csrf = csrfCookie?.split(";", 1)[0]?.split("=", 2)[1] ?? "";
    return {csrf, guestCookie, secret: secret ?? "", url: result.url};
  }

  test("enable, exchange, comment, enforce CSRF and artifact scope, then revoke every session", async () => {
    const invited = await enable();
    const status = await owner("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    const statusText = await status.text();
    expect(JSON.parse(statusText)).toMatchObject({enabled: true});
    expect(statusText).not.toContain(invited.secret);

    const headers = {Cookie: invited.guestCookie};
    const current = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/current`, {headers});
    expect(current.status).toBe(201);
    const currentBody = z.object({bootstrapUrl: z.url(), versionId: z.string()}).parse(await current.json());
    expect(new URL(currentBody.bootstrapUrl).searchParams.has("__artifact_bootstrap")).toBe(true);
    const bootstrap = await fetchVersion(server, currentBody.bootstrapUrl);
    expect(bootstrap.status).toBe(200);

    const withoutCsrf = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments`, {
      body: JSON.stringify({body: "No token", versionId: currentBody.versionId}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin"}, method: "POST",
    });
    expect(withoutCsrf.status).toBe(403);
    const create = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments`, {
      body: JSON.stringify({anchor: {point: {x: 0.5, y: 0.5}}, body: "Guest comment", versionId: currentBody.versionId}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf, "Idempotency-Key": "guest-thread-key-0001"}, method: "POST",
    });
    expect(create.status).toBe(201);
    const created = z.object({thread: z.object({id: z.string(), author: z.object({principalId: z.string(), displayName: z.string()})})}).parse(await create.json());
    expect(created.thread.author.principalId).toMatch(/^guest_/);
    expect(created.thread.author.displayName).toBe("Guest Reviewer (guest)");
    const secondExchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {body: JSON.stringify({displayName: "Second", secret: invited.secret}), headers: {"Content-Type": "application/json"}, method: "POST"});
    const secondCookies = secondExchange.headers.getSetCookie();
    const secondSession = secondCookies.find((item) => item.startsWith("artifact_guest_session="))?.split(";", 1)[0];
    const secondCsrfCookie = secondCookies.find((item) => item.startsWith("artifact_guest_csrf="))?.split(";", 1)[0];
    const secondCsrf = secondCsrfCookie?.split("=", 2)[1] ?? "";
    const otherGuest = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}`, {headers: {Cookie: secondSession ?? ""}});
    expect(otherGuest.status).toBe(200);
    const forbiddenEdit = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}`, {
      body: JSON.stringify({body: "Hijacked"}), headers: {Cookie: `${secondSession ?? ""}; ${secondCsrfCookie ?? ""}`, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": secondCsrf}, method: "PATCH",
    });
    expect(forbiddenEdit.status).toBe(403);
    const ownEdit = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}`, {
      body: JSON.stringify({body: "Edited guest comment"}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf}, method: "PATCH",
    });
    expect(ownEdit.status).toBe(200);
    const forbiddenResolve = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}`, {
      body: JSON.stringify({state: "resolved"}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf}, method: "PATCH",
    });
    expect(forbiddenResolve.status).toBe(403);
    const reply = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}/replies`, {
      body: JSON.stringify({body: "Guest reply"}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf, "Idempotency-Key": "guest-reply-key-0001"}, method: "POST",
    });
    expect(reply.status).toBe(201);
    const replyBody = z.object({reply: z.object({id: z.string()})}).parse(await reply.json());
    const editReply = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}/replies/${replyBody.reply.id}`, {
      body: JSON.stringify({body: "Edited reply"}), headers: {...headers, "Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf}, method: "PATCH",
    });
    expect(editReply.status).toBe(200);
    const deleteReply = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}/replies/${replyBody.reply.id}`, {
      headers: {...headers, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf}, method: "DELETE",
    });
    expect(deleteReply.status).toBe(204);
    const list = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments`, {headers});
    expect(z.object({items: z.array(z.unknown())}).parse(await list.json()).items).toHaveLength(1);
    const deleteThread = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments/${created.thread.id}`, {
      headers: {...headers, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": invited.csrf}, method: "DELETE",
    });
    expect(deleteThread.status).toBe(204);
    const isolated = await Promise.all([
      fetch(`${server.baseUrl}/api/v1/session`, {headers}),
      fetch(`${server.baseUrl}/api/v1/artifacts/${artifactId}/state`, {headers}),
      fetch(`${server.baseUrl}/api/v1/public/artifacts/${otherArtifactId}/guest/comments`, {headers}),
    ]);
    expect(isolated.map((response) => response.status)).toEqual([401, 401, 404]);

    const revoked = await owner("DELETE", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    expect(revoked.status).toBe(204);
    const afterRevoke = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/comments`, {headers});
    expect(afterRevoke.status).toBe(404);
  });

  test("wrong and revoked invitations share the same generic not-found response; regenerating invalidates the prior link", async () => {
    const first = await enable();
    const wrong = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {body: JSON.stringify({displayName: "Guest", secret: "x".repeat(40)}), headers: {"Content-Type": "application/json"}, method: "POST"});
    expect(wrong.status).toBe(404);
    const regenerated = await enable();
    const old = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {body: JSON.stringify({displayName: "Guest", secret: first.secret}), headers: {"Content-Type": "application/json"}, method: "POST"});
    expect(old.status).toBe(404);
    const otherArtifact = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${otherArtifactId}/guest-session`, {body: JSON.stringify({displayName: "Guest", secret: regenerated.secret}), headers: {"Content-Type": "application/json"}, method: "POST"});
    expect(otherArtifact.status).toBe(404);
    const genericBody = await wrong.text();
    expect(await old.text()).toBe(genericBody);
    expect(await otherArtifact.text()).toBe(genericBody);
    expect(regenerated.secret).not.toBe(first.secret);
  });
});

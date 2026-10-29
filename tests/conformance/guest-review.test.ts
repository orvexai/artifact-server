import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import {createTestInstallation, fetchVersion, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const invitationSchema = z.object({createdAt: z.string(), enabled: z.literal(true), url: z.url()});
const guestSessionResponseSchema = z.object({displayName: z.string(), expiresAt: z.string()});
const guestSessionCookieSchema = z.object({cookie: z.string(), csrf: z.string()});
const guestThreadSchema = z.object({
  author: z.object({displayName: z.string(), isYou: z.boolean()}),
  body: z.string(),
  id: z.string(),
  replyCount: z.number(),
  resolvedBy: z.object({displayName: z.string(), isYou: z.boolean()}).nullable(),
});
const guestThreadPageSchema = z.object({items: z.array(guestThreadSchema), nextCursor: z.string().nullable()});
const guestThreadDetailsSchema = z.object({replies: z.array(z.object({author: z.object({displayName: z.string(), isYou: z.boolean()}), body: z.string()})), thread: guestThreadSchema});

describe("invited guest review", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let artifactId: string;
  let otherArtifactId: string;
  let projectId: string;
  let currentVersionId: string;
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
    currentVersionId = published.body.version.id;
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

  async function ownerRequest(method: string, path: string, body?: string, extraHeaders?: HeadersInit): Promise<Response> {
    const headers = new Headers({Cookie: ownerCookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": ownerCsrf});
    if (body !== undefined) headers.set("Content-Type", "application/json");
    new Headers(extraHeaders).forEach((value, name) => headers.set(name, value));
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = body;
    return fetch(`${server.baseUrl}${path}`, init);
  }

  async function enableInvitation(): Promise<{readonly secret: string; readonly url: string}> {
    const response = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`, "{}");
    expect(response.status).toBe(201);
    const invitation = invitationSchema.parse(await response.json());
    const link = new URL(invitation.url);
    expect(link.search).not.toContain("invite");
    const secret = new URLSearchParams(link.hash.slice(1)).get("invite");
    expect(secret).toBeTruthy();
    return {secret: secret ?? "", url: invitation.url};
  }

  async function exchange(artifact: string, secret: string, displayName = "Guest Reviewer"): Promise<z.infer<typeof guestSessionCookieSchema>> {
    const response = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifact}/guest-session`, {
      body: JSON.stringify({displayName, secret}), headers: {"Content-Type": "application/json"}, method: "POST",
    });
    expect(response.status).toBe(201);
    expect(guestSessionResponseSchema.parse(await response.json()).displayName).toBe(displayName.trim());
    const cookies = response.headers.getSetCookie();
    const session = cookies.find((item) => item.startsWith("artifact_guest_session="))?.split(";", 1)[0];
    const csrfCookie = cookies.find((item) => item.startsWith("artifact_guest_csrf="))?.split(";", 1)[0];
    expect(session).toBeDefined();
    expect(csrfCookie).toBeDefined();
    return {
      cookie: `${session ?? ""}; ${csrfCookie ?? ""}`,
      csrf: csrfCookie?.split("=", 2)[1] ?? "",
    };
  }

  async function guestRequest(
    guest: z.infer<typeof guestSessionCookieSchema>,
    method: string,
    path: string,
    body?: string,
    includeCsrf = true,
    idempotencyKey?: string,
  ): Promise<Response> {
    const headers = new Headers({Cookie: guest.cookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin"});
    if (body !== undefined) headers.set("Content-Type", "application/json");
    if (includeCsrf && method !== "GET") headers.set("X-CSRF-Token", guest.csrf);
    if (idempotencyKey !== undefined) headers.set("Idempotency-Key", idempotencyKey);
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = body;
    return fetch(`${server.baseUrl}${path}`, init);
  }

  async function createGuestThread(guest: z.infer<typeof guestSessionCookieSchema>, body: string): Promise<z.infer<typeof guestThreadSchema>> {
    const response = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({anchor: {point: {x: 0.5, y: 0.5}}, body, versionId: currentVersionId}), true, `guest-thread-key-${crypto.randomUUID()}`);
    expect(response.status).toBe(201);
    const responseText = await response.text();
    expect(responseText).not.toMatch(/principalId|authorizedByPrincipalId|principalKind|email/i);
    return z.object({thread: guestThreadSchema}).parse(JSON.parse(responseText)).thread;
  }

  async function createMemberThread(body: string): Promise<{readonly id: string; readonly author: {readonly displayName: string; readonly principalId: string}}> {
    const response = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/versions/${currentVersionId}/comments?projectId=${projectId}`, JSON.stringify({anchor: {point: {x: 0.5, y: 0.5}}, body}), {"Idempotency-Key": `member-thread-key-${crypto.randomUUID()}`});
    expect(response.status).toBe(201);
    return z.object({thread: z.object({id: z.string(), author: z.object({displayName: z.string(), principalId: z.string()})})}).parse(await response.json()).thread;
  }

  test("status reports enabled and createdAt without disclosing the invitation secret", async () => {
    const invitation = await enableInvitation();
    const response = await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    const text = await response.text();
    expect(JSON.parse(text)).toMatchObject({enabled: true, createdAt: expect.any(String)});
    expect(text).not.toContain(invitation.secret);
  });

  test("wrong, revoked, and other-artifact secrets return the same 404; regeneration revokes the prior secret", async () => {
    const first = await enableInvitation();
    const wrong = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: "Guest", secret: "x".repeat(40)}), headers: {"Content-Type": "application/json"}, method: "POST",
    });
    expect(wrong.status).toBe(404);
    const regenerated = await enableInvitation();
    const revoked = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: "Guest", secret: first.secret}), headers: {"Content-Type": "application/json"}, method: "POST",
    });
    const otherArtifact = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${otherArtifactId}/guest-session`, {
      body: JSON.stringify({displayName: "Guest", secret: regenerated.secret}), headers: {"Content-Type": "application/json"}, method: "POST",
    });
    expect(revoked.status).toBe(404);
    expect(otherArtifact.status).toBe(404);
    const genericBody = await wrong.text();
    expect(await revoked.text()).toBe(genericBody);
    expect(await otherArtifact.text()).toBe(genericBody);
  });

  test("a guest can edit and delete only their own thread and replies", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const otherGuest = await exchange(artifactId, invitation.secret, "Other Guest");
    const mine = await createGuestThread(guest, "My comment");
    const other = await createGuestThread(otherGuest, "Other guest comment");
    const repliesPath = `/api/v1/public/artifacts/${artifactId}/guest/comments/${mine.id}/replies`;
    const createReply = await guestRequest(guest, "POST", repliesPath, JSON.stringify({body: "My reply"}), true, "guest-own-reply-key-00001");
    expect(createReply.status).toBe(201);
    const replyText = await createReply.text();
    expect(replyText).not.toMatch(/principalId|authorizedByPrincipalId|principalKind|email/i);
    const replyId = z.object({reply: z.object({id: z.string()})}).parse(JSON.parse(replyText)).reply.id;
    const editReply = await guestRequest(guest, "PATCH", `${repliesPath}/${replyId}`, JSON.stringify({body: "Edited reply"}));
    expect(editReply.status).toBe(200);
    const editOwn = await guestRequest(guest, "PATCH", `/api/v1/public/artifacts/${artifactId}/guest/comments/${mine.id}`, JSON.stringify({body: "Edited comment"}));
    expect(editOwn.status).toBe(200);
    const editedResponses = await Promise.all([editReply.text(), editOwn.text()]);
    for (const responseText of editedResponses) expect(responseText).not.toMatch(/principalId|authorizedByPrincipalId|principalKind|email/i);
    const deleteReply = await guestRequest(guest, "DELETE", `${repliesPath}/${replyId}`);
    expect(deleteReply.status).toBe(204);
    const deleteOwn = await guestRequest(guest, "DELETE", `/api/v1/public/artifacts/${artifactId}/guest/comments/${mine.id}`);
    expect(deleteOwn.status).toBe(204);

    const unauthorized = await Promise.all(([
      ["GET", `/api/v1/public/artifacts/${artifactId}/guest/comments/${other.id}`, undefined],
      ["POST", `/api/v1/public/artifacts/${artifactId}/guest/comments/${other.id}/replies`, JSON.stringify({body: "No"})],
      ["PATCH", `/api/v1/public/artifacts/${artifactId}/guest/comments/${other.id}`, JSON.stringify({body: "No"})],
      ["DELETE", `/api/v1/public/artifacts/${artifactId}/guest/comments/${other.id}`, undefined],
    ] as const).map(([method, path, body]) => guestRequest(guest, method, path, body, true, method === "POST" ? "forbidden-guest-reply-key-001" : undefined)));
    expect(unauthorized.map((response) => response.status)).toEqual([404, 404, 404, 404]);
  });

  test("guests cannot resolve comments or use authenticated API routes", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const thread = await createGuestThread(guest, "Cannot resolve me");
    const resolve = await guestRequest(guest, "PATCH", `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`, JSON.stringify({state: "resolved"}));
    expect(resolve.status).toBe(403);
    const responses = await Promise.all([
      guestRequest(guest, "GET", "/api/v1/session"),
      guestRequest(guest, "GET", `/api/v1/artifacts/${artifactId}/state`),
      guestRequest(guest, "GET", `/api/v1/public/artifacts/${otherArtifactId}/guest/comments`),
    ]);
    expect(responses.map((response) => response.status)).toEqual([401, 401, 404]);
  });

  test("mutations without the guest CSRF token are refused", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const response = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: "Blocked", versionId: currentVersionId}), false, "guest-no-csrf-key-0001");
    expect(response.status).toBe(403);
  });

  test("a guest views the private artifact's current version through the content origin", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const currentResponse = await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`);
    expect(currentResponse.status).toBe(201);
    const current = z.object({bootstrapUrl: z.url(), versionId: z.string(), number: z.number()}).parse(await currentResponse.json());
    expect(current.versionId).toBe(currentVersionId);
    expect(new URL(current.bootstrapUrl).searchParams.has("__artifact_bootstrap")).toBe(true);
    expect((await fetchVersion(server, current.bootstrapUrl)).status).toBe(200);
  });

  test("guest listing, detail, replies, paging, and author projections are isolated", async () => {
    const invitation = await enableInvitation();
    const guestA = await exchange(artifactId, invitation.secret, "Guest A");
    const guestB = await exchange(artifactId, invitation.secret, "Guest B");
    const ownFirst = await createGuestThread(guestA, "A first");
    const otherGuestThread = await createGuestThread(guestB, "B private thread");
    const ownSecond = await createGuestThread(guestA, "A second");
    const memberThread = await createMemberThread("Member private thread");
    const memberReplyPath = `/api/v1/artifacts/${artifactId}/comments/${ownFirst.id}/replies?projectId=${projectId}`;
    const memberReply = await ownerRequest("POST", memberReplyPath, JSON.stringify({body: "Team reply"}), {"Idempotency-Key": "team-reply-on-guest-thread-001"});
    expect(memberReply.status).toBe(201);

    const firstPageResponse = await guestRequest(guestA, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments?limit=1`);
    const firstPageText = await firstPageResponse.text();
    expect(firstPageText).not.toMatch(/principalId|authorizedByPrincipalId|principalKind|email/i);
    const firstPage = guestThreadPageSchema.parse(JSON.parse(firstPageText));
    expect(firstPage.items).toHaveLength(1);
    expect(firstPage.items[0]?.replyCount).toBe(0);
    expect(firstPage.nextCursor).not.toBeNull();
    const secondPageResponse = await guestRequest(guestA, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments?limit=1&cursor=${encodeURIComponent(firstPage.nextCursor ?? "")}`);
    const secondPage = guestThreadPageSchema.parse(await secondPageResponse.json());
    expect(secondPage.items).toHaveLength(1);
    expect(secondPage.items[0]?.replyCount).toBe(1);
    expect(secondPage.nextCursor).toBeNull();
    expect(new Set([...firstPage.items, ...secondPage.items].map((thread) => thread.id))).toEqual(new Set([ownFirst.id, ownSecond.id]));

    const inaccessible = await Promise.all([otherGuestThread.id, memberThread.id].flatMap((id) => [
      guestRequest(guestA, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments/${id}`),
      guestRequest(guestA, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments/${id}/replies`, JSON.stringify({body: "Not allowed"}), true, `guest-forbidden-reply-${crypto.randomUUID()}`),
    ]));
    expect(inaccessible.map((response) => response.status)).toEqual([404, 404, 404, 404]);

    const detailResponse = await guestRequest(guestA, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments/${ownFirst.id}`);
    const detailText = await detailResponse.text();
    const detail = guestThreadDetailsSchema.parse(JSON.parse(detailText));
    expect(detail.thread.author).toEqual({displayName: "Guest A (guest)", isYou: true});
    expect(detail.thread.replyCount).toBe(detail.replies.length);
    expect(detail.replies).toContainEqual({author: {displayName: expect.any(String), isYou: false}, body: "Team reply"});
    expect(detailText).not.toMatch(/principalId|authorizedByPrincipalId|principalKind|email/i);
    expect(detailText).not.toContain(memberThread.author.principalId);

    const memberList = await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/comments?projectId=${projectId}`);
    const memberText = await memberList.text();
    expect(memberText).toContain("Guest A (guest)");
    expect(memberText).toContain(ownFirst.id);
  });
});

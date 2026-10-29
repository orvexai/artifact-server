import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";
import {DatabaseSync} from "node:sqlite";
import nodePath from "node:path";

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
    const response = await exchangeResponse(artifact, secret, displayName);
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

  function exchangeResponse(artifact: string, secret: string, displayName = "Guest Reviewer", headers: HeadersInit = {}): Promise<Response> {
    return fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifact}/guest-session`, {
      body: JSON.stringify({displayName, secret}), headers: {Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json", ...Object.fromEntries(new Headers(headers))}, method: "POST",
    });
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

  async function createMemberThread(body: string, key = `member-thread-key-${crypto.randomUUID()}`): Promise<{readonly id: string; readonly author: {readonly displayName: string; readonly principalId: string}}> {
    const response = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/versions/${currentVersionId}/comments?projectId=${projectId}`, JSON.stringify({anchor: {point: {x: 0.5, y: 0.5}}, body}), {"Idempotency-Key": key});
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
    const wrong = await exchangeResponse(artifactId, "x".repeat(40), "Guest");
    expect(wrong.status).toBe(404);
    const regenerated = await enableInvitation();
    const revoked = await exchangeResponse(artifactId, first.secret, "Guest");
    const otherArtifact = await exchangeResponse(otherArtifactId, regenerated.secret, "Guest");
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
    const contentResponse = await fetchVersion(server, current.bootstrapUrl);
    expect(contentResponse.status).toBe(200);
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

  test("archiving the project invalidates guest current, comment creation, and comment listing", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const archive = await ownerRequest("POST", `/api/v1/projects/${projectId}/archive`, "{}");
    expect(archive.status).toBe(200);
    const responses = await Promise.all([
      guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`),
      guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: "Archived", versionId: currentVersionId}), true, "archived-guest-create-0001"),
      guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments`),
    ]);
    expect(responses.map((response) => response.status)).toEqual([404, 404, 404]);
  });

  test("exchange requires a same-origin JSON request", async () => {
    const invitation = await enableInvitation();
    const response = await exchangeResponse(artifactId, invitation.secret, "Guest", {Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site"});
    expect(response.status).toBe(403);
  });

  test("the 101st exchange is refused without evicting any live guest session", async () => {
    const invitation = await enableInvitation();
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    const resetExchangeWindow = () => database.prepare("UPDATE guest_review_invitations SET exchange_window_started_at = NULL, exchange_count = 0 WHERE artifact_id = ?").run(artifactId);
    const guests = [await exchange(artifactId, invitation.secret, "Guest 0")];
    await Array.from({length: 99}, (_, offset) => offset + 1).reduce(async (previous, index) => {
      await previous;
      resetExchangeWindow();
      guests.push(await exchange(artifactId, invitation.secret, `Guest ${index}`));
    }, Promise.resolve());
    resetExchangeWindow();
    expect((await exchangeResponse(artifactId, invitation.secret, "Guest 101")).status).toBe(429);
    expect((await Promise.all(guests.map((guest) => guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)))).map((response) => response.status))
      .toEqual(Array.from({length: 100}, () => 201));
    const status = await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    expect(await status.json()).toMatchObject({activeSessionCount: 100, limitHitRecently: true});
    database.close();
  });

  test("the 31st exchange for one invitation in a minute is rate limited", async () => {
    const invitation = await enableInvitation();
    expect((await Promise.all(Array.from({length: 30}, (_, index) => exchangeResponse(artifactId, invitation.secret, `Guest ${index}`)))).map((response) => response.status))
      .toEqual(Array.from({length: 30}, () => 201));
    expect((await exchangeResponse(artifactId, invitation.secret, "Guest 31")).status).toBe(429);
    expect(await (await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`)).json())
      .toMatchObject({activeSessionCount: 30, limitHitRecently: true});
  });

  test("owners can list guest sessions and revoke one session including its content cookie", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret, "Reviewer to revoke");
    const current = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).json());
    const contentResponse = await fetchVersion(server, current.bootstrapUrl);
    const contentCookie = contentResponse.headers.getSetCookie().find((cookie) => cookie.startsWith("artifact_content="))?.split(";", 1)[0];
    expect(contentResponse.status).toBe(200);
    expect(contentCookie).toBeDefined();
    const listPath = `/api/v1/artifacts/${artifactId}/guest-invitation/sessions?projectId=${projectId}`;
    const listed = z.object({sessions: z.array(z.object({createdAt: z.string(), displayName: z.string(), guestId: z.string(), lastUsedAt: z.string()}))}).parse(await (await ownerRequest("GET", listPath)).json());
    expect(listed.sessions).toHaveLength(1);
    expect(listed.sessions[0]?.displayName).toBe("Reviewer to revoke");
    expect((await ownerRequest("DELETE", `/api/v1/artifacts/${artifactId}/guest-invitation/sessions/${listed.sessions[0]?.guestId}?projectId=${projectId}`)).status).toBe(204);
    expect((await (await ownerRequest("GET", listPath)).json())).toEqual({sessions: []});
    expect((await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(404);
    const contentUrl = new URL("/", current.bootstrapUrl).toString();
    expect((await fetchVersion(server, contentUrl, "GET", {Cookie: contentCookie ?? ""})).status).not.toBe(200);
  });

  test("a visible guest heartbeat refreshes the two-hour idle window", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    const soon = new Date(Date.now() + 500).toISOString();
    database.prepare("UPDATE guest_review_sessions SET expires_at = ? WHERE display_name = ?").run(soon, "Guest Reviewer");
    database.close();
    expect((await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/heartbeat`)).status).toBe(204);
    const afterHeartbeat = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    expect(afterHeartbeat.prepare("SELECT comment_write_count AS comments, bootstrap_issue_count AS bootstraps FROM guest_review_sessions WHERE display_name = ?")
      .get("Guest Reviewer")).toEqual({comments: 0, bootstraps: 0});
    afterHeartbeat.close();
    await new Promise((resolve) => setTimeout(resolve, 700));
    expect((await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(201);
  });

  test("an idle-expired guest session does not count toward the invitation session cap", async () => {
    const invitation = await enableInvitation();
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    const resetExchangeWindow = () => database.prepare("UPDATE guest_review_invitations SET exchange_window_started_at = NULL, exchange_count = 0 WHERE artifact_id = ?").run(artifactId);
    const first = await exchange(artifactId, invitation.secret, "Idle expired");
    await Array.from({length: 99}, (_, offset) => offset + 1).reduce(async (previous, index) => {
      await previous;
      resetExchangeWindow();
      expect((await exchangeResponse(artifactId, invitation.secret, `Guest ${index}`)).status).toBe(201);
    }, Promise.resolve());
    database.prepare("UPDATE guest_review_sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE artifact_id = ? AND display_name = 'Idle expired'").run(artifactId);
    resetExchangeWindow();
    expect((await exchangeResponse(artifactId, invitation.secret, "Replacement")).status).toBe(201);
    expect((await guestRequest(first, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(404);
    const activeCount = z.object({count: z.number()}).parse(database.prepare("SELECT COUNT(*) AS count FROM guest_review_sessions WHERE artifact_id = ? AND expires_at > ? AND absolute_expires_at > ?").get(artifactId, new Date().toISOString(), new Date().toISOString()));
    expect(activeCount.count).toBe(100);
    database.close();
  });

  test("a guest session can create no more than 30 comments per hour", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const writes = await Promise.all(Array.from({length: 30}, (_, index) => guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: `Comment ${index}`, versionId: currentVersionId}), true, `guest-hourly-${index.toString().padStart(4, "0")}`)));
    expect(writes.map((response) => response.status)).toEqual(Array.from({length: 30}, () => 201));
    const limited = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: "Over limit", versionId: currentVersionId}), true, "guest-hourly-over-limit");
    expect(limited.status).toBe(429);
  });

  test("guest edits count toward the 30-action hourly budget", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const thread = await createGuestThread(guest, "Patch budget");
    const path = `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`;
    await Array.from({length: 29}, (_, index) => index).reduce(async (previous, index) => {
      await previous;
      expect((await guestRequest(guest, "PATCH", path, JSON.stringify({body: `Edit ${index}`}))).status).toBe(200);
    }, Promise.resolve());
    expect((await guestRequest(guest, "PATCH", path, JSON.stringify({body: "Over limit"}))).status).toBe(429);
  });

  test("guest current bootstrap issuance is limited to 60 per hour", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const path = `/api/v1/public/artifacts/${artifactId}/guest/current`;
    expect((await Promise.all(Array.from({length: 60}, () => guestRequest(guest, "GET", path)))).map((response) => response.status))
      .toEqual(Array.from({length: 60}, () => 201));
    expect((await guestRequest(guest, "GET", path)).status).toBe(429);
  });

  test("invitation-wide comment budget is shared across rotated guest sessions", async () => {
    const invitation = await enableInvitation();
    const first = await exchange(artifactId, invitation.secret, "First session");
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    database.prepare("UPDATE guest_review_invitations SET comment_window_started_at = ?, comment_write_count = 2999 WHERE artifact_id = ?")
      .run(new Date().toISOString(), artifactId);
    database.close();
    expect((await guestRequest(first, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: "Three thousand", versionId: currentVersionId}), true, "guest-invitation-write-3000-001")).status).toBe(201);
    const second = await exchange(artifactId, invitation.secret, "Rotated session");
    expect((await guestRequest(second, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({body: "Over invitation budget", versionId: currentVersionId}), true, "guest-invitation-write-3001-001")).status).toBe(429);
    const status = await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    expect(await status.json()).toMatchObject({limitHitRecently: true});
  });

  test("invitation-wide bootstrap budget is shared across rotated guest sessions", async () => {
    const invitation = await enableInvitation();
    const first = await exchange(artifactId, invitation.secret, "First session");
    const second = await exchange(artifactId, invitation.secret, "Rotated session");
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    database.prepare("UPDATE guest_review_invitations SET bootstrap_window_started_at = ?, bootstrap_issue_count = 5999 WHERE artifact_id = ?")
      .run(new Date().toISOString(), artifactId);
    database.close();
    expect((await guestRequest(first, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(201);
    expect((await guestRequest(second, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(429);
    const status = await ownerRequest("GET", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`);
    expect(await status.json()).toMatchObject({limitHitRecently: true});
  });

  test("repeated current requests issue bounded bootstraps and revocation invalidates its content URL", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const currentPath = `/api/v1/public/artifacts/${artifactId}/guest/current`;
    const first = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", currentPath)).json());
    const second = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", currentPath)).json());
    expect(second.bootstrapUrl).not.toBe(first.bootstrapUrl);
    const beforeRevoke = await fetchVersion(server, first.bootstrapUrl);
    expect(beforeRevoke.status).toBe(200);
    const contentCookie = beforeRevoke.headers.getSetCookie().find((cookie) => cookie.startsWith("artifact_content="))?.split(";", 1)[0];
    expect(contentCookie).toBeDefined();
    const contentUrl = new URL("/", first.bootstrapUrl).toString();
    expect((await fetchVersion(server, contentUrl, "GET", {Cookie: contentCookie ?? ""})).status).toBe(200);
    expect((await ownerRequest("DELETE", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`)).status).toBe(204);
    expect((await fetchVersion(server, contentUrl, "GET", {Cookie: contentCookie ?? ""})).status).not.toBe(200);
    expect((await fetchVersion(server, first.bootstrapUrl)).status).not.toBe(200);
  });

  test("guest content bootstraps and sessions are swept after expiry on guest authentication", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const current = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).json());
    expect((await fetchVersion(server, current.bootstrapUrl)).status).toBe(200);
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    database.prepare("UPDATE content_bootstraps SET expires_at = '2000-01-01T00:00:00.000Z' WHERE guest_session_id IS NOT NULL").run();
    database.prepare("UPDATE content_sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE guest_session_id IS NOT NULL").run();
    await server.stop();
    server = await startTestServer(installation);
    expect((await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(201);
    expect(database.prepare("SELECT COUNT(*) AS count FROM content_bootstraps WHERE guest_session_id IS NOT NULL AND expires_at <= '2000-01-01T00:00:00.000Z'").get()).toMatchObject({count: 0});
    expect(database.prepare("SELECT COUNT(*) AS count FROM content_sessions WHERE guest_session_id IS NOT NULL AND expires_at <= '2000-01-01T00:00:00.000Z'").get()).toMatchObject({count: 0});
    database.close();
  });

  test("guest idempotency replay cannot disclose a member thread", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const key = "member-thread-known-key-12345";
    const member = await createMemberThread("Member replay body", key);
    const replay = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({anchor: {point: {x: 0.5, y: 0.5}}, body: "Member replay body", versionId: currentVersionId}), true, key);
    expect(replay.status).toBe(404);
    expect(await replay.text()).toBe(JSON.stringify({error: {code: "COMMENT_NOT_FOUND", message: "The comment thread does not exist."}}));
    const replyKey = "member-reply-known-key-12345";
    const memberReply = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/comments/${member.id}/replies?projectId=${projectId}`, JSON.stringify({body: "Member reply replay"}), {"Idempotency-Key": replyKey});
    expect(memberReply.status).toBe(201);
    const replyReplay = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments/${member.id}/replies`, JSON.stringify({body: "Member reply replay"}), true, replyKey);
    expect(replyReplay.status).toBe(404);
    expect(await replyReplay.text()).toBe(JSON.stringify({error: {code: "COMMENT_NOT_FOUND", message: "The comment thread does not exist."}}));
  });

  test("guest thread and reply idempotency conflicts return the generic 404", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const threadKey = "guest-thread-conflict-key-001";
    const threadInput = {body: "First body", versionId: currentVersionId};
    expect((await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify(threadInput), true, threadKey)).status).toBe(201);
    const threadConflict = await guestRequest(guest, "POST", `/api/v1/public/artifacts/${artifactId}/guest/comments`, JSON.stringify({...threadInput, body: "Different body"}), true, threadKey);
    expect(threadConflict.status).toBe(404);
    expect(await threadConflict.text()).toBe(JSON.stringify({error: {code: "COMMENT_NOT_FOUND", message: "The comment thread does not exist."}}));

    const thread = await createGuestThread(guest, "Reply conflict root");
    const replyPath = `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}/replies`;
    const replyKey = "guest-reply-conflict-key-001";
    expect((await guestRequest(guest, "POST", replyPath, JSON.stringify({body: "First reply"}), true, replyKey)).status).toBe(201);
    const replyConflict = await guestRequest(guest, "POST", replyPath, JSON.stringify({body: "Different reply"}), true, replyKey);
    expect(replyConflict.status).toBe(404);
    expect(await replyConflict.text()).toBe(JSON.stringify({error: {code: "COMMENT_NOT_FOUND", message: "The comment thread does not exist."}}));
  });

  test("a guest cannot delete a thread containing a team reply", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const thread = await createGuestThread(guest, "Keep this with team reply");
    const memberReply = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/comments/${thread.id}/replies?projectId=${projectId}`, JSON.stringify({body: "Team reply"}), {"Idempotency-Key": "team-reply-keeps-thread-001"});
    expect(memberReply.status).toBe(201);
    expect((await guestRequest(guest, "DELETE", `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`)).status).toBe(409);
  });

  test("a concurrent team reply cannot be removed by guest thread deletion", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const thread = await createGuestThread(guest, "Concurrent team reply");
    const deletion = guestRequest(guest, "DELETE", `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`);
    const reply = ownerRequest("POST", `/api/v1/artifacts/${artifactId}/comments/${thread.id}/replies?projectId=${projectId}`, JSON.stringify({body: "Must not be silently removed"}), {"Idempotency-Key": "guest-delete-reply-race-001"});
    const [deleted, replied] = await Promise.all([deletion, reply]);
    const detail = await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`);
    const replyWon = replied.status === 201;
    expect([deleted.status, replied.status]).toEqual(replyWon ? [409, 201] : [204, 404]);
    expect(detail.status).toBe(replyWon ? 200 : 404);
    expect((await detail.text()).includes("Must not be silently removed")).toBe(replyWon);
  });

  test("guest member-author projections hide emails for replies and resolvedBy", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const thread = await createGuestThread(guest, "Team response will be private");
    const memberReply = await ownerRequest("POST", `/api/v1/artifacts/${artifactId}/comments/${thread.id}/replies?projectId=${projectId}`, JSON.stringify({body: "Email author reply"}), {"Idempotency-Key": "email-author-reply-guest-001"});
    expect(memberReply.status).toBe(201);
    const resolve = await ownerRequest("PATCH", `/api/v1/artifacts/${artifactId}/comments/${thread.id}?projectId=${projectId}`, JSON.stringify({state: "resolved"}));
    expect(resolve.status).toBe(200);
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      database.prepare("UPDATE comment_replies SET author_display_name = 'reviewer@example.test' WHERE thread_id = ?").run(thread.id);
      database.prepare("UPDATE comment_threads SET resolved_by_display_name = 'reviewer@example.test' WHERE id = ?").run(thread.id);
    } finally {
      database.close();
    }
    const response = await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/comments/${thread.id}`);
    const text = await response.text();
    const details = guestThreadDetailsSchema.parse(JSON.parse(text));
    expect(text).not.toContain("@");
    expect(text).not.toMatch(/principalId|authorizedByPrincipalId|principalKind/i);
    expect(details.thread.resolvedBy).toEqual({displayName: "Team member", isYou: false});
    expect(details.replies).toContainEqual({author: {displayName: "Team member", isYou: false}, body: "Email author reply"});
  });

  test("creator losing active membership invalidates exchange, guest sessions and existing content sessions", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const current = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).json());
    const fetched = await fetchVersion(server, current.bootstrapUrl);
    const contentCookie = fetched.headers.getSetCookie().find((cookie) => cookie.startsWith("artifact_content="))?.split(";", 1)[0];
    expect(fetched.status).toBe(200);
    expect(contentCookie).toBeDefined();
    const contentUrl = new URL("/", current.bootstrapUrl).toString();
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      database.prepare("UPDATE installation_members SET status = 'inactive' WHERE id = (SELECT created_by_principal_id FROM guest_review_invitations WHERE artifact_id = ?)").run(artifactId);
    } finally {
      database.close();
    }
    const deniedExchange = await exchangeResponse(artifactId, invitation.secret);
    expect(deniedExchange.status).toBe(404);
    expect(await deniedExchange.text()).toBe(JSON.stringify({error: {code: "NOT_FOUND", message: "The requested route does not exist."}}));
    expect((await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).status).toBe(404);
    expect((await fetchVersion(server, contentUrl, "GET", {Cookie: contentCookie ?? ""})).status).not.toBe(200);
    expect((await fetchVersion(server, current.bootstrapUrl)).status).not.toBe(200);
  });

  test("guest content follows project group-grant removal", async () => {
    const invitation = await enableInvitation();
    const guest = await exchange(artifactId, invitation.secret);
    const bootstrapOne = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).json());
    const bootstrapTwo = z.object({bootstrapUrl: z.url()}).parse(await (await guestRequest(guest, "GET", `/api/v1/public/artifacts/${artifactId}/guest/current`)).json());
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    const invitationRow = z.object({creatorId: z.string(), installationId: z.string()}).parse(database.prepare(`SELECT i.created_by_principal_id AS creatorId,
      m.installation_id AS installationId FROM guest_review_invitations i JOIN installation_members m ON m.id = i.created_by_principal_id
      WHERE i.artifact_id = ?`).get(artifactId));
    const creator = z.object({email: z.string()}).parse(database.prepare("SELECT email FROM installation_members WHERE id = ?").get(invitationRow.creatorId));
    const provider = "round4-test-provider";
    const subject = `round4-${crypto.randomUUID()}`;
    const groupId = `round4-${crypto.randomUUID()}`;
    const now = new Date().toISOString();
    database.prepare("UPDATE installation_members SET role = 'member' WHERE id = ?").run(invitationRow.creatorId);
    database.prepare("UPDATE projects SET access_mode = 'restricted', created_by_member_id = NULL WHERE id = ?").run(projectId);
    database.prepare("INSERT INTO external_identities (provider, subject, member_id, email, bound_at) VALUES (?, ?, ?, ?, ?)")
      .run(provider, subject, invitationRow.creatorId, creator.email, now);
    database.prepare("INSERT INTO directory_groups (installation_id, id, name, path, synced_at) VALUES (?, ?, ?, ?, ?)")
      .run(invitationRow.installationId, groupId, "Round 4 project reviewers", `/round4/${groupId}`, now);
    database.prepare("INSERT INTO directory_group_members (installation_id, group_id, subject, email, provider) VALUES (?, ?, ?, ?, ?)")
      .run(invitationRow.installationId, groupId, subject, creator.email, provider);
    database.prepare(`INSERT INTO project_group_grants (installation_id, project_id, group_id, role, granted_at, granted_by_principal_id)
      VALUES (?, ?, ?, 'manager', ?, ?)`)
      .run(invitationRow.installationId, projectId, groupId, now, invitationRow.creatorId);
    database.close();

    const fetched = await fetchVersion(server, bootstrapOne.bootstrapUrl);
    const contentCookie = fetched.headers.getSetCookie().find((cookie) => cookie.startsWith("artifact_content="))?.split(";", 1)[0];
    expect(fetched.status).toBe(200);
    expect(contentCookie).toBeDefined();
    const contentUrl = new URL("/", bootstrapOne.bootstrapUrl).toString();

    const revokeGrant = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    revokeGrant.prepare("DELETE FROM project_group_grants WHERE project_id = ? AND group_id = ?").run(projectId, groupId);
    revokeGrant.close();
    expect((await fetchVersion(server, contentUrl, "GET", {Cookie: contentCookie ?? ""})).status).not.toBe(200);
    expect((await fetchVersion(server, bootstrapTwo.bootstrapUrl)).status).not.toBe(200);
  });
});

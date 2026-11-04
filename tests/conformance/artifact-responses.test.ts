import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {DatabaseSync} from "node:sqlite";
import nodePath from "node:path";
import {z} from "zod";

import {createTestInstallation, issueLocalBrowserLogin, removeTestInstallation, startTestServer, type RunningTestServer, type TestInstallation} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const responseSchema = z.object({
  artifactId: z.string(), authorDisplayName: z.string(), authorEmail: z.string().nullable(),
  authorKind: z.enum(["member", "guest"]), authorSubject: z.string(), choice: z.string().nullable(),
  createdAt: z.string(), data: z.unknown().nullable(), externalQuestion: z.boolean(),
  guestSessionId: z.string().nullable(), id: z.string(), questionId: z.string(), versionId: z.string(),
});

describe("artifact responses", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let artifactId: string;
  let projectId: string;
  let versionId: string;
  let cookie: string;
  let csrf: string;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation);
    const published = await publishNew(server, installation, {
      accessSetting: "account_required", content: "<!doctype html><title>Responses</title>",
      idempotencyKey: "artifact-responses",
    });
    artifactId = published.body.artifact.id;
    projectId = published.body.artifact.projectId;
    versionId = published.body.version.id;
    const token = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(`${server.baseUrl}/auth/local?token=${token}`, {redirect: "manual"});
    const cookies = login.headers.getSetCookie();
    cookie = cookies.filter((item) => /^artifact_(session|csrf)=/.test(item)).map((item) => item.split(";", 1)[0]).join("; ");
    csrf = cookies.find((item) => item.startsWith("artifact_csrf="))?.split(";", 1)[0]?.split("=", 2)[1] ?? "";
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  function memberRequest(method: string, path: string, body?: string): Promise<Response> {
    const headers = new Headers({Cookie: cookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf});
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const init: RequestInit = {headers, method};
    if (body !== undefined) init.body = body;
    return fetch(`${server.baseUrl}${path}`, init);
  }

  test("members can append, poll, and fetch immutable responses by id", async () => {
    const path = `/api/v1/artifacts/${artifactId}/responses?projectId=${projectId}`;
    const createdResponse = await memberRequest("POST", path, JSON.stringify({questionId: "approval", choice: "yes", data: {note: "ship"}, versionId}));
    expect(createdResponse.status).toBe(201);
    const created = responseSchema.parse(await createdResponse.json());
    expect(created).toMatchObject({artifactId, authorKind: "member", choice: "yes", data: {note: "ship"}, questionId: "approval", versionId});
    const listed = await memberRequest("GET", `${path}&questionId=approval`);
    expect(listed.status).toBe(200);
    expect((await listed.json()).items).toEqual([created]);
    const fetched = await memberRequest("GET", `/api/v1/artifacts/${artifactId}/responses/${created.id}?projectId=${projectId}`);
    expect(await fetched.json()).toEqual(created);
    const tooLarge = await memberRequest("POST", path, JSON.stringify({questionId: "approval", versionId, data: "x".repeat(16_385)}));
    expect(tooLarge.status).toBe(413);
    expect((await tooLarge.json()).error.message).toContain("16 KB");
    const tooLongQuestion = await memberRequest("POST", path, JSON.stringify({questionId: "q".repeat(201), versionId}));
    expect(tooLongQuestion.status).toBe(413);
    expect((await tooLongQuestion.json()).error.message).toContain("200 character limit");
    const tooLongChoice = await memberRequest("POST", path, JSON.stringify({choice: "c".repeat(201), questionId: "approval", versionId}));
    expect(tooLongChoice.status).toBe(413);
    expect((await tooLongChoice.json()).error.message).toContain("200 character limit");
    expect((await memberRequest("POST", path, JSON.stringify({questionId: "approval", versionId: "ver_not_this_artifact"}))).status).toBe(404);

    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      // SAFETY: Every test installation seeds an administrator before publishing the artifact.
      const identity = z.object({installationId: z.string()}).parse(database.prepare("SELECT installation_id AS installationId FROM installation_members LIMIT 1").get());
      database.prepare(`INSERT INTO artifact_responses (
        id, installation_id, project_id, artifact_id, version_id, question_id,
        choice, data_json, author_kind, author_subject, author_display_name,
        author_email, guest_session_id, created_at, external_question
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        "rsp_external_question_test", identity.installationId, projectId, artifactId, versionId,
        "external", null, null, "member", "member_external_test", "External test", "member@example.test", null,
        new Date().toISOString(), 1,
      );
      expect(() => database.prepare("UPDATE artifact_responses SET choice = 'changed' WHERE id = ?").run("rsp_external_question_test")).toThrow(/immutable/u);
      expect(() => database.prepare("DELETE FROM artifact_responses WHERE id = ?").run("rsp_external_question_test")).toThrow(/immutable/u);
    } finally {
      database.close();
    }
    const external = await memberRequest("GET", `/api/v1/artifacts/${artifactId}/responses/rsp_external_question_test?projectId=${projectId}`);
    expect((await external.json()).externalQuestion).toBe(true);
  });

  test("guest response routes expose only that guest's immutable answers", async () => {
    const invitation = await memberRequest("POST", `/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`, "{}");
    const inviteUrl = new URL(z.object({url: z.url()}).parse(await invitation.json()).url);
    const secret = new URLSearchParams(inviteUrl.hash.slice(1)).get("invite") ?? "";
    async function join(name: string) {
      const exchange = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest-session`, {
        body: JSON.stringify({displayName: name, secret}),
        headers: {"Content-Type": "application/json", Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin"},
        method: "POST",
      });
      const cookies = exchange.headers.getSetCookie();
      const session = cookies.find((item) => item.startsWith("artifact_guest_session="))?.split(";", 1)[0] ?? "";
      const csrfCookie = cookies.find((item) => item.startsWith("artifact_guest_csrf="))?.split(";", 1)[0] ?? "";
      return {cookie: `${session}; ${csrfCookie}`, csrf: csrfCookie.split("=", 2)[1] ?? ""};
    }
    async function guestRequest(guest: {cookie: string; csrf: string}, method: string, body?: string) {
      const headers = new Headers({Cookie: guest.cookie, Origin: server.baseUrl, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": guest.csrf});
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const init: RequestInit = {headers, method};
      if (body !== undefined) init.body = body;
      return fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/responses`, init);
    }
    const guestA = await join("Guest A");
    const guestB = await join("Guest B");
    const created = responseSchema.parse(await (await guestRequest(guestA, "POST", JSON.stringify({questionId: "q", choice: "a", versionId}))).json());
    expect(created.authorKind).toBe("guest");
    expect(created.authorEmail).toBeNull();
    const guestDatabase = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    try {
      expect(guestDatabase.prepare("SELECT comment_write_count AS count FROM guest_review_invitations WHERE artifact_id = ?").get(artifactId)).toEqual({count: 1});
    } finally {
      guestDatabase.close();
    }
    expect((await guestRequest(guestB, "GET")).status).toBe(200);
    expect((await (await guestRequest(guestB, "GET")).json()).items).toEqual([]);
    const own = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/responses/${created.id}`, {headers: {Cookie: guestA.cookie}});
    expect((await own.json()).id).toBe(created.id);
    const hidden = await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/responses/${created.id}`, {headers: {Cookie: guestB.cookie}});
    expect(hidden.status).toBe(404);
    expect((await hidden.text())).toBe(await (await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/guest/responses/missing`, {headers: {Cookie: guestB.cookie}})).text());
    expect((await fetch(`${server.baseUrl}/api/v1/public/artifacts/${artifactId}/responses`)).status).toBe(401);
  });
});

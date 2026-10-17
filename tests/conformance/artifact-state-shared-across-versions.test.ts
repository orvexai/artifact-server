import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {BearerCredentialVerifier} from
  "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import type {Principal} from "../../src/core/identity.js";
import {
  createTestInstallation,
  issueLocalBrowserLogin,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {
  publishNew,
  publishVersion,
  type PublishResponse,
} from "../support/publishing.js";

const memberCredential = "artifact-state-member";

const entrySchema = z.object({
  artifactId: z.string(),
  key: z.string(),
  projectId: z.string(),
  updatedAt: z.string(),
  updatedBy: z.object({displayName: z.string(), principalId: z.string()}),
  value: z.unknown(),
});
const failureSchema = z.object({
  error: z.object({code: z.string(), message: z.string()}),
});
const issuedKeySchema = z.object({token: z.string()});

describe("artifact state shared across versions", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let published: PublishResponse;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      externalApiBearerVerifier: memberVerifier,
    });
    published = (await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Triage v1</title>",
      idempotencyKey: "artifact-state-publish-v1",
      name: "Triage board",
    })).body;
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("a written value survives a republish and records its writer", async () => {
    const statePath = `/api/v1/artifacts/${published.artifact.id}/state`;
    const choices = {"bug-1": "before-refreeze", "bug-2": "backlog"};

    const written = await memberFetch(`${statePath}/triage`, {
      body: JSON.stringify({value: choices}),
      method: "PUT",
    });
    expect(written.status).toBe(200);

    await publishVersion(server, installation, {
      artifactId: published.artifact.id,
      content: "<!doctype html><title>Triage v2</title>",
      expectedCurrentVersionId: published.version.id,
      idempotencyKey: "artifact-state-publish-v2",
    });

    const read = await memberFetch(`${statePath}/triage`);
    expect(read.status).toBe(200);
    const entry = z.object({entry: entrySchema}).parse(await read.json()).entry;
    expect(entry.value).toEqual(choices);
    expect(entry.updatedBy).toEqual({
      displayName: "Priya Member",
      principalId: "member_state_writer",
    });

    const listed = await memberFetch(statePath);
    expect(z.object({entries: z.array(entrySchema)}).parse(await listed.json())
      .entries.map((item) => item.key)).toEqual(["triage"]);

    const deleted = await memberFetch(`${statePath}/triage`, {method: "DELETE"});
    expect(deleted.status).toBe(204);
    const gone = await memberFetch(`${statePath}/triage`);
    expect(z.object({entry: entrySchema.nullable()}).parse(await gone.json()).entry)
      .toBeNull();
  });

  test("a read-only key can read state but not change it", async () => {
    const statePath = `/api/v1/artifacts/${published.artifact.id}/state`;
    await memberFetch(`${statePath}/triage`, {
      body: JSON.stringify({value: {seeded: true}}),
      method: "PUT",
    });
    const readOnly = await issueKey(["artifact:read"]);

    const read = await fetch(`${server.baseUrl}${statePath}/triage`, {
      headers: {Authorization: `Bearer ${readOnly}`},
    });
    expect(read.status).toBe(200);

    const denials = await Promise.all([
      {body: JSON.stringify({value: {overwritten: true}}), method: "PUT"},
      {method: "DELETE"},
    ].map(async (init) => {
      const denied = await fetch(`${server.baseUrl}${statePath}/triage`, {
        ...init,
        headers: {
          Authorization: `Bearer ${readOnly}`,
          "Content-Type": "application/json",
        },
      });
      return {
        code: failureSchema.parse(await denied.json()).error.code,
        status: denied.status,
      };
    }));
    expect(denials).toEqual([
      {code: "AUTHORIZATION_DENIED", status: 403},
      {code: "AUTHORIZATION_DENIED", status: 403},
    ]);
  });

  test("an oversized value is rejected before it is stored", async () => {
    const statePath = `/api/v1/artifacts/${published.artifact.id}/state`;
    const rejected = await memberFetch(`${statePath}/big`, {
      body: JSON.stringify({value: "x".repeat(70 * 1_024)}),
      method: "PUT",
    });
    expect(rejected.status).toBeGreaterThanOrEqual(400);
    expect(rejected.status).toBeLessThan(500);
    const absent = await memberFetch(`${statePath}/big`);
    expect(z.object({entry: entrySchema.nullable()}).parse(await absent.json()).entry)
      .toBeNull();
  });

  async function memberFetch(
    pathname: string,
    init: RequestInit = {},
  ): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${memberCredential}`);
    headers.set("Content-Type", "application/json");
    return fetch(`${server.baseUrl}${pathname}`, {...init, headers});
  }

  async function issueKey(capabilities: readonly string[]): Promise<string> {
    const localBrowserToken = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(
      `${server.baseUrl}/auth/local?token=${localBrowserToken}`,
      {redirect: "manual"},
    );
    const cookies = login.headers.getSetCookie();
    const session = cookies.find((value) => value.startsWith("artifact_session="));
    const csrf = cookies.find((value) => value.startsWith("artifact_csrf="));
    const sessionPair = session?.split(";", 1)[0];
    const csrfPair = csrf?.split(";", 1)[0];
    if (sessionPair === undefined || csrfPair === undefined) {
      throw new Error("The administrator login did not issue both cookies.");
    }
    const response = await fetch(`${server.baseUrl}/api/v1/api-keys`, {
      body: JSON.stringify({
        capabilities,
        expiresAt: "2099-01-01T00:00:00.000Z",
        name: "State reader",
      }),
      headers: {
        "Content-Type": "application/json",
        Cookie: `${sessionPair}; ${csrfPair}`,
        Origin: server.baseUrl,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "X-CSRF-Token": csrfPair.slice(csrfPair.indexOf("=") + 1),
      },
      method: "POST",
    });
    expect(response.status).toBe(201);
    return issuedKeySchema.parse(await response.json()).token;
  }
});

const memberPrincipal: Principal = {
  authorizedByPrincipalId: null,
  capabilities: [],
  displayName: "Priya Member",
  id: "member_state_writer",
  installationId: "local",
  kind: "human",
  membershipRole: "member",
};

const memberVerifier: BearerCredentialVerifier = {
  verify: (credential) =>
    Redacted.value(credential) === memberCredential
      ? Effect.succeed(memberPrincipal)
      : Effect.fail(new AuthenticationRequired({
        message: "The external state credential is invalid.",
      })),
};

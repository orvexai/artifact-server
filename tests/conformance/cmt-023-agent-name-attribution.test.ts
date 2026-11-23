import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {Effect, Redacted} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {BearerCredentialVerifier} from
  "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {
  membershipRoles,
  principalCapabilities,
  principalKinds,
} from "../../src/core/identity.js";
import {
  createTestInstallation,
  issueLocalBrowserLogin,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";
import {publishNew} from "../support/publishing.js";

const protocolVersion = "2026-07-28";
const externalBearerToken = "cmt-023-external-bearer";

const authorSchema = z.object({
  actor: z.object({
    clientId: z.string(),
    kind: z.literal("mcp-client"),
  }).nullable(),
  authorizedByPrincipalId: z.string().nullable(),
  displayName: z.string(),
  principalId: z.string(),
  principalKind: z.enum(["human", "service"]),
});
const threadSchema = z.object({
  author: authorSchema,
  id: z.string(),
  resolvedBy: authorSchema.nullable(),
  state: z.enum(["open", "resolved"]),
});
const createResultSchema = z.object({
  replayed: z.boolean(),
  thread: threadSchema,
});
const replyResultSchema = z.object({
  replayed: z.boolean(),
  reply: z.object({
    author: authorSchema,
    id: z.string(),
    threadId: z.string(),
  }),
});
const resolveResultSchema = z.object({thread: threadSchema});
const toolCallResultSchema = z.object({
  id: z.union([z.string(), z.number()]),
  jsonrpc: z.literal("2.0"),
  result: z.object({
    content: z.array(z.object({text: z.string(), type: z.literal("text")})),
    isError: z.boolean().optional(),
    resultType: z.literal("complete"),
    structuredContent: z.unknown().optional(),
  }).loose(),
}).loose();
const issuedKeySchema = z.object({
  token: z.string().startsWith("as_key_"),
}).loose();

describe("CMT-023 MCP agent display attribution", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let administratorCookies: ApplicationCookies;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      externalMcpBearerVerifier,
    });
    const localBrowserToken = await issueLocalBrowserLogin(server, installation);
    const login = await fetch(
      `${server.baseUrl}/auth/local?token=${localBrowserToken}`,
      {redirect: "manual"},
    );
    if (login.status !== 303) {
      throw new Error(`The administrator login failed with ${login.status}.`);
    }
    administratorCookies = applicationCookies(login.headers.getSetCookie());
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("CMT-023-B: managed API-key and external-bearer writes keep the principal as actor", async () => {
    expect.hasAssertions();
    const published = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Agent attribution</title>",
      idempotencyKey: "cmt-023-behavior-publish",
      name: "Agent attribution",
    });
    const credentials = [
      {
        displayName: "Local",
        kind: "service" as const,
        principalId: "local-api-token",
        token: installation.apiToken,
      },
      {
        displayName: "Write-only agent",
        kind: "service" as const,
        principalId: "service:key_write_only",
        token: externalBearerToken,
      },
    ];

    const managedApiKey = credentials[0];
    const externalBearer = credentials[1];
    if (managedApiKey === undefined || externalBearer === undefined) {
      throw new Error("The CMT-023 credentials were not initialized.");
    }
    await exerciseCredential(managedApiKey);
    await exerciseCredential(externalBearer);

    async function exerciseCredential(credential: NonNullable<typeof managedApiKey>) {
      const attributedName = `Release agent (via ${credential.displayName})`;
      const created = await callTool(credential.token, "comment_create", {
        agentName: "Release agent",
        artifactId: published.body.artifact.id,
        body: "Release review comment.",
        idempotencyKey: `cmt-023-create-${credential.principalId}`,
        projectId: published.body.artifact.projectId,
        versionId: published.body.version.id,
      });
      expect(created.isError).not.toBe(true);
      const thread = createResultSchema.parse(created.structuredContent).thread;
      expect(thread.author).toEqual({
        actor: null,
        authorizedByPrincipalId: null,
        displayName: attributedName,
        principalId: credential.principalId,
        principalKind: credential.kind,
      });

      const replied = await callTool(credential.token, "comment_reply", {
        agentName: "Release agent",
        artifactId: published.body.artifact.id,
        body: "Release review reply.",
        idempotencyKey: `cmt-023-reply-${credential.principalId}`,
        projectId: published.body.artifact.projectId,
        threadId: thread.id,
      });
      expect(replied.isError).not.toBe(true);
      const reply = replyResultSchema.parse(replied.structuredContent).reply;
      expect(reply.threadId).toBe(thread.id);
      expect(reply.author).toEqual(thread.author);

      const resolved = await callTool(credential.token, "comment_resolve", {
        agentName: "Release agent",
        artifactId: published.body.artifact.id,
        projectId: published.body.artifact.projectId,
        resolved: true,
        threadId: thread.id,
      });
      expect(resolved.isError).not.toBe(true);
      const resolvedThread = resolveResultSchema.parse(
        resolved.structuredContent,
      ).thread;
      expect(resolvedThread.state).toBe("resolved");
      expect(resolvedThread.author).toEqual(thread.author);
      expect(resolvedThread.resolvedBy).toEqual(thread.author);
    }
  });

  test("CMT-023-F: sanitization, validation, and comment-write authorization stay fail closed", async () => {
    expect.hasAssertions();
    const published = await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "<!doctype html><title>Agent label safety</title>",
      idempotencyKey: "cmt-023-failure-publish",
      name: "Agent label safety",
    });
    const hostileLabel = "\u202EtnegA<b>x</b>";
    const hostile = await callTool(externalBearerToken, "comment_create", {
      agentName: hostileLabel,
      artifactId: published.body.artifact.id,
      body: "Sanitized label.",
      idempotencyKey: "cmt-023-hostile-label",
      projectId: published.body.artifact.projectId,
      versionId: published.body.version.id,
    });
    expect(hostile.isError).not.toBe(true);
    const hostileThread = createResultSchema.parse(hostile.structuredContent).thread;
    expect(hostileThread.author.displayName).toContain("(via Write-only agent)");
    expect(hostileThread.author.displayName).not.toContain("\u202E");
    expect(hostileThread.author.displayName).not.toContain("<");
    expect(hostileThread.author.displayName).not.toContain(">");
    expect(hostileThread.author.displayName).not.toBe(hostileLabel);

    const emptyLabel = await callTool(externalBearerToken, "comment_create", {
      agentName: "\u200B",
      artifactId: published.body.artifact.id,
      body: "Empty sanitized label.",
      idempotencyKey: "cmt-023-empty-label",
      projectId: published.body.artifact.projectId,
      versionId: published.body.version.id,
    });
    expect(emptyLabel.isError).not.toBe(true);
    const emptyThread = createResultSchema.parse(emptyLabel.structuredContent).thread;
    expect(emptyThread.author.displayName).toBe("Write-only agent");
    expect(emptyThread.author.displayName).not.toBe("\u200B");

    const expandedLabel = "\uFDFA".repeat(80);
    const expanded = await callTool(externalBearerToken, "comment_create", {
      agentName: expandedLabel,
      artifactId: published.body.artifact.id,
      body: "Expanded label is capped.",
      idempotencyKey: "cmt-023-expanded-label",
      projectId: published.body.artifact.projectId,
      versionId: published.body.version.id,
    });
    expect(expanded.isError).not.toBe(true);
    const expandedThread = createResultSchema.parse(expanded.structuredContent).thread;
    expect(expandedThread.author.displayName).toMatch(/^.{1,80} \(via Write-only agent\)$/u);

    const controlLabel = await callTool(externalBearerToken, "comment_create", {
      agentName: "Release\u0001agent",
      artifactId: published.body.artifact.id,
      body: "Rejected control character.",
      idempotencyKey: "cmt-023-control-label",
      projectId: published.body.artifact.projectId,
      versionId: published.body.version.id,
    });
    expect(controlLabel.isError).toBe(true);
    expect(controlLabel.content[0]?.text).toContain("control characters");

    const readOnlyTokenValue = await issueKey(
      ["artifact:read"],
      "Read-only automation",
    );
    const denied = await callTool(readOnlyTokenValue, "comment_create", {
      agentName: "Release agent",
      artifactId: published.body.artifact.id,
      body: "Must remain unauthorized.",
      idempotencyKey: "cmt-023-read-only-write",
      projectId: published.body.artifact.projectId,
      versionId: published.body.version.id,
    });
    expect(denied.isError).toBe(true);
    expect(denied.content[0]?.text).toContain("AUTHORIZATION_DENIED");
  });

  async function callTool(
    token: string,
    name: string,
    arguments_: McpParameters,
  ) {
    const response = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "artifact-server-test", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: protocolVersion,
          },
          arguments: arguments_,
          name,
        },
      }),
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
      },
      method: "POST",
    });
    expect(response.status).toBe(200);
    return toolCallResultSchema.parse(await response.json()).result;
  }

  async function issueKey(
    capabilities: readonly string[],
    name: string,
  ): Promise<string> {
    const response = await fetch(`${server.baseUrl}/api/v1/api-keys`, {
      body: JSON.stringify({
        capabilities,
        expiresAt: "2099-01-01T00:00:00.000Z",
        name,
      }),
      headers: browserMutationHeaders(server.baseUrl, administratorCookies),
      method: "POST",
    });
    expect(response.status).toBe(201);
    return issuedKeySchema.parse(await response.json()).token;
  }
});

interface McpParameters {
  readonly [key: string]: McpParameterValue;
}

type McpParameterValue =
  | boolean
  | number
  | string
  | null
  | readonly McpParameterValue[]
  | McpParameters;

interface ApplicationCookies {
  readonly csrf: string;
  readonly header: string;
}

function applicationCookies(
  setCookieHeaders: readonly string[],
): ApplicationCookies {
  const session = setCookieHeaders.find((value) =>
    value.startsWith("artifact_session=")
  );
  const csrf = setCookieHeaders.find((value) =>
    value.startsWith("artifact_csrf=")
  );
  if (session === undefined || csrf === undefined) {
    throw new Error("The login response did not issue both application cookies.");
  }
  const sessionPair = session.split(";", 1)[0];
  const csrfPair = csrf.split(";", 1)[0];
  if (sessionPair === undefined || csrfPair === undefined) {
    throw new Error("The login response issued a malformed application cookie.");
  }
  return {
    csrf: csrfPair.slice(csrfPair.indexOf("=") + 1),
    header: `${sessionPair}; ${csrfPair}`,
  };
}

function browserMutationHeaders(
  origin: string,
  cookies: ApplicationCookies,
): Headers {
  return new Headers({
    "Content-Type": "application/json",
    Cookie: cookies.header,
    Origin: origin,
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "X-CSRF-Token": cookies.csrf,
  });
}

const externalMcpBearerVerifier: BearerCredentialVerifier = {
  verify: (credential) =>
    Redacted.value(credential) === externalBearerToken
      ? Effect.succeed({
        authorizedByPrincipalId: null,
        capabilities: [principalCapabilities.writeComments],
        displayName: "Write-only agent",
        id: "service:key_write_only",
        installationId: "local",
        kind: principalKinds.service,
        membershipRole: membershipRoles.member,
      })
      : Effect.fail(new AuthenticationRequired({
        message: "The CMT-023 external MCP bearer credential is invalid.",
      })),
};

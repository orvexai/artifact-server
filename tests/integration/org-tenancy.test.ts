import {createHash, randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {request as httpRequest} from "node:http";

import {
  CreateBucketCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {Effect, Redacted} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {afterAll, beforeAll, describe, expect, test} from "vitest";
import {z} from "zod";

import {createOrgRuntime, type ExternalStorageRuntimeConfig} from
  "../../src/external-storage/create-external-storage-runtime.js";
import {OrganizationRegistry} from
  "../../src/external-storage/organization-registry.js";
import {startExternalStorageServer} from
  "../../src/external-storage/start-external-storage-server.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import {createOidcIdentityProvider} from
  "../../src/identity/oidc-identity-provider.js";
import {startStubOidcProvider} from "../support/stub-oidc-provider.js";
import {createS3ObjectStorageProviderFactory} from
  "../../src/storage/s3-object-storage.js";
import {PostgresDatabase} from "../../src/storage/postgres-database.js";

const region = "us-east-1";
const applicationOrigin = "https://artifacts.example.com";
const adminEmail = "administrator@example.test";
const bytes = new TextEncoder().encode("org B private artifact");
const crossOrgMatrix = [
  {surface: "hono", identifier: "ALL /*", coverage: "organization router dispatches into an installation-scoped Hono app"},
  {surface: "hono", identifier: "ALL /api/*", coverage: "cross-org project and artifact identifiers return 404"},
  {surface: "hono", identifier: "ALL /mcp", coverage: "foreign-org API key is rejected before MCP dispatch"},
  {surface: "hono", identifier: "GET /api/v1/projects/:projectId", coverage: "Org B project requested through Org A returns 404"},
  {surface: "hono", identifier: "GET /api/v1/artifacts/:artifactId", coverage: "Org B artifact requested through Org A returns 404"},
  {surface: "hono", identifier: "GET /api/v1/session", coverage: "Org A session cookie is ignored by Org B"},
  {surface: "hono", identifier: "GET /auth/login", coverage: "org-scoped login handshake cookie"},
  {surface: "hono", identifier: "GET /auth/callback", coverage: "shared callback selects org from handshake cookie"},
] as const;

const pendingCrossOrgCases = [
  "hono:DELETE /api/v1/artifacts/:artifactId",
  "hono:DELETE /api/v1/artifacts/:artifactId/comments/:threadId",
  "hono:DELETE /api/v1/artifacts/:artifactId/comments/:threadId/replies/:replyId",
  "hono:DELETE /api/v1/artifacts/:artifactId/guest-invitation",
  "hono:DELETE /api/v1/artifacts/:artifactId/guest-invitation/sessions/:guestId",
  "hono:DELETE /api/v1/artifacts/:artifactId/state/:key",
  "hono:DELETE /api/v1/projects/:projectId/groups/:group",
  "hono:DELETE /api/v1/public/artifacts/:artifactId/guest/comments/:threadId",
  "hono:DELETE /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies/:replyId",
  "hono:GET /",
  "hono:GET /.well-known/oauth-protected-resource/api",
  "hono:GET /administration/api-keys",
  "hono:GET /administration/members",
  "hono:GET /administration/public-links",
  "hono:GET /api/v1/administration/public-links",
  "hono:GET /api/v1/agent-dispatches",
  "hono:GET /api/v1/agent-dispatches/:dispatchId",
  "hono:GET /api/v1/agents",
  "hono:GET /api/v1/api-keys",
  "hono:GET /api/v1/artifacts",
  "hono:GET /api/v1/artifacts/:artifactId/actions",
  "hono:GET /api/v1/artifacts/:artifactId/comments",
  "hono:GET /api/v1/artifacts/:artifactId/comments/:threadId",
  "hono:GET /api/v1/artifacts/:artifactId/comparisons",
  "hono:GET /api/v1/artifacts/:artifactId/guest-invitation",
  "hono:GET /api/v1/artifacts/:artifactId/guest-invitation/sessions",
  "hono:GET /api/v1/artifacts/:artifactId/responses",
  "hono:GET /api/v1/artifacts/:artifactId/responses/:responseId",
  "hono:GET /api/v1/artifacts/:artifactId/state",
  "hono:GET /api/v1/artifacts/:artifactId/state/:key",
  "hono:GET /api/v1/artifacts/:artifactId/versions",
  "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId",
  "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/archive",
  "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/file",
  "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/media",
  "hono:GET /api/v1/embed/artifacts/:artifactId/bootstrap",
  "hono:GET /api/v1/groups",
  "hono:GET /api/v1/members",
  "hono:GET /api/v1/projects",
  "hono:GET /api/v1/projects/:projectId/audit",
  "hono:GET /api/v1/projects/:projectId/git-history",
  "hono:GET /api/v1/projects/:projectId/sharing",
  "hono:GET /api/v1/public/artifacts/:artifactId",
  "hono:GET /api/v1/public/artifacts/:artifactId/guest/comments",
  "hono:GET /api/v1/public/artifacts/:artifactId/guest/comments/:threadId",
  "hono:GET /api/v1/public/artifacts/:artifactId/guest/current",
  "hono:GET /api/v1/public/artifacts/:artifactId/guest/responses",
  "hono:GET /api/v1/public/artifacts/:artifactId/guest/responses/:responseId",
  "hono:GET /api/v1/public/embed/artifacts/:artifactId/bootstrap",
  "hono:GET /artifacts/:artifactId",
  "hono:GET /assets/*",
  "hono:GET /auth/context",
  "hono:GET /auth/local",
  "hono:GET /embed/artifacts/:artifactId",
  "hono:GET /embed/signed-in",
  "hono:GET /health",
  "hono:GET /projects",
  "hono:GET /projects/:projectId/artifacts",
  "hono:GET /projects/:projectId/artifacts/:artifactId",
  "hono:GET /projects/:projectId/artifacts/:artifactId/versions/:versionId/review",
  "hono:GET /ready",
  "hono:GET /review",
  "hono:GET /review-frame",
  "hono:GET /review/*",
  "hono:GET /workbench",
  "hono:HEAD /",
  "hono:HEAD /administration/api-keys",
  "hono:HEAD /administration/members",
  "hono:HEAD /administration/public-links",
  "hono:HEAD /api/v1/artifacts/:artifactId/versions/:versionId/archive",
  "hono:HEAD /api/v1/artifacts/:artifactId/versions/:versionId/media",
  "hono:HEAD /assets/*",
  "hono:HEAD /embed/artifacts/:artifactId",
  "hono:HEAD /projects",
  "hono:HEAD /projects/:projectId/artifacts",
  "hono:HEAD /projects/:projectId/artifacts/:artifactId",
  "hono:HEAD /projects/:projectId/artifacts/:artifactId/versions/:versionId/review",
  "hono:HEAD /review",
  "hono:HEAD /review-frame",
  "hono:HEAD /review/*",
  "hono:HEAD /workbench",
  "hono:PATCH /api/v1/artifacts/:artifactId/access",
  "hono:PATCH /api/v1/artifacts/:artifactId/comments/:threadId",
  "hono:PATCH /api/v1/artifacts/:artifactId/comments/:threadId/replies/:replyId",
  "hono:PATCH /api/v1/artifacts/:artifactId/tags",
  "hono:PATCH /api/v1/projects/:projectId",
  "hono:PATCH /api/v1/public/artifacts/:artifactId/guest/comments/:threadId",
  "hono:PATCH /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies/:replyId",
  "hono:POST /api/v1/administration/public-links/make-private",
  "hono:POST /api/v1/agent-dispatches",
  "hono:POST /api/v1/agent-dispatches/:dispatchId/cancel",
  "hono:POST /api/v1/agent-dispatches/:dispatchId/delivered",
  "hono:POST /api/v1/agent-dispatches/:dispatchId/failed",
  "hono:POST /api/v1/agents",
  "hono:POST /api/v1/agents/:agentId/activity",
  "hono:POST /api/v1/agents/:agentId/claims",
  "hono:POST /api/v1/agents/:agentId/disconnect",
  "hono:POST /api/v1/api-keys",
  "hono:POST /api/v1/api-keys/:keyId/revoke",
  "hono:POST /api/v1/api-keys/:keyId/rotate",
  "hono:POST /api/v1/artifacts",
  "hono:POST /api/v1/artifacts/:artifactId/capture",
  "hono:POST /api/v1/artifacts/:artifactId/comments/:threadId/replies",
  "hono:POST /api/v1/artifacts/:artifactId/content-sessions",
  "hono:POST /api/v1/artifacts/:artifactId/guest-invitation",
  "hono:POST /api/v1/artifacts/:artifactId/live-sessions",
  "hono:POST /api/v1/artifacts/:artifactId/responses",
  "hono:POST /api/v1/artifacts/:artifactId/restore",
  "hono:POST /api/v1/artifacts/:artifactId/versions",
  "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/comments",
  "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/content-sessions",
  "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/preview-leases",
  "hono:POST /api/v1/artifacts/link",
  "hono:POST /api/v1/embed/artifacts/:artifactId/binding",
  "hono:POST /api/v1/members",
  "hono:POST /api/v1/members/:memberId/deactivate",
  "hono:POST /api/v1/projects",
  "hono:POST /api/v1/projects/:projectId/archive",
  "hono:POST /api/v1/projects/:projectId/artifacts/:artifactId/comments/clear",
  "hono:POST /api/v1/projects/:projectId/artifacts/:artifactId/history/clone-token",
  "hono:POST /api/v1/projects/:projectId/git-history/estimate",
  "hono:POST /api/v1/projects/:projectId/unarchive",
  "hono:POST /api/v1/public/artifacts/:artifactId/guest-session",
  "hono:POST /api/v1/public/artifacts/:artifactId/guest/comments",
  "hono:POST /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies",
  "hono:POST /api/v1/public/artifacts/:artifactId/guest/heartbeat",
  "hono:POST /api/v1/public/artifacts/:artifactId/guest/responses",
  "hono:POST /api/v1/session/logout",
  "hono:POST /api/v1/uploads",
  "hono:POST /api/v1/uploads/:uploadId/commit",
  "hono:POST /auth/local",
  "hono:POST /auth/local-owner",
  "hono:PUT /api/v1/artifacts/:artifactId/source",
  "hono:PUT /api/v1/artifacts/:artifactId/state/:key",
  "hono:PUT /api/v1/groups/:groupId/role",
  "hono:PUT /api/v1/mcp-uploads/:uploadId/files/:storageToken",
  "hono:PUT /api/v1/projects/:projectId/access",
  "hono:PUT /api/v1/projects/:projectId/git-history",
  "hono:PUT /api/v1/projects/:projectId/groups/:group",
  "hono:PUT /api/v1/uploads/:uploadId/files/:storageToken",
  "mcp:artifact_capabilities",
  "mcp:artifact_capture",
  "mcp:artifact_commit_upload",
  "mcp:artifact_create_upload",
  "mcp:artifact_delete",
  "mcp:artifact_diff",
  "mcp:artifact_download",
  "mcp:artifact_enable_guest_invitation",
  "mcp:artifact_get",
  "mcp:artifact_guest_invitation_sessions",
  "mcp:artifact_guest_invitation_status",
  "mcp:artifact_history_clone_token",
  "mcp:artifact_link",
  "mcp:artifact_list",
  "mcp:artifact_open",
  "mcp:artifact_relink",
  "mcp:artifact_response_list",
  "mcp:artifact_restore_version",
  "mcp:artifact_revoke_guest_invitation",
  "mcp:artifact_revoke_guest_session",
  "mcp:artifact_set_tags",
  "mcp:artifact_set_visibility",
  "mcp:artifact_state_delete",
  "mcp:artifact_state_get",
  "mcp:artifact_state_list",
  "mcp:artifact_state_set",
  "mcp:artifact_version_list",
  "mcp:comment_clear",
  "mcp:comment_create",
  "mcp:comment_delete",
  "mcp:comment_get",
  "mcp:comment_list",
  "mcp:comment_reply",
  "mcp:comment_resolve",
  "mcp:comment_update",
  "mcp:dispatch_inbox",
  "mcp:group_list",
  "mcp:group_set_role",
  "mcp:project_archive",
  "mcp:project_create",
  "mcp:project_git_history_estimate",
  "mcp:project_git_history_status",
  "mcp:project_list",
  "mcp:project_rename",
  "mcp:project_set_access",
  "mcp:project_set_git_history",
  "mcp:project_share",
  "mcp:project_sharing",
  "mcp:project_unarchive",
  "mcp:project_unshare",
] as const;

function assertCrossOrgMatrixComplete(
  registeredRoutes: readonly string[],
  registeredTools: readonly string[],
): void {
  const matrixCases = crossOrgMatrix.map(({surface, identifier}) =>
    `${surface}:${identifier}`,
  );
  const knownCases = [...matrixCases, ...pendingCrossOrgCases];
  const knownCaseSet = new Set(knownCases);
  const currentCases = new Set([
    ...registeredRoutes.map((route) => `hono:${route}`),
    ...registeredTools.map((tool) => `mcp:${tool}`),
  ]);
  expect(knownCaseSet.size).toBe(knownCases.length);
  expect(currentCases.size).toBeGreaterThan(0);
  for (const identifier of currentCases) {
    expect(knownCaseSet.has(identifier)).toBe(true);
  }
  for (const identifier of knownCaseSet) {
    expect(currentCases.has(identifier)).toBe(true);
  }
}
describe.sequential("organization tenancy security boundary", () => {
  const databaseUrl = process.env["ARTIFACT_SERVER_TEST_DATABASE_URL"];
  const endpoint = process.env["ARTIFACT_SERVER_TEST_S3_ENDPOINT"];
  const accessKey = process.env["ARTIFACT_SERVER_TEST_S3_ACCESS_KEY"];
  const secretKey = process.env["ARTIFACT_SERVER_TEST_S3_SECRET_KEY"];
  const bucket = `org-tenancy-${randomUUID().replaceAll("-", "")}`;
  const installationId = `org-tenancy-${randomUUID()}`;
  const apiTokenA = managedTestKey("org-tenancy-a");
  const apiTokenB = managedTestKey("org-tenancy-b");
  let database: PostgresDatabase;
  let s3: S3Client;
  let oidc: Awaited<ReturnType<typeof startStubOidcProvider>>;
  let router: Awaited<ReturnType<typeof startExternalStorageServer>>;
  let orgB: Awaited<ReturnType<OrganizationRegistry["create"]>>;
  let config: ExternalStorageRuntimeConfig;

  beforeAll(async () => {
    if (databaseUrl === undefined || endpoint === undefined || accessKey === undefined || secretKey === undefined) {
      throw new Error("Run this test through scripts/with-external-storage-test-providers.sh.");
    }
    oidc = await startStubOidcProvider({clientId: "org-tenancy-test"});
    s3 = new S3Client({
      credentials: {accessKeyId: accessKey, secretAccessKey: secretKey},
      endpoint,
      forcePathStyle: true,
      region,
    });
    await s3.send(new CreateBucketCommand({Bucket: bucket}));
    database = await PostgresDatabase.open({
      applicationName: "artifact-server-org-tenancy-test",
      maxConnections: 12,
      url: Redacted.make(databaseUrl),
    }, "apply");
    const registry = new OrganizationRegistry(database);
    await registry.ensureOrvex(installationId);
    const orgSlug = `team-${randomUUID().slice(0, 8)}`;
    const cliEnvironment = {
      ...process.env,
      ARTIFACT_SERVER_DATABASE_URL: databaseUrl,
      ARTIFACT_SERVER_INSTALLATION_ID: installationId,
    };
    const createResult = spawnSync(process.execPath, [
      "--import", "tsx", "src/cli/main.ts", "org", "create", orgSlug,
      "--name", "Org B",
    ], {cwd: process.cwd(), encoding: "utf8", env: cliEnvironment});
    if (createResult.status !== 0) {
      throw new Error(`org create CLI failed: ${createResult.stderr}`);
    }
    orgB = z.object({
      displayName: z.string(),
      id: z.string(),
      routeId: z.string(),
      slug: z.string(),
      status: z.enum(["active", "suspended"]),
    })
      .parse(JSON.parse(createResult.stdout));
    if (orgB.slug !== orgSlug) throw new Error("org create CLI returned the wrong slug.");
    const listResult = spawnSync(process.execPath, [
      "--import", "tsx", "src/cli/main.ts", "org", "list",
    ], {cwd: process.cwd(), encoding: "utf8", env: cliEnvironment});
    if (listResult.status !== 0) {
      throw new Error(`org list CLI failed: ${listResult.stderr}`);
    }
    const listed = z.array(z.object({slug: z.string()}))
      .parse(JSON.parse(listResult.stdout));
    if (!listed.some(({slug}) => slug === orgSlug)) {
      throw new Error("org list CLI omitted the created organization.");
    }
    const objectStorage = createS3ObjectStorageProviderFactory({
      accessKeyId: accessKey,
      bucket,
      endpoint,
      forcePathStyle: true,
      region,
      secretAccessKey: Redacted.make(secretKey),
    });
    config = {
      apiToken: Redacted.make(apiTokenA),
      applicationOrigin,
      bootstrapAdministratorEmail: adminEmail,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "content.example.net",
      databaseUrl: Redacted.make(databaseUrl),
      installationId,
      interactiveIdentityProvider: createOidcIdentityProvider({
        applicationOrigin,
        clientId: "org-tenancy-test",
        clientSecret: null,
        issuer: oidc.issuer,
        scopes: "openid email profile",
      }),
      objectStorage,
    };

    const setupB = await createOrgRuntime(orgB.id, {
      bootstrapApiToken: Redacted.make(apiTokenB),
      cookieRouteId: orgB.routeId,
    }, config, database);
    try {
      const projectResponse = await setupB.app.fetch(appRequest(
        "/api/v1/projects",
        apiTokenB,
        "POST",
        {name: "Org B project"},
      ));
      if (projectResponse.status !== 201) {
        throw new Error(`Could not create the Org B fixture project: HTTP ${projectResponse.status}.`);
      }
      const projectId = z.object({project: z.object({id: z.string()})})
        .parse(await projectResponse.json()).project.id;
      const artifactId = await publishOrgBArtifact(
        (request) => setupB.app.fetch(request),
        apiTokenB,
        projectId,
      );
      if (!artifactId.startsWith("art_")) throw new Error("The Org B fixture artifact ID is malformed.");
    } finally {
      await setupB.close();
    }
    router = await startExternalStorageServer({
      ...config,
      hostname: "127.0.0.1",
      organizationTenancy: true,
      port: 0,
    });
  }, 60_000);

  afterAll(async () => {
    await router?.close();
    await database?.close();
    s3?.destroy();
    await oidc?.stop();
  });

  test("isolates resources and runs the explicit route/tool completeness guard", async () => {
    const baseUrl = `http://${router.hostname}:${router.port}`;
    const host = {Host: "artifacts.example.com"};
    const registry = new OrganizationRegistry(database);
    const [projectRows, artifactRows] = await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const projects = yield* sql`SELECT id FROM projects
        WHERE installation_id = ${orgB.id} AND name = 'Org B project'`;
      const artifacts = yield* sql`SELECT id FROM artifacts
        WHERE installation_id = ${orgB.id} AND name = 'Org B artifact'`;
      return [projects, artifacts] as const;
    }));
    const projectId = z.object({id: z.string()}).parse(projectRows[0]).id;
    const artifactId = z.object({id: z.string()}).parse(artifactRows[0]).id;

    const project = await fetch(`${baseUrl}/o/orvex/api/v1/projects/${projectId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenA}`},
    });
    const artifact = await fetch(`${baseUrl}/o/orvex/api/v1/artifacts/${artifactId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenA}`},
    });
    expect(project.status).toBe(404);
    expect(artifact.status).toBe(404);

    const login = await fetch(`${baseUrl}/o/orvex/auth/login`, {
      headers: host,
      redirect: "manual",
    });
    expect(login.status).toBe(302);
    const handshake = login.headers.getSetCookie().find((value) =>
      value.startsWith("__Host-artifact_login-"),
    );
    const authorizationUrl = login.headers.get("location");
    if (handshake === undefined || authorizationUrl === null) {
      throw new Error("Org A login did not set its scoped handshake cookie and redirect.");
    }
    const authorization = await fetch(authorizationUrl, {redirect: "manual"});
    const callbackUrl = authorization.headers.get("location");
    if (callbackUrl === null || new URL(callbackUrl).pathname !== "/auth/callback") {
      throw new Error("Org A login callback did not use the shared callback route.");
    }
    const callback = new URL(callbackUrl);
    const session = await fetch(`${baseUrl}${callback.pathname}${callback.search}`, {
      headers: {...host, Cookie: handshake.split(";", 1)[0] ?? ""},
      redirect: "manual",
    });
    const sessionCookie = session.headers.getSetCookie().find((value) =>
      value.startsWith("__Host-artifact_session-"),
    );
    expect(session.status).toBe(303);
    if (sessionCookie === undefined) throw new Error("Org A login did not issue an org-scoped session cookie.");
    const foreignSession = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/session`, {
      headers: {...host, Cookie: sessionCookie.split(";", 1)[0] ?? ""},
    });
    expect(foreignSession.status).toBe(401);

    const mcp = await fetchWithHost(`${baseUrl}/o/${orgB.slug}/mcp`, {
      body: JSON.stringify({id: 1, jsonrpc: "2.0", method: "tools/list"}),
      headers: {
        ...host,
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${apiTokenA}`,
        "Content-Type": "application/json",
        Origin: applicationOrigin,
      },
      method: "POST",
    }, router.hostname, router.port);
    expect(mcp.status).toBe(401);

    const suspended = await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`UPDATE artifact_installations SET status = 'suspended'
        WHERE id = ${orgB.id}`;
    }));
    expect(suspended.length).toBe(0);
    const suspendedResponse = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/projects`, {
      headers: host,
    });
    const unknownResponse = await fetch(`${baseUrl}/o/no-such-org/api/v1/projects`, {
      headers: host,
    });
    const suspendedMcp = await fetch(`${baseUrl}/o/${orgB.slug}/mcp`, {headers: host});
    const suspendedReview = await fetch(`${baseUrl}/o/${orgB.slug}/review/artifact`, {headers: host});
    expect(suspendedResponse.status).toBe(404);
    expect(await suspendedResponse.text()).toBe(await unknownResponse.text());
    expect(suspendedMcp.status).toBe(404);
    expect(suspendedReview.status).toBe(404);
    await Promise.all(["/api/v1/session", "/mcp", "/review"].map(async (legacyPath) => {
      const redirect = await fetch(`${baseUrl}${legacyPath}`, {
        headers: host,
        redirect: "manual",
      });
      expect(redirect.status).toBe(308);
      expect(redirect.headers.get("location")).toBe(`/o/orvex${legacyPath}`);
    }));

    const runtime = await createOrgRuntime(orgB.id, {
      bootstrapApiToken: Redacted.make(apiTokenB),
      cookieRouteId: orgB.routeId,
    }, config, database);
    try {
      const registeredRoutes = runtime.app.routes.map(({method, path}) => `${method} ${path}`);
      const toolsResponse = await runtime.app.fetch(appRequest("/mcp", apiTokenB, "POST", {
        id: 1,
        jsonrpc: "2.0",
        method: "tools/list",
      }, {Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
      const toolNames = await mcpToolNames(toolsResponse);
      assertCrossOrgMatrixComplete(registeredRoutes, toolNames);
    } finally {
      await runtime.close();
    }
    expect(await registry.find(orgB.slug)).toMatchObject({status: "suspended"});
  }, 60_000);
});

function managedTestKey(label: string): string {
  const id = createHash("sha256").update(`id:${label}`).digest("hex").slice(0, 32);
  const secret = createHash("sha256").update(`secret:${label}`).digest("base64url");
  return `as_key_key_${id}_${secret}`;
}

type JsonValue = boolean | number | string | null | readonly JsonValue[] | JsonObject;
interface JsonObject {
  readonly [key: string]: JsonValue;
}

function appRequest(
  path: string,
  token: string,
  method: "GET" | "POST" | "PUT",
  body?: JsonObject,
  extraHeaders: Record<string, string> = {},
): Request {
  const headers = new Headers({
    Authorization: `Bearer ${token}`,
    Host: "artifacts.example.com",
    ...extraHeaders,
  });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const requestOptions: RequestInit = {headers, method};
  if (body !== undefined) requestOptions.body = JSON.stringify(body);
  return new Request(`${applicationOrigin}${path}`, requestOptions);
}

async function publishOrgBArtifact(
  appFetch: (request: Request) => Response | Promise<Response>,
  token: string,
  projectId: string,
): Promise<string> {
  const digest = createHash("sha256").update(bytes).digest("hex");
  const uploadResponse = await appFetch(appRequest("/api/v1/uploads", token, "POST", {
    entryPath: "index.html",
    files: [{mediaType: "text/html; charset=utf-8", path: "index.html", sha256: digest, size: bytes.byteLength}],
    projectId,
  }));
  expect(uploadResponse.status).toBe(201);
  const upload = z.object({
    commitUrl: z.url(),
    files: z.array(z.object({path: z.string(), uploadUrl: z.url()})),
  }).parse(await uploadResponse.json());
  const planned = upload.files[0];
  if (planned === undefined) throw new Error("Upload plan is missing its declared file.");
  const putUrl = new URL(planned.uploadUrl);
  const put = await appFetch(new Request(`${applicationOrigin}${putUrl.pathname}${putUrl.search}`, {
    body: bytes,
    headers: {Authorization: `Bearer ${token}`, Host: "artifacts.example.com"},
    method: "PUT",
  }));
  expect(put.status).toBe(200);
  const commitUrl = new URL(upload.commitUrl);
  const commit = await appFetch(appRequest(
    `${commitUrl.pathname}${commitUrl.search}`,
    token,
    "POST",
    {target: {accessSetting: "account_required", kind: "new_artifact", name: "Org B artifact"}},
    {"Idempotency-Key": "org-tenancy-b-artifact"},
  ));
  expect(commit.status).toBe(201);
  return z.object({artifact: z.object({id: z.string()})})
    .parse(await commit.json()).artifact.id;
}

async function mcpToolNames(response: Response): Promise<string[]> {
  const body = await response.text();
  const payload = response.headers.get("content-type")?.includes("text/event-stream")
    ? body.split("\n").find((line) => line.startsWith("data: "))?.slice(6) ?? "{}"
    : body;
  return z.object({result: z.object({tools: z.array(z.object({name: z.string()}))})})
    .parse(JSON.parse(payload)).result.tools.map(({name}) => name);
}

function fetchWithHost(
  url: string,
  init: RequestInit,
  hostname: string,
  port: number,
): Promise<Response> {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const body = z.string().parse(init.body);
    const request = httpRequest({
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      hostname,
      method: init.method,
      path: `${target.pathname}${target.search}`,
      port,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        const headers = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (value !== undefined) {
            for (const item of Array.isArray(value) ? value : [value]) {
              headers.append(name, item);
            }
          }
        }
        resolve(new Response(Buffer.concat(chunks), {
          headers,
          status: z.number().parse(response.statusCode),
        }));
      });
    });
    request.on("error", reject);
    request.end(body);
  });
}

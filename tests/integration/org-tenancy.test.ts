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
  {surface: "hono", matches: (path: string) => path.startsWith("/api/"), evidence: "cross-org project and artifact IDs"},
  {surface: "hono", matches: (path: string) => path === "/mcp", evidence: "cross-org API key rejection"},
  {surface: "hono", matches: (path: string) => /^\/(?:auth|login|logout)(?:\/|$)/u.test(path), evidence: "organization-scoped browser cookies"},
  {surface: "hono", matches: (path: string) => path.startsWith("/review/"), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path === "/review", evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path === "/review-frame", evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path.startsWith("/embed/"), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path === "/projects" || path.startsWith("/projects/"), evidence: "org runtime scopes project and artifact data"},
  {surface: "hono", matches: (path: string) => path.startsWith("/administration/"), evidence: "org runtime scopes administration data"},
  {surface: "hono", matches: (path: string) => path.startsWith("/artifacts/"), evidence: "org runtime scopes artifact content routes"},
  {surface: "hono", matches: (path: string) => path.startsWith("/.well-known/"), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path.startsWith("/workbench"), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path.startsWith("/assets/"), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => ["/health", "/ready", "/live"].includes(path), evidence: "suspended organization rejection"},
  {surface: "hono", matches: (path: string) => path === "/*", evidence: "suspended and unknown org 404"},
  {surface: "hono", matches: (path: string) => path === "/", evidence: "suspended organization rejection"},
  {surface: "mcp", matches: (name: string) => name.length > 0, evidence: "cross-org API key rejection"},
] as const;

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

  test("isolates resources, cookies, MCP keys, and suspended slugs; route/tool matrix stays complete", async () => {
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
      const registeredRoutes = runtime.app.routes.map(({path}) => path);
      const toolsResponse = await runtime.app.fetch(appRequest("/mcp", apiTokenB, "POST", {
        id: 1,
        jsonrpc: "2.0",
        method: "tools/list",
      }, {Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
      const toolNames = await mcpToolNames(toolsResponse);
      expect(registeredRoutes.length).toBeGreaterThan(0);
      expect(toolNames.length).toBeGreaterThan(0);
      for (const path of registeredRoutes) {
        expect(crossOrgMatrix.some((entry) => entry.surface === "hono" && entry.matches(path))).toBe(true);
      }
      for (const name of toolNames) {
        expect(crossOrgMatrix.some((entry) => entry.surface === "mcp" && entry.matches(name))).toBe(true);
      }
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

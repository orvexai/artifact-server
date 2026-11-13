import {createHash, randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {request as httpRequest} from "node:http";

import {
  CreateBucketCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {Effect, Redacted} from "effect";
import {SqlClient} from "effect/unstable/sql/SqlClient";
import {PostgresIdentityRepository} from "../../src/storage/postgres-identity-repository.js";
import {afterAll, beforeAll, describe, expect, test} from "vitest";
import {z} from "zod";

import {
  createExternalStorageRuntime,
  createOrgRuntime,
  type ExternalStorageRuntimeConfig,
} from
  "../../src/external-storage/create-external-storage-runtime.js";
import type {GroupRolePolicy} from "../../src/core/group-role-policy.js";
import {createOrganizationRouter} from
  "../../src/external-storage/create-organization-router.js";
import {
  checkExternalStorageIntegrity,
  IntegrityCheckError,
} from "../../src/lifecycle/integrity-check.js";
import {
  OrganizationRegistry,
  type OrganizationAdmissionPolicy,
} from "../../src/external-storage/organization-registry.js";
import {findDisappearedOrganizations} from
  "../../src/external-storage/organization-registry.js";
import {startExternalStorageServer} from
  "../../src/external-storage/start-external-storage-server.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import {createOidcIdentityProvider} from
  "../../src/identity/oidc-identity-provider.js";
import {WorkOsMcpBearerVerifier} from
  "../../src/identity/workos-mcp-bearer-verifier.js";
import type {ExternalMcpBearerVerifier} from
  "../../src/application/authentication.js";
import type {
  DirectoryOrganization,
  DirectoryOrganizationMember,
  OrganizationDirectory,
} from "../../src/identity/keycloak-directory.js";
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
  "hono:GET /.well-known/oauth-protected-resource/o/:organization/api",
  "hono:GET /.well-known/oauth-protected-resource/o/:organization/mcp",
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
  "hono:POST /api/v1/members/:memberId/reactivate",
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
  "mcp:member_reactivate",
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
    ...registeredRoutes.map((route) =>
      `hono:${route.replaceAll(/\/o\/[^/]+/gu, "/o/:organization")}`,
    ),
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
    oidc.claims.email = adminEmail;
    oidc.claims.emailVerified = true;
    oidc.claims.groups = ["/orvex/admin"];
    const groupRoles = {claim: "groups", seed: [{role: "administrator" as const, selector: "/orvex/admin"}]};
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
    const groupRoot = `/teams/${orgSlug}/`;
    const admissionPolicy = {
      groupRoots: [groupRoot],
      seed: [{role: "administrator" as const, selector: `${groupRoot}admins`}],
    };
    const cliEnvironment = {
      ...process.env,
      ARTIFACT_SERVER_DATABASE_URL: databaseUrl,
      ARTIFACT_SERVER_INSTALLATION_ID: installationId,
    };
    const invalidPolicyResult = spawnSync(process.execPath, [
      "--import", "tsx", "src/cli/main.ts", "org", "create", `invalid-${orgSlug}`,
      "--name", "Invalid selector",
      "--group-role-seed", JSON.stringify({
        groupRoots: [groupRoot],
        seed: [{role: "administrator", selector: "admins"}],
      }),
    ], {cwd: process.cwd(), encoding: "utf8", env: cliEnvironment});
    if (invalidPolicyResult.status === 0) {
      throw new Error("org create accepted a bare-name group selector.");
    }
    const createResult = spawnSync(process.execPath, [
      "--import", "tsx", "src/cli/main.ts", "org", "create", orgSlug,
      "--name", "Org B",
      "--group-role-seed", JSON.stringify(admissionPolicy),
    ], {cwd: process.cwd(), encoding: "utf8", env: cliEnvironment});
    if (createResult.status !== 0) {
      throw new Error(`org create CLI failed: ${createResult.stderr}`);
    }
    orgB = z.object({
      admissionPolicy: z.object({
        groupRoots: z.array(z.string()),
        seed: z.array(z.object({
          role: z.enum(["administrator", "guest", "member", "owner", "viewer"]),
          selector: z.string(),
        })),
      }).nullable(),
      displayName: z.string(),
      id: z.string(),
      keycloakId: z.string().nullable(),
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
    let testMcpVerifier!: ExternalMcpBearerVerifier;
    testMcpVerifier = {
      forApplicationResources: () => testMcpVerifier,
      forOrganization: () => testMcpVerifier,
      verify: () => Effect.succeed({
        clientId: "orgvex-service",
        expiresAt: Math.floor(Date.now() / 1_000) + 60,
        provider: "test-oidc",
        scopes: [],
        subject: "service-account",
      }),
      resolveIdentity: () => Effect.succeed({
        displayName: "service account",
        email: null,
        emailVerified: false,
        groups: ["/orvex/admin"],
        provider: "test-oidc",
        serviceAccount: true,
        subject: "service-account",
      }),
    };
    config = {
      apiToken: Redacted.make(apiTokenA),
      apiOAuthResource: {
        authorizationServers: [oidc.issuer],
        resource: `${applicationOrigin}/api`,
      },
      applicationOrigin,
      bootstrapAdministratorEmail: adminEmail,
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
      contentDomain: "content.example.net",
      databaseUrl: Redacted.make(databaseUrl),
      installationId,
      groupRolePolicy: {seed: [{role: "administrator", selector: "/orvex/admin"}]},
      externalMcpOAuthVerifier: testMcpVerifier,
      mcpOAuthResource: {
        authorizationServerMetadata: {
          authorization_endpoint: `${oidc.issuer}/authorize`,
          client_id_metadata_document_supported: true,
          code_challenge_methods_supported: ["S256"],
          grant_types_supported: ["authorization_code"],
          issuer: oidc.issuer,
          response_types_supported: ["code"],
          scopes_supported: ["openid", "email", "profile"],
          token_endpoint: `${oidc.issuer}/token`,
        },
        resource: `${applicationOrigin}/mcp`,
      },
      interactiveIdentityProvider: createOidcIdentityProvider({
        applicationOrigin,
        clientId: "org-tenancy-test",
        clientSecret: null,
        issuer: oidc.issuer,
        groupRoles,
        scopes: "openid email profile",
      }),
      objectStorage,
    };

    const setupB = await createOrgRuntime(orgB.id, {
      admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
      applicationOrigin: new URL(`/o/${orgB.slug}`, applicationOrigin).toString(),
      bootstrapApiToken: Redacted.make(apiTokenB),
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
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
        orgB.slug,
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
    expect(orgB.admissionPolicy).toMatchObject({groupRoots: [`/teams/${orgB.slug}/`]});
    const admissionRuntime = await createOrgRuntime(orgB.id, {
      admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
      applicationOrigin: `${applicationOrigin}/o/${orgB.slug}`,
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
    }, config, database);
    try {
      const loginWithGroups = async (groups: readonly string[], subject: string) => {
        oidc.claims.email = `${subject}@example.test`;
        oidc.claims.emailVerified = true;
        oidc.claims.groups = groups;
        oidc.claims.subject = subject;
        const login = await admissionRuntime.app.fetch(new Request(
          `https://artifacts.example.com/auth/login`,
          {redirect: "manual"},
        ));
        const cookieName = `__Host-artifact_login-${orgB.routeId}`;
        const cookie = login.headers.getSetCookie().find((value) => value.startsWith(`${cookieName}=`));
        const authorizationUrl = login.headers.get("location");
        if (cookie === undefined || authorizationUrl === null) {
          throw new Error("Org B login did not issue its scoped handshake.");
        }
        const authorization = await fetch(authorizationUrl, {redirect: "manual"});
        const callbackLocation = authorization.headers.get("location");
        if (callbackLocation === null) throw new Error("OIDC did not redirect to its callback.");
        const callbackUrl = new URL(callbackLocation);
        return admissionRuntime.app.fetch(new Request(
          `https://artifacts.example.com/auth/callback${callbackUrl.search}`,
          {headers: {Cookie: cookie.split(";", 1)[0] ?? ""}},
        ));
      };
      const foreignRoot = await loginWithGroups(["/orvex/admin"], "foreign-root-user");
      expect(foreignRoot.status).toBe(403);
      expect(foreignRoot.headers.getSetCookie().some((cookie) =>
        cookie.startsWith(`__Host-artifact_login-${orgB.routeId}=`) && /Max-Age=0/iu.test(cookie)
      )).toBe(true);
      const siblingRoot = await loginWithGroups(["/teams/other/admins"], "sibling-root-user");
      expect(siblingRoot.status).toBe(403);
      const admitted = await loginWithGroups([`/teams/${orgB.slug}/admins`], "org-b-admin-user");
      expect(admitted.status).toBe(303);
    } finally {
      await admissionRuntime.close();
    }
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

    const invalidRegistryId = `invalid-org-${randomUUID()}`;
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id, admission_policy
      ) VALUES (
        ${invalidRegistryId}, ${new Date().toISOString()},
        ${`invalid-${randomUUID().slice(0, 8)}`}, 'Invalid registry row',
        'active', 'badroute', ${JSON.stringify({seed: [], groupRoots: "invalid"})}::jsonb
      )`;
    }));
    const listedOrganizations = await registry.list();
    expect(listedOrganizations.some(({id}) => id === invalidRegistryId)).toBe(false);
    expect(listedOrganizations.some(({id}) => id === orgB.id)).toBe(true);

    const project = await fetch(`${baseUrl}/o/orvex/api/v1/projects/${projectId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenA}`},
    });
    const artifact = await fetch(`${baseUrl}/o/orvex/api/v1/artifacts/${artifactId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenA}`},
    });
    expect(project.status).toBe(404);
    expect(artifact.status).toBe(404);

    oidc.claims.email = adminEmail;
    oidc.claims.emailVerified = true;
    oidc.claims.groups = ["/orvex/admin"];
    oidc.claims.subject = "stub-oidc-subject-1";
    const orgBLogin = await fetch(`${baseUrl}/o/${orgB.slug}/auth/login`, {
      headers: host,
      redirect: "manual",
    });
    expect(orgBLogin.status).toBe(302);
    const orgBHandshake = orgBLogin.headers.getSetCookie().find((value) =>
      value.startsWith(`__Host-artifact_login-${orgB.routeId}=`),
    );
    const orgBAuthorizationUrl = orgBLogin.headers.get("location");
    if (orgBHandshake === undefined || orgBAuthorizationUrl === null) {
      throw new Error("Org B login did not set its scoped handshake cookie and redirect.");
    }
    const orgBAuthorization = await fetch(orgBAuthorizationUrl, {redirect: "manual"});
    const orgBCallbackUrl = orgBAuthorization.headers.get("location");
    if (orgBCallbackUrl === null || new URL(orgBCallbackUrl).pathname !== `/o/${orgB.slug}/auth/callback`) {
      throw new Error("Org B login did not use its organization callback route.");
    }
    const callbackBase = `${baseUrl}${new URL(orgBCallbackUrl).pathname}`;
    const malformedCallback = await fetchWithHost(`${callbackBase}?code=&state=`, {
      headers: host,
      method: "GET",
    }, router.hostname, router.port);
    expect(malformedCallback.status).toBe(422);
    expect((await malformedCallback.json()).error.message)
      .toBe("The request does not match the API contract.");
    expect(malformedCallback.headers.getSetCookie().some((value) =>
      value.startsWith(`__Host-artifact_login-${orgB.routeId}=`) && /Max-Age=0/u.test(value),
    )).toBe(true);
    const callbackWithoutHandshake = await fetchWithHost(
      `${callbackBase}${new URL(orgBCallbackUrl).search}`,
      {headers: host, method: "GET"},
      router.hostname,
      router.port,
    );
    expect(callbackWithoutHandshake.status).toBe(401);
    expect(callbackWithoutHandshake.headers.get("cache-control"))
      .toBe("private, no-store");
    expect(callbackWithoutHandshake.headers.getSetCookie().some((value) =>
      value.startsWith(`__Host-artifact_login-${orgB.routeId}=`) && /Max-Age=0/u.test(value),
    )).toBe(true);
    const apiAuthenticationRequired = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/session`, {
      headers: host,
    });
    expect(apiAuthenticationRequired.status).toBe(401);
    expect(apiAuthenticationRequired.headers.get("cache-control"))
      .toBe("private, no-store");
    expect(apiAuthenticationRequired.headers.get("www-authenticate"))
      .toMatch(/^Bearer resource_metadata=/u);
    const orgBLoginCallback = await fetch(`${baseUrl}${new URL(orgBCallbackUrl).pathname}${new URL(orgBCallbackUrl).search}`, {
      headers: {...host, Cookie: orgBHandshake.split(";", 1)[0] ?? ""},
      redirect: "manual",
    });
    expect(orgBLoginCallback.status).toBe(403);
    expect(orgBLoginCallback.headers.getSetCookie().some((value) =>
      value.startsWith(`__Host-artifact_login-${orgB.routeId}=`) && /Max-Age=0/u.test(value),
    )).toBe(true);
    expect(orgBLoginCallback.headers.getSetCookie().some((value) =>
      value.startsWith(`__Host-artifact_session-${orgB.routeId}=`),
    )).toBe(false);

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
      throw new Error("Orvex login did not preserve its legacy callback route.");
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
    const legacyCookieName = sessionCookie.split(";", 1)[0]?.replace("__Host-", "");
    const secureCookieOnly = await fetch(`${baseUrl}/o/orvex/api/v1/session`, {
      headers: {...host, Cookie: legacyCookieName ?? ""},
    });
    expect(secureCookieOnly.status).toBe(401);

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

    const serviceAccount = await fetchWithHost(`${baseUrl}/o/${orgB.slug}/mcp`, {
      body: JSON.stringify({id: 2, jsonrpc: "2.0", method: "tools/list"}),
      headers: {
        ...host,
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer oidc-service-account",
        "Content-Type": "application/json",
      },
      method: "POST",
    }, router.hostname, router.port);
    expect(serviceAccount.status).toBe(401);
    const orvexMcpBearer = await fetchWithHost(`${baseUrl}/o/orvex/mcp`, {
      body: JSON.stringify({id: 3, jsonrpc: "2.0", method: "tools/list"}),
      headers: {
        ...host,
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${apiTokenA}`,
        "Content-Type": "application/json",
      },
      method: "POST",
    }, router.hostname, router.port);
    expect(orvexMcpBearer.status).toBe(200);

    const resourceMetadata = await fetch(`${baseUrl}/o/${orgB.slug}/.well-known/oauth-protected-resource/o/${orgB.slug}/mcp`, {
      headers: host,
    });
    expect(resourceMetadata.status).toBe(200);
    expect((await resourceMetadata.json()).resource).toBe(`${applicationOrigin}/o/${orgB.slug}/mcp`);
    const rootResourceMetadata = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/o/${orgB.slug}/mcp`, {headers: host});
    expect(rootResourceMetadata.status).toBe(200);
    expect((await rootResourceMetadata.json()).resource).toBe(`${applicationOrigin}/o/${orgB.slug}/mcp`);
    const orvexMetadata = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`, {headers: host});
    expect(orvexMetadata.status).toBe(200);
    expect((await orvexMetadata.json()).resource).toBe(`${applicationOrigin}/mcp`);
    expect((await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {headers: host})).status).toBe(200);
    const orvexLogin = await fetchWithHost(`${baseUrl}/o/orvex/auth/login`, {
      headers: host,
      method: "GET",
    }, router.hostname, router.port);
    expect(orvexLogin.status).toBe(302);
    const loginLocation = orvexLogin.headers.get("location");
    if (loginLocation === null) throw new Error("Orvex login did not start OIDC.");
    const orvexAuthorization = await fetch(loginLocation, {redirect: "manual"});
    const callbackLocation = orvexAuthorization.headers.get("location");
    if (callbackLocation === null) throw new Error("Orvex OIDC did not return to a callback.");
    const orvexCallbackUrl = new URL(callbackLocation);
    expect(orvexCallbackUrl.pathname).toBe("/auth/callback");
    const orvexRecord = await registry.find("orvex");
    if (orvexRecord === null) throw new Error("The Orvex registry entry is missing.");
    const orvexHandshake = orvexLogin.headers.getSetCookie().find((cookie) =>
      cookie.startsWith(`__Host-artifact_login-${orvexRecord.routeId}=`)
    );
    if (orvexHandshake === undefined) throw new Error("Orvex login did not issue its handshake cookie.");
    const legacyCallback = await fetchWithHost(`${baseUrl}/auth/callback${orvexCallbackUrl.search}`, {
      headers: {...host, Cookie: orvexHandshake.split(";", 1)[0] ?? ""},
      method: "GET",
    }, router.hostname, router.port);
    expect(legacyCallback.status).toBe(303);
    expect(legacyCallback.headers.getSetCookie().some((cookie) =>
      cookie.startsWith("__Host-artifact_login-") && /Max-Age=0/iu.test(cookie)
    )).toBe(true);

    await expect(createOrgRuntime(orgB.id, {
      admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
      applicationOrigin: `${applicationOrigin}/o/${orgB.slug}`,
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
    }, {
      ...config,
      externalMcpOAuthVerifier: new WorkOsMcpBearerVerifier({
        apiKey: Redacted.make("test-workos-api-key"),
        issuer: "https://issuer.example.test",
        resource: `${applicationOrigin}/mcp`,
      }),
    }, database)).rejects.toThrow("cannot scope OAuth resources");

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
      applicationOrigin: new URL(`/o/${orgB.slug}`, applicationOrigin).toString(),
      bootstrapApiToken: Redacted.make(apiTokenB),
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
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

    // A failed lazy startup racing close must not publish its runtime after
    // closeResources has completed.
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`UPDATE artifact_installations SET status = 'active'
        WHERE id = ${orgB.id}`;
    }));
    let readinessEntered!: () => void;
    let releaseReadiness!: () => void;
    const enteredReadiness = new Promise<void>((resolve) => { readinessEntered = resolve; });
    const readinessGate = new Promise<void>((resolve) => { releaseReadiness = resolve; });
    let raceProviderCloseCount = 0;
    const raceFactory = trackedObjectStorageFactory({
      onClose: () => { raceProviderCloseCount += 1; },
      readiness: async (signal, provider) => {
        readinessEntered();
        await readinessGate;
        await provider.readiness(signal);
      },
    }, {
      accessKey: requiredIntegrationSetting(accessKey, "S3 access key"),
      bucket,
      endpoint: requiredIntegrationSetting(endpoint, "S3 endpoint"),
      secretKey: requiredIntegrationSetting(secretKey, "S3 secret key"),
    });
    const racingRouter = await createOrganizationRouter({...config, objectStorage: raceFactory});
    const racingRequest = racingRouter.fetch(new Request(
      `https://artifacts.example.com/o/${orgB.slug}/api/v1/projects`,
      {headers: {Host: "artifacts.example.com"}},
    ));
    await enteredReadiness;
    const closeDuringStartup = racingRouter.close();
    releaseReadiness();
    await closeDuringStartup;
    expect((await racingRequest).status).toBe(503);
    expect(raceProviderCloseCount).toBe(1);
    expect((await racingRouter.fetch(new Request(
      `https://artifacts.example.com/o/${orgB.slug}/api/v1/projects`,
    ))).status).toBe(503);

    // A response body keeps its runtime active until it is consumed or
    // cancelled, even when the idle timeout is zero.
    let streamProviderCloseCount = 0;
    const streamFactory = trackedObjectStorageFactory({
      onClose: () => { streamProviderCloseCount += 1; },
    }, {
      accessKey: requiredIntegrationSetting(accessKey, "S3 access key"),
      bucket,
      endpoint: requiredIntegrationSetting(endpoint, "S3 endpoint"),
      secretKey: requiredIntegrationSetting(secretKey, "S3 secret key"),
    });
    const streamingRouter = await createOrganizationRouter(
      {...config, objectStorage: streamFactory},
      {evictionIntervalMilliseconds: 5, idleMilliseconds: 0},
    );
    const streamResponse = await streamingRouter.fetch(new Request(
      `https://artifacts.example.com/o/${orgB.slug}/mcp`,
      {
        body: JSON.stringify({id: 9, jsonrpc: "2.0", method: "tools/list"}),
        headers: {
          Accept: "application/json, text/event-stream",
          Authorization: `Bearer ${apiTokenB}`,
          "Content-Type": "application/json",
          Host: "artifacts.example.com",
          Origin: applicationOrigin,
        },
        method: "POST",
      },
    ));
    expect(streamResponse.status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(streamProviderCloseCount).toBe(0);
    await streamResponse.body?.cancel();
    await waitFor(() => streamProviderCloseCount === 1);
    await streamingRouter.close();

    // Maintenance runtimes share the same composition path but never seed
    // the configured bootstrap API key. Closing this non-router runtime must
    // close both its provider and its factory.
    let maintenanceProviderCloseCount = 0;
    let maintenanceFactoryCloseCount = 0;
    const maintenanceFactory = trackedObjectStorageFactory({
      onClose: () => { maintenanceProviderCloseCount += 1; },
      onFactoryClose: () => { maintenanceFactoryCloseCount += 1; },
    }, {
      accessKey: requiredIntegrationSetting(accessKey, "S3 access key"),
      bucket,
      endpoint: requiredIntegrationSetting(endpoint, "S3 endpoint"),
      secretKey: requiredIntegrationSetting(secretKey, "S3 secret key"),
    });
    const maintenanceRuntime = await createExternalStorageRuntime({
      ...config,
      bootstrapApiTokenEnabled: false,
      installationId: `maintenance-${randomUUID()}`,
      objectStorage: maintenanceFactory,
    });
    try {
      const bootstrapKey = await maintenanceRuntime.app.fetch(appRequest(
        "/api/v1/projects",
        apiTokenA,
        "GET",
      ));
      expect(bootstrapKey.status).toBe(401);
    } finally {
      await maintenanceRuntime.close();
    }
    expect(maintenanceProviderCloseCount).toBe(1);
    expect(maintenanceFactoryCloseCount).toBe(1);

    let failedFactoryCloseCount = 0;
    const constructionFailure: ExternalStorageRuntimeConfig["objectStorage"] = {
      close: async () => { failedFactoryCloseCount += 1; },
      create: () => { throw new Error("provider constructor failed"); },
      kind: "s3",
    };
    await expect(checkExternalStorageIntegrity({
      databaseUrl: config.databaseUrl,
      installationId: orgB.id,
      objectStorage: constructionFailure,
    })).rejects.toBeInstanceOf(IntegrityCheckError);
    expect(failedFactoryCloseCount).toBe(1);
  }, 60_000);

  test("an org member removal deactivates only that installation's member", async () => {
    const registry = new OrganizationRegistry(database);
    const aliasA = `org-a-${randomUUID().slice(0, 8)}`;
    const aliasB = `org-b-${randomUUID().slice(0, 8)}`;
    const idA = randomUUID();
    const idB = randomUUID();
    const orgAResult = await registry.syncKeycloakOrganization(aliasA, "Org A", idA);
    const orgBResult = await registry.syncKeycloakOrganization(aliasB, "Org B", idB);
    if (orgAResult.kind !== "synced" || orgBResult.kind !== "synced") {
      throw new Error("New Keycloak organizations were not registered.");
    }
    const orgA = orgAResult.organization;
    const orgBRecord = orgBResult.organization;
    const organizationA: DirectoryOrganization = {alias: aliasA, id: idA, name: "Org A"};
    const organizationB: DirectoryOrganization = {alias: aliasB, id: idB, name: "Org B"};
    const usersA = [
      {id: "owner-a", username: "owner-a", email: "owner-a@example.test", emailVerified: true, enabled: true, firstName: null, lastName: null, role: "owner" as const},
      {id: "owner-a-two", username: "owner-a-two", email: "owner-a-two@example.test", emailVerified: true, enabled: true, firstName: null, lastName: null, role: "owner" as const},
      {id: "editor-a", username: "editor-a", email: "editor-a@example.test", emailVerified: true, enabled: true, firstName: null, lastName: null, role: "editor" as const},
    ];
    const usersB = [
      {id: "owner-b", username: "owner-b", email: "owner-b@example.test", emailVerified: true, enabled: true, firstName: null, lastName: null, role: "owner" as const},
      {id: "editor-b", username: "editor-b", email: "editor-b@example.test", emailVerified: true, enabled: true, firstName: null, lastName: null, role: "editor" as const},
    ];
    let snapshotA: readonly DirectoryOrganizationMember[] = usersA;
    const directory: OrganizationDirectory = {
      listOrganizations: () => Effect.succeed([organizationA, organizationB]),
      listOrganizationMembers: (organization) =>
        Effect.succeed(organization.id === idA ? snapshotA : usersB),
    };
    const openOrgRuntime = (record: typeof orgA) =>
      createOrgRuntime(record.id, {
        cookieRouteId: record.routeId,
        keycloakOrganizationId: record.keycloakId,
        slug: record.slug,
      }, config, database);
    const runtimeA = await openOrgRuntime(orgA);
    const runtimeB = await openOrgRuntime(orgBRecord);
    try {
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      await runtimeB.syncOrganizationMembers(directory, organizationB);
      const roleLogin = async (
        email: string,
        subject: string,
        groups: readonly string[],
      ) => {
        oidc.claims.email = email;
        oidc.claims.emailVerified = true;
        oidc.claims.identityProvider = "google";
        oidc.claims.organization = {[aliasA]: {id: idA, groups}};
        oidc.claims.subject = subject;
        const baseUrl = `http://${router.hostname}:${router.port}`;
        const login = await startRoutedOidcLogin(baseUrl, aliasA);
        const response = await fetch(login.callbackUrl, {
          headers: {Cookie: login.handshakeCookie},
          redirect: "manual",
        });
        return response;
      };
      const editorLogin = await roleLogin(
        "editor-a@example.test", "editor-a", ["/editor"],
      );
      expect(editorLogin.status).toBe(303);
      const promotedLogin = await roleLogin(
        "editor-a@example.test", "editor-a", ["/owner"],
      );
      expect(promotedLogin.status).toBe(303);
      let editorRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT role FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'editor-a@example.test'`;
      }));
      expect(editorRows[0]?.["role"]).toBe("owner");
      const demotedLogin = await roleLogin(
        "editor-a@example.test", "editor-a", ["/editor"],
      );
      expect(demotedLogin.status).toBe(303);
      editorRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT role FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'editor-a@example.test'`;
      }));
      expect(editorRows[0]?.["role"]).toBe("member");
      const ownerA = usersA.at(0);
      const secondOwnerA = usersA.at(1);
      if (ownerA === undefined || secondOwnerA === undefined) throw new Error("The Org A owner fixtures are missing.");
      snapshotA = [ownerA, secondOwnerA];
      const removed = await runtimeA.syncOrganizationMembers(directory, organizationA);
      if ("kind" in removed) {
        throw new Error("Org A's non-empty snapshot was skipped.");
      }
      expect(removed.deactivated).toBe(1);
      const rows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT installation_id, email, status FROM installation_members
          WHERE email IN ('editor-a@example.test', 'editor-b@example.test')`;
      }));
      expect(rows).toEqual(expect.arrayContaining([
        expect.objectContaining({installation_id: orgA.id, email: "editor-a@example.test", status: "inactive"}),
        expect.objectContaining({installation_id: orgBRecord.id, email: "editor-b@example.test", status: "active"}),
      ]));
      const reactivatedLogin = await roleLogin(
        "editor-a@example.test", "editor-a", ["/editor"],
      );
      expect(reactivatedLogin.status).toBe(303);
      const reactivatedRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT status FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'editor-a@example.test'`;
      }));
      expect(reactivatedRows[0]?.["status"]).toBe("active");
      const memberRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id FROM installation_members
          WHERE installation_id = ${orgA.id}
            AND email IN ('owner-a@example.test', 'owner-a-two@example.test')`;
      }));
      const ownerRepo = new PostgresIdentityRepository(database, orgA.id);
      const ownerIds = z.array(z.string()).parse(memberRows.map((row) => row["id"]));
      expect(ownerIds).toHaveLength(2);
      const secondOwnerRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'owner-a-two@example.test'`;
      }));
      const secondOwnerId = z.string().parse(secondOwnerRows[0]?.["id"]);
      await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`UPDATE installation_members SET status = 'inactive',
          manual_deactivation = TRUE WHERE installation_id = ${orgA.id} AND id = ${secondOwnerId}`;
      }));
      snapshotA = [
        {...ownerA, role: "editor" as const},
        {...secondOwnerA, role: "owner" as const},
      ];
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      const protectedOwner = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT role FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'owner-a@example.test'`;
      }));
      expect(protectedOwner[0]?.["role"]).toBe("owner");
      await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        yield* sql`UPDATE installation_members SET status = 'active',
          manual_deactivation = FALSE WHERE installation_id = ${orgA.id} AND id = ${secondOwnerId}`;
      }));
      snapshotA = usersA;
      await Promise.all(ownerIds.map((memberId) => ownerRepo.setOrganizationMemberRole(
        orgA.id, memberId, "member", new Date().toISOString(),
      )));
      const remainingOwners = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_members
          WHERE installation_id = ${orgA.id} AND status = 'active' AND role = 'owner'`;
      }));
      expect(remainingOwners[0]?.["count"]).toBe(1);
      const editorRow = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'editor-a@example.test'`;
      }));
      const editorId = z.string().parse(editorRow[0]?.["id"]);
      snapshotA = usersA;
      oidc.claims.email = "owner-a@example.test";
      oidc.claims.emailVerified = true;
      oidc.claims.identityProvider = "google";
      oidc.claims.subject = "owner-a";
      oidc.claims.organization = {
        [aliasA]: {id: idA, groups: ["/owner"]},
      };
      const baseUrl = `http://${router.hostname}:${router.port}`;
      const loginA = await startRoutedOidcLogin(baseUrl, aliasA);
      expect(new URLSearchParams(loginA.authorizationUrl.search).get("scope"))
        .toContain("organization:*");
      const completedA = await fetch(loginA.callbackUrl, {
        headers: {Cookie: loginA.handshakeCookie},
        redirect: "manual",
      });
      expect(completedA.status).toBe(303);
      const cookieA = completedA.headers.getSetCookie()
        .map((value) => value.split(";", 1)[0])
        .filter((value): value is string => value !== undefined)
        .join("; ");
      const sessionA = await fetch(`${baseUrl}/o/${aliasA}/api/v1/session`, {
        headers: {Cookie: cookieA, Host: "artifacts.example.com"},
      });
      expect(sessionA.status).toBe(200);
      const csrfPair = cookieA.split("; ").find((pair) =>
        pair.slice(0, pair.indexOf("=")).toLowerCase().includes("csrf"),
      );
      const csrfCookie = csrfPair?.slice(csrfPair.indexOf("=") + 1);
      if (csrfCookie === undefined) throw new Error("The org session has no CSRF cookie.");
      const deactivated = await fetch(`${baseUrl}/o/${aliasA}/api/v1/members/${editorId}/deactivate`, {
        method: "POST",
        headers: {
          Cookie: cookieA,
          Host: "artifacts.example.com",
          Origin: "https://artifacts.example.com",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfCookie,
        },
        body: "{}",
      });
      expect(deactivated.status).toBe(200);
      const manualRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT status, manual_deactivation FROM installation_members
          WHERE installation_id = ${orgA.id} AND id = ${editorId}`;
      }));
      expect(manualRows[0]).toMatchObject({status: "inactive", manual_deactivation: true});
      const manuallyDeactivatedLogin = await roleLogin(
        "editor-a@example.test", "editor-a", ["/owner"],
      );
      expect(manuallyDeactivatedLogin.status).toBe(403);
      const activeManualSessions = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM application_sessions
          WHERE installation_id = ${orgA.id} AND member_id = ${editorId}
            AND revoked_at IS NULL`;
      }));
      expect(activeManualSessions[0]?.["count"]).toBe(0);
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      const stillManualRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT status, manual_deactivation FROM installation_members
          WHERE installation_id = ${orgA.id} AND id = ${editorId}`;
      }));
      expect(stillManualRows[0]).toMatchObject({status: "inactive", manual_deactivation: true});
      const reactivated = await fetch(`${baseUrl}/o/${aliasA}/api/v1/members/${editorId}/reactivate`, {
        method: "POST",
        headers: {
          Cookie: cookieA,
          Host: "artifacts.example.com",
          Origin: "https://artifacts.example.com",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfCookie,
        },
        body: "{}",
      });
      expect(reactivated.status).toBe(200);
      const reactivatedManualRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT status, manual_deactivation FROM installation_members
          WHERE installation_id = ${orgA.id} AND id = ${editorId}`;
      }));
      expect(reactivatedManualRows[0]).toMatchObject({status: "active", manual_deactivation: false});
      const loginB = await startRoutedOidcLogin(baseUrl, aliasB);
      const completedB = await fetch(loginB.callbackUrl, {
        headers: {Cookie: loginB.handshakeCookie},
        redirect: "manual",
      });
      expect(completedB.status).not.toBe(303);
      const identityRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT identity_provider FROM external_identities
          WHERE installation_id = ${orgA.id} AND email = 'owner-a@example.test'`;
      }));
      expect(identityRows[0]?.["identity_provider"]).toBe("google");
      // The discovered organizations remain registered even when omitted from
      // a later complete Keycloak organization listing.
      expect((await registry.list()).map(({id}) => id)).toContain(orgA.id);
      const registryRows = await registry.list();
      expect(findDisappearedOrganizations(registryRows, [organizationB]))
        .toContainEqual({alias: aliasA, id: idA});
      expect(await registry.find(aliasA)).toMatchObject({keycloakId: idA});
      expect(await registry.syncKeycloakOrganization("orvex", "Takeover", randomUUID()))
        .toMatchObject({kind: "conflict"});
      const unbound = await registry.create(`manual-${randomUUID().slice(0, 8)}`, "Manual org");
      expect(await registry.syncKeycloakOrganization(unbound.slug, "Manual org", randomUUID()))
        .toMatchObject({kind: "conflict"});
      const linked = await registry.linkKeycloakOrganization(unbound.slug, randomUUID());
      const linkedId = linked.keycloakId;
      if (linkedId === null) throw new Error("The deliberate organization link was not stored.");
      expect(await registry.syncKeycloakOrganization(unbound.slug, "Renamed", linkedId))
        .toMatchObject({kind: "synced", organization: {id: unbound.id}});
      expect(await registry.syncKeycloakOrganization(unbound.slug, "Recreated", randomUUID()))
        .toMatchObject({kind: "conflict"});
      expect(await registry.syncKeycloakOrganization(`${unbound.slug}-renamed`, "Alias rename", linkedId))
        .toMatchObject({kind: "conflict"});
      await expect(registry.syncKeycloakOrganization("Invalid Slug", "Invalid", randomUUID()))
        .rejects.toThrow(/slug/u);
      const manuallyDeactivatedAgain = await fetch(`${baseUrl}/o/${aliasA}/api/v1/members/${editorId}/deactivate`, {
        method: "POST",
        headers: {
          Cookie: cookieA,
          Host: "artifacts.example.com",
          Origin: "https://artifacts.example.com",
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfCookie,
        },
        body: "{}",
      });
      expect(manuallyDeactivatedAgain.status).toBe(200);
      snapshotA = [];
      expect(await runtimeA.syncOrganizationMembers(directory, organizationA))
        .toMatchObject({kind: "emptied"});
      expect(await registry.suspend(aliasA)).toMatchObject({status: "suspended"});
      const suspendedRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_members
          WHERE installation_id = ${orgA.id} AND suspended_by_org_at IS NOT NULL
            AND status = 'inactive' AND manual_deactivation = TRUE`;
      }));
      const allOrgMembers = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_members
          WHERE installation_id = ${orgA.id}`;
      }));
      expect(suspendedRows[0]?.["count"]).toBe(allOrgMembers[0]?.["count"]);
      snapshotA = usersA;
      await expect(runtimeA.syncOrganizationMembers(directory, organizationA))
        .rejects.toThrow("suspended organization installation");
      expect(await registry.resume(aliasA)).toMatchObject({status: "active"});
      const resumedEditor = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT status, manual_deactivation, suspended_by_org_at
          FROM installation_members WHERE installation_id = ${orgA.id} AND id = ${editorId}`;
      }));
      expect(resumedEditor[0]).toMatchObject({
        status: "inactive", manual_deactivation: true, suspended_by_org_at: null,
      });
    } finally {
      await Promise.all([runtimeA.close(), runtimeB.close()]);
    }
  }, 60_000);
});

function trackedObjectStorageFactory(
  hooks: {
    readonly onClose: () => void;
    readonly onFactoryClose?: () => void;
    readonly readiness?: (
      signal: AbortSignal,
      provider: ReturnType<ExternalStorageRuntimeConfig["objectStorage"]["create"]>,
    ) => Promise<void>;
  },
  settings: {
    readonly accessKey: string;
    readonly bucket: string;
    readonly endpoint: string;
    readonly secretKey: string;
  },
): ExternalStorageRuntimeConfig["objectStorage"] {
  const factory = createS3ObjectStorageProviderFactory({
    accessKeyId: settings.accessKey,
    bucket: settings.bucket,
    endpoint: settings.endpoint,
    forcePathStyle: true,
    region,
    secretAccessKey: Redacted.make(settings.secretKey),
  });
  return {
    close: async () => {
      hooks.onFactoryClose?.();
      await factory.close?.();
    },
    create: (id) => {
      const provider = factory.create(id);
      return {
        ...provider,
        close: async () => {
          hooks.onClose();
          await provider.close();
        },
        readiness: (signal) => hooks.readiness === undefined
          ? provider.readiness(signal)
          : hooks.readiness(signal, provider),
      };
    },
    kind: factory.kind,
  };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1_000;
  await new Promise<void>((resolve, reject) => {
    const poll = () => {
      if (predicate()) {
        resolve();
      } else if (Date.now() >= deadline) {
        reject(new Error("Timed out waiting for organization runtime eviction."));
      } else {
        setTimeout(poll, 5);
      }
    };
    poll();
  });
}

function requiredIntegrationSetting(value: string | undefined, name: string): string {
  if (value === undefined) throw new Error(`Missing integration setting: ${name}.`);
  return value;
}

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
  orgSlug: string,
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
  const appPath = (url: URL) => url.pathname.replace(`/o/${orgSlug}`, "");
  const put = await appFetch(new Request(`${applicationOrigin}${appPath(putUrl)}${putUrl.search}`, {
    body: bytes,
    headers: {Authorization: `Bearer ${token}`, Host: "artifacts.example.com"},
    method: "PUT",
  }));
  expect(put.status, `${putUrl.pathname}: ${await put.clone().text()}`).toBe(200);
  const commitUrl = new URL(upload.commitUrl);
  const commit = await appFetch(appRequest(
    `${appPath(commitUrl)}${commitUrl.search}`,
    token,
    "POST",
    {target: {accessSetting: "account_required", kind: "new_artifact", name: "Org B artifact"}},
    {"Idempotency-Key": "org-tenancy-b-artifact"},
  ));
  expect(commit.status).toBe(201);
  return z.object({artifact: z.object({id: z.string()})})
    .parse(await commit.json()).artifact.id;
}

function runtimeAdmissionPolicy(
  policy: OrganizationAdmissionPolicy | null,
): GroupRolePolicy | null {
  if (policy === null) return null;
  const groupRolePolicy = {
    groupRoots: policy.groupRoots,
    seed: policy.seed,
  };
  if (policy.guestGroupPrefixes === undefined) return groupRolePolicy;
  return {...groupRolePolicy, guestGroupPrefixes: policy.guestGroupPrefixes};
}

async function startRoutedOidcLogin(baseUrl: string, slug: string) {
  const loginResponse = await fetch(`${baseUrl}/o/${slug}/auth/login`, {
    headers: {Host: "artifacts.example.com"},
    redirect: "manual",
  });
  const authorization = loginResponse.headers.get("location");
  if (authorization === null) {
    throw new Error(`Organization login answered HTTP ${loginResponse.status} without a redirect.`);
  }
  const authorizationUrl = new URL(authorization);
  const authorizationResponse = await fetch(authorizationUrl, {redirect: "manual"});
  const callback = authorizationResponse.headers.get("location");
  if (callback === null) {
    throw new Error(`Stub authorization answered HTTP ${authorizationResponse.status} without a callback.`);
  }
  const callbackUrl = new URL(callback);
  callbackUrl.host = new URL(baseUrl).host;
  callbackUrl.protocol = new URL(baseUrl).protocol;
  return {
    authorizationUrl,
    callbackUrl,
    handshakeCookie: routedLoginHandshakeCookie(loginResponse),
  };
}

function routedLoginHandshakeCookie(response: Response): string {
  const cookie = response.headers.getSetCookie().find((value) =>
    /^(?:__Host-)?artifact_login(?:-|=)/u.test(value),
  );
  if (cookie === undefined) throw new Error("Organization login did not set its handshake cookie.");
  return cookie.split(";", 1)[0] ?? "";
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
    const body = init.body === undefined ? undefined : z.string().parse(init.body);
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

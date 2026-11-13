import {createHash, randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {request as httpRequest} from "node:http";

import {
  CreateBucketCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
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
import {principalCapabilities} from "../../src/core/identity.js";
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
import {PlatformSessions} from
  "../../src/external-storage/platform-sessions.js";
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
import {DirectoryUnavailable} from "../../src/application/directory-sync.js";
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
  {surface: "platform", identifier: "GET /api/v1/platform/me/orgs", coverage: "shared platform session lists only verified memberships"},
  {surface: "platform", identifier: "POST /api/v1/platform/session/last-org", coverage: "last-org accepts only a current membership"},
  {surface: "platform", identifier: "POST /api/v1/platform/session/logout", coverage: "logout deletes the shared platform session and expires its cookie"},
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
    ...registeredRoutes.map((route) =>
      `hono:${route.replaceAll(/\/o\/[^/]+/gu, "/o/:organization")}`,
    ),
    "platform:GET /api/v1/platform/me/orgs",
    "platform:POST /api/v1/platform/session/last-org",
    "platform:POST /api/v1/platform/session/logout",
    ...registeredTools.map((tool) => `mcp:${tool}`),
  ]);
  expect(knownCaseSet.size).toBe(knownCases.length);
  expect(currentCases.size).toBeGreaterThan(0);
  for (const identifier of currentCases) {
    expect(knownCaseSet.has(identifier)).toBe(true);
  }
  for (const identifier of knownCaseSet) {
    if (!currentCases.has(identifier)) throw new Error(`Cross-org matrix case is no longer registered: ${identifier}`);
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
  let orgC: Awaited<ReturnType<OrganizationRegistry["create"]>>;
  let platformMemberships: {displayName: string; role: string; slug: string}[];
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
      seed: [
        {role: "administrator" as const, selector: `${groupRoot}admins`},
        {role: "member" as const, selector: `${groupRoot}editors`},
        {role: "viewer" as const, selector: `${groupRoot}viewers`},
        {role: "administrator" as const, selector: `${groupRoot}support`, staff: true},
      ],
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
          staff: z.boolean().optional(),
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
    orgC = await registry.create(`team-${randomUUID().slice(0, 8)}`, "Org C");
    platformMemberships = [
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: "Unregistered", role: "owner", slug: "not-a-member"},
    ];
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
      organizationMemberships: {forIdentity: async () => platformMemberships},
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

  test("platform membership discovery and single-org landing stay scoped", async () => {
    const identity = {
      displayName: "Platform member",
      email: null,
      emailVerified: false,
      groups: [],
      provider: "test-oidc",
      subject: "platform-member",
    };
    let membershipReads = 0;
    let claimMemberships = [
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: "Unregistered", role: "owner", slug: "not-a-member"},
    ];
    const sessions = new PlatformSessions(database, {forIdentity: async () => {
      membershipReads += 1;
      return claimMemberships;
    }});
    let token = await sessions.issue(identity);
    const refreshed = await sessions.find(token);
    expect(refreshed?.organizations).toEqual([
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: "Unregistered", role: "owner", slug: "not-a-member"},
    ]);
    expect(membershipReads).toBe(1);
    expect(await sessions.find(token)).not.toBeNull();
    expect(membershipReads).toBe(1);
    const priorToken = token;
    claimMemberships = [
      {displayName: "Org C", role: "editor", slug: orgC.slug},
    ];
    token = await sessions.issue(identity, priorToken);
    expect(token).not.toBe(priorToken);
    expect(await sessions.find(priorToken)).toBeNull();
    expect((await sessions.find(token))?.organizations).toEqual(claimMemberships);
    const sameSubjectToken = token;
    token = await sessions.issue({...identity, subject: "different-subject"}, sameSubjectToken);
    expect(token).not.toBe(sameSubjectToken);
    expect(await sessions.find(sameSubjectToken)).toBeNull();
    expect((await sessions.find(token))?.organizations).toEqual(claimMemberships);
    const baseUrl = `http://${router.hostname}:${router.port}`;
    const cookie = `__Host-artifact_platform=${token}`;
    platformMemberships = [];
    const orgs = await fetch(`${baseUrl}/api/v1/platform/me/orgs`, {headers: {Cookie: cookie}});
    expect(orgs.status).toBe(200);
    expect(await orgs.json()).toEqual([]);
    const noOrgLanding = await fetch(`${baseUrl}/`, {headers: {Cookie: cookie}});
    expect(await noOrgLanding.text()).toContain("You don't belong to any organization yet.");
    platformMemberships = [
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: "Unregistered", role: "owner", slug: "not-a-member"},
    ];
    const memberOrgs = await fetch(`${baseUrl}/api/v1/platform/me/orgs`, {headers: {Cookie: cookie}});
    expect(await memberOrgs.json()).toEqual([{displayName: "Org B", role: "viewer", slug: orgB.slug}]);
    const memberLanding = await fetch(`${baseUrl}/`, {headers: {Cookie: cookie}, redirect: "manual"});
    expect(memberLanding.status).toBe(302);
    expect(memberLanding.headers.get("location")).toBe(`/o/${orgB.slug}/`);
    const unknown = await fetch(`${baseUrl}/api/v1/platform/me/orgs`);
    expect(unknown.status).toBe(404);
    const lastOrg = await fetch(`${baseUrl}/api/v1/platform/session/last-org`, {
      body: JSON.stringify({slug: orgC.slug}),
      headers: {Cookie: cookie, "Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Site": "same-origin"},
      method: "POST",
    });
    expect(lastOrg.status).toBe(404);

    const platformLogin = await fetch(`${baseUrl}/`, {redirect: "manual"});
    expect(platformLogin.headers.get("location")).toBe("/auth/platform/login?returnTo=%2F");

    const multiOrgSessions = new PlatformSessions(database, {forIdentity: async () => [
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: orgC.displayName, role: "editor", slug: orgC.slug},
    ]});
    const multiOrgToken = await multiOrgSessions.issue(identity);
    platformMemberships = [
      {displayName: "Org B", role: "viewer", slug: orgB.slug},
      {displayName: orgC.displayName, role: "editor", slug: orgC.slug},
    ];
    expect(await sessions.find(token)).not.toBeNull();
    const chooser = await fetch(`${baseUrl}/`, {
      headers: {Cookie: `__Host-artifact_platform=${multiOrgToken}`},
    });
    expect(chooser.status).toBe(200);
    expect(await chooser.text()).toContain("Choose an organization");
    expect(await sessions.find(token)).not.toBeNull();
    const logout = await fetch(`${baseUrl}/api/v1/platform/session/logout`, {
      headers: {Cookie: `__Host-artifact_platform=${multiOrgToken}`, Origin: applicationOrigin, "Sec-Fetch-Site": "same-origin"}, method: "POST",
    });
    expect(logout.status).toBe(204);
    expect(logout.headers.get("set-cookie")).toContain("SameSite=Lax");
    expect(await multiOrgSessions.find(multiOrgToken)).toBeNull();

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
      assertCrossOrgMatrixComplete(registeredRoutes, await mcpToolNames(toolsResponse));
    } finally {
      await runtime.close();
    }
  });

  test("Orvex under the tenancy router matches standalone projections and permissions", async () => {
    const baseUrl = `http://${router.hostname}:${router.port}`;
    const standalone = await createOrgRuntime(installationId, {
      bootstrapApiToken: Redacted.make(apiTokenA),
      cookieRouteId: "",
    }, config, database);
    const projectResponse = await standalone.app.fetch(appRequest(
      "/api/v1/projects", apiTokenA, "POST", {name: `Orvex compatibility ${randomUUID()}`},
    ));
    expect(projectResponse.status).toBe(201);
    const projectId = z.object({project: z.object({id: z.string()})})
      .parse(await projectResponse.json()).project.id;
    const artifactId = await publishOrgBArtifact(
      (request) => standalone.app.fetch(request), apiTokenA, projectId, "orvex",
    );
    const versionRows = await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`SELECT current_version_id AS "versionId" FROM artifacts WHERE id = ${artifactId}`;
    }));
    const versionId = z.object({versionId: z.string()}).parse(versionRows[0]).versionId;
    const commentResponse = await standalone.app.fetch(appRequest(
      `/api/v1/artifacts/${artifactId}/versions/${versionId}/comments?projectId=${projectId}`,
      apiTokenA,
      "POST",
      {body: "Orvex dispatch compatibility"},
      {"Idempotency-Key": `orvex-compat-comment-${randomUUID()}`},
    ));
    expect(commentResponse.status).toBe(201);
    const threadId = z.object({thread: z.object({id: z.string()})})
      .parse(await commentResponse.json()).thread.id;
    const agentResponse = await standalone.app.fetch(appRequest(
      "/api/v1/agents", apiTokenA, "POST", {
        displayName: "Orvex compatibility agent",
        kind: "worker",
        workingDirectory: "/tmp/orvex-compatibility",
      },
    ));
    expect(agentResponse.status).toBe(200);
    const agentId = z.object({agent: z.object({id: z.string()})})
      .parse(await agentResponse.json()).agent.id;
    const dispatchCreate = await standalone.app.fetch(appRequest(
      "/api/v1/agent-dispatches", apiTokenA, "POST", {
        agentId,
        projectId,
        threadIds: [threadId],
      }, {"Idempotency-Key": `orvex-compat-dispatch-${randomUUID()}`},
    ));
    expect(dispatchCreate.status).toBe(201);
    const compareRoute = async (path: string, method: "GET" | "POST" | "PUT", body?: JsonObject) => {
      const standaloneResponse = await standalone.app.fetch(appRequest(path, apiTokenA, method, body));
      const routedHeaders = new Headers({
        Authorization: `Bearer ${apiTokenA}`,
        Host: "artifacts.example.com",
      });
      if (body !== undefined) {
        routedHeaders.set("Content-Type", "application/json");
        routedHeaders.set("Origin", applicationOrigin);
        routedHeaders.set("Sec-Fetch-Site", "same-origin");
      }
      const requestInit: RequestInit = {
        headers: routedHeaders,
        method,
      };
      if (body !== undefined) requestInit.body = JSON.stringify(body);
      const routedResponse = await fetchWithHost(`${baseUrl}/o/orvex${path}`, requestInit, router.hostname, router.port);
      const [standaloneBody, routedBody] = await Promise.all([
        standaloneResponse.json(), routedResponse.json(),
      ]);
      expect(routedResponse.status).toBe(standaloneResponse.status);
      expect(routedBody).toEqual(standaloneBody);
      return {body: routedBody, status: routedResponse.status};
    };
    try {
      const session = await compareRoute("/api/v1/session", "GET");
      expect(session.status).toBe(200);
      expect(session.body).not.toHaveProperty("principal.staff");
      expect(session.body).not.toHaveProperty("principal.tenantStaffPrincipalIds");

      const groupRole = await compareRoute("/api/v1/groups/not-a-real-group/role", "PUT", {role: "viewer"});
      expect(groupRole.status).toBe(403);

      const guestResponses = await compareRoute(`/api/v1/public/artifacts/${artifactId}/guest/responses`, "GET");
      expect(guestResponses.status).toBe(404);
      const guestResponsePost = await compareRoute(
        `/api/v1/public/artifacts/${artifactId}/guest/responses`, "POST",
        {choice: "yes", questionId: "orvex-compat-question", versionId},
      );
      expect(guestResponsePost.status).toBe(404);

      const dispatches = await compareRoute(`/api/v1/agent-dispatches?projectId=${projectId}`, "GET");
      expect(dispatches.status).toBe(200);
      expect(JSON.stringify(dispatches.body)).toContain("sender");
      expect(JSON.stringify(dispatches.body)).not.toContain('"email":null');
      expect(JSON.stringify(dispatches.body)).not.toContain("Orvex Support");
      const dispatchMcpBody: JsonObject = {
        id: `orvex-dispatch-inbox-${randomUUID()}`,
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "orvex-compatibility", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
          },
          arguments: {agentName: agentId, operation: "list"},
          name: "dispatch_inbox",
        },
      };
      const mcpHeaders = {
        Accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "dispatch_inbox",
        Origin: applicationOrigin,
      };
      const standaloneMcp = await standalone.app.fetch(appRequest("/mcp", apiTokenA, "POST", dispatchMcpBody, mcpHeaders));
      const routedMcp = await fetchWithHost(`${baseUrl}/o/orvex/mcp`, {
        body: JSON.stringify(dispatchMcpBody),
        headers: {...mcpHeaders, Authorization: `Bearer ${apiTokenA}`, "Content-Type": "application/json", Host: "artifacts.example.com"},
        method: "POST",
      }, router.hostname, router.port);
      expect(routedMcp.status).toBe(standaloneMcp.status);
      expect(await routedMcp.json()).toEqual(await standaloneMcp.json());
    } finally {
      await standalone.close();
    }
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
        oidc.claims.name = subject === "tenant-support-user" ? "Private Tenant Support Identity" : "Stub Administrator";
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

      const staffLogin = await loginWithGroups([`/teams/${orgB.slug}/support`], "tenant-support-user");
      expect(staffLogin.status).toBe(303);
      const staffCookies = staffLogin.headers.getSetCookie();
      const staffCookieHeader = staffCookies.map((cookie) => cookie.split(";", 1)[0]).join("; ");
      const csrfCookie = staffCookies.find((cookie) => cookie.startsWith(`__Host-artifact_csrf-${orgB.routeId}=`));
      if (csrfCookie === undefined) throw new Error("Staff login did not issue its CSRF cookie.");
      const csrfToken = csrfCookie.split(";", 1)[0]?.split("=", 2)[1];
      if (csrfToken === undefined) throw new Error("Staff login issued an invalid CSRF cookie.");

      const staffProjectResponse = await admissionRuntime.app.fetch(new Request("https://artifacts.example.com/api/v1/projects", {
        body: JSON.stringify({name: "Staff authored project"}),
        headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
          "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
        method: "POST",
      }));
      expect(staffProjectResponse.status).toBe(201);
      const staffProjectId = z.object({project: z.object({id: z.string()})}).parse(await staffProjectResponse.json()).project.id;
      const staffArtifactId = await publishOrgBArtifactWithSession(
        (request) => admissionRuntime.app.fetch(request), staffCookieHeader, csrfToken,
        staffProjectId, orgB.slug, "Staff authored artifact",
      );
      const artifactRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT current_version_id AS "versionId" FROM artifacts
          WHERE installation_id = ${orgB.id} AND id = ${staffArtifactId}`;
      }));
      const staffArtifact = {id: staffArtifactId};
      let staffVersionId = z.object({versionId: z.string()}).parse(artifactRows?.[0]).versionId;
      const firstVersionId = staffVersionId;
      await publishOrgBArtifactWithSession((request) => admissionRuntime.app.fetch(request),
        staffCookieHeader, csrfToken, staffProjectId, orgB.slug, "Staff authored second version",
        {artifactId: staffArtifact.id, expectedCurrentVersionId: firstVersionId});
      const secondVersionRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT current_version_id AS "versionId" FROM artifacts
          WHERE installation_id = ${orgB.id} AND id = ${staffArtifact.id}`;
      }));
      const secondVersionId = z.object({versionId: z.string()}).parse(secondVersionRows?.[0]).versionId;
      const restored = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/restore?projectId=${staffProjectId}`,
        {body: JSON.stringify({expectedCurrentVersionId: secondVersionId, versionId: firstVersionId}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
            Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST"},
      ));
      expect(restored.status).toBe(200);
      staffVersionId = z.object({version: z.object({id: z.string()})}).parse(await restored.json()).version.id;
      const installVisibleProject = await admissionRuntime.app.fetch(appRequest(
        `/api/v1/projects/${staffProjectId}/access`, apiTokenB, "PUT", {accessMode: "installation"},
      ));
      expect(installVisibleProject.status).toBe(200);
      const staffMembers = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/members`, {headers: {Cookie: staffCookieHeader}},
      ));
      expect(staffMembers.status).toBe(200);
      expect(await staffMembers.text()).not.toContain("tenant-support-user@example.test");
      const createComment = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/versions/${staffVersionId}/comments?projectId=${staffProjectId}`,
        {body: JSON.stringify({body: "Support authored comment"}), headers: {
          Cookie: staffCookieHeader,
          "Content-Type": "application/json",
          "Idempotency-Key": randomUUID(),
          Origin: applicationOrigin,
          "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin",
          "X-CSRF-Token": csrfToken,
        }, method: "POST"},
      ));
      expect(createComment.status).toBe(201);
      const staffThread = z.object({thread: z.object({id: z.string()})}).passthrough().parse(await createComment.json()).thread;
      const createResponse = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/responses?projectId=${staffProjectId}`,
        {body: JSON.stringify({choice: "approve", questionId: "staff-authored-question", versionId: staffVersionId}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
            "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken}, method: "POST"},
      ));
      expect(createResponse.status).toBe(201);
      const staffResponseId = z.object({id: z.string()}).passthrough().parse(await createResponse.json()).id;
      const stateWrite = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/state/staff-authored?projectId=${staffProjectId}`,
        {body: JSON.stringify({value: {privatePayload: "staff state fixture"}}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
            "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken}, method: "PUT"},
      ));
      expect(stateWrite.status).toBe(200);

      const staffAgentName = `staff-support-${randomUUID()}`;
      const staffAgentResponse = await admissionRuntime.app.fetch(new Request(
        "https://artifacts.example.com/api/v1/agents", {
          body: JSON.stringify({
            agentSessionId: "private-agent-session",
            connectionKey: "private-agent-connection-key",
            displayName: staffAgentName,
            kind: "mcp-mailbox",
            workingDirectory: "/private/support/worktree",
          }),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
            "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST",
        },
      ));
      expect(staffAgentResponse.status).toBe(200);
      const staffAgentId = z.object({agent: z.object({id: z.string()})})
        .parse(await staffAgentResponse.json()).agent.id;
      const staffDispatchResponse = await admissionRuntime.app.fetch(new Request(
        "https://artifacts.example.com/api/v1/agent-dispatches", {
          body: JSON.stringify({agentId: staffAgentId, note: "Staff authored dispatch", projectId: staffProjectId, threadIds: [staffThread.id]}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
            Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST",
        },
      ));
      expect(staffDispatchResponse.status).toBe(201);
      const staffDispatchId = z.object({dispatch: z.object({id: z.string()})})
        .parse(await staffDispatchResponse.json()).dispatch.id;
      const guestInvitationResponse = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/guest-invitation?projectId=${staffProjectId}`,
        {body: "{}", headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
          "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken}, method: "POST"},
      ));
      expect(guestInvitationResponse.status).toBe(201);
      const guestInvitationUrl = z.object({url: z.url()}).parse(await guestInvitationResponse.json()).url;
      const guestSecret = new URLSearchParams(new URL(guestInvitationUrl).hash.slice(1)).get("invite");
      if (guestSecret === null) throw new Error("The tenant guest invitation did not include a link secret.");
      const reservedGuestResponse = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/public/artifacts/${staffArtifact.id}/guest-session`,
        {body: JSON.stringify({displayName: "օrvex սupport", secret: guestSecret}),
          headers: {"Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Site": "same-origin"}, method: "POST"},
      ));
      expect(reservedGuestResponse.status).toBe(201);
      expect(await reservedGuestResponse.clone().text()).toContain("Orvex Support (member)");
      const tenantGuestSessions = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/guest-invitation/sessions?projectId=${staffProjectId}`,
        {headers: {Cookie: staffCookieHeader}},
      ));
      expect(tenantGuestSessions.status).toBe(200);
      expect(await tenantGuestSessions.text()).toContain("Orvex Support (member)");

      const staffMemberRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id, email, display_name AS "displayName" FROM installation_members
          WHERE installation_id = ${orgB.id} AND email = 'tenant-support-user@example.test'`;
      }));
      const staffMember = z.object({displayName: z.string(), email: z.string(), id: z.string()}).parse(staffMemberRows[0]);

      type RouteWalkerActor = {readonly csrf: string; readonly cookie: string; readonly memberId: string; readonly token?: string};
      const roleGroups = [["admin", "admins"], ["editor", "editors"], ["viewer", "viewers"]] as const;
      const actorEntries = await roleGroups.reduce<Promise<Array<[string, RouteWalkerActor]>>>(
        async (previous, [role, group]) => {
          const entries = await previous;
          const login = await loginWithGroups([`/teams/${orgB.slug}/${group}`], `route-walker-${role}`);
          expect(login.status).toBe(303);
          const cookieParts = login.headers.getSetCookie();
          const cookieHeader = cookieParts.map((value) => value.split(";", 1)[0]).join("; ");
          const actorCsrfCookie = cookieParts.find((value) => value.startsWith(`__Host-artifact_csrf-${orgB.routeId}=`));
          if (actorCsrfCookie === undefined) throw new Error(`${role} login did not issue a CSRF cookie.`);
          const csrf = actorCsrfCookie.split(";", 1)[0]?.split("=", 2)[1];
          if (csrf === undefined) throw new Error(`${role} login issued an invalid CSRF cookie.`);
          const sessionResponse = await admissionRuntime.app.fetch(new Request(
            "https://artifacts.example.com/api/v1/session", {headers: {Cookie: cookieHeader}},
          ));
          const sessionPrincipal = z.object({principal: z.object({id: z.string()}).passthrough()}).parse(await sessionResponse.json()).principal;
          return [...entries, [role, {csrf, cookie: cookieHeader, memberId: sessionPrincipal.id}]];
        },
        Promise.resolve([]),
      );
      const actorCookies = new Map<string, RouteWalkerActor>(actorEntries);
      const adminActor = actorCookies.get("admin");
      if (adminActor === undefined) throw new Error("The route walker has no administrator session.");
      const issuedActorKeys = await Promise.all([...actorCookies].map(async ([role, actor]) => {
        const keyResponse = await admissionRuntime.app.fetch(new Request("https://artifacts.example.com/api/v1/api-keys", {
          body: JSON.stringify({
            capabilities: [
              principalCapabilities.connectAgents, principalCapabilities.createArtifact,
              principalCapabilities.issueContentSession, principalCapabilities.manageAnyArtifact,
              principalCapabilities.manageProjects, principalCapabilities.publishAnyArtifact,
              principalCapabilities.readArtifacts, principalCapabilities.readArtifactResponses,
              principalCapabilities.writeComments,
            ],
            expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            memberId: actor.memberId,
            name: `route-walker-${role}`,
          }),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
            "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST",
        }));
        expect(keyResponse.status).toBe(201);
        const token = z.object({token: z.string()}).parse(await keyResponse.json()).token;
        return [role, {...actor, token}] as const;
      }));
      for (const [role, actor] of issuedActorKeys) actorCookies.set(role, actor);
      const mcpActorTokens = new Map<string, string>([...actorCookies].flatMap(([role, actor]) => actor.token === undefined ? [] : [[role, actor.token] as const]));

      const routeInventory = admissionRuntime.app.routes.map(({method, path}) => `${method} ${path}`);
      const toolInventoryResponse = await admissionRuntime.app.fetch(appRequest("/mcp", apiTokenB, "POST", {
        id: "route-walker-tools", jsonrpc: "2.0", method: "tools/list",
      }, {Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
      const toolDefinitions = await mcpToolDefinitions(toolInventoryResponse);
      const toolInventory = toolDefinitions.map(({name}) => name);
      assertCrossOrgMatrixComplete(routeInventory, toolInventory);

      const staffSecrets = [staffMember.displayName, staffMember.email, staffMember.id];
      const routeParam = (name: string, readOnly: boolean): string => {
        if (!readOnly) return `missing-${name}-${randomUUID()}`;
        switch (name) {
          case "artifactId": return staffArtifact.id;
          case "projectId": return staffProjectId;
          case "threadId": return staffThread.id;
          case "responseId": return staffResponseId;
          case "dispatchId": return staffDispatchId;
          case "versionId": return staffVersionId;
          default: return `missing-${name}`;
        }
      };
      const orderedRoutes = [...routeInventory].toSorted((left, right) =>
        Number(left.endsWith("/session/logout")) - Number(right.endsWith("/session/logout"))
      );
      // The generic walker bodies intentionally exercise both successful reads
      // and documented validation/authorization/not-found outcomes. No route
      // may fail with a server error, and each role must reach successful data.
      const expectedHttpStatuses = {
        GET: [200, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 409, 410, 415, 422],
        HEAD: [200, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 415, 422],
        POST: [200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 409, 410, 422],
        PUT: [200, 201, 204, 400, 401, 403, 404, 405, 409, 410, 422],
        PATCH: [200, 204, 400, 401, 403, 404, 405, 409, 410, 422],
        DELETE: [200, 202, 204, 400, 401, 403, 404, 405, 409, 410, 422],
      } as const satisfies Readonly<Record<string, readonly number[]>>;
      const actorScans = await Promise.all([...actorCookies].map(async ([role, actor]) => {
        const routeResponses = await Promise.all(orderedRoutes.map(async (route) => {
            const [rawMethod, rawPath] = route.split(" ", 2);
            if (rawMethod === undefined || rawPath === undefined) throw new Error(`Invalid route inventory entry: ${route}`);
            const method = rawMethod === "ALL" ? "GET" : rawMethod;
            const readOnly = method === "GET" || method === "HEAD";
            const path = rawPath.replace(/:([A-Za-z][A-Za-z0-9_]*)/gu, (_match, name: string) => routeParam(name, readOnly)).replace(/\/\*/gu, "/route-walker");
            const url = new URL(path, "https://artifacts.example.com");
            if (path.includes("artifact") || path.includes("project") || path.includes("agent-dispatches")) url.searchParams.set("projectId", staffProjectId);
            if (path.includes("/compare")) {
              url.searchParams.set("fromVersionId", firstVersionId);
              url.searchParams.set("toVersionId", staffVersionId);
            }
            if (path.includes("/media") || path.includes("embed")) url.searchParams.set("path", "index.html");
            const headers = new Headers({Cookie: actor.cookie});
            if (!readOnly) {
              headers.set("Content-Type", "application/json");
              headers.set("Origin", applicationOrigin);
              headers.set("Sec-Fetch-Site", "same-origin");
              headers.set("X-CSRF-Token", actor.csrf);
            }
            const requestInit: RequestInit = {headers, method};
            if (!readOnly) requestInit.body = "{}";
            const response = await admissionRuntime.app.fetch(new Request(url, requestInit));
            const body = await response.text();
            assertNoStaffIdentity(body, staffSecrets);
            // SAFETY: method is normalized from the live route inventory, and the table explicitly covers each registered HTTP verb.
            const acceptedStatuses = expectedHttpStatuses[method as keyof typeof expectedHttpStatuses];
            expect(acceptedStatuses).toContain(response.status);
            return {route, status: response.status};
        }));
        expect(routeResponses).toHaveLength(orderedRoutes.length);
        expect(routeResponses.filter(({status}) => status >= 200 && status < 300).length, `${role} HTTP routes must include successful results`).toBeGreaterThanOrEqual(2);
        const agents = await admissionRuntime.app.fetch(new Request("https://artifacts.example.com/api/v1/agents", {
          headers: {Cookie: actor.cookie},
        }));
        expect(agents.status).toBe(200);
        const listedAgents = z.object({items: z.array(z.object({
          agentSessionId: z.string().nullable(), connectionKey: z.string().nullable(), displayName: z.string(),
          id: z.string(), principalId: z.string().nullable(), workingDirectory: z.string().nullable(),
        }).passthrough())}).parse(await agents.json()).items;
        expect(listedAgents).toContainEqual(expect.objectContaining({
          agentSessionId: null, connectionKey: null, displayName: "Orvex Support", id: staffAgentId,
          principalId: null, workingDirectory: null,
        }));
        const dispatch = await admissionRuntime.app.fetch(new Request(
          `https://artifacts.example.com/api/v1/agent-dispatches/${staffDispatchId}?projectId=${staffProjectId}`,
          {headers: {Cookie: actor.cookie}},
        ));
        expect(dispatch.status).toBe(200);
        const dispatchBody = await dispatch.text();
        assertNoStaffIdentity(dispatchBody, staffSecrets);
        expect(dispatchBody).toContain("Orvex Support");

        const token = mcpActorTokens.get(role);
        if (token === undefined) throw new Error(`The route walker has no ${role} MCP credential.`);
        const toolResponses = await Promise.all(toolDefinitions.map(async (tool) => {
          const argumentsValue = tool.name === "dispatch_inbox"
            ? {agentName: staffAgentName, operation: "list"}
            : tool.readOnly ? safeMcpReadArguments(tool.inputSchema, staffArtifact.id, staffProjectId, staffVersionId, staffThread.id)
            : {};
          const response = await admissionRuntime.app.fetch(appRequest("/mcp", token, "POST", {
            id: `route-walker-${role}-${tool.name}`, jsonrpc: "2.0", method: "tools/call", params: {
              _meta: {
                [CLIENT_CAPABILITIES_META_KEY]: {},
                [CLIENT_INFO_META_KEY]: {name: "tenant-route-walker", version: "1"},
                [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
              },
              arguments: argumentsValue,
              name: tool.name,
            },
          }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": tool.name, Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
          const responseBody = await response.text();
          assertNoStaffIdentity(responseBody, staffSecrets);
          expect(response.status, `${role} MCP tool ${tool.name}`).toBe(200);
          return response.status;
        }));
        expect(toolResponses).toHaveLength(toolDefinitions.length);
        expect(toolResponses.filter((status) => status >= 200 && status < 300).length, `${role} MCP tools must include successful results`).toBeGreaterThanOrEqual(2);
        return {role, routes: routeResponses.length, tools: toolResponses.length};
      }));
      expect(actorScans).toHaveLength(3);

      const staffMcpRuntime = await createOrgRuntime(orgB.id, {
        admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
        applicationOrigin: `${applicationOrigin}/o/${orgB.slug}`,
        bootstrapApiToken: Redacted.make(apiTokenB),
        cookieRouteId: orgB.routeId,
        slug: orgB.slug,
      }, config, database);
      try {
        const mcpCommentList = await staffMcpRuntime.app.fetch(appRequest("/mcp", apiTokenB, "POST", {
          id: 1, jsonrpc: "2.0", method: "tools/call", params: {
            name: "comment_get", arguments: {artifactId: staffArtifact.id, projectId: staffProjectId, threadId: staffThread.id},
            _meta: {
              [CLIENT_CAPABILITIES_META_KEY]: {},
              [CLIENT_INFO_META_KEY]: {name: "artifact-server-test", version: "1"},
              [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
            },
          },
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "comment_get", Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
        expect(mcpCommentList.status).toBe(200);
        const mcpText = await mcpCommentList.text();
        expect(mcpText).toContain("Orvex Support");
        expect(mcpText).not.toContain("tenant-support-user@example.test");
      } finally {
        await staffMcpRuntime.close();
      }
      const orgSessionCookie = staffCookies.find((cookie) => cookie.startsWith(`__Host-artifact_session-${orgB.routeId}=`));
      if (orgSessionCookie === undefined) throw new Error("Staff login did not issue its organization session cookie.");
      const platformLogout = await fetch(`http://${router.hostname}:${router.port}/api/v1/platform/session/logout`, {
        headers: {Cookie: staffCookieHeader, Origin: applicationOrigin, "Sec-Fetch-Site": "same-origin"},
        method: "POST",
      });
      expect(platformLogout.status).toBe(204);
      const endedOrgSession = await fetchWithHost(`http://${router.hostname}:${router.port}/o/${orgB.slug}/api/v1/session`, {
        headers: {Cookie: orgSessionCookie.split(";", 1)[0] ?? "", Host: "artifacts.example.com"},
      }, router.hostname, router.port);
      expect(endedOrgSession.status).toBe(401);
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
      const editorIdRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id FROM installation_members
          WHERE installation_id = ${orgA.id} AND email = 'editor-a@example.test'`;
      }));
      const editorId = z.string().parse(editorIdRows[0]?.["id"]);
      await expect(new PostgresIdentityRepository(database, orgA.id).reactivateMember(orgA.id, editorId))
        .rejects.toThrow("Only a manually deactivated organization member");
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
      snapshotA = [ownerA];
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      await expect(ownerRepo.reactivateMember(orgA.id, secondOwnerId))
        .rejects.toThrow("Only a manually deactivated organization member");
      const ownerAfterRejectedReactivation = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT role, status FROM installation_members
          WHERE installation_id = ${orgA.id} AND id = ${secondOwnerId}`;
      }));
      expect(ownerAfterRejectedReactivation[0]).toMatchObject({role: "owner", status: "inactive"});
      const activeOwnerCountAfterRejectedReactivation = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_members
          WHERE installation_id = ${orgA.id} AND status = 'active' AND role = 'owner'`;
      }));
      expect(activeOwnerCountAfterRejectedReactivation[0]?.["count"]).toBe(1);
      snapshotA = usersA;
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      await Promise.all(ownerIds.map((memberId) => ownerRepo.setOrganizationMemberRole(
        orgA.id, memberId, "member", new Date().toISOString(),
      )));
      const remainingOwners = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_members
          WHERE installation_id = ${orgA.id} AND status = 'active' AND role = 'owner'`;
      }));
      expect(remainingOwners[0]?.["count"]).toBe(1);
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
      const editorBIdRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT id FROM installation_members
          WHERE installation_id = ${orgBRecord.id} AND email = 'editor-b@example.test'`;
      }));
      const editorBId = z.string().parse(editorBIdRows[0]?.["id"]);
      const crossOrgReactivation = await fetch(
        `${baseUrl}/o/${aliasA}/api/v1/members/${editorBId}/reactivate`,
        {method: "POST", headers: {
          Cookie: cookieA, Host: "artifacts.example.com",
          Origin: "https://artifacts.example.com", "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json",
          "X-CSRF-Token": csrfCookie,
        }, body: "{}"},
      );
      expect(crossOrgReactivation.status).toBe(404);

      const viewerLogin = await roleLogin("editor-a@example.test", "editor-a", ["/viewer"]);
      expect(viewerLogin.status).toBe(303);
      const viewerCookie = viewerLogin.headers.getSetCookie()
        .map((value) => value.split(";", 1)[0])
        .filter((value): value is string => value !== undefined)
        .join("; ");
      const viewerCsrfPair = viewerCookie.split("; ").find((pair) =>
        pair.slice(0, pair.indexOf("=")).toLowerCase().includes("csrf"),
      );
      const viewerCsrf = viewerCsrfPair?.slice(viewerCsrfPair.indexOf("=") + 1);
      if (viewerCsrf === undefined) throw new Error("The viewer session has no CSRF cookie.");
      const viewerReactivation = await fetch(
        `${baseUrl}/o/${aliasA}/api/v1/members/${editorId}/reactivate`,
        {method: "POST", headers: {
          Cookie: viewerCookie, Host: "artifacts.example.com",
          Origin: "https://artifacts.example.com", "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json",
          "X-CSRF-Token": viewerCsrf,
        }, body: "{}"},
      );
      expect(viewerReactivation.status).toBe(403);
      expect((await roleLogin("editor-a@example.test", "editor-a", ["/editor"])).status).toBe(303);

      const rejectedServicePrincipals = await Promise.all(["oidc-service-account", "oidc-provisioner"]
        .map(async (bearer) => fetchWithHost(`${baseUrl}/o/${aliasA}/mcp`, {
          body: JSON.stringify({
            id: 20, jsonrpc: "2.0", method: "tools/call",
            params: {name: "member_reactivate", arguments: {memberId: editorId}},
          }),
          headers: {
            Accept: "application/json, text/event-stream", Authorization: `Bearer ${bearer}`,
            "Content-Type": "application/json", Host: "artifacts.example.com",
          },
          method: "POST",
        }, router.hostname, router.port)));
      expect(rejectedServicePrincipals.map(({status}) => status)).toEqual([401, 401]);
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
      expect(reactivatedManualRows[0]).toMatchObject({status: "inactive", manual_deactivation: false});
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
      snapshotA = usersA.map((user) => user.id === "owner-a-two"
        ? {...user, role: "editor" as const}
        : user);
      await runtimeA.syncOrganizationMembers(directory, organizationA);
      snapshotA = [];
      expect(await runtimeA.syncOrganizationMembers(directory, organizationA))
        .toMatchObject({kind: "emptied"});
      expect(await registry.suspend(aliasA)).toMatchObject({status: "suspended"});
      await expect(ownerRepo.reactivateMember(orgA.id, editorId))
        .rejects.toThrow("Only a manually deactivated organization member");
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
      const resumedSync = await runtimeA.syncOrganizationMembers(directory, organizationA);
      expect(resumedSync).toMatchObject({roleChanged: 1});
      const resumedOwner = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT role, status FROM installation_members
          WHERE installation_id = ${orgA.id} AND id = ${secondOwnerId}`;
      }));
      expect(resumedOwner[0]).toMatchObject({role: "owner", status: "active"});

      const failingDirectory: OrganizationDirectory = {
        listOrganizations: directory.listOrganizations,
        listOrganizationMembers: () => Effect.fail(new DirectoryUnavailable({
          message: "The Keycloak organization member read failed.",
        })),
      };
      await expect(runtimeA.syncOrganizationMembers(failingDirectory, organizationA))
        .rejects.toThrow("Keycloak organization member read failed");
      expect(await registry.find(aliasA)).toMatchObject({status: "active"});
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

async function publishOrgBArtifactWithSession(
  appFetch: (request: Request) => Response | Promise<Response>,
  cookie: string,
  csrf: string,
  projectId: string,
  orgSlug: string,
  name: string,
  existing?: {readonly artifactId: string; readonly expectedCurrentVersionId: string},
): Promise<string> {
  const content = new TextEncoder().encode(`<!doctype html><title>${name}</title>`);
  const digest = createHash("sha256").update(content).digest("hex");
  const headers = {Cookie: cookie, "Content-Type": "application/json", Origin: applicationOrigin,
    "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf};
  const uploadResponse = await appFetch(new Request(`${applicationOrigin}/api/v1/uploads`, {
    body: JSON.stringify({entryPath: "index.html", files: [{mediaType: "text/html; charset=utf-8",
      path: "index.html", sha256: digest, size: content.byteLength}], projectId}),
    headers, method: "POST",
  }));
  expect(uploadResponse.status).toBe(201);
  const upload = z.object({commitUrl: z.url(), files: z.array(z.object({uploadUrl: z.url()}))})
    .parse(await uploadResponse.json());
  const planned = upload.files[0];
  if (planned === undefined) throw new Error("Session upload plan is missing its file.");
  const appPath = (url: URL) => url.pathname.replace(`/o/${orgSlug}`, "");
  const putUrl = new URL(planned.uploadUrl);
  const put = await appFetch(new Request(`${applicationOrigin}${appPath(putUrl)}${putUrl.search}`, {
    body: content,
    headers: {Cookie: cookie, Host: "artifacts.example.com", Origin: applicationOrigin,
      "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf},
    method: "PUT",
  }));
  expect(put.status).toBe(200);
  const commitUrl = new URL(upload.commitUrl);
  const commit = await appFetch(new Request(`${applicationOrigin}${appPath(commitUrl)}${commitUrl.search}`, {
    body: JSON.stringify({target: existing === undefined
      ? {accessSetting: "account_required", kind: "new_artifact", name, tags: []}
      : {kind: "new_version", artifactId: existing.artifactId,
        expectedCurrentVersionId: existing.expectedCurrentVersionId}}),
    headers: {...headers, "Idempotency-Key": randomUUID()}, method: "POST",
  }));
  expect(commit.status).toBe(201);
  return z.object({artifact: z.object({id: z.string()})}).parse(await commit.json()).artifact.id;
}

function runtimeAdmissionPolicy(
  policy: OrganizationAdmissionPolicy | null,
): GroupRolePolicy | null {
  if (policy === null) return null;
  const groupRolePolicy = {
    groupRoots: policy.groupRoots,
    seed: policy.seed.map(({role, selector, staff}) =>
      staff === undefined ? {role, selector} : {role, selector, staff}
    ),
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

interface McpToolDefinition {
  readonly inputSchema: McpInputSchema;
  readonly name: string;
  readonly readOnly: boolean;
}

interface McpInputSchema {
  readonly properties?: Readonly<Record<string, McpInputProperty>>;
}

interface McpInputProperty {
  readonly anyOf?: readonly {readonly type?: string | undefined}[] | undefined;
  readonly enum?: readonly string[] | undefined;
  readonly type?: string | readonly string[] | undefined;
}

interface McpArgumentMap {
  readonly [name: string]: JsonValue;
}

async function mcpToolDefinitions(response: Response): Promise<McpToolDefinition[]> {
  const body = await response.text();
  const payload = response.headers.get("content-type")?.includes("text/event-stream")
    ? body.split("\n").find((line) => line.startsWith("data: "))?.slice(6) ?? "{}"
    : body;
  const propertySchema = z.object({
    anyOf: z.array(z.object({type: z.string().optional()}).passthrough()).optional(),
    enum: z.array(z.string()).optional(),
    type: z.union([z.string(), z.array(z.string())]).optional(),
  }).passthrough();
  const tools = z.object({result: z.object({tools: z.array(z.object({
    annotations: z.object({readOnlyHint: z.boolean().optional()}).passthrough().optional(),
    inputSchema: z.object({properties: z.record(z.string(), propertySchema).optional()}).passthrough(),
    name: z.string(),
  }).passthrough())})}).parse(JSON.parse(payload)).result.tools;
  return tools.map(({annotations, inputSchema, name}) => ({
    inputSchema: {...inputSchema, properties: inputSchema.properties ?? {}},
    name,
    readOnly: annotations?.readOnlyHint === true,
  }));
}

async function mcpToolNames(response: Response): Promise<string[]> {
  return (await mcpToolDefinitions(response)).map(({name}) => name);
}

function safeMcpReadArguments(inputSchema: McpInputSchema, artifactId: string, projectId: string, versionId: string, threadId: string): McpArgumentMap {
  const argumentsValue: McpArgumentMap = {};
  for (const [name, property] of Object.entries(inputSchema.properties ?? {})) {
    if (property.enum !== undefined && property.enum.length > 0) {
      Object.assign(argumentsValue, {[name]: property.enum[0]});
    } else if (name === "artifactId") Object.assign(argumentsValue, {[name]: artifactId});
    else if (name === "projectId") Object.assign(argumentsValue, {[name]: projectId});
    else if (name === "versionId") Object.assign(argumentsValue, {[name]: versionId});
    else if (name === "threadId") Object.assign(argumentsValue, {[name]: threadId});
    else if (property.anyOf?.some(({type}) => type === "null")) Object.assign(argumentsValue, {[name]: null});
    else if (property.type === "integer" || property.type === "number") Object.assign(argumentsValue, {[name]: 1});
    else if (property.type === "boolean") Object.assign(argumentsValue, {[name]: false});
    else if (property.type === "array") Object.assign(argumentsValue, {[name]: []});
    else if (property.type === "object") Object.assign(argumentsValue, {[name]: {}});
    else if (property.type === "string") Object.assign(argumentsValue, {[name]: "route-walker"});
  }
  return argumentsValue;
}

function assertNoStaffIdentity(responseBody: string, staffSecrets: readonly string[]): void {
  for (const secret of staffSecrets) expect(responseBody).not.toContain(secret);
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

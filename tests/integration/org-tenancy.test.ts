import {createHash, createHmac, randomUUID} from "node:crypto";
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
import {staffMemberOpaqueId} from "../../src/application/installation-access.js";
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
import {defaultGitHistoryFileCopyBytes, defaultGitHistoryVersionCopyBytes} from
  "../../src/git-history/git-history-capability.js";
import type {NodeGitHistoryConfiguration} from
  "../../src/git-history/node-git-history-configuration.js";
import type {GitHistoryProviderHealthProbe} from
  "../../src/git-history/git-history-provider-health.js";
import {RecordingGitHistoryProvider} from "../support/git-history-provider.js";
import {gitHistoryMetadataFiles} from "../../src/git-history/git-history-mirror.js";
import {isLiveContentToken, liveContentToken} from
  "../../src/application/linked-artifacts.js";
import type {ExternalMcpBearerVerifier} from
  "../../src/application/authentication.js";
import {startStubOidcProvider} from "../support/stub-oidc-provider.js";
import {createS3ObjectStorageProviderFactory} from
  "../../src/storage/s3-object-storage.js";
import {PostgresDatabase} from "../../src/storage/postgres-database.js";
import type {NodeGitHistoryConfiguration} from "../../src/git-history/node-git-history-configuration.js";
import type {GitHistoryProviderHealthProbe} from "../../src/git-history/git-history-provider-health.js";
import {RecordingGitHistoryProvider} from "../support/git-history-provider.js";

const region = "us-east-1";
const applicationOrigin = "https://artifacts.example.com";
const embedBindingSecret = "org-tenancy-test-embed-binding-secret-with-32-bytes-minimum";
const orgTenancyGitProvider = new RecordingGitHistoryProvider();
const orgTenancyGitHistory: NodeGitHistoryConfiguration = {
  _tag: "CloudflareArtifactsRest",
  apiToken: Redacted.make("org-tenancy-test-git-provider-token"),
  capability: {
    limits: {
      fileCopyBytes: 10 * 1024 * 1024,
      logicalCopiedBytes: 0,
      logicalReservedBytes: 0,
      storageBudgetBytes: null,
      versionCopyBytes: 50 * 1024 * 1024,
    },
    provider: "cloudflare-artifacts",
    providerState: "checking",
  },
  identity: {
    accountId: "org-tenancy-account",
    namespace: "org-tenancy-test",
    provider: "cloudflare-artifacts",
  },
  issues: [],
};
const orgTenancyGitHistoryProbe: GitHistoryProviderHealthProbe = {
  check: () => Effect.succeed({state: "available"}),
};
const adminEmail = "administrator@example.test";
const bytes = new TextEncoder().encode("org B private artifact");
const crossOrgMatrix = [
  {surface: "hono", identifier: "ALL /*", coverage: "organization router dispatches into an installation-scoped Hono app"},
  {surface: "hono", identifier: "ALL /api/*", coverage: "cross-org project and artifact identifiers return 404"},
  {surface: "hono", identifier: "ALL /mcp", coverage: "foreign-org API key is rejected before MCP dispatch"},
  {surface: "hono", identifier: "GET /api/v1/projects/:projectId", coverage: "Org B project requested through Org A returns 404"},
  {surface: "hono", identifier: "GET /api/v1/artifacts/:artifactId", coverage: "Org B artifact requested through Org A returns 404"},
  {surface: "hono", identifier: "GET /api/v1/session", coverage: "Org A session cookie is ignored by Org B"},
  {surface: "hono", identifier: "POST /api/v1/members/:memberId/reactivate", coverage: "admin-only per-org reactivation cannot cross installations"},
  {surface: "mcp", identifier: "member_reactivate", coverage: "org-only admin reactivation tool rejects service principals"},
  {surface: "hono", identifier: "GET /embed/artifacts/:artifactId", coverage: "Org B embed CSP and parent origin are read from its registry row"},
  {surface: "hono", identifier: "GET /embed/signed-in", coverage: "Org scoped embed sign-in endpoint remains separate from content hosts"},
  {surface: "hono", identifier: "GET /review-frame", coverage: "Org B review frame CSP uses its registry embed origins"},
  {surface: "hono", identifier: "GET /.well-known/oauth-protected-resource/o/:organization/api", coverage: "root OAuth metadata advertises the selected org API origin"},
  {surface: "hono", identifier: "GET /.well-known/oauth-protected-resource/o/:organization/mcp", coverage: "root OAuth metadata advertises the selected org MCP origin"},
  {surface: "hono", identifier: "PUT /api/v1/uploads/:uploadId/files/:storageToken", coverage: "Org A upload capability fails when its path is routed through Org B"},
  {surface: "hono", identifier: "GET /api/v1/public/artifacts/:artifactId/guest/current", coverage: "Org B guest cookie is valid only in Org B"},
  {surface: "hono", identifier: "POST /api/v1/projects/:projectId/artifacts/:artifactId/history/clone-token", coverage: "An Orvex clone credential and remote cannot be reused to resolve Orvex project and artifact identifiers through Org B"},
  {surface: "mcp", identifier: "artifact_open", coverage: "returned review and content URLs include Org B base path and content token prefix"},
  {surface: "mcp", identifier: "artifact_link", coverage: "Org B refuses linked-file publication without a local linked-file source and mints no URL or token"},
  {surface: "mcp", identifier: "artifact_relink", coverage: "Org B refuses relinking without a local linked-file source and mints no URL or token"},
  {surface: "mcp", identifier: "artifact_create_upload", coverage: "returned upload URL and commit target retain Org B base path"},
  {surface: "mcp", identifier: "artifact_history_clone_token", coverage: "Org B refuses clone-token issuance when Git history is not provisioned"},
  {surface: "mcp", identifier: "artifact_enable_guest_invitation", coverage: "guest invitation URL retains Org B base path"},
  {surface: "platform", identifier: "GET /api/v1/platform/me/orgs", coverage: "shared platform session lists only verified memberships"},
  {surface: "platform", identifier: "POST /api/v1/platform/session/last-org", coverage: "last-org accepts only a current membership"},
  {surface: "platform", identifier: "POST /api/v1/platform/session/logout", coverage: "logout deletes the shared platform session and expires its cookie"},
  {surface: "hono", identifier: "GET /auth/login", coverage: "org-scoped login handshake cookie"},
  {surface: "hono", identifier: "GET /auth/callback", coverage: "shared callback selects org from handshake cookie"},
] as const;

const pendingCrossOrgCases = [
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId/comments/:threadId/replies/:replyId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId/guest-invitation", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId/guest-invitation/sessions/:guestId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/artifacts/:artifactId/state/:key", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/projects/:projectId/groups/:group", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:DELETE /api/v1/public/artifacts/:artifactId/guest/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:DELETE /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies/:replyId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /administration/api-keys", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /administration/members", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /administration/public-links", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/administration/public-links", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /api/v1/agent-dispatches", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/agent-dispatches/:dispatchId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/agents", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/api-keys", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /api/v1/artifacts", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/actions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/comments", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/comparisons", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/guest-invitation", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/guest-invitation/sessions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/responses", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/responses/:responseId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/state", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/state/:key", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/versions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/archive", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/file", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/artifacts/:artifactId/versions/:versionId/media", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/embed/artifacts/:artifactId/bootstrap", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /api/v1/groups", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /api/v1/members", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:GET /api/v1/projects", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/projects/:projectId/audit", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/projects/:projectId/git-history", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/projects/:projectId/sharing", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/artifacts/:artifactId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/artifacts/:artifactId/guest/comments", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/artifacts/:artifactId/guest/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/artifacts/:artifactId/guest/responses", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/artifacts/:artifactId/guest/responses/:responseId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /api/v1/public/embed/artifacts/:artifactId/bootstrap", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /artifacts/:artifactId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /assets/*", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /auth/context", group: "authentication routes", justification: "Authentication state is scoped by the organization cookie suffix; the login and callback probes verify foreign handshakes are rejected."},
  {identifier: "hono:GET /auth/local", group: "authentication routes", justification: "Local bootstrap login is an installation-local authentication flow and carries no foreign artifact identifier; org-specific OAuth handshake and callback isolation are tested separately."},
  {identifier: "hono:GET /health", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /projects", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /projects/:projectId/artifacts", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /projects/:projectId/artifacts/:artifactId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:GET /projects/:projectId/artifacts/:artifactId/versions/:versionId/review", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /ready", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /review", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /review/*", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:GET /workbench", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /administration/api-keys", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:HEAD /administration/members", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:HEAD /administration/public-links", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /api/v1/artifacts/:artifactId/versions/:versionId/archive", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /api/v1/artifacts/:artifactId/versions/:versionId/media", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /assets/*", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /embed/artifacts/:artifactId", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /projects", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /projects/:projectId/artifacts", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /projects/:projectId/artifacts/:artifactId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:HEAD /projects/:projectId/artifacts/:artifactId/versions/:versionId/review", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /review", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /review-frame", group: "static and shell routes", justification: "HEAD returns only review-frame shell headers and no artifact bytes; the GET shell CSP and tenant embed-origin behavior are probed directly."},
  {identifier: "hono:HEAD /review/*", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:HEAD /workbench", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:PATCH /api/v1/artifacts/:artifactId/access", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/artifacts/:artifactId/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/artifacts/:artifactId/comments/:threadId/replies/:replyId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/artifacts/:artifactId/tags", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/projects/:projectId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/public/artifacts/:artifactId/guest/comments/:threadId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PATCH /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies/:replyId", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/administration/public-links/make-private", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/agent-dispatches", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agent-dispatches/:dispatchId/cancel", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agent-dispatches/:dispatchId/delivered", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agent-dispatches/:dispatchId/failed", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agents", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agents/:agentId/activity", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agents/:agentId/claims", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/agents/:agentId/disconnect", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/api-keys", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/api-keys/:keyId/revoke", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/api-keys/:keyId/rotate", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/artifacts", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/capture", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/comments/:threadId/replies", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/content-sessions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/guest-invitation", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/live-sessions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/responses", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/restore", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/versions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/comments", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/content-sessions", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/:artifactId/versions/:versionId/preview-leases", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/artifacts/link", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/embed/artifacts/:artifactId/binding", group: "static and shell routes", justification: "This shell, static asset, or health response contains no cross-installation artifact data; artifact access is separately tested through scoped APIs and content capabilities."},
  {identifier: "hono:POST /api/v1/members", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/members/:memberId/deactivate", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:POST /api/v1/projects", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/projects/:projectId/archive", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/projects/:projectId/artifacts/:artifactId/comments/clear", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/projects/:projectId/git-history/estimate", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/projects/:projectId/unarchive", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/public/artifacts/:artifactId/guest-session", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/public/artifacts/:artifactId/guest/comments", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/public/artifacts/:artifactId/guest/comments/:threadId/replies", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/public/artifacts/:artifactId/guest/heartbeat", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/public/artifacts/:artifactId/guest/responses", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/session/logout", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/uploads", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /api/v1/uploads/:uploadId/commit", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:POST /auth/local", group: "authentication routes", justification: "Local bootstrap login is an installation-local authentication flow and carries no foreign artifact identifier; org-specific OAuth handshake and callback isolation are tested separately."},
  {identifier: "hono:POST /auth/local-owner", group: "authentication routes", justification: "Local bootstrap login is an installation-local authentication flow and carries no foreign artifact identifier; org-specific OAuth handshake and callback isolation are tested separately."},
  {identifier: "hono:PUT /api/v1/artifacts/:artifactId/source", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PUT /api/v1/artifacts/:artifactId/state/:key", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PUT /api/v1/groups/:groupId/role", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "hono:PUT /api/v1/mcp-uploads/:uploadId/files/:storageToken", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PUT /api/v1/projects/:projectId/access", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PUT /api/v1/projects/:projectId/git-history", group: "resource-id routes", justification: "The handler resolves identifiers through the selected installation\u2019s repositories; resource IDs belonging to another installation return the same not-found response."},
  {identifier: "hono:PUT /api/v1/projects/:projectId/groups/:group", group: "admin routes", justification: "The endpoint reads or changes installation-owned membership or credentials; the selected runtime\u2019s verifier and repository prevent foreign installation records from being addressed."},
  {identifier: "mcp:artifact_capabilities", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_capture", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_commit_upload", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_delete", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_diff", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_download", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_get", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_guest_invitation_sessions", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_guest_invitation_status", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_response_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_restore_version", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_revoke_guest_invitation", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_revoke_guest_session", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_set_tags", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_set_visibility", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_state_delete", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_state_get", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_state_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_state_set", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:artifact_version_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_clear", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_create", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_delete", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_get", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_reply", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_resolve", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:comment_update", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:dispatch_inbox", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:group_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:group_set_role", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_archive", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_create", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_git_history_estimate", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_git_history_status", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_list", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_rename", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_set_access", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_set_git_history", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_share", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_sharing", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_unarchive", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
  {identifier: "mcp:project_unshare", group: "MCP tools", justification: "The tool executes with the selected installation-scoped application services; the foreign bearer is rejected at MCP authentication before any tool can run."},
] as const;

function assertCrossOrgMatrixComplete(
  registeredRoutes: readonly string[],
  registeredTools: readonly string[],
): void {
  const matrixCases = crossOrgMatrix.map(({surface, identifier}) =>
    `${surface}:${identifier}`,
  );
  const knownCases = [...matrixCases, ...pendingCrossOrgCases.map(({identifier}) => identifier)];
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
  expect(pendingCrossOrgCases.every(({identifier, group, justification}) =>
    identifier.length > 0 && group.length > 0 && justification.length > 0
  )).toBe(true);
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
  let orgBPathContentToken = "";
  let legacyPathContentToken = "";

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
        {role: "owner" as const, selector: `${groupRoot}owners`},
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
      embedOrigins: z.array(z.string()),
      id: z.string(),
      registryVersion: z.string().regex(/^\d+$/u),
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
      verify: (credential) => {
        const staffMailbox = Redacted.value(credential) === "tenant-staff-mailbox-token";
        return Effect.succeed({
          clientId: staffMailbox ? "tenant-staff-mailbox" : "orgvex-service",
          expiresAt: Math.floor(Date.now() / 1_000) + 60,
          provider: staffMailbox ? oidc.issuer : "test-oidc",
          scopes: [],
          subject: staffMailbox ? "tenant-staff-mailbox-subject" : "service-account",
        });
      },
      resolveIdentity: (verified) => verified.subject === "tenant-staff-mailbox-subject"
        ? Effect.succeed({
          displayName: "Tenant support",
          email: "tenant-support-user@example.test",
          emailVerified: true,
          groups: [`/teams/${orgB.slug}/support`],
          provider: oidc.issuer,
          serviceAccount: false,
          subject: "tenant-staff-mailbox-subject",
        })
        : Effect.succeed({
          displayName: "service account",
          email: null,
          emailVerified: false,
          groups: ["/orvex/admin"],
          provider: "test-oidc",
          serviceAccount: true,
          subject: "service-account",
        }),
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
      embedBindingSecret: Redacted.make(embedBindingSecret),
      databaseUrl: Redacted.make(databaseUrl),
      installationId,
      organizationMemberships: {forIdentity: async () => platformMemberships},
      groupRolePolicy: {seed: [{role: "administrator", selector: "/orvex/admin"}]},
      gitHistory: orgTenancyGitHistory,
      gitHistoryHealthProbe: orgTenancyGitHistoryProbe,
      gitHistoryProvider: orgTenancyGitProvider,
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
      webAssets: {
        fetch: async (assetPath) => assetPath === "/embed.html"
          ? new Response("<!doctype html><html><head></head><body>embed</body></html>")
          : assetPath === "/review-frame.html"
          ? new Response("<!doctype html><html><head></head><body>review frame</body></html>")
          : assetPath === "/assets/embed-signed-in.js"
          ? new Response("window.close();")
          : null,
      },
    };

    const setupB = await createOrgRuntime(orgB.id, {
      admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
      applicationOrigin: new URL(`/o/${orgB.slug}`, applicationOrigin).toString(),
      bootstrapApiToken: Redacted.make(apiTokenB),
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
      contentTokenPrefix: `${orgB.routeId}-`,
      embedOrigins: [],
    }, withoutGitHistory(config), database);
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
      const pathArtifactId = await publishOrgPathFilesArtifact(
        (request) => setupB.app.fetch(request),
        apiTokenB,
        projectId,
        orgB.slug,
        "Org B reserved path files",
      );
      const pathVersionRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT content_token AS "contentToken" FROM versions
          WHERE installation_id = ${orgB.id} AND artifact_id = ${pathArtifactId}`;
      }));
      orgBPathContentToken = z.object({contentToken: z.string()}).parse(pathVersionRows[0]).contentToken;
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
      expect(JSON.stringify(dispatches.body)).not.toContain('"staff"');
      expect(JSON.stringify(dispatches.body)).not.toContain("Orvex Support");
      const dispatchId = z.object({dispatch: z.object({id: z.string()})})
        .parse(await dispatchCreate.json()).dispatch.id;
      const dispatch = await compareRoute(`/api/v1/agent-dispatches/${dispatchId}?projectId=${projectId}`, "GET");
      expect(dispatch.status).toBe(200);
      expect(JSON.stringify(dispatch.body)).not.toContain('"staff"');
      expect(JSON.stringify(dispatch.body)).not.toContain('"email":null');
      expect(JSON.stringify(dispatch.body)).not.toContain("Orvex Support");
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
    let orgBMemberCookie = "";
    let orgBCsrf = "";
    expect(orgB.admissionPolicy).toMatchObject({groupRoots: [`/teams/${orgB.slug}/`]});
    const gitHistoryProvider = new RecordingGitHistoryProvider();
    const tenantGitHistory: NodeGitHistoryConfiguration = {
      _tag: "CloudflareArtifactsRest",
      apiToken: Redacted.make("org-tenancy-git-history-test-token"),
      capability: {
        limits: {
          fileCopyBytes: defaultGitHistoryFileCopyBytes,
          logicalCopiedBytes: 0,
          logicalReservedBytes: 0,
          storageBudgetBytes: null,
          versionCopyBytes: defaultGitHistoryVersionCopyBytes,
        },
        provider: "cloudflare-artifacts",
        providerState: "available",
      },
      identity: {accountId: "org-tenancy-test", namespace: "org-tenancy-test", provider: "cloudflare-artifacts"},
      issues: [],
    };
    const gitHistoryHealthProbe: GitHistoryProviderHealthProbe = {
      check: () => Effect.succeed({state: "available"}),
    };
    const admissionRuntime = await createOrgRuntime(orgB.id, {
      admissionPolicy: runtimeAdmissionPolicy(orgB.admissionPolicy),
      applicationOrigin: `${applicationOrigin}/o/${orgB.slug}`,
      cookieRouteId: orgB.routeId,
      slug: orgB.slug,
    }, {...config, gitHistory: tenantGitHistory, gitHistoryHealthProbe, gitHistoryProvider}, database);
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

      const callStaffMailbox = async (operation: "claim" | "list") => {
        const response = await admissionRuntime.app.fetch(appRequest("/mcp", "tenant-staff-mailbox-token", "POST", {
          id: `tenant-staff-mailbox-${operation}-${randomUUID()}`,
          jsonrpc: "2.0",
          method: "tools/call",
          params: {
            _meta: {
              [CLIENT_CAPABILITIES_META_KEY]: {},
              [CLIENT_INFO_META_KEY]: {name: "Support Reviewer", version: "1"},
              [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
            },
            arguments: {agentName: "Support Reviewer", operation},
            name: "dispatch_inbox",
          },
        }, {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "dispatch_inbox",
          Accept: "application/json, text/event-stream", Origin: applicationOrigin}));
        expect(response.status).toBe(200);
        const text = await response.text();
        const payload = response.headers.get("content-type")?.includes("text/event-stream")
          ? text.split("\n").find((line) => line.startsWith("data: "))?.slice(6) ?? "{}"
          : text;
        const decoded = z.object({result: z.object({isError: z.boolean().optional(), structuredContent: z.unknown().optional()})})
          .parse(JSON.parse(payload));
        expect(decoded.result.isError).not.toBe(true);
        return z.object({agent: z.object({displayName: z.string(), id: z.string()}), claimed: z.unknown().nullable(),
          inbox: z.array(z.object({agentDisplayName: z.string(), senderDisplayName: z.string(), id: z.string()})).nullable(),
          operation: z.enum(["claim", "list"])}).parse(decoded.result.structuredContent);
      };
      const staffMailbox = await callStaffMailbox("list");
      expect(staffMailbox.agent.displayName).toBe("Support Reviewer for Orvex Support");
      const staffMailboxAgentId = staffMailbox.agent.id;
      const mailboxThreadResponse = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/versions/${staffVersionId}/comments?projectId=${staffProjectId}`,
        {body: JSON.stringify({body: "Staff-authored mailbox fixture."}), headers: {
          Cookie: staffCookieHeader, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
          Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken,
        }, method: "POST"},
      ));
      expect(mailboxThreadResponse.status).toBe(201);
      const mailboxThreadId = z.object({thread: z.object({id: z.string()})})
        .parse(await mailboxThreadResponse.json()).thread.id;
      const mailboxDispatchResponse = await admissionRuntime.app.fetch(new Request(
        "https://artifacts.example.com/api/v1/agent-dispatches", {
          body: JSON.stringify({agentId: staffMailboxAgentId, note: "Mailbox staff projection", projectId: staffProjectId, threadIds: [mailboxThreadId]}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
            Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST",
        },
      ));
      expect(mailboxDispatchResponse.status).toBe(201);
      const listedStaffMailbox = await callStaffMailbox("list");
      expect(listedStaffMailbox.inbox).toEqual([expect.objectContaining({
        agentDisplayName: "Orvex Support", senderDisplayName: "Orvex Support",
      })]);
      const claimedStaffMailbox = await callStaffMailbox("claim");
      expect(claimedStaffMailbox.agent.displayName).toBe("Support Reviewer for Orvex Support");
      expect(claimedStaffMailbox.claimed).not.toBeNull();

      const editorLogin = await loginWithGroups([`/teams/${orgB.slug}/editors`], "route-walker-editor-mutations");
      expect(editorLogin.status).toBe(303);
      const editorCookies = editorLogin.headers.getSetCookie();
      const editorCookie = editorCookies.map((value) => value.split(";", 1)[0]).join("; ");
      const editorCsrfCookie = editorCookies.find((value) => value.startsWith(`__Host-artifact_csrf-${orgB.routeId}=`));
      if (editorCsrfCookie === undefined) throw new Error("The editor mutation login did not issue a CSRF cookie.");
      const editorCsrf = editorCsrfCookie.split(";", 1)[0]?.split("=", 2)[1];
      if (editorCsrf === undefined) throw new Error("The editor mutation login issued an invalid CSRF cookie.");
      const editorActor = {cookie: editorCookie, csrf: editorCsrf};
      const editorComment = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/versions/${staffVersionId}/comments?projectId=${staffProjectId}`,
        {body: JSON.stringify({body: "Tenant editor dispatches to the support mailbox."}), headers: {
          Cookie: editorActor.cookie, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
          Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": editorActor.csrf,
        }, method: "POST"},
      ));
      expect(editorComment.status).toBe(201);
      const editorThreadId = z.object({thread: z.object({id: z.string()})}).parse(await editorComment.json()).thread.id;
      const editorDispatch = await admissionRuntime.app.fetch(new Request(
        "https://artifacts.example.com/api/v1/agent-dispatches", {
          body: JSON.stringify({agentId: staffAgentId, note: "Tenant member handoff", projectId: staffProjectId, threadIds: [editorThreadId]}),
          headers: {Cookie: editorActor.cookie, "Content-Type": "application/json", "Idempotency-Key": randomUUID(),
            Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": editorActor.csrf},
          method: "POST",
        },
      ));
      expect(editorDispatch.status).toBe(201);
      const editorDispatchBody = await editorDispatch.json();
      expect(JSON.stringify(editorDispatchBody)).toContain("Orvex Support");
      expect(JSON.stringify(editorDispatchBody)).not.toContain(staffMember.displayName);
      const editorMutationHeaders = new Headers({Cookie: editorActor.cookie, "Content-Type": "application/json",
        Origin: applicationOrigin, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": editorActor.csrf});
      const editorRestore = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/restore?projectId=${staffProjectId}`,
        {body: JSON.stringify({expectedCurrentVersionId: staffVersionId, versionId: firstVersionId}), headers: new Headers([...editorMutationHeaders, ["Idempotency-Key", randomUUID()]]), method: "POST"},
      ));
      expect(editorRestore.status).toBe(200);
      staffVersionId = z.object({version: z.object({id: z.string()})}).parse(await editorRestore.json()).version.id;
      const editorTags = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/tags?projectId=${staffProjectId}`,
        {body: JSON.stringify({expectedCurrentVersionId: staffVersionId, tags: ["walker-proof"]}), headers: new Headers([...editorMutationHeaders, ["Idempotency-Key", randomUUID()]]), method: "PATCH"},
      ));
      expect(editorTags.status).toBe(200);
      staffVersionId = z.object({version: z.object({id: z.string()})}).parse(await editorTags.json()).version.id;
      const editorReply = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/comments/${editorThreadId}/replies?projectId=${staffProjectId}`,
        {body: JSON.stringify({body: "Reply from the tenant editor."}), headers: new Headers([...editorMutationHeaders, ["Idempotency-Key", randomUUID()]]), method: "POST"},
      ));
      expect(editorReply.status).toBe(201);
      const editorResolve = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/comments/${editorThreadId}?projectId=${staffProjectId}`,
        {body: JSON.stringify({state: "resolved"}), headers: editorMutationHeaders, method: "PATCH"},
      ));
      expect(editorResolve.status).toBe(200);
      const editorAccess = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${staffArtifact.id}/access?projectId=${staffProjectId}`,
        {body: JSON.stringify({accessSetting: "public_link", expectedCurrentVersionId: staffVersionId}), headers: new Headers([...editorMutationHeaders, ["Idempotency-Key", randomUUID()]]), method: "PATCH"},
      ));
      expect(editorAccess.status).toBe(200);
      staffVersionId = z.object({version: z.object({id: z.string()})}).parse(await editorAccess.json()).version.id;
      const publicEmbedBootstrap = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/public/embed/artifacts/${staffArtifact.id}/bootstrap?path=index.html`,
      ));
      expect(publicEmbedBootstrap.status).toBe(200);
      const enableGitHistory = await admissionRuntime.app.fetch(appRequest(
        `/api/v1/projects/${staffProjectId}/git-history`, apiTokenB, "PUT",
        {confirmEstimate: true, enabled: true},
      ));
      expect(enableGitHistory.status).toBe(200);
      await expect.poll(() => gitHistoryProvider.commitCalls, {timeout: 8_000}).toBeGreaterThan(0);
      const requiredEditorMutationPairs = [
        ["editor", "POST /api/v1/artifacts/:artifactId/restore", editorRestore.status],
        ["editor", "PATCH /api/v1/artifacts/:artifactId/tags", editorTags.status],
        ["editor", "POST /api/v1/artifacts/:artifactId/versions/:versionId/comments", editorComment.status],
        ["editor", "POST /api/v1/artifacts/:artifactId/comments/:threadId/replies", editorReply.status],
        ["editor", "PATCH /api/v1/artifacts/:artifactId/comments/:threadId", editorResolve.status],
        ["editor", "PATCH /api/v1/artifacts/:artifactId/access", editorAccess.status],
      ] as const;
      for (const [role, operation, status] of requiredEditorMutationPairs) {
        expect(status, `${role} must successfully perform ${operation} with the seeded resource`).toBeGreaterThanOrEqual(200);
        expect(status, `${role} must successfully perform ${operation} with the seeded resource`).toBeLessThan(300);
      }

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
      const viewerWithKey = actorCookies.get("viewer");
      if (viewerWithKey?.token === undefined) throw new Error("The route walker has no viewer API key.");
      const viewerClone = await admissionRuntime.app.fetch(appRequest(
        `/api/v1/projects/${staffProjectId}/artifacts/${staffArtifact.id}/history/clone-token`,
        viewerWithKey.token, "POST", {ttlSeconds: 60},
      ));
      expect(viewerClone.status).toBe(201);
      expect(await viewerClone.json()).toMatchObject({remote: `https://git.example.test/${staffArtifact.id}`});
      const clonedCommitFiles = gitHistoryProvider.commitRequests.flatMap((request) =>
        request.files.concat(gitHistoryMetadataFiles(request))
      );
      expect(clonedCommitFiles.length).toBeGreaterThan(0);
      for (const file of clonedCommitFiles) {
        const contents = new TextDecoder().decode(file.bytes);
        expect(contents).not.toContain(staffMember.id);
        expect(contents).not.toContain(staffMember.email);
        expect(contents).not.toContain(staffMember.displayName);
      }
      const versionMetadataFiles = clonedCommitFiles
        .filter(({path}) => path === ".artifactserver/version.json");
      expect(versionMetadataFiles.length).toBeGreaterThan(0);
      for (const file of versionMetadataFiles) {
        const metadata = z.record(z.string(), z.unknown()).parse(JSON.parse(new TextDecoder().decode(file.bytes)));
        expect(metadata).not.toHaveProperty("publisherPrincipalId");
        expect(JSON.stringify(metadata)).not.toContain(staffMember.id);
      }
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
        if (name === "memberId" && !readOnly) return staffMemberOpaqueId(orgB.id, apiTokenA, staffMember.id);
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
      const mustSucceedRoutePairs = [
        ...["admin", "editor", "viewer"].flatMap((role) => [
          [role, "GET /api/v1/members"], [role, "GET /api/v1/groups"],
          [role, "GET /api/v1/artifacts/:artifactId"], [role, "GET /api/v1/artifacts/:artifactId/versions"],
          [role, "GET /api/v1/artifacts/:artifactId/comments"], [role, "GET /api/v1/artifacts/:artifactId/comments/:threadId"],
          [role, "GET /api/v1/artifacts/:artifactId/responses"], [role, "GET /api/v1/artifacts/:artifactId/state"],
          [role, "GET /api/v1/agents"], [role, "GET /api/v1/agent-dispatches/:dispatchId"],
          [role, "GET /api/v1/public/artifacts/:artifactId"], [role, "GET /api/v1/public/embed/artifacts/:artifactId/bootstrap"],
        ] as const),
        ["admin", "GET /api/v1/administration/public-links"] as const,
      ] as const;
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
      const expectedHttpMethod = z.enum(["DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"]);
      const actorScans = await Promise.all([...actorCookies].map(async ([role, actor]) => {
        const routeResponses = await Promise.all(orderedRoutes.map(async (route) => {
            const [rawMethod, rawPath] = route.split(" ", 2);
            if (rawMethod === undefined || rawPath === undefined) throw new Error(`Invalid route inventory entry: ${route}`);
            const method = rawMethod === "ALL" ? "GET" : rawMethod;
            const readOnly = method === "GET" || method === "HEAD";
            const path = rawPath.replace(/:([A-Za-z][A-Za-z0-9_]*)/gu, (_match, name: string) => routeParam(name, readOnly)).replace(/\/\*/gu, "/route-walker");
            const url = new URL(path, "https://artifacts.example.com");
            if (!path.startsWith("/api/v1/public/") &&
              (path.includes("artifact") || path.includes("project") || path.includes("agent-dispatches"))) {
              url.searchParams.set("projectId", staffProjectId);
            }
            if (path.includes("/compare")) {
              url.searchParams.set("fromVersionId", firstVersionId);
              url.searchParams.set("toVersionId", staffVersionId);
            }
            if (path.includes("/media") || path.includes("embed")) url.searchParams.set("path", "index.html");
            const headers = new Headers();
            if (!path.startsWith("/api/v1/public/")) headers.set("Cookie", actor.cookie);
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
            const acceptedStatuses = expectedHttpStatuses[expectedHttpMethod.parse(method)];
            expect(acceptedStatuses).toContain(response.status);
            return {route, status: response.status};
        }));
        expect(routeResponses).toHaveLength(orderedRoutes.length);
        for (const [, requiredRoute] of mustSucceedRoutePairs.filter(([candidateRole]) => candidateRole === role)) {
          const successfulRead = routeResponses.find(({route}) => route === requiredRoute);
          expect(successfulRead?.status, `${role} must successfully read ${requiredRoute}`).toBeGreaterThanOrEqual(200);
          expect(successfulRead?.status, `${role} must successfully read ${requiredRoute}`).toBeLessThan(300);
        }
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
          expect(response.status).toBe(200);
          const payload = response.headers.get("content-type")?.includes("text/event-stream")
            ? responseBody.split("\n").find((line) => line.startsWith("data: "))?.slice(6) ?? "{}"
            : responseBody;
          const decoded = z.object({result: z.object({isError: z.boolean().optional(), content: z.array(z.unknown()).optional(), structuredContent: z.unknown().optional()}).passthrough()}).passthrough().parse(JSON.parse(payload));
          const mustSucceed = new Set(["artifact_get", "comment_list", "comment_get", "artifact_response_list", "artifact_state_list", "project_git_history_status"]);
          expect(!mustSucceed.has(tool.name) || decoded.result.isError !== true).toBe(true);
          expect(decoded.result.content !== undefined || decoded.result.structuredContent !== undefined,
            `${role} MCP ${tool.name} must include a result payload: ${responseBody}`).toBe(true);
          return response.status;
        }));
        expect(toolResponses).toHaveLength(toolDefinitions.length);
        expect(toolResponses.filter((status) => status >= 200 && status < 300).length, `${role} MCP tools must include successful results`).toBeGreaterThanOrEqual(2);
        return {role, routes: routeResponses.length, tools: toolResponses.length};
      }));
      expect(actorScans).toHaveLength(3);

      const makePrivate = await admissionRuntime.app.fetch(new Request(
        "https://artifacts.example.com/api/v1/administration/public-links/make-private", {
          body: JSON.stringify({items: [{artifactId: staffArtifact.id, expectedCurrentVersionId: staffVersionId,
            idempotencyKey: randomUUID(), projectId: staffProjectId}]}),
          headers: {Cookie: staffCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin,
            "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrfToken},
          method: "POST",
        },
      ));
      expect(makePrivate.status).toBe(200);
      const requiredAdminMutationPair = ["admin", "POST /api/v1/administration/public-links/make-private", makePrivate.status] as const;
      expect(requiredAdminMutationPair[2], `${requiredAdminMutationPair[0]} must successfully perform ${requiredAdminMutationPair[1]}`).toBe(200);

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
      const ownerLogin = await loginWithGroups([`/teams/${orgB.slug}/owners`], "tenant-owner-user");
      expect(ownerLogin.status).toBe(303);
      const ownerCookies = ownerLogin.headers.getSetCookie();
      const ownerCookieHeader = ownerCookies.map((cookie) => cookie.split(";", 1)[0]).join("; ");
      const ownerCsrfCookie = ownerCookies.find((cookie) => cookie.startsWith(`__Host-artifact_csrf-${orgB.routeId}=`));
      const ownerCsrf = ownerCsrfCookie?.split(";", 1)[0]?.split("=", 2)[1];
      if (ownerCsrf === undefined) throw new Error("Owner login did not issue a CSRF token.");
      const ownerMembersResponse = await admissionRuntime.app.fetch(new Request("https://artifacts.example.com/api/v1/members", {
        headers: {Cookie: ownerCookieHeader},
      }));
      expect(ownerMembersResponse.status).toBe(200);
      const ownerMembers = z.object({members: z.array(z.object({id: z.string(), displayName: z.string(), status: z.string().optional()}).passthrough())})
        .parse(await ownerMembersResponse.json()).members;
      const staffSectionRow = ownerMembers.find(({displayName}) => displayName === "Orvex Support");
      if (staffSectionRow === undefined) throw new Error("Owner directory omitted the staff section.");
      expect(staffSectionRow.id).toMatch(/^staff_[A-Za-z0-9_-]{22}$/u);
      expect(staffSectionRow.status).toBe("active");
      expect(JSON.stringify(ownerMembers)).not.toContain(staffMember.id);
      expect(JSON.stringify(ownerMembers)).not.toContain(staffMember.email);
      const adminCookieHeader = admitted.headers.getSetCookie().map((cookie) => cookie.split(";", 1)[0]).join("; ");
      const adminCsrfCookie = admitted.headers.getSetCookie().find((cookie) => cookie.startsWith(`__Host-artifact_csrf-${orgB.routeId}=`));
      const adminCsrf = adminCsrfCookie?.split(";", 1)[0]?.split("=", 2)[1];
      if (adminCsrf === undefined) throw new Error("Administrator login did not issue a CSRF token.");
      const hiddenStaffAttempt = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/members/${staffMember.id}/deactivate`,
        {body: "{}", headers: {Cookie: adminCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": adminCsrf}, method: "POST"},
      ));
      const missingMemberAttempt = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/members/missing-${randomUUID()}/deactivate`,
        {body: "{}", headers: {Cookie: adminCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": adminCsrf}, method: "POST"},
      ));
      expect(hiddenStaffAttempt.status).toBe(404);
      expect(missingMemberAttempt.status).toBe(404);
      const walkerAdmin = actorCookies.get("admin");
      const walkerEditor = actorCookies.get("editor");
      if (walkerAdmin === undefined || walkerEditor === undefined) throw new Error("Route walker did not retain its admin and editor identities.");
      const ordinaryMemberDeactivation = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/members/${walkerEditor.memberId}/deactivate`,
        {body: "{}", headers: {Cookie: walkerAdmin.cookie, "Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": walkerAdmin.csrf}, method: "POST"},
      ));
      expect(ordinaryMemberDeactivation.status).toBe(200);
      expect(await ordinaryMemberDeactivation.json()).toMatchObject({member: {id: walkerEditor.memberId, status: "inactive"}});
      const ownerDeactivateStaff = await admissionRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/members/${staffSectionRow.id}/deactivate`,
        {body: "{}", headers: {Cookie: ownerCookieHeader, "Content-Type": "application/json", Origin: applicationOrigin, "Sec-Fetch-Mode": "cors",
          "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": ownerCsrf}, method: "POST"},
      ));
      expect(ownerDeactivateStaff.status).toBe(200);
      const ownerDeactivateBody = await ownerDeactivateStaff.text();
      assertNoStaffIdentity(ownerDeactivateBody, staffSecrets);
      expect(JSON.parse(ownerDeactivateBody)).toMatchObject({member: {id: staffSectionRow.id, status: "inactive"}});
      expect(ownerDeactivateBody).not.toContain(staffMember.displayName);
      expect(ownerDeactivateBody).not.toContain(staffMember.email);
      expect(ownerDeactivateBody).not.toContain(staffMember.id);
      const deactivatedStaff = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT staff, manual_deactivation FROM installation_members
          WHERE installation_id = ${orgB.id} AND id = ${staffMember.id}`;
      }));
      expect(deactivatedStaff[0]).toMatchObject({staff: true, manual_deactivation: true});
      expect((await loginWithGroups([`/teams/${orgB.slug}/support`], "tenant-support-user")).status).toBe(403);
      const memberCliEnvironment = {
        ...process.env,
        ARTIFACT_SERVER_DATABASE_URL: databaseUrl,
        ARTIFACT_SERVER_INSTALLATION_ID: installationId,
      };
      const clearStaff = spawnSync(process.execPath, ["--import", "tsx", "src/cli/main.ts", "member", "clear-staff", orgB.slug, staffMember.email, "--yes"], {
        cwd: process.cwd(), encoding: "utf8", env: memberCliEnvironment,
      });
      expect(clearStaff.status).toBe(0);
      const clearAudit = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        const members = yield* sql`SELECT staff FROM installation_members WHERE installation_id = ${orgB.id} AND id = ${staffMember.id}`;
        const audits = yield* sql`SELECT COUNT(*)::integer AS count FROM installation_member_staff_audit
          WHERE installation_id = ${orgB.id} AND member_id = ${staffMember.id} AND action = 'clear_staff'`;
        return {audits, members};
      }));
      expect(clearAudit.members[0]).toMatchObject({staff: false});
      expect(clearAudit.audits[0]?.["count"]).toBe(1);
      const repeatedClearStaff = spawnSync(process.execPath, ["--import", "tsx", "src/cli/main.ts", "member", "clear-staff", orgB.slug, staffMember.email, "--yes"], {
        cwd: process.cwd(), encoding: "utf8", env: memberCliEnvironment,
      });
      expect(repeatedClearStaff.status).toBe(0);
      const repeatedAudit = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT COUNT(*)::integer AS count FROM installation_member_staff_audit
          WHERE installation_id = ${orgB.id} AND member_id = ${staffMember.id} AND action = 'clear_staff'`;
      }));
      expect(repeatedAudit[0]?.["count"]).toBe(1);
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
    const forwardedHost = {
      ...host,
      "x-forwarded-host": "artifacts.example.com",
      "x-forwarded-proto": "https",
    };
    const registry = new OrganizationRegistry(database);
    const [projectRows, artifactRows, versionRows] = await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const projects = yield* sql`SELECT id FROM projects
        WHERE installation_id = ${orgB.id} AND name = 'Org B project'`;
      const artifacts = yield* sql`SELECT id FROM artifacts
        WHERE installation_id = ${orgB.id} AND name = 'Org B artifact'`;
      const versions = yield* sql`SELECT id, content_token AS "contentToken"
        FROM versions WHERE installation_id = ${orgB.id}
          AND artifact_id = (SELECT id FROM artifacts
            WHERE installation_id = ${orgB.id} AND name = 'Org B artifact')`;
      return [projects, artifacts, versions] as const;
    }));
    const projectId = z.object({id: z.string()}).parse(projectRows[0]).id;
    const artifactId = z.object({id: z.string()}).parse(artifactRows[0]).id;
    const version = z.object({id: z.string(), contentToken: z.string()}).parse(versionRows[0]);
    expect(version.contentToken).toMatch(new RegExp(`^${orgB.routeId}-[A-Za-z0-9_-]{16,100}$`, "u"));
    const reservedPathResponses = await Promise.all(reservedContentPathFiles.map(async (pathEntry) => {
      const response = await fetchWithHost(
        `http://${router.hostname}:${router.port}/${pathEntry.path}`,
        {headers: {Host: `${orgBPathContentToken}.content.example.net`}},
        router.hostname,
        router.port,
      );
      return {
        body: await response.text(),
        path: pathEntry.path,
        status: response.status,
      };
    }));
    expect(reservedPathResponses).toEqual(reservedContentPathFiles.map((pathEntry) => ({
      body: pathEntry.body,
      path: pathEntry.path,
      status: 200,
    })));
    const prefixedLiveToken = liveContentToken("art_00000000-0000-4000-8000-000000000001", `${orgB.routeId}-`);
    expect(prefixedLiveToken).toMatch(new RegExp(`^${orgB.routeId}-live-[0-9a-f-]+$`, "u"));
    expect(isLiveContentToken(prefixedLiveToken ?? "", `${orgB.routeId}-`)).toBe(true);
    expect(isLiveContentToken(prefixedLiveToken ?? "", `${orgB.routeId.slice(0, 7)}-`)).toBe(false);

    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`UPDATE artifact_installations
        SET embed_origins = ${JSON.stringify(["https://org-b-embed.example.test"])}::jsonb
        WHERE id = ${orgB.id}`;
    }));

    const orgBContent = await fetchWithHost(
      `http://${router.hostname}:${router.port}/`,
      {headers: {Host: `${version.contentToken}.content.example.net`}},
      router.hostname,
      router.port,
    );
    expect(orgBContent.status).toBe(401);
    const contentSession = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/content-sessions?projectId=${projectId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenB}`},
      method: "POST",
    });
    expect(contentSession.status).toBe(201);
    const contentBootstrapUrl = z.object({bootstrapUrl: z.url()})
      .parse(await contentSession.json()).bootstrapUrl;
    const contentSessionToken = new URL(contentBootstrapUrl).hostname.split(".")[0] ?? "";
    expect(contentSessionToken).toMatch(new RegExp(`^${orgB.routeId}-[A-Za-z0-9_-]{16,100}$`, "u"));

    const previewLease = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/versions/${version.id}/preview-leases?projectId=${projectId}`, {
      headers: {...host, Authorization: `Bearer ${apiTokenB}`},
      method: "POST",
    });
    expect(previewLease.status).toBe(201);
    const previewUrl = z.object({baseUrl: z.url()}).parse(await previewLease.json()).baseUrl;
    const previewToken = new URL(previewUrl).hostname.split(".")[0] ?? "";
    expect(previewToken).toMatch(new RegExp(`^${orgB.routeId}-review-[a-f0-9]+$`, "u"));
    const previewContent = await fetchWithHost(
      `http://${router.hostname}:${router.port}/`,
      {headers: {Host: `${previewToken}.content.example.net`}},
      router.hostname,
      router.port,
    );
    expect(previewContent.status).toBe(200);

    const forbiddenContentHostPaths = ["/api", "/%61pi/v1/projects", "/mcp", "/review", "/review-frame"];
    const blockedContentResponses = await Promise.all(forbiddenContentHostPaths.map((path) =>
      fetchWithHost(
        `http://${router.hostname}:${router.port}${path}`,
        {headers: {Host: `${version.contentToken}.content.example.net`}},
        router.hostname,
        router.port,
      )
    ));
    expect(blockedContentResponses.map(({status}) => status)).toEqual(
      forbiddenContentHostPaths.map(() => 404),
    );
    const malformedContentHostResponses = await Promise.all(
      ["short", `${version.contentToken}.nested`].map((hostLabel) => fetchWithHost(
        `http://${router.hostname}:${router.port}/%61pi/v1/projects`,
        {headers: {Host: `${hostLabel}.content.example.net`}},
        router.hostname,
        router.port,
      )),
    );
    expect(malformedContentHostResponses.map(({status}) => status)).toEqual([404, 404]);
    const trailingDotContent = await fetchWithHost(
      `http://${router.hostname}:${router.port}/`,
      {headers: {Host: `${version.contentToken}.content.example.net.`}},
      router.hostname,
      router.port,
    );
    expect(trailingDotContent.status).toBe(401);

    // Tenancy has never been enabled in production, so old unprefixed
    // capabilities can only belong to the Orvex installation.
    const legacyInstallationId = installationId;
    const legacyRuntime = await createExternalStorageRuntime({
      ...config,
      installationId: legacyInstallationId,
      objectStorage: createS3ObjectStorageProviderFactory({
        accessKeyId: requiredIntegrationSetting(accessKey, "ARTIFACT_SERVER_TEST_S3_ACCESS_KEY"),
        bucket,
        endpoint: requiredIntegrationSetting(endpoint, "ARTIFACT_SERVER_TEST_S3_ENDPOINT"),
        forcePathStyle: true,
        region,
        secretAccessKey: Redacted.make(requiredIntegrationSetting(secretKey, "ARTIFACT_SERVER_TEST_S3_SECRET_KEY")),
      }),
    });
    try {
      const legacyProjectResponse = await legacyRuntime.app.fetch(appRequest(
        "/api/v1/projects", apiTokenA, "POST", {name: "Legacy content project"},
      ));
      expect(legacyProjectResponse.status).toBe(201);
      const legacyProjectId = z.object({project: z.object({id: z.string()})})
        .parse(await legacyProjectResponse.json()).project.id;
      const legacyArtifactId = await publishOrgBArtifact(
        (request) => legacyRuntime.app.fetch(request), apiTokenA, legacyProjectId, "orvex",
      );
      const legacyPathsArtifactId = await publishOrgPathFilesArtifact(
        (request) => legacyRuntime.app.fetch(request),
        apiTokenA,
        legacyProjectId,
        "orvex",
        "Orvex reserved path files",
      );
      const legacyPathVersionRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT content_token AS "contentToken" FROM versions
          WHERE installation_id = ${installationId} AND artifact_id = ${legacyPathsArtifactId}`;
      }));
      legacyPathContentToken = z.object({contentToken: z.string()}).parse(legacyPathVersionRows[0]).contentToken;
      const flagOffContent = await Promise.all(reservedContentPathFiles.map(async (pathEntry) => {
        const response = await legacyRuntime.app.fetch(new Request(
          `https://${legacyPathContentToken}.content.example.net/${pathEntry.path}`,
        ));
        return {body: await response.text(), path: pathEntry.path, status: response.status};
      }));
      expect(flagOffContent).toEqual(reservedContentPathFiles.map((pathEntry) => ({
        body: pathEntry.body,
        path: pathEntry.path,
        status: 200,
      })));
      const legacyRouterContent = await Promise.all(reservedContentPathFiles.map(async (pathEntry) => {
        const response = await fetchWithHost(
          `http://${router.hostname}:${router.port}/${pathEntry.path}`,
          {headers: {Host: `${legacyPathContentToken}.content.example.net`}},
          router.hostname,
          router.port,
        );
        return {body: await response.text(), path: pathEntry.path, status: response.status};
      }));
      expect(legacyRouterContent).toEqual(reservedContentPathFiles.map((pathEntry) => ({
        body: pathEntry.body,
        path: pathEntry.path,
        status: 200,
      })));
      const legacyVersionRows = await database.run(Effect.gen(function*() {
        const sql = yield* SqlClient;
        return yield* sql`SELECT content_token AS "contentToken", id FROM versions
          WHERE installation_id = ${legacyInstallationId} AND artifact_id = ${legacyArtifactId}`;
      }));
      const legacyVersion = z.object({contentToken: z.string(), id: z.string()}).parse(legacyVersionRows[0]);
      expect(legacyVersion.contentToken).toMatch(/^[A-Za-z0-9_-]{16,100}$/u);
      expect(legacyVersion.contentToken).not.toMatch(/^[a-z0-9]{8}-/u);
      const makeLegacyPublic = await legacyRuntime.app.fetch(new Request(
        `https://artifacts.example.com/api/v1/artifacts/${legacyArtifactId}/access?projectId=${legacyProjectId}`,
        {
          body: JSON.stringify({accessSetting: "public_link", expectedCurrentVersionId: legacyVersion.id}),
          headers: {
            Authorization: `Bearer ${apiTokenA}`,
            "Content-Type": "application/json",
            "Idempotency-Key": "org-tenancy-legacy-public-001",
          },
          method: "PATCH",
        },
      ));
      expect(makeLegacyPublic.status).toBe(200);
      const legacyContent = await fetchWithHost(
        `http://${router.hostname}:${router.port}/`,
        {headers: {Host: `${legacyVersion.contentToken}.content.example.net`}},
        router.hostname,
        router.port,
      );
      expect(legacyContent.status).toBe(200);
      expect(await legacyContent.text()).toContain("org B private artifact");
    } finally {
      await legacyRuntime.close();
    }
    const orvex = await registry.find("orvex");
    if (orvex === null) throw new Error("Orvex was not registered.");
    const forgedForeignRouteToken = `${orvex.routeId}-not-a-real-content-token`;
    const forgedContent = await fetchWithHost(
      `http://${router.hostname}:${router.port}/`,
      {headers: {Host: `${forgedForeignRouteToken}.content.example.net`}},
      router.hostname,
      router.port,
    );
    expect(forgedContent.status).toBe(404);
    const alteredContentResponses = await Promise.all([
      `${orvex.routeId}-${version.contentToken.slice(orgB.routeId.length + 1)}`,
      version.contentToken.slice(orgB.routeId.length + 1),
    ].map((alteredToken) => fetchWithHost(
      `http://${router.hostname}:${router.port}/`,
      {headers: {Host: `${alteredToken}.content.example.net`}},
      router.hostname,
      router.port,
    )));
    expect(alteredContentResponses.map(({status}) => status)).toEqual([404, 404]);

    const orgBReviewFrame = await fetch(`${baseUrl}/o/${orgB.slug}/review-frame?embed=1`, {
      headers: host,
    });
    expect(orgBReviewFrame.headers.get("content-security-policy"))
      .toContain("frame-ancestors 'self' https://org-b-embed.example.test");
    const makeEmbedArtifactPublic = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/access?projectId=${projectId}`, {
      body: JSON.stringify({accessSetting: "public_link", expectedCurrentVersionId: version.id}),
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json", "Idempotency-Key": "org-tenancy-embed-public-001"},
      method: "PATCH",
    });
    expect(makeEmbedArtifactPublic.status).toBe(200);
    const orgBEmbed = await fetch(`${baseUrl}/o/${orgB.slug}/embed/artifacts/${artifactId}?path=index.html`, {
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, Referer: "https://org-b-embed.example.test/page"},
    });
    expect(orgBEmbed.status).toBe(200);
    expect(orgBEmbed.headers.get("content-security-policy"))
      .toContain("https://org-b-embed.example.test");
    expect(await orgBEmbed.text()).toContain('name="as-embed-parent" content="https://org-b-embed.example.test"');
    const orgBEmbedSignedIn = await fetch(`${baseUrl}/o/${orgB.slug}/embed/signed-in`, {headers: host});
    expect(orgBEmbedSignedIn.status).toBe(200);
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`UPDATE artifact_installations SET embed_origins = '[]'::jsonb
        WHERE id = ${orgB.id}`;
    }));
    const orgBReviewFrameAfterOriginRemoval = await fetch(`${baseUrl}/o/${orgB.slug}/review-frame?embed=1`, {
      headers: host,
    });
    expect(orgBReviewFrameAfterOriginRemoval.headers.get("content-security-policy"))
      .not.toContain("https://org-b-embed.example.test");

    const refreshedPolicyRoot = `/teams/${orgB.slug}/refreshed/`;
    const currentPolicy = orgB.admissionPolicy;
    if (currentPolicy === null) throw new Error("Org B admission policy is missing.");
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      const updatedPolicy = {
        ...currentPolicy,
        groupRoots: [refreshedPolicyRoot],
        seed: currentPolicy.seed.map((entry) => Object.assign({}, entry, {selector: `${refreshedPolicyRoot}admins`})),
      };
      return yield* sql`UPDATE artifact_installations SET admission_policy = ${JSON.stringify(updatedPolicy)}::jsonb
        WHERE id = ${orgB.id}`;
    }));
    oidc.claims.email = "policy-refresh@example.test";
    oidc.claims.emailVerified = true;
    oidc.claims.groups = ["/teams/not-currently-allowed/admins", `${refreshedPolicyRoot}admins`];
    oidc.claims.subject = "policy-refresh-user";
    const refreshedPolicyLogin = await fetchWithHost(`${baseUrl}/o/${orgB.slug}/auth/login`, {
      headers: host,
      method: "GET",
    }, router.hostname, router.port);
    expect(refreshedPolicyLogin.status).toBe(302);
    const refreshedHandshake = refreshedPolicyLogin.headers.getSetCookie().find((cookie) =>
      cookie.startsWith(`__Host-artifact_login-${orgB.routeId}=`),
    );
    const refreshedAuthorizationUrl = refreshedPolicyLogin.headers.get("location");
    if (refreshedHandshake === undefined || refreshedAuthorizationUrl === null) {
      throw new Error("Policy-refresh login did not issue its organization handshake.");
    }
    const refreshedAuthorization = await fetch(refreshedAuthorizationUrl, {redirect: "manual"});
    const refreshedCallbackLocation = refreshedAuthorization.headers.get("location");
    if (refreshedCallbackLocation === null) throw new Error("Policy-refresh OIDC did not redirect to callback.");
    const refreshedCallback = await fetchWithHost(refreshedCallbackLocation, {
      headers: {...host, Cookie: refreshedHandshake.split(";", 1)[0] ?? ""},
      method: "GET",
    }, router.hostname, router.port);
    expect(refreshedCallback.status).toBe(303);

    const bindingClaims = Buffer.from(JSON.stringify({
      artifactId,
      exp: Math.floor(Date.now() / 1_000) + 60,
      installation_id: installationId,
      jti: randomUUID(),
      mode: "respond",
      questionId: "cross-org-binding",
      versionId: version.id,
    })).toString("base64url");
    const bindingSignature = createHmac("sha256", embedBindingSecret)
      .update(`artifact-embed-v1.${bindingClaims}`).digest("base64url");
    const crossOrgBinding = `${bindingClaims}.${bindingSignature}`;
    const crossOrgResponse = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/responses?projectId=${projectId}`, {
      body: JSON.stringify({embedBinding: crossOrgBinding, questionId: "cross-org-binding", versionId: version.id}),
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json"},
      method: "POST",
    });
    expect(crossOrgResponse.status).toBe(403);
    expect((await crossOrgResponse.json()).error.message)
      .toBe("The embed response binding is invalid or expired.");
    const orgBBinding = Buffer.from(JSON.stringify({
      artifactId,
      exp: Math.floor(Date.now() / 1_000) + 60,
      installation_id: orgB.id,
      jti: randomUUID(),
      mode: "respond",
      questionId: "same-org-binding",
      versionId: version.id,
    })).toString("base64url");
    const orgBBindingSignature = createHmac("sha256", embedBindingSecret)
      .update(`artifact-embed-v1.${orgBBinding}`).digest("base64url");
    const positiveBindingResponse = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/responses?projectId=${projectId}`, {
      body: JSON.stringify({choice: "yes", embedBinding: `${orgBBinding}.${orgBBindingSignature}`, questionId: "same-org-binding", versionId: version.id}),
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json"},
      method: "POST",
    });
    expect(positiveBindingResponse.status).toBe(403);
    expect((await positiveBindingResponse.json()).error.message)
      .toBe("Only members can submit artifact responses.");

    const makePublic = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/access?projectId=${projectId}`, {
      body: JSON.stringify({accessSetting: "public_link", expectedCurrentVersionId: version.id}),
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json", "Idempotency-Key": "org-tenancy-make-public-001"},
      method: "PATCH",
    });
    expect(makePublic.status).toBe(200);
    const publicB = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/public/artifacts/${artifactId}`, {headers: host});
    const publicA = await fetch(`${baseUrl}/o/orvex/api/v1/public/artifacts/${artifactId}`, {headers: host});
    expect(publicB.status).toBe(200);
    expect(publicA.status).toBe(404);

    const invitation = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/artifacts/${artifactId}/guest-invitation?projectId=${projectId}`, {
      headers: {
        ...forwardedHost,
        Cookie: orgBMemberCookie,
        Origin: applicationOrigin,
        "Sec-Fetch-Site": "same-origin",
        "X-CSRF-Token": orgBCsrf,
      },
      method: "POST",
    });
    expect(invitation.status).toBe(201);
    const invitationUrl = z.object({url: z.url()}).parse(await invitation.json()).url;
    const invitationSecret = new URL(invitationUrl).hash.slice("#invite=".length);
    expect(new URL(invitationUrl).pathname).toBe(`/o/${orgB.slug}/review`);
    const invitationDigestRows = await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`SELECT token_digest AS "tokenDigest" FROM guest_review_invitations
        WHERE installation_id = ${orgB.id} AND artifact_id = ${artifactId}`;
    }));
    expect(z.object({tokenDigest: z.string()}).parse(invitationDigestRows[0]).tokenDigest)
      .toBe(createHash("sha256").update(invitationSecret).digest("hex"));
    const foreignGuestExchange = await fetch(`${baseUrl}/o/orvex/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: "Org B guest", secret: invitationSecret}),
      headers: {
        ...host,
        "Content-Type": "application/json",
        Origin: applicationOrigin,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
      },
      method: "POST",
    });
    expect(foreignGuestExchange.status).toBe(404);
    const guestExchange = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/public/artifacts/${artifactId}/guest-session`, {
      body: JSON.stringify({displayName: "Org B guest", secret: invitationSecret}),
      headers: {
        ...host,
        "Content-Type": "application/json",
        Origin: applicationOrigin,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
      },
      method: "POST",
    });
    expect(guestExchange.status).toBe(201);
    const guestCookie = guestExchange.headers.getSetCookie().find((value) =>
      value.startsWith(`__Host-artifact_guest_session-${orgB.routeId}=`),
    );
    if (guestCookie === undefined) throw new Error("Org B guest exchange did not issue its scoped cookie.");
    const ownGuestCurrent = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/public/artifacts/${artifactId}/guest/current`, {
      headers: {...host, Cookie: guestCookie.split(";", 1)[0] ?? ""},
    });
    const foreignGuestCurrent = await fetch(`${baseUrl}/o/orvex/api/v1/public/artifacts/${artifactId}/guest/current`, {
      headers: {...host, Cookie: guestCookie.split(";", 1)[0] ?? ""},
    });
    expect(ownGuestCurrent.status).toBe(201);
    expect(foreignGuestCurrent.status).toBe(404);

    const invalidRegistryId = `invalid-org-${randomUUID()}`;
    await database.run(Effect.gen(function*() {
      const sql = yield* SqlClient;
      return yield* sql`INSERT INTO artifact_installations (
        id, created_at, slug, display_name, status, route_id, admission_policy, embed_origins
      ) VALUES (
        ${invalidRegistryId}, ${new Date().toISOString()},
        ${`invalid-${randomUUID().slice(0, 8)}`}, 'Invalid registry row',
        'active', 'badroute', ${JSON.stringify({seed: [], groupRoots: "invalid"})}::jsonb,
        ${JSON.stringify(["https://not-an-origin.example.test/path"])}::jsonb
      )`;
    }));
    const listedOrganizations = await registry.list();
    expect(listedOrganizations.some(({id}) => id === invalidRegistryId)).toBe(false);
    expect(listedOrganizations.some(({id}) => id === orgB.id)).toBe(true);

    const foreignCloneToken = await fetch(`${baseUrl}/o/orvex/api/v1/projects/${projectId}/artifacts/${artifactId}/history/clone-token`, {
      body: JSON.stringify({ttlSeconds: 60}),
      headers: {...host, Authorization: `Bearer ${apiTokenA}`, "Content-Type": "application/json"},
      method: "POST",
    });
    expect(foreignCloneToken.status).toBe(404);

    const orgAProjectResponse = await fetch(`${baseUrl}/o/orvex/api/v1/projects`, {
      body: JSON.stringify({name: "Orvex clone boundary project"}),
      headers: {...host, Authorization: `Bearer ${apiTokenA}`, "Content-Type": "application/json"},
      method: "POST",
    });
    expect(orgAProjectResponse.status).toBe(201);
    const orgAProjectId = z.object({project: z.object({id: z.string()})})
      .parse(await orgAProjectResponse.json()).project.id;
    const orgAAppFetch = (request: Request) => {
      const target = new URL(request.url);
      target.pathname = `/o/orvex${target.pathname}`;
      return fetch(new Request(new URL(`${target.pathname}${target.search}`, baseUrl), request));
    };
    const orgAArtifactId = await publishOrgBArtifact(
      orgAAppFetch,
      apiTokenA,
      orgAProjectId,
      "orvex",
    );
    const orgAEstimate = await fetch(
      `${baseUrl}/o/orvex/api/v1/projects/${orgAProjectId}/git-history/estimate`,
      {headers: {...host, Authorization: `Bearer ${apiTokenA}`}, method: "POST"},
    );
    expect(orgAEstimate.status).toBe(200);
    const orgAHistoryEnabled = await fetch(
      `${baseUrl}/o/orvex/api/v1/projects/${orgAProjectId}/git-history`,
      {
        body: JSON.stringify({confirmEstimate: true, enabled: true}),
        headers: {...host, Authorization: `Bearer ${apiTokenA}`, "Content-Type": "application/json"},
        method: "PUT",
      },
    );
    expect(orgAHistoryEnabled.status).toBe(200);
    await expect.poll(
      () => orgTenancyGitProvider.repositories.has(orgAArtifactId),
      {timeout: 5_000},
    ).toBe(true);
    const orgACloneCredentialResponse = await fetch(
      `${baseUrl}/o/orvex/api/v1/projects/${orgAProjectId}/artifacts/${orgAArtifactId}/history/clone-token`,
      {
        body: JSON.stringify({ttlSeconds: 60}),
        headers: {...host, Authorization: `Bearer ${apiTokenA}`, "Content-Type": "application/json"},
        method: "POST",
      },
    );
    expect(orgACloneCredentialResponse.status).toBe(201);
    const orgACloneCredential = z.object({remote: z.url(), token: z.string().min(1)})
      .parse(await orgACloneCredentialResponse.json());
    const orgACloneThroughB = await fetch(
      `${baseUrl}/o/${orgB.slug}/api/v1/projects/${orgAProjectId}/artifacts/${orgAArtifactId}/history/clone-token?remote=${encodeURIComponent(orgACloneCredential.remote)}&token=${encodeURIComponent(orgACloneCredential.token)}`,
      {
        body: JSON.stringify({ttlSeconds: 60}),
        headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json"},
        method: "POST",
      },
    );
    expect(orgACloneThroughB.status).toBe(404);

    const crossOrgHttpCases = [
      {expectedStatus: 404, name: "project resource ID", path: `/o/orvex/api/v1/projects/${projectId}`},
      {expectedStatus: 404, name: "artifact resource ID", path: `/o/orvex/api/v1/artifacts/${artifactId}?projectId=${projectId}`},
      {expectedStatus: 401, name: "project list", path: `/o/${orgB.slug}/api/v1/projects`},
      {expectedStatus: 401, name: "administration API-key list", path: `/o/${orgB.slug}/api/v1/api-keys`},
    ] as const;
    const crossOrgResponses = await Promise.all(crossOrgHttpCases.map((crossOrgCase) =>
      fetch(`${baseUrl}${crossOrgCase.path}`, {
        headers: {...host, Authorization: `Bearer ${apiTokenA}`},
      })
    ));
    expect(crossOrgResponses.map(({status}) => status)).toEqual(
      crossOrgHttpCases.map(({expectedStatus}) => expectedStatus),
    );


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
    if (login.status !== 302) throw new Error(`Orvex login failed: HTTP ${login.status} ${await login.text()}`);
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
    const callOrgBTool = async (name: string, args: JsonObject) => {
      const response = await fetchWithHost(`${baseUrl}/o/${orgB.slug}/mcp`, {
        body: JSON.stringify({id: randomUUID(), jsonrpc: "2.0", method: "tools/call", params: {name, arguments: args}}),
        headers: {
          ...host,
          Accept: "application/json, text/event-stream",
          Authorization: `Bearer ${apiTokenB}`,
          "Content-Type": "application/json",
        },
        method: "POST",
      }, router.hostname, router.port);
      expect(response.status).toBe(200);
      const raw = await response.text();
      const dataLine = raw.split("\n").find((line) => line.startsWith("data: "));
      if (dataLine === undefined) throw new Error(`MCP ${name} returned no data event.`);
      return z.object({result: z.object({
        content: z.array(z.object({text: z.string().optional()})).optional(),
        isError: z.boolean().optional(),
        structuredContent: z.unknown().optional(),
      })})
        .parse(JSON.parse(dataLine.slice(6))).result;
    };
    const linkedToolRefusals = await Promise.all([
      callOrgBTool("artifact_link", {
        name: "Unavailable linked source",
        path: "/tmp/org-b-linked-source.html",
        projectId,
      }),
      callOrgBTool("artifact_relink", {
        artifactId,
        expectedSha256: createHash("sha256").update(bytes).digest("hex"),
        path: "/tmp/org-b-linked-source.html",
        projectId,
      }),
    ]);
    for (const refusal of linkedToolRefusals) {
      expect(refusal.isError).toBe(true);
      expect(refusal.structuredContent).toMatchObject({
        error: {code: "CAPABILITY_UNAVAILABLE", message: "Linked artifacts are not available on this deployment."},
      });
      expect(JSON.stringify(refusal.structuredContent)).not.toMatch(/"(?:url|token|remote|browserUrl)"/u);
    }
    const cloneMcpRefusal = await callOrgBTool("artifact_history_clone_token", {
      artifactId,
      projectId,
      ttlSeconds: 60,
    });
    expect(cloneMcpRefusal.isError).toBe(true);
    expect(cloneMcpRefusal.structuredContent).toMatchObject({
      error: {message: "Git history is not available for this artifact."},
    });
    expect(JSON.stringify(cloneMcpRefusal.structuredContent)).not.toMatch(/"(?:url|token|remote|browserUrl)"/u);
    const cloneHttpRefusal = await fetch(`${baseUrl}/o/${orgB.slug}/api/v1/projects/${projectId}/artifacts/${artifactId}/history/clone-token`, {
      body: JSON.stringify({ttlSeconds: 60}),
      headers: {...host, Authorization: `Bearer ${apiTokenB}`, "Content-Type": "application/json"},
      method: "POST",
    });
    expect(cloneHttpRefusal.status).toBe(404);
    const cloneHttpBody = await cloneHttpRefusal.text();
    expect(cloneHttpBody).not.toContain('"token"');
    expect(cloneHttpBody).not.toContain('"remote"');

    const openResult = await callOrgBTool("artifact_open", {
      artifactId,
      projectId,
      versionId: version.id,
    });
    const openOutput = z.object({browserUrl: z.url(), reviewUrl: z.url()})
      .parse(openResult.structuredContent ?? JSON.parse(openResult.content?.[0]?.text ?? "{}"));
    expect(new URL(openOutput.reviewUrl).pathname).toContain(`/o/${orgB.slug}/`);
    expect(new URL(openOutput.browserUrl).hostname.split(".")[0])
      .toMatch(new RegExp(`^${orgB.routeId}-[A-Za-z0-9_-]{16,100}$`, "u"));
    const uploadDigest = createHash("sha256").update(bytes).digest("hex");
    const mcpUploadResult = await callOrgBTool("artifact_create_upload", {
      entryPath: "index.html",
      files: [{mediaType: "text/html; charset=utf-8", path: "index.html", sha256: uploadDigest, size: bytes.byteLength}],
      projectId,
    });
    const mcpUpload = z.object({files: z.array(z.object({uploadUrl: z.url()}))})
      .parse(mcpUploadResult.structuredContent ?? JSON.parse(mcpUploadResult.content?.[0]?.text ?? "{}"));
    expect(new URL(mcpUpload.files[0]?.uploadUrl ?? "").pathname).toContain(`/o/${orgB.slug}/`);
    const orgBUploadUrl = mcpUpload.files[0]?.uploadUrl;
    if (orgBUploadUrl === undefined) throw new Error("Org B upload plan did not return a capability URL.");
    const uploadUrlForOrvex = new URL(orgBUploadUrl);
    uploadUrlForOrvex.pathname = uploadUrlForOrvex.pathname.replace(`/o/${orgB.slug}/`, "/o/orvex/");
    const foreignUploadCapability = await fetchWithHost(uploadUrlForOrvex.toString(), {
      body: new TextDecoder().decode(bytes),
      headers: host,
      method: "PUT",
    }, router.hostname, router.port);
    expect(foreignUploadCapability.status).toBe(404);
    const mcpGuestResult = await callOrgBTool("artifact_enable_guest_invitation", {artifactId, projectId});
    const mcpGuestUrl = z.object({url: z.url()})
      .parse(mcpGuestResult.structuredContent ?? JSON.parse(mcpGuestResult.content?.[0]?.text ?? "{}" )).url;
    expect(new URL(mcpGuestUrl).pathname).toBe(`/o/${orgB.slug}/review`);

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
      const staffOwnerLogin = await roleLogin("owner-a@example.test", "owner-a", ["/owner"]);
      expect(staffOwnerLogin.status).toBe(303);
      const staffOwnerCookies = staffOwnerLogin.headers.getSetCookie();
      const staffOwnerCookie = staffOwnerCookies.map((value) => value.split(";", 1)[0]).join("; ");
      const staffOwnerCsrfPair = staffOwnerCookie.split("; ").find((pair) =>
        pair.slice(0, pair.indexOf("=")).toLowerCase().includes("csrf"),
      );
      const staffOwnerCsrf = staffOwnerCsrfPair?.slice(staffOwnerCsrfPair.indexOf("=") + 1);
      if (staffOwnerCsrf === undefined) throw new Error("The staff owner session has no CSRF token.");
      const staffMember = await new PostgresIdentityRepository(database, orgA.id).admitMember({
        createdAt: new Date().toISOString(),
        displayName: "staff-a",
        email: "staff-a@example.test",
        id: `member_${randomUUID()}`,
        installationId: orgA.id,
        role: "member",
        staff: true,
      });
      const staffHandle = staffMemberOpaqueId(orgA.id, apiTokenA, staffMember.id);
      const staffHeaders = {
        Cookie: staffOwnerCookie, Host: "artifacts.example.com", Origin: "https://artifacts.example.com",
        "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json",
        "X-CSRF-Token": staffOwnerCsrf,
      };
      const admitAttempt = async (email: string) => fetch(`${baseUrl}/o/${aliasA}/api/v1/members`, {
        method: "POST",
        headers: staffHeaders,
        body: JSON.stringify({displayName: "New member", email, role: "member"}),
      });
      const staffAdmissionAttempt = await admitAttempt(staffMember.email);
      const newAddressAdmissionAttempt = await admitAttempt(`not-admittable-${randomUUID()}@example.test`);
      expect(staffAdmissionAttempt.status).toBe(409);
      expect(newAddressAdmissionAttempt.status).toBe(409);
      const staffAdmissionBody = await staffAdmissionAttempt.json();
      expect(staffAdmissionBody).toEqual(await newAddressAdmissionAttempt.json());
      expect(staffAdmissionBody).toEqual({error: {code: "IDENTITY_CONFLICT", message: "Members are managed by your identity provider."}});
      const staffDeactivate = await fetch(`${baseUrl}/o/${aliasA}/api/v1/members/${staffHandle}/deactivate`, {
        method: "POST", headers: staffHeaders, body: "{}",
      });
      expect(staffDeactivate.status).toBe(200);
      const staffDeactivateBody = await staffDeactivate.text();
      assertNoStaffIdentity(staffDeactivateBody, ["staff-a", "staff-a@example.test", staffMember.id]);
      expect(JSON.parse(staffDeactivateBody)).toEqual({member: {id: staffHandle, status: "inactive"}});
      const staffReactivate = await fetch(`${baseUrl}/o/${aliasA}/api/v1/members/${staffHandle}/reactivate`, {
        method: "POST", headers: staffHeaders, body: "{}",
      });
      expect(staffReactivate.status).toBe(200);
      const staffReactivateBody = await staffReactivate.text();
      assertNoStaffIdentity(staffReactivateBody, ["staff-a", "staff-a@example.test", staffMember.id]);
      expect(JSON.parse(staffReactivateBody)).toEqual({member: {id: staffHandle, status: "inactive"}});
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
  method: "GET" | "POST" | "PUT" | "PATCH",
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

const reservedContentPathFiles = [
  {body: '{"ok":true}', mediaType: "application/json", path: "api/x.json"},
  {body: "<main>org path</main>", mediaType: "text/html", path: "o/x.html"},
  {body: "<main>case path</main>", mediaType: "text/html", path: "Auth/index.html"},
] as const;

async function publishOrgPathFilesArtifact(
  appFetch: (request: Request) => Response | Promise<Response>,
  token: string,
  projectId: string,
  orgSlug: string,
  name: string,
): Promise<string> {
  const files = reservedContentPathFiles.map((file) => ({
    mediaType: file.mediaType,
    path: file.path,
    sha256: createHash("sha256").update(file.body).digest("hex"),
    size: Buffer.byteLength(file.body),
  }));
  const uploadResponse = await appFetch(appRequest("/api/v1/uploads", token, "POST", {
    entryPath: reservedContentPathFiles[0].path,
    files,
    projectId,
  }));
  expect(uploadResponse.status).toBe(201);
  const upload = z.object({
    commitUrl: z.url(),
    files: z.array(z.object({path: z.string(), uploadUrl: z.url()})),
  }).parse(await uploadResponse.json());
  const appPath = (url: URL) => url.pathname.replace(`/o/${orgSlug}`, "");
  await Promise.all(upload.files.map(async (planned) => {
    const file = reservedContentPathFiles.find(({path: filePath}) => filePath === planned.path);
    if (file === undefined) throw new Error(`Unexpected staged path ${planned.path}.`);
    const putUrl = new URL(planned.uploadUrl);
    const put = await appFetch(new Request(`${applicationOrigin}${appPath(putUrl)}${putUrl.search}`, {
      body: file.body,
      headers: {Authorization: `Bearer ${token}`, Host: "artifacts.example.com"},
      method: "PUT",
    }));
    expect(put.status, `${putUrl.pathname}: ${await put.clone().text()}`).toBe(200);
  }));
  const commitUrl = new URL(upload.commitUrl);
  const commit = await appFetch(appRequest(
    `${appPath(commitUrl)}${commitUrl.search}`,
    token,
    "POST",
    {target: {accessSetting: "account_required", kind: "new_artifact", name}},
    {"Idempotency-Key": `org-tenancy-${orgSlug}-reserved-paths`},
  ));
  expect(commit.status).toBe(201);
  const committed = z.object({
    artifact: z.object({id: z.string()}),
    version: z.object({id: z.string()}),
  }).parse(await commit.json());
  const access = await appFetch(appRequest(
    `/api/v1/artifacts/${committed.artifact.id}/access?projectId=${projectId}`,
    token,
    "PATCH",
    {accessSetting: "public_link", expectedCurrentVersionId: committed.version.id},
    {"Idempotency-Key": `org-tenancy-${orgSlug}-reserved-paths-public`},
  ));
  expect(access.status).toBe(200);
  return committed.artifact.id;
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
    {"Idempotency-Key": `org-tenancy-${orgSlug}-artifact`},
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

function withoutGitHistory(config: ExternalStorageRuntimeConfig): ExternalStorageRuntimeConfig {
  const {gitHistory, gitHistoryHealthProbe, gitHistoryProvider, ...remaining} = config;
  void gitHistory;
  void gitHistoryHealthProbe;
  void gitHistoryProvider;
  return remaining;
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
    if (init.body === undefined) {
      request.end();
    } else {
      request.end(z.string().parse(init.body));
    }
  });
}

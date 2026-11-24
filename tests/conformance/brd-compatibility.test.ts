import {readFile, readdir} from "node:fs/promises";

import {z} from "zod";
import {expect, test} from "vitest";

const environmentNames = `
ARTIFACT_SERVER_AGENT_NAME ARTIFACT_SERVER_AGENT_TOKEN ARTIFACT_SERVER_API_TOKEN
ARTIFACT_SERVER_AZURE_BLOB_ACCOUNT_URL ARTIFACT_SERVER_AZURE_BLOB_CONTAINER
ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL ARTIFACT_SERVER_BROWSER_COMMAND
ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_ACCOUNT_ID ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_API_TOKEN
ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_API_TOKEN_FILE ARTIFACT_SERVER_CLOUDFLARE_ARTIFACTS_NAMESPACE
ARTIFACT_SERVER_CONTENT_DOMAIN ARTIFACT_SERVER_CREDENTIAL_HELPER ARTIFACT_SERVER_CREDENTIAL_STORE
ARTIFACT_SERVER_CURSOR_MCP_CONFIG ARTIFACT_SERVER_DATA ARTIFACT_SERVER_DATABASE_URL
ARTIFACT_SERVER_DEVELOPMENT_PROXY_CREDENTIAL ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS
ARTIFACT_SERVER_EMBED_BINDING_SECRET ARTIFACT_SERVER_EMBED_BINDING_SECRET_PREVIOUS
ARTIFACT_SERVER_EMBED_ORIGINS ARTIFACT_SERVER_GCS_BUCKET ARTIFACT_SERVER_GCS_PROJECT_ID
ARTIFACT_SERVER_GIT_HISTORY_COPY_LIMIT_BYTES ARTIFACT_SERVER_GIT_HISTORY_PROVIDER
ARTIFACT_SERVER_GIT_HISTORY_STORAGE_BUDGET_BYTES ARTIFACT_SERVER_GIT_HISTORY_VERSION_COPY_LIMIT_BYTES
ARTIFACT_SERVER_HOME ARTIFACT_SERVER_HOST ARTIFACT_SERVER_IMAGE_REVISION ARTIFACT_SERVER_INSTALLATION_ID
ARTIFACT_SERVER_LINKED_FILES ARTIFACT_SERVER_LINK_ROOTS ARTIFACT_SERVER_MCP_UPLOAD_URL_LIFETIME_MS
ARTIFACT_SERVER_OBJECT_STORAGE_PROVIDER ARTIFACT_SERVER_OIDC_ ARTIFACT_SERVER_OIDC_ADMINISTRATOR_GROUPS
ARTIFACT_SERVER_OIDC_API_JWKS_URI ARTIFACT_SERVER_OIDC_API_RESOURCE ARTIFACT_SERVER_OIDC_CLIENT_ID
ARTIFACT_SERVER_OIDC_CLIENT_SECRET ARTIFACT_SERVER_OIDC_CLIENT_SECRET_FILE ARTIFACT_SERVER_OIDC_DIRECTORY_
ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_ID ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET
ARTIFACT_SERVER_OIDC_DIRECTORY_CLIENT_SECRET_FILE ARTIFACT_SERVER_OIDC_DIRECTORY_KEYCLOAK_URL
ARTIFACT_SERVER_OIDC_DIRECTORY_PROVIDER ARTIFACT_SERVER_OIDC_EMBED_BIND_CLIENTS
ARTIFACT_SERVER_OIDC_GROUPS_CLAIM ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED
ARTIFACT_SERVER_OIDC_GUEST_GROUP_PREFIXES ARTIFACT_SERVER_OIDC_ISSUER ARTIFACT_SERVER_OIDC_MEMBER_GROUPS
ARTIFACT_SERVER_OIDC_PROVISIONER_CLIENTS ARTIFACT_SERVER_OIDC_PROVISIONER_GROUP_PREFIXES
ARTIFACT_SERVER_OIDC_SCOPES ARTIFACT_SERVER_OIDC_SERVICE_CLIENTS ARTIFACT_SERVER_ORG_STAFF_GROUPS
ARTIFACT_SERVER_ORG_TENANCY ARTIFACT_SERVER_ORIGIN ARTIFACT_SERVER_PORT
ARTIFACT_SERVER_POSTGRES_MAX_CONNECTIONS ARTIFACT_SERVER_PUBLIC_LINK_KEY
ARTIFACT_SERVER_PUBLIC_LINK_KEY_PREVIOUS ARTIFACT_SERVER_READINESS_WITHDRAWAL_MS
ARTIFACT_SERVER_REQUEST_LOG_SAMPLE_RATE ARTIFACT_SERVER_S3_ACCESS_KEY_ID ARTIFACT_SERVER_S3_BUCKET
ARTIFACT_SERVER_S3_ENDPOINT ARTIFACT_SERVER_S3_FORCE_PATH_STYLE ARTIFACT_SERVER_S3_REGION
ARTIFACT_SERVER_S3_SECRET_ACCESS_KEY ARTIFACT_SERVER_SHUTDOWN_DEADLINE_MS ARTIFACT_SERVER_STAGING_CLEANUP
ARTIFACT_SERVER_STAGING_CLEANUP_BATCH_SIZE ARTIFACT_SERVER_STAGING_CLEANUP_CONCURRENCY
ARTIFACT_SERVER_STAGING_CLEANUP_INTERVAL_MS ARTIFACT_SERVER_STAGING_CLEANUP_SCHEDULE
ARTIFACT_SERVER_STAGING_CLEANUP_SETTLE_DELAY_MS ARTIFACT_SERVER_URL ARTIFACT_SERVER_VSCODE_MCP_CONFIG
ARTIFACT_SERVER_WORKOS_ ARTIFACT_SERVER_WORKOS_API_KEY ARTIFACT_SERVER_WORKOS_API_KEY_FILE
ARTIFACT_SERVER_WORKOS_CLIENT_ID ARTIFACT_SERVER_WORKOS_ISSUER
`.trim().split(/\s+/u).toSorted();

const toolNames = `
artifact_capabilities member_reactivate project_list group_list group_set_role project_create project_sharing
project_share project_unshare project_set_access project_rename project_git_history_status project_git_history_estimate
project_set_git_history artifact_history_clone_token artifact_list artifact_get artifact_open artifact_version_list
artifact_download artifact_diff artifact_create_upload artifact_commit_upload artifact_set_visibility artifact_public_link_get
artifact_public_link_create artifact_public_link_set_permission artifact_public_link_reset artifact_public_link_revoke
artifact_public_link_sessions artifact_public_link_revoke_session artifact_guest_invitation_status artifact_guest_invitation_sessions
artifact_revoke_guest_session artifact_enable_guest_invitation artifact_revoke_guest_invitation artifact_set_tags
artifact_restore_version artifact_delete artifact_link artifact_capture artifact_relink artifact_state_list artifact_state_get
artifact_state_set artifact_state_delete artifact_response_list comment_list comment_get comment_create comment_reply
comment_resolve comment_update comment_delete comment_clear dispatch_inbox
`.trim().split(/\s+/u).toSorted();

const packageSchema = z.object({bin: z.record(z.string(), z.string())});

test("BRD-007-B: binary, environment, MCP, tool, cookie and metadata URL names remain compatible", async () => {
  const packageJson = packageSchema.parse(JSON.parse(await readFile("package.json", "utf8")));
  expect(Object.keys(packageJson.bin)).toEqual(["artifactserver"]);

  const runtimePaths = [
    ...await sourceFiles("src"),
    "integrations/claude-channel/index.ts",
    "integrations/opencode/index.ts",
    "integrations/pi/index.ts",
  ];
  const runtimeFiles = await Promise.all(runtimePaths.map((file) => readFile(file, "utf8")));
  const allRuntimeSource = runtimeFiles.join("\n");
  const foundEnvironmentNames = [...new Set(allRuntimeSource.match(/ARTIFACT_SERVER_[A-Z0-9_]+/gu) ?? [])].toSorted();
  expect(foundEnvironmentNames).toEqual(environmentNames);

  const mcpServer = await readFile("src/mcp/artifact-mcp-server.ts", "utf8");
  expect(mcpServer.match(/\{name: "([^"]+)"/u)?.[1] ?? null).toBe("artifact-server");
  const foundToolNames = [...mcpServer.matchAll(/\bregisterNudgedTool\(\s*"([^"]+)"/gu)]
    .flatMap((match) => match[1] === undefined ? [] : [match[1]]).toSorted();
  expect(foundToolNames).toEqual(toolNames);

  const httpSource = await readFile("src/http/create-http-app.ts", "utf8");
  const cookieNames = [...httpSource.matchAll(/const\s+\w+Cookie\s*=\s*"([^"]+)"/gu)]
    .flatMap((match) => match[1] === undefined ? [] : [match[1]]).toSorted();
  expect(cookieNames).toEqual([
    "__Host-artifact_csrf",
    "__Host-artifact_guest_csrf",
    "__Host-artifact_guest_session",
    "__Host-artifact_login",
    "__Host-artifact_session",
    "artifact_csrf",
    "artifact_guest_csrf",
    "artifact_guest_session",
    "artifact_login",
    "artifact_session",
  ]);

  const oauthSource = await readFile("src/cli/cli-oauth-client.ts", "utf8");
  expect(oauthSource.match(/clientMetadataUrl\s*=\s*"([^"]+)"/u)?.[1] ?? null)
    .toBe("https://artifactserver.com/oauth/client-metadata.json");
});

test("BRD-007-F: a changed compatibility name differs from the established snapshot", () => {
  const compareNames = (actual: readonly string[], expected: readonly string[]) =>
    actual.toSorted().join("\n") === expected.toSorted().join("\n");
  expect(compareNames(["artifactserver-v2"], ["artifactserver"])).toBe(false);
  expect(compareNames(environmentNames, [...environmentNames, "ARTIFACT_SERVER_NEW"])).toBe(false);
  expect(compareNames(toolNames, toolNames.slice(1))).toBe(false);
});

async function sourceFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, {withFileTypes: true});
  const nested = await Promise.all(entries.map(async (entry) => {
    const file = `${root}/${entry.name}`;
    if (entry.isDirectory()) return sourceFiles(file);
    return entry.name.endsWith(".ts") ? [file] : [];
  }));
  return nested.flat();
}

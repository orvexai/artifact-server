import {Effect, Layer, ManagedRuntime} from "effect";
import {expect, test} from "vitest";
import path from "node:path";

import {InteractiveLoginService} from "../../src/application/interactive-login.js";
import type {ApplicationRuntime} from "../../src/application/application-runtime.js";
import type {ExternalIdentity} from "../../src/core/installation-identity.js";
import {SystemClock, SystemIdGenerator} from "../../src/core/system.js";
import {LocalBlobStore} from "../../src/storage/local-blob-store.js";
import {LocalStagingStore} from "../../src/storage/local-staging-store.js";
import {SqliteArtifactRepository} from "../../src/storage/sqlite-artifact-repository.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";
import {createApplicationLayer} from "../../src/local/create-local-application-layer.js";
import {createHttpApp} from "../../src/http/create-http-app.js";
import {
  createTestInstallation,
  removeTestInstallation,
} from "../support/runtime-harness.js";

test("AUTH-030-F: a refused organization callback renders the styled denied page without redirecting", async () => {
  const installation = await createTestInstallation();
  const installationId = "tenant-test";
  const databasePath = path.join(installation.dataDirectory, "artifact-server.db");
  const repository = new SqliteArtifactRepository(databasePath, installationId);
  const identityRepository = new SqliteIdentityRepository(databasePath);
  const blobs = new LocalBlobStore(path.join(installation.dataDirectory, "blobs"));
  const staging = new LocalStagingStore(path.join(installation.dataDirectory, "staging"));
  let identity: ExternalIdentity = {
    displayName: "Tenant User", email: "tenant.user@example.test", emailVerified: true, groups: null,
    organizationMembership: {alias: "tenant", id: "tenant-id", role: null},
    provider: "keycloak", subject: "subject",
  };
  const loginService = {
    complete: () => Effect.die(new Error("Unused login operation.")),
    completeIdentity: () => Effect.succeed({identity, returnTo: "/o/tenant/"}),
    start: () => Effect.die(new Error("Unused login operation.")),
  } satisfies InteractiveLoginService["Service"];
  const layer = Layer.mergeAll(
    createApplicationLayer({
      apiToken: null, blobs, bootstrapAdministratorEmail: null,
      clock: new SystemClock(), dispatches: repository,
      externalApiBearerVerifier: null, externalApiOAuthVerifier: null,
      externalMcpBearerVerifier: null, externalMcpOAuthVerifier: null,
      ids: new SystemIdGenerator(), identityRepository, installationId,
      interactiveIdentityProvider: null, localBootstrapCredential: null,
      organizationAdmission: {alias: "tenant", id: "tenant-id"},
      protectBootstrapAdministrator: false, repository, staging,
    }),
    Layer.succeed(InteractiveLoginService, loginService),
  );
  const applicationRuntime: ApplicationRuntime = ManagedRuntime.make(layer);
  const app = createHttpApp({
    applicationRuntime, blobs,
    browserAccess: {loginKind: "oidc", mode: "private_team"},
    completedRequestLogSampleRate: 0, contentDomain: "files.example.test",
    organizationSlug: "tenant", trustedApplicationOrigin: null,
  });
  try {
    const response = await app.request(
      "/auth/callback?code=valid-code&state=0123456789abcdef",
      {headers: {accept: "text/html", cookie: "artifact_login=valid-handshake"}},
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.has("location")).toBe(false);
    const html = await response.text();
    expect(html).toContain("Sign-in unavailable");
    expect(html).toContain("/o/tenant/assets/fonts/houston/");

    identity = {
      ...identity,
      organizationMembership: {alias: "tenant", id: "tenant-id", role: "viewer"},
    };
    const admitted = await app.request(
      "/auth/callback?code=valid-code&state=0123456789abcdef",
      {headers: {accept: "text/html", cookie: "artifact_login=valid-handshake"}},
    );
    expect(admitted.status).toBe(303);
    expect(admitted.headers.has("location")).toBe(true);
    expect(await admitted.text()).not.toContain("Sign-in unavailable");
  } finally {
    await applicationRuntime.dispose();
    identityRepository.close();
    repository.close();
    await removeTestInstallation(installation);
  }
});

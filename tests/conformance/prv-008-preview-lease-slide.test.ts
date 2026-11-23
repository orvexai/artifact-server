import {mkdtemp, mkdir, rm} from "node:fs/promises";
import {createHash} from "node:crypto";
import path from "node:path";

import {Effect, ManagedRuntime, Redacted, Result} from "effect";
import {afterEach, beforeEach, describe, expect, test} from "vitest";

import type {ApplicationRuntime} from "../../src/application/application-runtime.js";
import {ContentAccessService} from "../../src/application/content-access.js";
import {StagedUploadService} from "../../src/application/staged-upload.js";
import {
  membershipRoles,
  principalCapabilities,
  principalKinds,
  type Principal,
} from "../../src/core/identity.js";
import type {Clock} from "../../src/core/ports.js";
import {SystemIdGenerator} from "../../src/core/system.js";
import {createLocalApplicationLayer} from "../../src/local/create-local-application-layer.js";
import {LocalBlobStore} from "../../src/storage/local-blob-store.js";
import {LocalStagingStore} from "../../src/storage/local-staging-store.js";
import {SqliteArtifactRepository} from "../../src/storage/sqlite-artifact-repository.js";
import {SqliteIdentityRepository} from "../../src/storage/sqlite-identity-repository.js";

const installationId = "local";
const start = new Date("2026-11-23T00:00:00.000Z");

describe("PRV-008 preview lease renewal", () => {
  let clock: ControlledClock;
  let dataDirectory: string;
  let repository: SqliteArtifactRepository;
  let identityRepository: SqliteIdentityRepository;
  let runtime: ApplicationRuntime;
  let published: Awaited<ReturnType<typeof publishPrivateArtifact>>;

  beforeEach(async () => {
    const cacheDirectory = path.join(process.cwd(), "node_modules/.cache");
    await mkdir(cacheDirectory, {recursive: true});
    dataDirectory = await mkdtemp(path.join(cacheDirectory, "prv-008-"));
    clock = new ControlledClock(start);
    const databasePath = path.join(dataDirectory, "artifact-server.db");
    repository = new SqliteArtifactRepository(databasePath);
    identityRepository = new SqliteIdentityRepository(databasePath);
    runtime = ManagedRuntime.make(createLocalApplicationLayer({
      apiToken: Redacted.make("prv-008-test-api-token"),
      blobs: new LocalBlobStore(path.join(dataDirectory, "blobs")),
      bootstrapAdministratorEmail: "admin@example.test",
      clock,
      dispatches: repository,
      externalApiBearerVerifier: null,
      externalApiOAuthVerifier: null,
      externalMcpBearerVerifier: null,
      externalMcpOAuthVerifier: null,
      ids: new SystemIdGenerator(),
      identityRepository,
      installationId,
      interactiveIdentityProvider: null,
      localBootstrapCredential: null,
      protectBootstrapAdministrator: false,
      repository,
      staging: new LocalStagingStore(path.join(dataDirectory, "staging")),
    }));
    await runtime.context();
    published = await publishPrivateArtifact(runtime);
  });

  afterEach(async () => {
    await runtime.dispose();
    identityRepository.close();
    repository.close();
    await rm(dataDirectory, {force: true, recursive: true});
  });

  test("PRV-008-B: an active human preview lease slides under five minutes and stops at the eight-hour cap", async () => {
    const principal = await admitHuman("member-prv008-b");
    const issuedAt = clock.now();
    const lease = await issueLease(principal);

    clock.set(minutesAfter(issuedAt, 10));
    await readLease(lease.token);
    expect(await currentLease(lease.token)).toMatchObject({
      createdAt: issuedAt.toISOString(),
      expiresAt: minutesAfter(issuedAt, 15).toISOString(),
    });

    clock.set(minutesAfter(issuedAt, 11));
    await readLease(lease.token);
    expect(await currentLease(lease.token)).toMatchObject({
      expiresAt: minutesAfter(issuedAt, 26).toISOString(),
    });

    const hardCap = new Date(issuedAt.getTime() + 8 * 60 * 60_000);
    const slideTimes = [
      ...Array.from({length: 42}, (_, index) => 22 + index * 11),
      477,
    ];
    await slideTimes.reduce(async (previous, elapsedMinutes) => {
      await previous;
      clock.set(minutesAfter(issuedAt, elapsedMinutes));
      await readLease(lease.token);
      const row = await currentLease(lease.token);
      expect(row).not.toBeNull();
      expect(Date.parse(row?.expiresAt ?? "")).toBeLessThanOrEqual(hardCap.getTime());
    }, Promise.resolve());

    expect((await currentLease(lease.token))?.expiresAt).toBe(hardCap.toISOString());
    clock.set(hardCap);
    await expectFailure("ContentSessionRequired", lease.token);
    expect(await repository.extendPreviewLease(
      digest(lease.token),
      clock.now().toISOString(),
      new Date(hardCap.getTime() + 15 * 60_000).toISOString(),
    )).toBe(false);
  });

  test("PRV-008-F: revoked, unauthorized, non-human, and expired leases are served without sliding or revival", async () => {
    const deactivatedPrincipal = await admitHuman("member-prv008-deactivated");
    const deactivatedLease = await issueLease(deactivatedPrincipal);
    const deactivatedExpiry = deactivatedLease.expiresAt;
    clock.set(minutesAfter(start, 11));
    await identityRepository.deactivateMember(
      installationId,
      deactivatedPrincipal.id,
      clock.now().toISOString(),
    );
    await readLease(deactivatedLease.token);
    expect((await currentLease(deactivatedLease.token))?.expiresAt).toBe(deactivatedExpiry);

    clock.set(start);
    const removedAccessPrincipal = await admitHuman("member-prv008-project-access");
    const removedAccessLease = await issueLease(removedAccessPrincipal);
    const removedAccessExpiry = removedAccessLease.expiresAt;
    await identityRepository.setProjectAccessMode(
      installationId,
      published.artifact.projectId,
      "restricted",
    );
    clock.set(minutesAfter(start, 11));
    await readLease(removedAccessLease.token);
    expect((await currentLease(removedAccessLease.token))?.expiresAt).toBe(removedAccessExpiry);

    await identityRepository.setProjectAccessMode(
      installationId,
      published.artifact.projectId,
      "installation",
    );
    clock.set(start);
    const apiKeyLease = await issueLease(servicePrincipal);
    const apiKeyExpiry = apiKeyLease.expiresAt;
    clock.set(minutesAfter(start, 11));
    await readLease(apiKeyLease.token);
    expect((await currentLease(apiKeyLease.token))?.expiresAt).toBe(apiKeyExpiry);

    clock.set(start);
    const expiredPrincipal = await admitHuman("member-prv008-expired");
    const expiredLease = await issueLease(expiredPrincipal);
    clock.set(new Date(expiredLease.expiresAt));
    await expectFailure("ContentSessionRequired", expiredLease.token);
    expect(await repository.extendPreviewLease(
      digest(expiredLease.token),
      clock.now().toISOString(),
      minutesAfter(clock.now(), 15).toISOString(),
    )).toBe(false);
    expect(await repository.findPreviewLease(
      digest(expiredLease.token),
      clock.now().toISOString(),
    )).toBeNull();
  });

  async function admitHuman(id: string): Promise<Principal> {
    const member = await identityRepository.admitMember({
      createdAt: clock.now().toISOString(),
      displayName: id,
      email: `${id}@example.test`,
      id,
      installationId,
      role: membershipRoles.member,
    });
    return {
      authorizedByPrincipalId: null,
      capabilities: [],
      displayName: member.displayName,
      email: member.email,
      id: member.id,
      installationId: member.installationId,
      kind: principalKinds.human,
      membershipRole: member.role,
    };
  }

  async function issueLease(principal: Principal) {
    return runtime.runPromise(ContentAccessService.use((service) =>
      service.issuePreviewLease({
        artifactId: published.artifact.id,
        principal,
        projectId: published.artifact.projectId,
        versionId: published.version.id,
      })
    ));
  }

  async function readLease(token: Redacted.Redacted): Promise<void> {
    const result = await runtime.runPromise(Effect.result(
      ContentAccessService.use((service) => service.authorizePreviewContent({
        fallback: "entry",
        path: "index.html",
        token,
      }))
    ));
    expect(Result.isSuccess(result)).toBe(true);
  }

  async function expectFailure(tag: string, token: Redacted.Redacted): Promise<void> {
    const result = await runtime.runPromise(Effect.result(
      ContentAccessService.use((service) => service.authorizePreviewContent({
        fallback: "entry",
        path: "index.html",
        token,
      }))
    ));
    expect(Result.match(result, {
      onFailure: (failure) => failure._tag,
      onSuccess: () => "UnexpectedSuccess",
    })).toBe(tag);
  }

  async function currentLease(token: Redacted.Redacted) {
    return repository.findPreviewLease(digest(token), clock.now().toISOString());
  }
});

const servicePrincipal: Principal = {
  authorizedByPrincipalId: null,
  capabilities: [
    principalCapabilities.createArtifact,
    principalCapabilities.issueContentSession,
    principalCapabilities.publishAnyArtifact,
  ],
  displayName: "PRV-008 content fixture",
  id: "prv-008-service-principal",
  installationId,
  kind: principalKinds.service,
  membershipRole: membershipRoles.member,
};

async function publishPrivateArtifact(runtime: ApplicationRuntime) {
  const bytes = new TextEncoder().encode("<!doctype html><title>Private preview</title>");
  const upload = await runtime.runPromise(
    StagedUploadService.use((service) => service.createUpload({
      entryPath: "index.html",
      files: [{
        mediaType: "text/html; charset=utf-8",
        path: "index.html",
        sha256: createHash("sha256").update(bytes).digest("hex"),
        size: bytes.byteLength,
      }],
      principal: servicePrincipal,
      projectId: null,
    })),
  );
  const file = upload.files[0];
  if (file === undefined) throw new Error("The PRV-008 fixture upload has no file.");
  await runtime.runPromise(
    StagedUploadService.use((service) => service.uploadFile({
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }),
      principal: servicePrincipal,
      projectId: null,
      storageToken: file.storageToken,
      uploadId: upload.id,
    })),
  );
  return runtime.runPromise(
    StagedUploadService.use((service) => service.commitUpload({
      idempotencyKey: "prv-008-private-preview",
      principal: servicePrincipal,
      projectId: null,
      target: {
        accessSetting: "account_required",
        kind: "new_artifact",
        name: "PRV-008 preview fixture",
      },
      uploadId: upload.id,
    })),
  );
}

function digest(token: Redacted.Redacted): string {
  return createHash("sha256").update(Redacted.value(token)).digest("hex");
}

function minutesAfter(instant: Date, minutes: number): Date {
  return new Date(instant.getTime() + minutes * 60_000);
}

class ControlledClock implements Clock {
  #current: Date;

  constructor(initial: Date) {
    this.#current = new Date(initial);
  }

  now(): Date {
    return new Date(this.#current);
  }

  set(current: Date): void {
    this.#current = new Date(current);
  }
}

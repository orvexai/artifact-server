import {Effect, Redacted} from "effect";
import {DatabaseSync} from "node:sqlite";
import nodePath from "node:path";
import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {z} from "zod";

import type {BearerCredentialVerifier} from
  "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";
import {
  apiHeaders,
  createTestInstallation,
  fetchVersion,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
  openProjectToMembers,
} from "../support/runtime-harness.js";
import {
  publishNew,
  publishVersion,
  type PublishResponse,
} from "../support/publishing.js";

const administratorToken = "trusted-installation-administrator";
const publicLinkItemSchema = z.object({
  artifact: z.object({
    accessSetting: z.enum(["public_link", "account_required"]),
    currentVersionId: z.string(),
    id: z.string(),
    name: z.string(),
    projectId: z.string(),
  }),
  kind: z.enum(["legacy", "secret"]),
  currentVersion: z.object({
    createdAt: z.string(),
    id: z.string(),
    number: z.number().int().positive(),
  }),
  links: z.object({public: z.url()}),
  project: z.object({
    archivedAt: z.string().nullable(),
    id: z.string(),
    name: z.string(),
  }),
  secretLink: z.object({
    createdAt: z.string(),
    generation: z.number().int().positive(),
    invitationId: z.string(),
    permission: z.enum(["view", "comment"]),
    updatedAt: z.string(),
  }).nullable(),
});
const publicLinkPageSchema = z.object({
  nextCursor: z.string().nullable(),
  publicLinks: z.array(publicLinkItemSchema),
});
const mutationResultSchema = z.discriminatedUnion("status", [
  z.object({
    artifactId: z.string(),
    currentVersionId: z.string(),
    projectId: z.string(),
    replayed: z.boolean(),
    status: z.literal("made_private"),
  }),
  z.object({
    artifactId: z.string(),
    error: z.object({code: z.string(), message: z.string()}),
    expectedCurrentVersionId: z.string(),
    projectId: z.string(),
    retry: z.enum(["not_retryable", "refresh_current_version", "same_command"]),
    status: z.literal("failed"),
  }),
  z.object({
    artifactId: z.string(),
    expectedGeneration: z.number().int().positive(),
    projectId: z.string(),
    status: z.enum(["revoked", "stale_generation"]),
  }),
]);
const mutationResponseSchema = z.object({
  results: z.array(mutationResultSchema),
  summary: z.object({
    failed: z.number().int().nonnegative(),
    requested: z.number().int().positive(),
    succeeded: z.number().int().nonnegative(),
  }),
  warning: z.string(),
});

describe("public-link administration", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;

  beforeEach(async () => {
    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      externalApiBearerVerifier: administratorVerifier,
    });
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  test("installation administrators can turn public links off and back on", async () => {
    const read = await administratorFetch("/api/v1/administration/public-links/policy");
    expect(read.status).toBe(200);
    expect(await read.json()).toEqual({enabled: true});

    const disabled = await administratorFetch("/api/v1/administration/public-links/policy", {
      body: JSON.stringify({enabled: false}),
      method: "PATCH",
    });
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toEqual({enabled: false});

    const resumed = await administratorFetch("/api/v1/administration/public-links/policy", {
      body: JSON.stringify({enabled: true}),
      method: "PATCH",
    });
    expect(resumed.status).toBe(200);
    expect(await resumed.json()).toEqual({enabled: true});
  });

  test("AUTH-018-B: administrators page across projects and make one public artifact private", async () => {
    const projectA = await createProject("Product");
    const projectB = await createProject("Support");
    const published = [
      await publicArtifact("Default public", "public-admin-default", "prj_default"),
      await publicArtifact("Product one", "public-admin-product-one", projectA.id),
      await publicArtifact("Product two", "public-admin-product-two", projectA.id),
      await publicArtifact("Support one", "public-admin-support-one", projectB.id),
      await publicArtifact("Support two", "public-admin-support-two", projectB.id),
    ];
    await publishNew(server, installation, {
      accessSetting: "account_required",
      content: "private inventory exclusion",
      idempotencyKey: "public-admin-private-exclusion",
      name: "Private exclusion",
      projectId: projectB.id,
    });

    const pages = await listEveryPublicLink(2);
    const inventory = pages.flatMap((page) => page.publicLinks);
    expect(pages.length).toBe(3);
    expect(inventory).toHaveLength(5);
    expect(new Set(inventory.map(({artifact}) => artifact.id)).size).toBe(5);
    expect(new Set(inventory.map(({project}) => project.name))).toEqual(
      new Set(["Default", "Product", "Support"]),
    );
    expect(inventory.every(({artifact, currentVersion}) =>
      artifact.currentVersionId === currentVersion.id
    )).toBe(true);
    expect(inventory.every(({links}) => links.public.includes("/artifacts/")))
      .toBe(true);

    const target = published[1];
    if (target === undefined) throw new Error("The single-mutation fixture is missing.");
    const response = await makePrivate([privateCommand(
      target,
      "public-admin-single-private",
    )]);
    expect(response.status).toBe(200);
    const body = mutationResponseSchema.parse(await response.json());
    expect(body.summary).toEqual({failed: 0, requested: 1, succeeded: 1});
    expect(body.results).toEqual([
      expect.objectContaining({
        artifactId: target.artifact.id,
        replayed: false,
        status: "made_private",
      }),
    ]);
    expect(body.warning).toContain("cannot be recalled");

    const refreshed = (await listEveryPublicLink(100)).flatMap((page) =>
      page.publicLinks
    );
    expect(refreshed.map(({artifact}) => artifact.id)).not.toContain(
      target.artifact.id,
    );
    await expectNoPublicBytes(target);
    const actions = await administratorFetch(
      `/api/v1/artifacts/${target.artifact.id}/actions?projectId=${target.artifact.projectId}`,
    );
    expect(actions.status).toBe(200);
    const actionRecords = z.object({
      actions: z.array(z.object({
        action: z.string(),
        principalId: z.string(),
        versionId: z.string(),
      }).passthrough()),
    }).parse(await actions.json()).actions;
    expect(actionRecords).toContainEqual(expect.objectContaining({
        action: "change_access",
        principalId: "installation-administrator",
        versionId: target.version.id,
    }));
  });

  test("AUTH-018-F: bulk shutdown rejects invalid requests and preserves partial-failure retry semantics", async () => {
    const published = await publicArtifact(
      "Authorization fixture",
      "public-admin-authorization-fixture",
    );
    const deniedInventory = await fetch(
      `${server.baseUrl}/api/v1/administration/public-links`,
      {headers: apiHeaders(installation, "unused-public-inventory-key")},
    );
    expect(deniedInventory.status).toBe(403);
    await expect(deniedInventory.json()).resolves.toMatchObject({
      error: {code: "AUTHORIZATION_DENIED"},
    });

    const deniedMutation = await fetch(
      `${server.baseUrl}/api/v1/administration/public-links/make-private`,
      {
        body: JSON.stringify({
          items: [privateCommand(published, "public-admin-denied-mutation")],
        }),
        headers: apiHeaders(installation, "unused-public-bulk-key"),
        method: "POST",
      },
    );
    expect(deniedMutation.status).toBe(403);
    expect((await fetch(published.links.artifact, {redirect: "manual"})).status)
      .toBe(302);

    const oversized = await makePrivate(Array.from({length: 101}, (_, index) => ({
      artifactId: `oversized-artifact-${index}`,
      expectedCurrentVersionId: `oversized-version-${index}`,
      idempotencyKey: `oversized-public-link-item-${index}`,
      projectId: "prj_default",
    })));
    expect(oversized.status).toBe(422);
    await expect(oversized.json()).resolves.toMatchObject({
      error: {code: "INVALID_INPUT"},
    });
    expect((await fetch(published.links.artifact, {redirect: "manual"})).status)
      .toBe(302);

    const duplicate = await makePrivate([
      privateCommand(published, "public-admin-duplicate-first"),
      privateCommand(published, "public-admin-duplicate-second"),
    ]);
    expect(duplicate.status).toBe(422);
    await expect(duplicate.json()).resolves.toMatchObject({
      error: {code: "INVALID_INPUT"},
    });
    expect((await fetch(published.links.artifact, {redirect: "manual"})).status)
      .toBe(302);

    const first = await publicArtifact(
      "Bulk first",
      "public-admin-bulk-first",
    );
    const stale = await publicArtifact(
      "Bulk stale",
      "public-admin-bulk-stale",
    );
    const third = await publicArtifact(
      "Bulk third",
      "public-admin-bulk-third",
    );
    const staleUpdate = await publishVersion(server, installation, {
      artifactId: stale.artifact.id,
      content: "updated while the administrator held a selection",
      expectedCurrentVersionId: stale.version.id,
      idempotencyKey: "public-admin-bulk-stale-update",
    });

    const firstAttempt = await makePrivate([
      privateCommand(first, "public-admin-bulk-first-private"),
      privateCommand(stale, "public-admin-bulk-stale-private"),
      privateCommand(third, "public-admin-bulk-third-private"),
    ]);
    const partial = mutationResponseSchema.parse(await firstAttempt.json());
    expect(partial.summary).toEqual({failed: 1, requested: 3, succeeded: 2});
    expect(partial.results).toEqual(expect.arrayContaining([
      expect.objectContaining({artifactId: first.artifact.id, status: "made_private"}),
      expect.objectContaining({artifactId: third.artifact.id, status: "made_private"}),
      expect.objectContaining({
        artifactId: stale.artifact.id,
        error: {code: "ARTIFACT_MUTATION_CONFLICT", message: expect.any(String)},
        retry: "refresh_current_version",
        status: "failed",
      }),
    ]));
    expect(partial.warning).toContain("cannot be recalled");
    await Promise.all([
      expectNoPublicBytes(first),
      expectNoPublicBytes(third),
    ]);
    expect((await fetch(stale.links.artifact, {redirect: "manual"})).status).toBe(302);

    const retryCommand = privateCommand(
      staleUpdate.body,
      "public-admin-bulk-stale-retry",
    );
    const retry = mutationResponseSchema.parse(await (await makePrivate([
      retryCommand,
    ])).json());
    expect(retry.summary).toEqual({failed: 0, requested: 1, succeeded: 1});
    expect(retry.results[0]).toMatchObject({replayed: false, status: "made_private"});
    const replay = mutationResponseSchema.parse(await (await makePrivate([
      retryCommand,
    ])).json());
    expect(replay.results[0]).toMatchObject({replayed: true, status: "made_private"});

    await expectNoPublicBytes(staleUpdate.body);
  });

  test("PLK-023-B: inventory exposes secret-link metadata without secret material", async () => {
    const legacy = await publicArtifact("Legacy inventory", "public-admin-legacy-inventory");
    const published = await privateArtifact("Secret inventory", "public-admin-secret-inventory");
    const created = await administratorFetch(
      `/api/v1/artifacts/${published.artifact.id}/public-link?projectId=${published.artifact.projectId}`,
      {body: JSON.stringify({permission: "view"}), method: "POST"},
    );
    expect(created.status).toBe(201);
    const archived = await fetch(`${server.baseUrl}/api/v1/projects/${published.artifact.projectId}/archive`, {
      headers: apiHeaders(installation, "unused-public-admin-archive"),
      method: "POST",
    });
    expect(archived.status).toBe(200);
    const page = (await listEveryPublicLink(100)).flatMap(({publicLinks}) => publicLinks);
    const legacyItem = page.find(({artifact}) => artifact.id === legacy.artifact.id);
    expect(legacyItem).toMatchObject({kind: "legacy", secretLink: null});
    const item = page.find(({artifact}) => artifact.id === published.artifact.id);
    expect(item).toMatchObject({
      kind: "secret",
      project: {archivedAt: expect.any(String)},
      secretLink: {
        createdAt: expect.any(String), generation: 1, invitationId: expect.any(String),
        permission: "view", updatedAt: expect.any(String),
      },
    });
    const serialized = JSON.stringify(item);
    expect(serialized).not.toMatch(/sealedSecret|tokenDigest|#invite=/i);
    expect(serialized).not.toContain(new URL(z.object({url: z.url()}).parse(await created.json()).url).hash);
  });

  test("PLK-023-F: inventory refuses non-admins and omits deleted or revoked secret links", async () => {
    const published = await privateArtifact("Rotating inventory", "public-admin-secret-stale");
    const created = await administratorFetch(
      `/api/v1/artifacts/${published.artifact.id}/public-link?projectId=${published.artifact.projectId}`,
      {body: JSON.stringify({permission: "comment"}), method: "POST"},
    );
    expect(created.status).toBe(201);
    const before = (await listEveryPublicLink(100)).flatMap(({publicLinks}) => publicLinks)
      .find(({artifact}) => artifact.id === published.artifact.id)?.secretLink;
    if (before === null || before === undefined) throw new Error("Secret inventory metadata was missing.");
    const deniedList = await fetch(`${server.baseUrl}/api/v1/administration/public-links`, {
      headers: apiHeaders(installation, "unused-public-inventory-denial"),
    });
    expect(deniedList.status).toBe(403);
    const deniedSecretRevoke = await fetch(`${server.baseUrl}/api/v1/administration/public-links/make-private`, {
      body: JSON.stringify({items: [{artifactId: published.artifact.id, generation: before.generation, kind: "secret", projectId: published.artifact.projectId}]}),
      headers: apiHeaders(installation, "unused-public-secret-denial"),
      method: "POST",
    });
    expect(deniedSecretRevoke.status).toBe(403);
    const reset = await administratorFetch(
      `/api/v1/artifacts/${published.artifact.id}/public-link/reset?projectId=${published.artifact.projectId}`,
      {body: JSON.stringify({permission: "view"}), method: "POST"},
    );
    expect(reset.status).toBe(201);
    const stale = await makePrivate([{
      artifactId: published.artifact.id,
      generation: before.generation,
      kind: "secret",
      projectId: published.artifact.projectId,
    }]);
    expect(stale.status).toBe(200);
    expect(await stale.json()).toMatchObject({results: [{
      artifactId: published.artifact.id,
      expectedGeneration: before.generation,
      status: "stale_generation",
    }], summary: {failed: 1, requested: 1, succeeded: 0}});
    const after = (await listEveryPublicLink(100)).flatMap(({publicLinks}) => publicLinks)
      .find(({artifact}) => artifact.id === published.artifact.id)?.secretLink;
    expect(after).toMatchObject({generation: before.generation + 1, permission: "view"});
    const revoked = await makePrivate([{
      artifactId: published.artifact.id,
      generation: before.generation + 1,
      kind: "secret",
      projectId: published.artifact.projectId,
    }]);
    expect(await revoked.json()).toMatchObject({results: [{status: "revoked"}], summary: {failed: 0, requested: 1, succeeded: 1}});
    const afterRevoke = (await listEveryPublicLink(100)).flatMap(({publicLinks}) => publicLinks);
    expect(afterRevoke.some(({artifact}) => artifact.id === published.artifact.id)).toBe(false);

    const deleted = await privateArtifact("Deleted inventory", "public-admin-secret-deleted");
    const deletedInvitation = await administratorFetch(
      `/api/v1/artifacts/${deleted.artifact.id}/public-link?projectId=${deleted.artifact.projectId}`,
      {body: JSON.stringify({permission: "view"}), method: "POST"},
    );
    expect(deletedInvitation.status).toBe(201);
    const database = new DatabaseSync(nodePath.join(installation.dataDirectory, "artifact-server.db"));
    database.prepare("UPDATE artifacts SET deleted_at = ? WHERE id = ?")
      .run(new Date().toISOString(), deleted.artifact.id);
    database.close();
    const afterDelete = (await listEveryPublicLink(100)).flatMap(({publicLinks}) => publicLinks);
    expect(afterDelete.some(({artifact}) => artifact.id === deleted.artifact.id)).toBe(false);
  });

  async function publicArtifact(
    name: string,
    idempotencyKey: string,
    projectId?: string,
  ): Promise<PublishResponse> {
    const base = {
      accessSetting: "public_link",
      content: `${name} bytes`,
      idempotencyKey,
      name,
    } as const;
    return (await publishNew(
      server,
      installation,
      projectId === undefined ? base : {...base, projectId},
    )).body;
  }

  async function privateArtifact(
    name: string,
    idempotencyKey: string,
  ): Promise<PublishResponse> {
    return (await publishNew(server, installation, {
      accessSetting: "account_required",
      content: `${name} bytes`,
      idempotencyKey,
      name,
    })).body;
  }

  async function createProject(name: string): Promise<{readonly id: string}> {
    const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
      body: JSON.stringify({name}),
      headers: apiHeaders(installation, `unused-project-${name}`),
      method: "POST",
    });
    expect(response.status).toBe(201);
    const project = z.object({project: z.object({id: z.string()})})
      .parse(await response.json()).project;
    await openProjectToMembers(server, installation, project.id);
    return project;
  }

  async function listEveryPublicLink(limit: number) {
    const loadPage = async (
      cursor: string | null,
      pages: readonly z.infer<typeof publicLinkPageSchema>[],
    ): Promise<readonly z.infer<typeof publicLinkPageSchema>[]> => {
      const query = new URLSearchParams({limit: String(limit)});
      if (cursor !== null) query.set("cursor", cursor);
      const response = await administratorFetch(
        `/api/v1/administration/public-links?${query}`,
      );
      expect(response.status).toBe(200);
      const page = publicLinkPageSchema.parse(await response.json());
      const nextPages = [...pages, page];
      return page.nextCursor === null
        ? nextPages
        : loadPage(page.nextCursor, nextPages);
    };
    return loadPage(null, []);
  }

  async function makePrivate(
    items: readonly ({
      readonly artifactId: string;
      readonly expectedCurrentVersionId: string;
      readonly idempotencyKey: string;
      readonly projectId: string;
    } | {readonly artifactId: string; readonly generation: number; readonly kind: "secret"; readonly projectId: string})[],
  ): Promise<Response> {
    return administratorFetch(
      "/api/v1/administration/public-links/make-private",
      {body: JSON.stringify({items}), method: "POST"},
    );
  }

  async function administratorFetch(
    path: string,
    init: RequestInit = {},
  ): Promise<Response> {
    return fetch(`${server.baseUrl}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${administratorToken}`,
        "Content-Type": "application/json",
        ...Object.fromEntries(new Headers(init.headers)),
      },
    });
  }

  async function expectNoPublicBytes(published: PublishResponse): Promise<void> {
    const stable = await fetch(published.links.artifact, {redirect: "manual"});
    expect(stable.status).toBe(401);
    const exact = await fetchVersion(server, published.links.version);
    expect(exact.status).toBe(401);
  }
});

const administratorVerifier: BearerCredentialVerifier = {
  verify: (credential) =>
    Redacted.value(credential) === administratorToken
      ? Effect.succeed({
        authorizedByPrincipalId: null,
        capabilities: [],
        displayName: "Installation administrator",
        id: "installation-administrator",
        installationId: "local",
        kind: "human",
        membershipRole: "administrator",
      })
      : Effect.fail(new AuthenticationRequired({
        message: "The external administrator credential is invalid.",
      })),
};

function privateCommand(
  published: PublishResponse,
  idempotencyKey: string,
) {
  return {
    artifactId: published.artifact.id,
    expectedCurrentVersionId: published.artifact.currentVersionId,
    idempotencyKey,
    projectId: published.artifact.projectId,
  };
}

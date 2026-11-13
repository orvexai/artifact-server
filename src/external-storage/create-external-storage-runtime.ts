import {Effect, Layer, ManagedRuntime, type Redacted} from "effect";

import type {ApplicationRuntime} from "../application/application-runtime.js";
import type {
  BearerCredentialVerifier,
  ExternalMcpBearerVerifier,
} from "../application/authentication.js";
import type {InteractiveIdentityProvider} from "../application/interactive-login.js";
import type {ExternalIdentity} from "../core/installation-identity.js";
import type {OrganizationMembershipResolver} from "./organization-memberships.js";
import type {Clock} from "../core/ports.js";
import type {BrowserAccess} from "../core/browser-access.js";
import type {
  GroupRolePolicy,
  GroupRoleSeedEntry,
} from "../core/group-role-policy.js";
import type {GroupRoleSeedResult} from "../application/installation-access.js";
import type {
  DirectoryGroupSyncReport,
  DirectorySyncReport,
  OrganizationDirectorySyncResult,
  GroupDirectory,
} from "../application/directory-sync.js";
import type {DirectoryOrganization, OrganizationDirectory} from
  "../identity/keycloak-directory.js";
import {
  runDirectoryGroupSyncPass,
  runDirectorySyncPass,
  runOrganizationDirectorySyncPass,
  runIsGroupRoleSeedApplied,
  runGroupRoleSeed,
} from "../lifecycle/directory-sync.js";
import {SystemClock, SystemIdGenerator} from "../core/system.js";
import {createHttpApp} from "../http/create-http-app.js";
import type {
  ApiOAuthResourceConfiguration,
  DiscoveredOAuthResources,
  HttpAppDependencies,
  McpOAuthResourceConfiguration,
  WebAssetStore,
} from "../http/create-http-app.js";
import {
  defaultCompletedRequestLogSampleRate,
  otlpLayer,
  structuredLoggingLayer,
} from "../observability/application-observability.js";
import {createApplicationLayer} from "../local/create-local-application-layer.js";
import {PostgresArtifactRepository} from "../storage/postgres-artifact-repository.js";
import {PostgresDatabase} from "../storage/postgres-database.js";
import {PostgresIdentityRepository} from "../storage/postgres-identity-repository.js";
import type {
  ObjectStorageProvider,
  ObjectStorageProviderFactory,
} from "../storage/object-storage-provider.js";
import type {RuntimeLifecycle} from "../lifecycle/runtime-readiness.js";
import {
  defaultStagingCleanupPolicy,
  runStagingCleanupPass,
  startStagingCleanupSchedule,
  type StagingCleanupPolicy,
} from "../lifecycle/staging-cleanup.js";
import type {ExpiredStagingCleanupReport} from
  "../application/expired-staging-cleanup.js";
import {createNodeWebAssetStore} from "../http/node-web-assets.js";
import {ensureBootstrapManagedApiKey} from
  "../application/bootstrap-managed-api-key.js";
import {
  configuredNodeGitHistory,
  offNodeGitHistoryConfiguration,
  type NodeGitHistoryConfiguration,
} from "../git-history/node-git-history-configuration.js";
import {fixedGitHistoryCapabilityReader} from
  "../git-history/git-history-capability.js";
import type {GitHistoryProviderHealthProbe} from
  "../git-history/git-history-provider-health.js";
import {CloudflareArtifactsRestHealthProbe} from
  "../git-history/cloudflare-artifacts-rest-health-probe.js";
import {
  startGitHistoryCapabilityMonitor,
  type GitHistoryCapabilityMonitor,
} from "../git-history/git-history-capability-monitor.js";
import {PostgresGitHistoryProviderIdentityStore} from
  "../storage/postgres-git-history-provider-identity-store.js";
import {
  type GitHistoryProvider,
  startGitHistoryMirrorWorker,
} from "../git-history/git-history-mirror.js";
import {CloudflareArtifactsGitHistoryProvider} from
  "../git-history/cloudflare-artifacts-git-history-provider.js";

/** Configuration for one stateless Artifact Server process. */
export interface ExternalStorageRuntimeConfig {
  readonly apiToken: Redacted.Redacted;
  /** Disable only the bootstrap-key write for read-only maintenance runtimes. */
  readonly bootstrapApiTokenEnabled?: boolean;
  readonly apiOAuthResource?: ApiOAuthResourceConfiguration;
  readonly applicationOrigin?: string;
  readonly bootstrapAdministratorEmail: string;
  readonly browserAccess: Extract<BrowserAccess, {readonly mode: "private_team"}>;
  readonly clock?: Clock;
  readonly completedRequestLogSampleRate?: number;
  readonly contentDomain: string;
  readonly embedBindingSecret?: Redacted.Redacted | undefined;
  readonly embedBindingPreviousSecret?: Redacted.Redacted | undefined;
  readonly embedOrigins?: readonly string[];
  readonly databaseUrl: Redacted.Redacted;
  /** OIDC OAuth that turns on when the issuer is discovered, instead of the static resources. */
  readonly discoveredOAuth?: DiscoveredOAuthResources;
  readonly externalApiBearerVerifier?: BearerCredentialVerifier;
  readonly externalApiOAuthVerifier?: ExternalMcpBearerVerifier;
  readonly externalMcpBearerVerifier?: BearerCredentialVerifier;
  readonly externalMcpOAuthVerifier?: ExternalMcpBearerVerifier;
  readonly gitHistory?: NodeGitHistoryConfiguration;
  /** Optional provider seam for real-boundary tests; production composes REST. */
  readonly gitHistoryHealthProbe?: GitHistoryProviderHealthProbe;
  /** Complete provider seam for conformance tests; production composes REST and Git. */
  readonly gitHistoryProvider?: GitHistoryProvider;
  /** Issuer groups that admit people and set their role, when configured. */
  readonly groupRolePolicy?: GroupRolePolicy | null;
  readonly installationId: string;
  /** Verified Keycloak org claims; composed by the identity provider layer. */
  readonly organizationMemberships?: OrganizationMembershipResolver;
  readonly issuePlatformSession?: (identity: ExternalIdentity, existingToken?: string | null) => Promise<string>;
  readonly interactiveIdentityProvider?: InteractiveIdentityProvider;
  readonly localBootstrapCredential?: Redacted.Redacted;
  readonly mcpOAuthResource?: McpOAuthResourceConfiguration;
  readonly objectStorage: ObjectStorageProviderFactory;
  readonly postgresMaxConnections?: number;
  readonly runtimeLifecycle?: RuntimeLifecycle;
  readonly serviceVersion?: string;
  readonly uploadUrlLifetimeMilliseconds?: number;
  readonly stagingCleanupPolicy?: StagingCleanupPolicy;
  /** Optional in-process asset provider for tests and embedded deployments. */
  readonly webAssets?: WebAssetStore;
}

/** One ready external-storage runtime and its protocol adapter. */
export interface ExternalStorageRuntime {
  readonly app: ReturnType<typeof createHttpApp>;
  cleanupStaging(limit: number): Promise<ExpiredStagingCleanupReport>;
  close(): Promise<void>;
  /** Make the members match the directory under the stored group roles. */
  syncDirectory(directory: GroupDirectory): Promise<DirectorySyncReport>;
  /** Sync one Keycloak organization's complete member snapshot. */
  syncOrganizationMembers(
    directory: OrganizationDirectory,
    organization: DirectoryOrganization,
  ): Promise<OrganizationDirectorySyncResult>;
  /** Store the configured starting group roles, the first time only. */
  seedGroupRoles(seed: readonly GroupRoleSeedEntry[]): Promise<GroupRoleSeedResult>;
  /** Check whether starting group roles have been seeded for this installation. */
  isGroupRoleSeedApplied(): Promise<boolean>;
  /** Copy every directory group and its members. */
  syncDirectoryGroups(
    directory: GroupDirectory,
    syncedAt: string,
    provider: string,
    recomputeRoles?: boolean,
  ): Promise<DirectoryGroupSyncReport>;
}

/** Per-organization security values that differ on a shared process host. */
export interface ExternalStorageOrgConfig {
  readonly admissionPolicy?: GroupRolePolicy | null;
  readonly allowLegacyEmbedBinding?: boolean;
  readonly legacyEmbedBindingExpiresAt?: number;
  readonly applicationOrigin?: string;
  readonly bootstrapAdministratorEmail?: string | null;
  readonly bootstrapApiToken?: Redacted.Redacted;
  readonly cookieRouteId: string;
  readonly keycloakOrganizationId?: string | null;
  readonly contentTokenPrefix?: string;
  readonly embedOrigins?: readonly string[];
  readonly slug?: string;
  readonly issuePlatformSession?: (identity: ExternalIdentity, existingToken?: string | null) => Promise<string>;
}

/** Open the single Postgres pool owned by an external-storage process. */
export async function openExternalStorageDatabase(
  config: ExternalStorageRuntimeConfig,
  applicationName = `artifact-server:${config.installationId}`,
): Promise<PostgresDatabase> {
  return PostgresDatabase.open({
    applicationName,
    maxConnections: config.postgresMaxConnections ?? 10,
    url: config.databaseUrl,
  }, "validate");
}

/** Connect external providers, validate migrations, verify readiness, and build the app. */
export async function createExternalStorageRuntime(
  config: ExternalStorageRuntimeConfig,
): Promise<ExternalStorageRuntime> {
  const database = await openExternalStorageDatabase(config);
  try {
    const orgConfig: ExternalStorageOrgConfig = {
      cookieRouteId: "",
    };
    if (config.bootstrapApiTokenEnabled !== false) {
      Object.assign(orgConfig, {bootstrapApiToken: config.apiToken});
    }
    const runtime = await createOrgRuntime(config.installationId, orgConfig, config, database);
    return {
      ...runtime,
      close: async () => {
        await runtime.close();
        await Promise.all([config.objectStorage.close?.(), database.close()]);
      },
    };
  } catch (cause) {
    await Promise.all([config.objectStorage.close?.(), database.close()]);
    throw cause;
  }
}

/** Build one installation-scoped Hono app over shared process resources. */
export async function createOrgRuntime(
  installationId: string,
  orgConfig: ExternalStorageOrgConfig,
  config: ExternalStorageRuntimeConfig,
  database: PostgresDatabase,
): Promise<ExternalStorageRuntime> {
  const runtimeClock = config.clock ?? new SystemClock();
  const isOrvex = orgConfig.slug === undefined || orgConfig.slug === "orvex";
  const mayUseHostedOAuth = isOrvex || (
    orgConfig.keycloakOrganizationId !== undefined && orgConfig.keycloakOrganizationId !== null ||
    (orgConfig.admissionPolicy !== undefined && orgConfig.admissionPolicy !== null)
  );
  const applicationOrigin = orgConfig.applicationOrigin ?? config.applicationOrigin ?? null;
  const groupRolePolicy = isOrvex
    ? config.groupRolePolicy ?? null
    : orgConfig.admissionPolicy ?? null;
  const organizationOAuthResources = orgConfig.slug === undefined || isOrvex || applicationOrigin === null
    ? null
    : {
      apiResource: appendApplicationPath(applicationOrigin, "/api"),
      mcpResource: appendApplicationPath(applicationOrigin, "/mcp"),
    };
  const scopedOAuthVerifier = (verifier: ExternalMcpBearerVerifier | undefined) => {
    if (verifier === undefined) return null;
    let scoped = verifier;
    if (organizationOAuthResources !== null) {
      if (scoped.forApplicationResources === undefined) {
        if (mayUseHostedOAuth) {
          throw new Error("This identity provider cannot scope OAuth resources to an organization.");
        }
        return null;
      }
      scoped = scoped.forApplicationResources(organizationOAuthResources);
    }
    if (!isOrvex && orgConfig.keycloakOrganizationId !== undefined &&
      orgConfig.keycloakOrganizationId !== null && orgConfig.slug !== undefined) {
      if (scoped.forOrganization === undefined) {
        throw new Error("This identity provider cannot validate Keycloak organization claims.");
      }
      scoped = scoped.forOrganization({
        alias: orgConfig.slug,
        id: orgConfig.keycloakOrganizationId,
      });
    }
    return scoped;
  };
  const stagingCleanupPolicy = config.stagingCleanupPolicy ??
    defaultStagingCleanupPolicy;
  const gitHistory = config.gitHistory ?? offNodeGitHistoryConfiguration();
  let applicationGitHistory = fixedGitHistoryCapabilityReader(
    gitHistory.capability,
  );
  let objectStorage: ObjectStorageProvider | null = null;
  let applicationRuntime: ApplicationRuntime | null = null;
  let gitHistoryMonitor: GitHistoryCapabilityMonitor | null = null;
  let gitHistoryWorker: Awaited<ReturnType<typeof startGitHistoryMirrorWorker>> | null = null;
  try {
    const connectedObjectStorage = config.objectStorage.create(
      installationId,
    );
    objectStorage = connectedObjectStorage;
    await Promise.all([
      database.health(),
      connectedObjectStorage.readiness(AbortSignal.timeout(3_000)),
    ]);
    const repository = await PostgresArtifactRepository.open(
      database,
      installationId,
    );
    const identityRepository = new PostgresIdentityRepository(
      database,
      installationId,
    );
    const configuredGitHistory = configuredNodeGitHistory(gitHistory);
    const gitHistoryProvider = configuredGitHistory === null
      ? null
      : config.gitHistoryProvider ?? new CloudflareArtifactsGitHistoryProvider({
        apiToken: configuredGitHistory.apiToken,
        identity: configuredGitHistory.identity,
      });
    const gitHistoryIdentityStore = configuredGitHistory === null
      ? null
      : new PostgresGitHistoryProviderIdentityStore(
        database,
        installationId,
      );
    if (orgConfig.bootstrapApiToken !== undefined) {
      await ensureBootstrapManagedApiKey({
        credential: orgConfig.bootstrapApiToken,
        installationId,
        now: runtimeClock.now(),
        repository: identityRepository,
      });
    }
    const {blobs, staging} = connectedObjectStorage;
    const ids = new SystemIdGenerator();
    if (orgConfig.contentTokenPrefix !== undefined) {
      const createContentToken = ids.contentToken.bind(ids);
      Object.assign(ids, {
        contentToken: () => `${orgConfig.contentTokenPrefix}${createContentToken()}`,
      });
    }
    const applicationAdapters: Parameters<typeof createApplicationLayer>[0] = {
      apiToken: null,
      staffHandleSecret: config.apiToken,
      blobs,
      bootstrapAdministratorEmail: orgConfig.bootstrapAdministratorEmail === undefined
        ? config.bootstrapAdministratorEmail
        : orgConfig.bootstrapAdministratorEmail,
      clock: runtimeClock,
      dispatches: repository,
      externalApiBearerVerifier: isOrvex ? config.externalApiBearerVerifier ?? null : null,
      externalApiOAuthVerifier: mayUseHostedOAuth
        ? scopedOAuthVerifier(config.externalApiOAuthVerifier)
        : null,
      externalMcpBearerVerifier: isOrvex ? config.externalMcpBearerVerifier ?? null : null,
      externalMcpOAuthVerifier: mayUseHostedOAuth
        ? scopedOAuthVerifier(config.externalMcpOAuthVerifier)
        : null,
      groupRolePolicy,
      ids,
      identityRepository,
      installationId,
      organizationDirectoryVisibility: !isOrvex && orgConfig.slug !== undefined,
      gitHistory: {read: () => applicationGitHistory.read()},
      interactiveIdentityProvider: config.interactiveIdentityProvider === undefined
        ? null
        : orgConfig.slug === undefined
        ? config.interactiveIdentityProvider
        : organizationIdentityProvider(
          config.interactiveIdentityProvider,
          isOrvex ? config.applicationOrigin ?? applicationOrigin ?? "" : applicationOrigin ?? "",
          orgConfig,
        ),
      localBootstrapCredential: config.localBootstrapCredential ?? null,
      protectBootstrapAdministrator: false,
      repository,
      staging,
      stagingCleanupPolicy,
    };
    if (!isOrvex && orgConfig.keycloakOrganizationId !== undefined &&
      orgConfig.keycloakOrganizationId !== null && orgConfig.slug !== undefined) {
      Object.assign(applicationAdapters, {
        organizationAdmission: {
          alias: orgConfig.slug,
          id: orgConfig.keycloakOrganizationId,
        },
      });
    }
    if (config.uploadUrlLifetimeMilliseconds !== undefined) {
      Object.assign(applicationAdapters, {
        uploadUrlLifetimeMilliseconds: config.uploadUrlLifetimeMilliseconds,
      });
    }
    if (gitHistoryProvider !== null) {
      Object.assign(applicationAdapters, {gitHistoryProvider});
    }
    if (orgConfig.contentTokenPrefix !== undefined) {
      Object.assign(applicationAdapters, {contentTokenPrefix: orgConfig.contentTokenPrefix});
    }
    const applicationLayer = createApplicationLayer(applicationAdapters);
    const resources = Layer.effectDiscard(Effect.acquireRelease(
      Effect.void,
      () => Effect.promise(async () => {
        await connectedObjectStorage.close();
      }),
    ));
    const telemetry = otlpLayer({
      deploymentMode: "external-storage",
      installationId,
      serviceVersion: config.serviceVersion ?? "0.0.0",
    }).pipe(Layer.provideMerge(structuredLoggingLayer));
    applicationRuntime = ManagedRuntime.make(
      Layer.mergeAll(applicationLayer, resources, telemetry),
    );
    await applicationRuntime.context();
    const readyRuntime = applicationRuntime;
    if (
      configuredGitHistory !== null &&
      gitHistoryIdentityStore !== null &&
      gitHistoryProvider !== null
    ) {
      gitHistoryMonitor = startGitHistoryCapabilityMonitor(readyRuntime, {
        clock: runtimeClock,
        identity: configuredGitHistory.identity,
        identityStore: gitHistoryIdentityStore,
        initialCapability: configuredGitHistory.capability,
        providerHealth: config.gitHistoryHealthProbe ??
          new CloudflareArtifactsRestHealthProbe({
            apiToken: configuredGitHistory.apiToken,
            identity: configuredGitHistory.identity,
          }),
      });
      applicationGitHistory = gitHistoryMonitor.reader;
      gitHistoryWorker = await startGitHistoryMirrorWorker({
        blobs,
        capability: applicationGitHistory,
        includePublisherPrincipalId: isOrvex,
        installationId,
        provider: gitHistoryProvider,
        store: repository,
      });
    }
    const appDependenciesWithoutOAuth = {
      applicationRuntime: readyRuntime,
      blobs,
      browserAccess: config.browserAccess,
      completedRequestLogSampleRate:
        config.completedRequestLogSampleRate ??
          defaultCompletedRequestLogSampleRate,
      contentDomain: config.contentDomain,
      embedBindingSecret: config.embedBindingSecret,
      embedBindingPreviousSecret: config.embedBindingPreviousSecret,
      gitHistory: gitHistoryMonitor?.reader ??
        fixedGitHistoryCapabilityReader(gitHistory.capability),
      readiness: () => externalStorageReadiness(database, connectedObjectStorage),
      trustedApplicationOrigin: applicationOrigin,
      organizationSlug: orgConfig.slug,
      webAssets: config.webAssets ?? createNodeWebAssetStore(),    };
    if (orgConfig.issuePlatformSession !== undefined) {
      Object.assign(appDependenciesWithoutOAuth, {issuePlatformSession: orgConfig.issuePlatformSession});
    }
    let configuredAppDependencies: HttpAppDependencies = appDependenciesWithoutOAuth;
    if (orgConfig.contentTokenPrefix !== undefined) {
      configuredAppDependencies = {
        ...configuredAppDependencies,
        contentHostRoutingEnabled: true,
        contentTokenPrefix: orgConfig.contentTokenPrefix,
        installationId,
      };
    }
    if (orgConfig.allowLegacyEmbedBinding === true) {
      configuredAppDependencies = {...configuredAppDependencies, allowLegacyEmbedBinding: true};
    }
    if (orgConfig.legacyEmbedBindingExpiresAt !== undefined) {
      configuredAppDependencies = {
        ...configuredAppDependencies,
        legacyEmbedBindingExpiresAt: orgConfig.legacyEmbedBindingExpiresAt,
      };
    }
    if (orgConfig.cookieRouteId !== "") {
      configuredAppDependencies = {
        ...configuredAppDependencies,
        organizationCookieSuffix: `-${orgConfig.cookieRouteId}`,
      };
    }
    if (!isOrvex && orgConfig.keycloakOrganizationId !== null &&
      orgConfig.keycloakOrganizationId !== undefined && orgConfig.slug !== undefined) {
      configuredAppDependencies = {
        ...configuredAppDependencies,
        organizationAdmission: {
          alias: orgConfig.slug,
          id: orgConfig.keycloakOrganizationId,
        },
      };
    }
    if (orgConfig.slug === undefined || orgConfig.slug === "orvex") {
      if (config.embedOrigins !== undefined) {
        configuredAppDependencies = {...configuredAppDependencies, embedOrigins: config.embedOrigins};
      }
    } else if (orgConfig.embedOrigins !== undefined) {
      configuredAppDependencies = {...configuredAppDependencies, embedOrigins: orgConfig.embedOrigins};
    }
    let appDependencies: HttpAppDependencies = configuredAppDependencies;
    if (config.apiOAuthResource !== undefined) {
      appDependencies = {
        ...appDependencies,
        apiOAuthResource: {
          ...config.apiOAuthResource,
          resource: orgConfig.slug === undefined || isOrvex
            ? config.apiOAuthResource.resource
            : appendApplicationPath(applicationOrigin ?? config.apiOAuthResource.resource, "/api"),
        },
      };
    }
    if (config.mcpOAuthResource !== undefined) {
      appDependencies = {
        ...appDependencies,
        mcpOAuthResource: {
          ...config.mcpOAuthResource,
          resource: orgConfig.slug === undefined || isOrvex
            ? config.mcpOAuthResource.resource
            : appendApplicationPath(applicationOrigin ?? config.mcpOAuthResource.resource, "/mcp"),
        },
      };
    }
    if (config.discoveredOAuth !== undefined) {
      appDependencies = {
        ...appDependencies,
        discoveredOAuth: orgConfig.slug === undefined || isOrvex
          ? config.discoveredOAuth
          : {
            ...config.discoveredOAuth,
            apiResource: appendApplicationPath(applicationOrigin ?? config.discoveredOAuth.apiResource, "/api"),
            mcpResource: appendApplicationPath(applicationOrigin ?? config.discoveredOAuth.mcpResource, "/mcp"),
            current: () => {
              const state = config.discoveredOAuth?.current();
              if (state === undefined || state.status !== "enabled") return state ?? {status: "misconfigured"};
              return {
                ...state,
                api: {...state.api, resource: appendApplicationPath(applicationOrigin ?? state.api.resource, "/api")},
                mcp: {...state.mcp, resource: appendApplicationPath(applicationOrigin ?? state.mcp.resource, "/mcp")},
              };
            },
          },
      };
    }
    const closeCleanupSchedule = stagingCleanupPolicy.schedule === "background"
      ? startStagingCleanupSchedule(readyRuntime, stagingCleanupPolicy)
      : null;
    return {
      app: createHttpApp(config.runtimeLifecycle === undefined
        ? appDependencies
        : {...appDependencies, runtimeLifecycle: config.runtimeLifecycle}),
      cleanupStaging: (limit) => runStagingCleanupPass(readyRuntime, limit),
      seedGroupRoles: (seed) => runGroupRoleSeed(readyRuntime, seed),
      isGroupRoleSeedApplied: () => runIsGroupRoleSeedApplied(readyRuntime),
      syncDirectory: (directory) => runDirectorySyncPass(readyRuntime, directory),
      syncOrganizationMembers: (directory, organization) =>
        runOrganizationDirectorySyncPass(readyRuntime, directory, organization),
      syncDirectoryGroups: (directory, syncedAt, provider, recomputeRoles) =>
        runDirectoryGroupSyncPass(readyRuntime, directory, syncedAt, provider, recomputeRoles),
      close: async () => {
        if (closeCleanupSchedule !== null) await closeCleanupSchedule();
        if (gitHistoryWorker !== null) await gitHistoryWorker.close();
        if (gitHistoryMonitor !== null) await gitHistoryMonitor.close();
        await readyRuntime.dispose();
      },
    };
  } catch (cause) {
    if (gitHistoryWorker !== null) await gitHistoryWorker.close();
    if (gitHistoryMonitor !== null) await gitHistoryMonitor.close();
    if (applicationRuntime === null) {
      await (objectStorage?.close() ?? Promise.resolve());
    } else {
      await applicationRuntime.dispose();
    }
    throw cause;
  }
}

function organizationIdentityProvider(
  provider: InteractiveIdentityProvider,
  applicationOrigin: string | null,
  orgConfig: ExternalStorageOrgConfig,
): InteractiveIdentityProvider {
  let scoped = provider;
  if (provider.forApplicationOrigin !== undefined && applicationOrigin !== null) {
    scoped = provider.forApplicationOrigin(applicationOrigin);
  }
  if (orgConfig.keycloakOrganizationId !== undefined &&
    orgConfig.keycloakOrganizationId !== null && orgConfig.slug !== undefined &&
    scoped.forOrganization !== undefined) {
    scoped = scoped.forOrganization({
      alias: orgConfig.slug,
      id: orgConfig.keycloakOrganizationId,
    });
  }
  return scoped;
}

function appendApplicationPath(base: string, path: string): string {
  const url = new URL(base);
  const prefix = url.pathname.replace(/\/$/u, "");
  url.pathname = `${prefix}${path}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

async function externalStorageReadiness(
  database: PostgresDatabase,
  objectStorage: ObjectStorageProvider,
) {
  const [databaseResult, migrationResult, objectStorageResult] = await Promise.all([
    readinessComponent(() => database.health()),
    readinessComponent(async () => {
      const migrations = await database.migrationStatus();
      if (migrations.compatibility !== "current") {
        throw new Error("The database schema is not compatible with this build.");
      }
    }),
    readinessComponent((signal) => objectStorage.readiness(signal)),
  ]);
  const status = databaseResult.status === "ready"
    && migrationResult.status === "ready"
    && objectStorageResult.status === "ready"
    ? "ready" as const
    : "not_ready" as const;
  return {
    components: {
      configuration: readyComponent,
      database: databaseResult,
      migrations: migrationResult,
      objectStorage: objectStorageResult,
    },
    status,
  };
}

const readyComponent = {
  latencyMilliseconds: 0,
  status: "ready" as const,
};

async function readinessComponent(
  probe: (signal: AbortSignal) => Promise<void>,
): Promise<{readonly latencyMilliseconds: number; readonly status: "ready" | "unavailable"}> {
  const startedAt = performance.now();
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      probe(controller.signal),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Error("Readiness probe timed out."));
        }, 3_000);
      }),
    ]);
    return {
      latencyMilliseconds: performance.now() - startedAt,
      status: "ready",
    };
  } catch {
    return {
      latencyMilliseconds: performance.now() - startedAt,
      status: "unavailable",
    };
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

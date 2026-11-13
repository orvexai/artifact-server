import path from "node:path";

import {oidcIdentityProviderName} from "../core/project-access.js";
import {type Command, Option} from "commander";
import {Redacted} from "effect";

import {
  createExternalStorageRuntime,
  createOrgRuntime,
  openExternalStorageDatabase,
  type ExternalStorageRuntimeConfig,
} from "../external-storage/create-external-storage-runtime.js";
import {
  startExternalStorageServer,
  type ExternalStorageServerConfig,
} from "../external-storage/start-external-storage-server.js";
import type {DiscoveryEvent} from "../identity/discovery-retry.js";
import {
  startOidcHostedAuthentication,
  type StartedOidcHostedAuthentication,
} from "../identity/oidc-hosted-authentication.js";
import {createWorkOsHostedAuthentication} from
  "../identity/workos-hosted-authentication.js";
import {KeycloakDirectory, type KeycloakDirectoryConfig} from "../identity/keycloak-directory.js";
import {
  checkCompactIntegrity,
  checkExternalStorageIntegrity,
} from "../lifecycle/integrity-check.js";
import {initializeCompactInstallation} from
  "../lifecycle/compact-installation.js";
import {
  parseCompactRuntimeConfiguration,
  parseExternalMigrationConfiguration,
  parseExternalStorageRuntimeConfiguration,
  summarizeRuntimeConfiguration,
  type CompactRuntimeConfiguration,
  type ExternalStorageRuntimeConfiguration,
} from "../lifecycle/runtime-configuration.js";
import {inspectRuntimeConfiguration} from
  "../lifecycle/runtime-inspection.js";
import {
  createSupportManifest,
  type ProductBuildInformation,
} from "../lifecycle/support-manifest.js";
import {
  createLocalRuntime,
  type LocalRuntimeConfig,
} from "../local/create-local-runtime.js";
import {
  startLocalServer,
  type LocalServerConfig,
} from "../local/start-local-server.js";
import {PostgresDatabase} from "../storage/postgres-database.js";
import {
  OrganizationRegistry,
  findDisappearedOrganizations,
  parseOrganizationAdmissionPolicyJson,
  type OrganizationAdmissionPolicy,
} from "../external-storage/organization-registry.js";
import {runCliEffect} from "./run-cli-effect.js";
import {waitForProcessSignal} from "./wait-for-process-signal.js";
import {
  assertAtMostOneBrowserLoginProvider,
  loadOidcConfiguration,
  type OidcConfiguration,
} from "./oidc-configuration.js";
import {loadWorkOsConfiguration} from "./workos-configuration.js";
import {writeGitHistoryConfigurationWarnings} from
  "./git-history-configuration-warnings.js";
import {loadEmbedOrigins} from "./embed-configuration.js";
import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../core/browser-access.js";

interface StartExternalStorageOptions {
  readonly host: string;
  readonly port: string;
}

interface CompactOptions extends StartExternalStorageOptions {
  readonly data: string;
}

interface LifecycleOptions extends CompactOptions {
  readonly mode: "compact" | "external-storage";
}

interface InitOptions {
  readonly adminEmail: string;
  readonly data: string;
}

interface CleanupStagingOptions extends LifecycleOptions {
  readonly limit: string;
  readonly once: boolean;
}

interface SyncDirectoryOptions extends LifecycleOptions {
  readonly once: boolean;
}

/** Values injected from the release entrypoint into lifecycle commands. */
export interface LifecycleCommandOptions {
  readonly build: ProductBuildInformation;
}

/** Register the complete operator lifecycle surface on one CLI program. */
export function configureLifecycleCommands(
  program: Command,
  options: LifecycleCommandOptions,
): void {
  configureInitialization(program);
  configureCompactStart(program, options.build.productVersion);
  configureConfigurationInspection(program);
  configureMigrations(program);
  configureSupportManifest(program, options.build);
  configureIntegrity(program);
  configureMaintenance(program);
  configureOrganizations(program);
  configureExternalStorageStart(program, options.build.productVersion);
}

function configureMaintenance(program: Command): void {
  const maintenance = program
    .command("maintenance")
    .description("Run bounded operator maintenance tasks.");
  maintenance
    .command("cleanup-staging")
    .description("Remove expired uploads that were never committed.")
    .requiredOption("--once", "run one bounded pass and exit")
    .option("--limit <count>", "maximum uploads to examine", "100")
    .addOption(modeOption())
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: CleanupStagingOptions) => {
      const configuration = await lifecycleConfiguration(options);
      const runtime = configuration.deploymentMode === "compact"
        ? await createLocalRuntime(compactMaintenanceConfig(configuration))
        : await createExternalStorageRuntime(
          externalMaintenanceConfig(configuration),
        );
      try {
        const report = await runtime.cleanupStaging(
          parseCleanupLimit(options.limit),
        );
        console.log(JSON.stringify(report, null, 2));
        if (report.failed > 0) process.exitCode = 2;
      } finally {
        await runtime.close();
      }
    });
  maintenance
    .command("org-sync")
    .description("Discover Keycloak organizations and sync their members.")
    .requiredOption("--once", "run one complete pass and exit")
    .addOption(new Option("--mode <mode>", "external-storage only").choices(["external-storage"]).default("external-storage"))
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: SyncDirectoryOptions) => {
      const configuration = await lifecycleConfiguration(options);
      if (configuration.deploymentMode !== "external-storage") {
        throw new Error("Keycloak organization sync requires external-storage mode.");
      }
      const report = await syncKeycloakOrganizations(configuration);
      printOrganizationSyncReport(report);
    });
  maintenance
    .command("sync-directory")
    .description(
      "Make installation members match the OIDC issuer's directory groups.",
    )
    .requiredOption("--once", "run one complete pass and exit")
    .addOption(modeOption())
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: SyncDirectoryOptions) => {
      const configuration = await lifecycleConfiguration(options);
      assertAtMostOneBrowserLoginProvider(process.env);
      const oidc = await loadOidcConfiguration({
        ...process.env,
        ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL:
          configuration.bootstrapAdministratorEmail,
        ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
      });
      const groupRoles = oidc?.groupRoles ?? null;
      const directorySettings = oidc?.directory ?? null;
      if (oidc === null || groupRoles === null || directorySettings === null) {
        throw new Error(
          "maintenance sync-directory requires OIDC group roles (ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED) and the ARTIFACT_SERVER_OIDC_DIRECTORY_* settings.",
        );
      }
      const directoryConfig: KeycloakDirectoryConfig = {
        adminBaseUrl: directorySettings.adminBaseUrl,
        clientId: directorySettings.clientId,
        clientSecret: directorySettings.clientSecret,
        issuer: oidc.issuer,
      };
      const directory = new KeycloakDirectory(
        directorySettings.tokenEndpoint === undefined
          ? directoryConfig
          : {...directoryConfig, tokenEndpoint: directorySettings.tokenEndpoint},
      );
      const runtime = configuration.deploymentMode === "compact"
        ? await createLocalRuntime({
          ...compactMaintenanceConfig(configuration),
          groupRolePolicy: groupRoles,
        })
        : await createExternalStorageRuntime({
          ...externalMaintenanceConfig(configuration),
          groupRolePolicy: groupRoles,
        });
      try {
        // Roles belong to stored groups, so copy the groups first, then give
        // them their starting roles, then make the members match those roles.
        const groupSync = await runtime.syncDirectoryGroups(
          directory,
          new Date().toISOString(),
          oidcIdentityProviderName(oidc.issuer),
          false,
        );
        console.log(JSON.stringify({groupSync}));
        const groupRoleSeed = await runtime.seedGroupRoles(groupRoles.seed);
        console.log(JSON.stringify({groupRoleSeed}));
        const groupRoleSeedApplied = await runtime.isGroupRoleSeedApplied();
        let roleChangedDuringRecompute = 0;
        if (groupRoleSeedApplied) {
          const roleRecompute = await runtime.syncDirectoryGroups(
            directory,
            new Date().toISOString(),
            oidcIdentityProviderName(oidc.issuer),
          );
          roleChangedDuringRecompute = roleRecompute.roleChanged ?? 0;
          console.log(JSON.stringify({roleRecompute}));
        }
        if (groupRoleSeed.unresolved.length > 0) {
          console.error(
            groupRoleSeedApplied
              ? `ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED names groups that match no single directory group: ${groupRoleSeed.unresolved.join(", ")}. Role recomputation ran using the previously stored roles.`
              : `ARTIFACT_SERVER_OIDC_GROUP_ROLE_SEED names groups that match no single directory group: ${groupRoleSeed.unresolved.join(", ")}. No starting role was stored.`,
          );
        }
        const memberSync = await runtime.syncDirectory(directory);
        console.log(JSON.stringify(roleChangedDuringRecompute === 0
          ? memberSync
          : {...memberSync,
            unchanged: Math.max(0, memberSync.unchanged - roleChangedDuringRecompute),
            roleChanged: memberSync.roleChanged + roleChangedDuringRecompute,
          }));
        if (parseOrganizationTenancy(process.env["ARTIFACT_SERVER_ORG_TENANCY"])) {
          if (configuration.deploymentMode !== "external-storage") {
            throw new Error("Keycloak organization sync requires external-storage mode.");
          }
          const organizationSync = await syncKeycloakOrganizations(configuration);
          printOrganizationSyncReport(organizationSync);
        }
      } finally {
        await runtime.close();
      }
    });
}

function configureOrganizations(program: Command): void {
  const organization = program.command("org")
    .description("Manage configured Artifact Server organizations.");
  organization.command("create")
    .description("Register an organization without creating credentials.")
    .argument("<slug>", "lowercase organization route slug")
    .requiredOption("--name <display-name>", "organization display name")
    .option("--group-role-seed <json>", "admission policy JSON with seed and optional groupRoots")
    .action(async (slug: string, options: {readonly groupRoleSeed?: string; readonly name: string}) => {
      let admissionPolicy: OrganizationAdmissionPolicy | null = null;
      if (options.groupRoleSeed !== undefined) {
        admissionPolicy = parseOrganizationAdmissionPolicyJson(options.groupRoleSeed);
      }
      const configuration = await runCliEffect(
        parseExternalMigrationConfiguration(process.env),
      );
      const database = await PostgresDatabase.inspect({
        applicationName: `artifact-server-org-create:${configuration.installationId}`,
        maxConnections: 1,
        url: configuration.databaseUrl,
      });
      try {
        console.log(JSON.stringify(
          await new OrganizationRegistry(database).create(slug, options.name, admissionPolicy),
          null,
          2,
        ));
      } finally {
        await database.close();
      }
    });
  organization.command("list")
    .description("List configured organizations without sensitive data.")
    .action(async () => {
      const configuration = await runCliEffect(
        parseExternalMigrationConfiguration(process.env),
      );
      const database = await PostgresDatabase.inspect({
        applicationName: `artifact-server-org-list:${configuration.installationId}`,
        maxConnections: 1,
        url: configuration.databaseUrl,
      });
      try {
        console.log(JSON.stringify(
          await new OrganizationRegistry(database).list(),
          null,
          2,
        ));
      } finally {
        await database.close();
      }
    });
  organization.command("sync")
    .description("Discover Keycloak organizations and sync their members.")
    .addOption(new Option("--mode <mode>", "external-storage only").choices(["external-storage"]).default("external-storage"))
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: StartExternalStorageOptions) => {
      const configuration = await parseExternalConfiguration(options.host, options.port);
      const report = await syncKeycloakOrganizations(configuration);
      printOrganizationSyncReport(report);
    });
  organization.command("link")
    .description("Deliberately link a registered organization to a Keycloak organization id.")
    .argument("<slug>", "registered Artifact Server organization slug")
    .argument("<keycloak-id>", "Keycloak organization UUID")
    .action(async (slug: string, keycloakId: string) => {
      const configuration = await runCliEffect(
        parseExternalMigrationConfiguration(process.env),
      );
      const database = await PostgresDatabase.inspect({
        applicationName: `artifact-server-org-link:${configuration.installationId}`,
        maxConnections: 1,
        url: configuration.databaseUrl,
      });
      try {
        console.log(JSON.stringify(
          await new OrganizationRegistry(database).linkKeycloakOrganization(slug, keycloakId),
          null,
          2,
        ));
      } finally {
        await database.close();
      }
    });
}

interface OrganizationSyncReport {
  readonly discovered: readonly string[];
  readonly disappeared: readonly {readonly alias: string; readonly id: string}[];
  readonly skipped: readonly {readonly alias: string; readonly reason: string}[];
  readonly errors: readonly {readonly alias: string; readonly error: string}[];
  readonly memberSync: readonly {readonly alias: string; readonly report: unknown}[];
}

function printOrganizationSyncReport(report: OrganizationSyncReport): void {
  console.log(JSON.stringify(report, null, 2));
  if (report.errors.length > 0) process.exitCode = 2;
}

async function syncKeycloakOrganizations(
  configuration: ExternalStorageRuntimeConfiguration,
): Promise<OrganizationSyncReport> {
  if (configuration.deploymentMode !== "external-storage") {
    throw new Error("Keycloak organization sync requires external-storage mode.");
  }
  if (!parseOrganizationTenancy(process.env["ARTIFACT_SERVER_ORG_TENANCY"])) {
    throw new Error("Keycloak organization sync requires ARTIFACT_SERVER_ORG_TENANCY=on.");
  }
  assertAtMostOneBrowserLoginProvider(process.env);
  const oidc = await loadOidcConfiguration({
    ...process.env,
    ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL: configuration.bootstrapAdministratorEmail,
    ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
  });
  const directorySettings = oidc?.directory ?? null;
  if (oidc === null || directorySettings === null) {
    throw new Error("Keycloak organization sync requires OIDC and ARTIFACT_SERVER_OIDC_DIRECTORY_* settings.");
  }
  const directoryConfig: KeycloakDirectoryConfig = {
    adminBaseUrl: directorySettings.adminBaseUrl,
    clientId: directorySettings.clientId,
    clientSecret: directorySettings.clientSecret,
    issuer: oidc.issuer,
  };
  const directory = new KeycloakDirectory(directorySettings.tokenEndpoint === undefined
    ? directoryConfig
    : {...directoryConfig, tokenEndpoint: directorySettings.tokenEndpoint});
  const database = await openExternalStorageDatabase(externalMaintenanceConfig(configuration));
  try {
    const registry = new OrganizationRegistry(database);
    await registry.ensureOrvex(configuration.installationId);
    const before = await registry.list();
    const keycloakOrganizations = await runCliEffect(directory.listOrganizations());
    const discovered: string[] = [];
    const skipped: {alias: string; reason: string}[] = [];
    const errors: {alias: string; error: string}[] = [];
    const memberSync: {alias: string; report: unknown}[] = [];
    for (const keycloakOrganization of keycloakOrganizations) {
      try {
        if (keycloakOrganization.enabled === false) {
          skipped.push({alias: keycloakOrganization.alias, reason: "Keycloak organization is disabled."});
          continue;
        }
        // Keep each tenant operation sequential: the per-org catch below
        // records failures independently and shared connections are bounded.
        // oxlint-disable-next-line eslint/no-await-in-loop
        const result = await registry.syncKeycloakOrganization(
          keycloakOrganization.alias,
          keycloakOrganization.name,
          keycloakOrganization.id,
        );
        if (result.kind === "conflict") {
          errors.push({alias: keycloakOrganization.alias, error: result.reason});
          continue;
        }
        const organization = result.organization;
        discovered.push(organization.slug);
        // Orvex remains governed by the existing issuer-group policy.
        if (keycloakOrganization.alias === "orvex") continue;
        // oxlint-disable-next-line eslint/no-await-in-loop
        const orgRuntime = await createOrgRuntime(organization.id, {
          cookieRouteId: organization.routeId,
          keycloakOrganizationId: keycloakOrganization.id,
          slug: organization.slug,
          applicationOrigin: new URL(`/o/${organization.slug}`, configuration.applicationOrigin).toString(),
        }, externalMaintenanceConfig(configuration), database);
        try {
          // oxlint-disable-next-line eslint/no-await-in-loop
          const memberReport = await orgRuntime.syncOrganizationMembers(directory, keycloakOrganization);
          if ("kind" in memberReport && memberReport.kind === "skipped") {
            skipped.push({alias: keycloakOrganization.alias, reason: memberReport.reason});
          } else {
            memberSync.push({alias: keycloakOrganization.alias, report: memberReport});
          }
        } finally {
          // oxlint-disable-next-line eslint/no-await-in-loop
          await orgRuntime.close();
        }
      } catch (error) {
        errors.push({
          alias: keycloakOrganization.alias,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    const disappeared = findDisappearedOrganizations(before, keycloakOrganizations);
    return {discovered, disappeared, skipped, errors, memberSync};
  } finally {
    await Promise.all([configuration.objectStorage.close?.(), database.close()]);
  }
}

function configureInitialization(program: Command): void {
  program
    .command("init")
    .description("Initialize an empty compact Artifact Server data directory.")
    .requiredOption("--admin-email <email>", "initial administrator email")
    .addOption(dataOption())
    .action(async (options: InitOptions) => {
      const initialized = await runCliEffect(initializeCompactInstallation({
        bootstrapAdministratorEmail: options.adminEmail,
        dataDirectory: options.data,
      }));
      console.log(JSON.stringify({
        dataDirectory: path.resolve(options.data),
        installationId: initialized.installationId,
      }, null, 2));
    });
}

function configureCompactStart(program: Command, productVersion: string): void {
  program
    .command("start-compact")
    .description("Start an initialized compact team server.")
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: CompactOptions) => {
      const configuration = await runCliEffect(
        parseCompactRuntimeConfiguration({
          dataDirectory: options.data,
          environment: process.env,
          hostname: options.host,
          port: options.port,
        }),
      );
      const server = await startCompactServer(configuration, productVersion);
      console.log(JSON.stringify({
        deploymentMode: "compact",
        hostname: server.hostname,
        port: server.port,
        status: "ready",
      }));
      await waitForProcessSignal(() => server.close());
    });
}

function configureConfigurationInspection(program: Command): void {
  const configCommand = program
    .command("config")
    .description("Inspect runtime configuration without serving.");
  configCommand
    .command("check")
    .description("Parse and inspect one exact runtime configuration.")
    .addOption(modeOption())
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: LifecycleOptions) => {
      const configuration = await lifecycleConfiguration(options);
      const providers = await inspectRuntimeConfiguration(configuration);
      console.log(JSON.stringify({
        configuration: await summarizeConfiguration(configuration),
        providers,
      }, null, 2));
      if (providers.status !== "ready") process.exitCode = 2;
    });
}

function configureMigrations(program: Command): void {
  const migrateCommand = program
    .command("migrate")
    .description("Inspect or apply external-storage database migrations.");
  migrateCommand
    .command("status")
    .description("Report schema compatibility without changing Postgres.")
    .action(async () => {
      const configuration = await runCliEffect(
        parseExternalMigrationConfiguration(process.env),
      );
      const database = await PostgresDatabase.inspect({
        applicationName: `artifact-server-migration-status:${configuration.installationId}`,
        maxConnections: 1,
        url: configuration.databaseUrl,
      });
      try {
        console.log(JSON.stringify(await database.migrationStatus(), null, 2));
      } finally {
        await database.close();
      }
    });
  migrateCommand
    .command("apply")
    .description("Apply external-storage migrations under the advisory lock.")
    .action(async () => {
      const configuration = await runCliEffect(
        parseExternalMigrationConfiguration(process.env),
      );
      const database = await PostgresDatabase.open({
        applicationName: `artifact-server-migration-apply:${configuration.installationId}`,
        maxConnections: 1,
        url: configuration.databaseUrl,
      }, "apply");
      try {
        console.log(JSON.stringify(await database.migrationStatus(), null, 2));
      } finally {
        await database.close();
      }
    });
}

function configureSupportManifest(
  program: Command,
  build: ProductBuildInformation,
): void {
  const supportCommand = program
    .command("support")
    .description("Produce credential-free operator diagnostics.");
  supportCommand
    .command("manifest")
    .description("Print product, schema, provider, and configuration versions.")
    .addOption(modeOption())
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: LifecycleOptions) => {
      const configuration = await lifecycleConfiguration(options);
      const providers = await inspectRuntimeConfiguration(configuration);
      console.log(JSON.stringify(createSupportManifest(
        build,
        await summarizeConfiguration(configuration),
        providers,
      ), null, 2));
    });
}

function configureIntegrity(program: Command): void {
  const integrityCommand = program
    .command("integrity")
    .description("Inspect committed records and bytes without repairing them.");
  integrityCommand
    .command("check")
    .description("Verify one compact or external-storage installation.")
    .addOption(modeOption())
    .addOption(dataOption())
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: LifecycleOptions) => {
      let report: Awaited<ReturnType<typeof checkExternalStorageIntegrity>>;
      if (options.mode === "compact") {
        report = await runCliEffect(checkCompactIntegrity(path.resolve(options.data)));
      } else {
        const configuration = await parseExternalConfiguration(
          options.host,
          options.port,
        );
        try {
          report = await checkExternalStorageIntegrity(configuration);
        } finally {
          await configuration.objectStorage.close?.();
        }
      }
      console.log(JSON.stringify(report, null, 2));
      if (report.status !== "healthy") process.exitCode = 2;
    });
}

function configureExternalStorageStart(
  program: Command,
  productVersion: string,
): void {
  program
    .command("start-external-storage")
    .description("Start one stateless Postgres and object-storage server process.")
    .addOption(hostOption())
    .addOption(portOption())
    .action(async (options: StartExternalStorageOptions) => {
      const organizationTenancy = parseOrganizationTenancy(
        process.env["ARTIFACT_SERVER_ORG_TENANCY"],
      );
      const parsed = await parseExternalConfiguration(options.host, options.port);
      const embedOrigins = loadEmbedOrigins(process.env);
      writeGitHistoryConfigurationWarnings(parsed.gitHistory);
      assertAtMostOneBrowserLoginProvider(process.env);
      const workOs = await loadWorkOsConfiguration(process.env);
      const oidc = await loadOidcConfiguration(process.env);
      const hostedAuthentication = workOs === null
        ? null
        : await createWorkOsHostedAuthentication(workOs);
      const oidcAuthentication = oidc === null
        ? null
        : await startOidcAuthentication(oidc);
      const browserAccess = hostedAuthentication !== null
        ? privateTeamBrowserAccess(browserLoginKinds.workOs)
        : oidc !== null
        ? privateTeamBrowserAccess(browserLoginKinds.oidc)
        : missingPrivateTeamIdentityProvider();
      let serverConfig: ExternalStorageServerConfig = {
        apiToken: parsed.apiToken,
        embedBindingSecret: parsed.embedBindingSecret,
        embedBindingPreviousSecret: parsed.embedBindingPreviousSecret,
        applicationOrigin: parsed.applicationOrigin,
        bootstrapAdministratorEmail: parsed.bootstrapAdministratorEmail,
        browserAccess,
        completedRequestLogSampleRate: parsed.completedRequestLogSampleRate,
        contentDomain: parsed.contentDomain,
        databaseUrl: parsed.databaseUrl,
        embedOrigins,
        gitHistory: parsed.gitHistory,
        hostname: parsed.hostname,
        installationId: parsed.installationId,
        organizationTenancy,
        objectStorage: parsed.objectStorage,
        port: parsed.port,
        postgresMaxConnections: parsed.postgresMaxConnections,
        readinessWithdrawalMilliseconds: parsed.readinessWithdrawalMilliseconds,
        serviceVersion: productVersion,
        shutdownDeadlineMilliseconds: parsed.shutdownDeadlineMilliseconds,
        stagingCleanupPolicy: parsed.stagingCleanupPolicy,
        uploadUrlLifetimeMilliseconds: parsed.uploadUrlLifetimeMilliseconds,
      };
      if (hostedAuthentication !== null) {
        serverConfig = {
          ...serverConfig,
          ...hostedAuthentication,
        };
      }
      if (oidcAuthentication !== null) {
        serverConfig = {
          ...serverConfig,
          ...oidcServerAuthentication(oidcAuthentication),
        };
      }
      const server = await startExternalStorageServer(serverConfig);
      const displayHostname = options.host === "0.0.0.0"
        ? "localhost"
        : server.hostname;
      console.log(
        `Artifact Server (external-storage): http://${displayHostname}:${server.port}`,
      );
      await waitForProcessSignal(async () => {
        oidcAuthentication?.close();
        await server.close();
      });
    });
}

function parseOrganizationTenancy(value: string | undefined): boolean {
  if (value === undefined || value === "off") return false;
  if (value === "on") return true;
  throw new Error("ARTIFACT_SERVER_ORG_TENANCY must be 'off' or 'on'.");
}

async function startCompactServer(
  configuration: CompactRuntimeConfiguration,
  productVersion: string,
) {
  writeGitHistoryConfigurationWarnings(configuration.gitHistory);
  assertAtMostOneBrowserLoginProvider(process.env);
  const workOs = await loadWorkOsConfiguration({
    ...process.env,
    ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL:
      configuration.bootstrapAdministratorEmail,
    ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
  });
  const oidc = await loadOidcConfiguration({
    ...process.env,
    ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL:
      configuration.bootstrapAdministratorEmail,
    ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
  });
  const embedOrigins = loadEmbedOrigins(process.env);
  const hostedAuthentication = workOs === null
    ? null
    : await createWorkOsHostedAuthentication(workOs);
  const oidcAuthentication = oidc === null
    ? null
    : await startOidcAuthentication(oidc);
  const browserAccess = hostedAuthentication !== null
    ? privateTeamBrowserAccess(browserLoginKinds.workOs)
    : oidc !== null
    ? privateTeamBrowserAccess(browserLoginKinds.oidc)
    : missingPrivateTeamIdentityProvider();
  let serverConfig: LocalServerConfig = {
    apiToken: Redacted.value(configuration.apiToken),
    embedBindingSecret: configuration.embedBindingSecret,
    embedBindingPreviousSecret: configuration.embedBindingPreviousSecret,
    applicationOrigin: configuration.applicationOrigin,
    bootstrapAdministratorEmail: configuration.bootstrapAdministratorEmail,
    browserAccess,
    completedRequestLogSampleRate: configuration.completedRequestLogSampleRate,
    contentDomain: configuration.contentDomain,
    dataDirectory: configuration.dataDirectory,
    embedOrigins,
    gitHistory: configuration.gitHistory,
    hostname: configuration.hostname,
    installationId: configuration.installation.installationId,
    linkedFiles: configuration.linkedFiles,
    linkRoots: configuration.linkRoots,
    port: configuration.port,
    readinessWithdrawalMilliseconds:
      configuration.readinessWithdrawalMilliseconds,
    serviceVersion: productVersion,
    shutdownDeadlineMilliseconds: configuration.shutdownDeadlineMilliseconds,
    stagingCleanupPolicy: configuration.stagingCleanupPolicy,
    uploadUrlLifetimeMilliseconds: configuration.uploadUrlLifetimeMilliseconds,
  };
  if (hostedAuthentication !== null) {
    serverConfig = {
      ...serverConfig,
      ...hostedAuthentication,
    };
  }
  if (oidcAuthentication !== null) {
    serverConfig = {
      ...serverConfig,
      ...oidcServerAuthentication(oidcAuthentication),
    };
  }
  const server = await startLocalServer(serverConfig);
  return {
    hostname: server.hostname,
    port: server.port,
    close: async () => {
      oidcAuthentication?.close();
      await server.close();
    },
  };
}

/**
 * Start OIDC authentication whose OAuth follows issuer discovery.
 *
 * An issuer that is down at startup no longer turns MCP and API OAuth off for
 * the life of the process: discovery keeps retrying with capped backoff, the
 * process reports not ready meanwhile, and OAuth turns on without a restart.
 * Only a discovery document that contradicts the configuration leaves OAuth
 * off, as before, and that is reported as a configuration error.
 */
function startOidcAuthentication(
  oidc: OidcConfiguration,
): Promise<StartedOidcHostedAuthentication> {
  return startOidcHostedAuthentication(oidc, {
    onEvent: (event) => {
      process.stderr.write(oidcDiscoveryMessage(oidc.issuer, event));
    },
  });
}

function oidcServerAuthentication(
  started: StartedOidcHostedAuthentication,
): Omit<StartedOidcHostedAuthentication, "close"> {
  return {
    discoveredOAuth: started.discoveredOAuth,
    externalApiOAuthVerifier: started.externalApiOAuthVerifier,
    externalMcpOAuthVerifier: started.externalMcpOAuthVerifier,
    groupRolePolicy: started.groupRolePolicy,
    interactiveIdentityProvider: started.interactiveIdentityProvider,
  };
}

/** One operator-facing stderr line per discovery transition. */
function oidcDiscoveryMessage(
  issuer: string,
  event: DiscoveryEvent,
): string {
  if (event.kind === "retrying") {
    return `OIDC configuration warning (discovery_failed): API and MCP OAuth are waiting for ${issuer}: ${event.reason} Retrying in ${
      Math.max(1, Math.round(event.retryInMilliseconds / 1_000))
    }s (failure ${event.failures}); /ready reports not ready and OAuth requests answer 503 until discovery succeeds.\n`;
  }
  if (event.kind === "recovered") {
    return `OIDC discovery succeeded for ${issuer} after ${event.failures} failed attempt${
      event.failures === 1 ? "" : "s"
    }: API OAuth, MCP OAuth, and protected-resource metadata are on.\n`;
  }
  return `OIDC configuration error (discovery_misconfigured): MCP OAuth stays off for ${issuer}: ${event.reason} This is not retried; correct the issuer configuration and restart. Browser login and API keys keep working.\n`;
}

async function lifecycleConfiguration(
  options: LifecycleOptions,
): Promise<CompactRuntimeConfiguration | ExternalStorageRuntimeConfiguration> {
  return options.mode === "compact"
    ? runCliEffect(parseCompactRuntimeConfiguration({
      dataDirectory: options.data,
      environment: process.env,
      hostname: options.host,
      port: options.port,
    }))
    : parseExternalConfiguration(options.host, options.port);
}

function compactMaintenanceConfig(
  configuration: CompactRuntimeConfiguration,
): LocalRuntimeConfig {
  return {
    apiToken: Redacted.value(configuration.apiToken),
    applicationOrigin: configuration.applicationOrigin,
    bootstrapAdministratorEmail: configuration.bootstrapAdministratorEmail,
    browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
    completedRequestLogSampleRate: 0,
    contentDomain: configuration.contentDomain,
    dataDirectory: configuration.dataDirectory,
    gitHistory: configuration.gitHistory,
    installationId: configuration.installation.installationId,
    observability: true,
    stagingCleanupPolicy: {
      ...configuration.stagingCleanupPolicy,
      schedule: "external",
    },
    uploadUrlLifetimeMilliseconds: configuration.uploadUrlLifetimeMilliseconds,
  };
}

function externalMaintenanceConfig(
  configuration: ExternalStorageRuntimeConfiguration,
): ExternalStorageRuntimeConfig {
  return {
    apiToken: configuration.apiToken,
    bootstrapApiTokenEnabled: false,
    applicationOrigin: configuration.applicationOrigin,
    bootstrapAdministratorEmail: configuration.bootstrapAdministratorEmail,
    browserAccess: privateTeamBrowserAccess(browserLoginKinds.oidc),
    completedRequestLogSampleRate: 0,
    contentDomain: configuration.contentDomain,
    databaseUrl: configuration.databaseUrl,
    gitHistory: configuration.gitHistory,
    installationId: configuration.installationId,
    objectStorage: configuration.objectStorage,
    postgresMaxConnections: configuration.postgresMaxConnections,
    stagingCleanupPolicy: {
      ...configuration.stagingCleanupPolicy,
      schedule: "external",
    },
    uploadUrlLifetimeMilliseconds: configuration.uploadUrlLifetimeMilliseconds,
  };
}

function missingPrivateTeamIdentityProvider(): never {
  throw new Error(
    "A private-team server requires exactly one OIDC or WorkOS browser-login provider.",
  );
}

function parseCleanupLimit(value: string): number {
  const limit = Number(value);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
    throw new Error("The cleanup limit must be an integer from 1 through 1000.");
  }
  return limit;
}

async function summarizeConfiguration(
  configuration: CompactRuntimeConfiguration | ExternalStorageRuntimeConfiguration,
) {
  assertAtMostOneBrowserLoginProvider(process.env);
  const workOs = await loadWorkOsConfiguration({
    ...process.env,
    ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL:
      configuration.bootstrapAdministratorEmail,
    ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
  });
  const oidc = await loadOidcConfiguration({
    ...process.env,
    ARTIFACT_SERVER_BOOTSTRAP_ADMIN_EMAIL:
      configuration.bootstrapAdministratorEmail,
    ARTIFACT_SERVER_ORIGIN: configuration.applicationOrigin,
  });
  if (workOs === null && oidc === null) missingPrivateTeamIdentityProvider();
  return summarizeRuntimeConfiguration(
    configuration,
    workOs === null ? "oidc" : "workos",
    oidc?.groupRoles ?? null,
    oidc?.directory ?? null,
  );
}

function parseExternalConfiguration(
  hostname = process.env["ARTIFACT_SERVER_HOST"] ?? "127.0.0.1",
  port = process.env["ARTIFACT_SERVER_PORT"] ?? "8787",
): Promise<ExternalStorageRuntimeConfiguration> {
  return runCliEffect(parseExternalStorageRuntimeConfiguration({
    environment: process.env,
    hostname,
    port,
  }));
}

function modeOption(): Option {
  return new Option("--mode <mode>", "compact or external-storage")
    .choices(["compact", "external-storage"])
    .default("compact");
}

function dataOption(): Option {
  return new Option("--data <directory>", "compact data directory")
    .default(".artifact-server");
}

function hostOption(): Option {
  return new Option("--host <hostname>", "HTTP bind hostname")
    .default("127.0.0.1")
    .env("ARTIFACT_SERVER_HOST");
}

function portOption(): Option {
  return new Option("--port <number>", "HTTP port")
    .default("8787")
    .env("ARTIFACT_SERVER_PORT");
}

import path from "node:path";
import {connect as connectTcp} from "node:net";
import {once} from "node:events";

import {type Command, Option} from "commander";
import {z} from "zod";

import {
  localMcpHttpRelayAddressPath,
  localMcpHttpRelayOrigin,
  readLocalMcpHttpRelayAddress,
  startLocalMcpHttpRelay,
} from "../mcp/start-local-mcp-http-relay.js";
import {startLocalMcpStdioBridge} from "../mcp/start-local-mcp-stdio-bridge.js";
import {currentCliInvocation} from "./current-cli-invocation.js";
import {runCliEffect} from "./run-cli-effect.js";
import {ensureManagedLocalService, inspectManagedLocalService} from "./local-service-manager.js";
import {
  connectMcpClient,
  detectInstalledMcpClients,
  disconnectMcpClient,
  inspectMcpClientRegistrations,
  managedMcpClients,
  parseMcpClientId,
  type McpClientId,
} from "./mcp-client-registrations.js";
import {ensureMcpHttpRelayService} from "./mcp-http-relay-service.js";
import {
  readDefaultMcpCliProfileAddress,
  resolveDefaultMcpCliProfile,
} from "./mcp-cli-profile.js";
import {CliCredentialStoreError} from "./system-credential-store.js";


interface DataOptions {
  readonly data: string;
}

/** Build values needed by the local MCP onboarding commands. */
export interface McpOnboardingCommandOptions {
  readonly defaultDataDirectory: string;
  readonly productVersion: string;
}

/** Register local MCP serving, connection, removal, and diagnostics commands. */
export function configureMcpOnboardingCommands(
  program: Command,
  options: McpOnboardingCommandOptions,
): void {
  configureMcpCommand(program, options);
  configureConnectCommand(program, options);
  configureDisconnectCommand(program, options);
  configureDoctorCommand(program, options);
}

function configureMcpCommand(
  program: Command,
  options: McpOnboardingCommandOptions,
): void {
  const mcp = program
    .command("mcp")
    .description("Run Houston Artifacts MCP transports.")
    .addOption(dataOption(options.defaultDataDirectory))
    .action((commandOptions: DataOptions) => {
      startLocalMcpStdioBridge({
        dataDirectory: path.resolve(commandOptions.data),
        invocation: currentCliInvocation(),
        productVersion: options.productVersion,
      });
    });
  const relay = mcp
    .command("relay")
    .description("Run the local HTTP MCP relay using available CLI or local service auth.")
    .addOption(dataOption(options.defaultDataDirectory))
    .addOption(new Option("--port <number>", "loopback relay port; 0 selects and saves a free port").default("0"))
    .addOption(new Option("--address-file <file>", "saved relay address file"))
    .action(async (commandOptions: DataOptions & {readonly port: string; readonly addressFile?: string}) => {
      const port = Number(commandOptions.port);
      if (!Number.isInteger(port) || port < 0 || port > 65_535) {
        throw new Error("The MCP relay port must be an integer from 0 to 65535.");
      }
      const dataDirectory = path.resolve(commandOptions.data);
      await startLocalMcpHttpRelay(
        dataDirectory,
        port,
        path.resolve(commandOptions.addressFile ?? localMcpHttpRelayAddressPath(dataDirectory)),
        currentCliInvocation(),
      );
    });
  relay
    .command("ensure")
    .description("Install and start the persistent per-user MCP relay service.")
    .addOption(dataOption(options.defaultDataDirectory))
    .action(async (commandOptions: DataOptions) => {
      const service = await ensureMcpHttpRelayService(
        path.resolve(commandOptions.data),
        currentCliInvocation(),
      );
      console.log(JSON.stringify({
        serverAddress: `${service.origin}/mcp`,
        service: service.systemdManaged ? "systemd --user" : "local HTTP relay",
      }, null, 2));
    });
}

function configureConnectCommand(
  program: Command,
  options: McpOnboardingCommandOptions,
): void {
  program
    .command("connect [client]")
    .description("Connect Houston Artifacts to an installed AI client.")
    .addOption(dataOption(options.defaultDataDirectory))
    .action(async (clientName: string | undefined, commandOptions: DataOptions) => {
      const dataDirectory = path.resolve(commandOptions.data);
      const client = await selectInstalledClient(clientName);
      const invocation = currentCliInvocation();
      const service = client === "codex" || client === "claude"
        ? await ensureMcpHttpRelayService(dataDirectory, invocation)
        : {origin: (await ensureManagedLocalService(dataDirectory, invocation)).origin, systemdManaged: false};
      await connectMcpClient(
        client,
        dataDirectory,
        invocation,
        process.env,
        client === "codex" || client === "claude" ? `${service.origin}/mcp` : undefined,
      );
      console.log(JSON.stringify({
        client,
        serverAddress: service.origin,
        service: service.systemdManaged ? "systemd --user" : "local HTTP relay",
      }, null, 2));
    });
}

function configureDisconnectCommand(
  program: Command,
  options: McpOnboardingCommandOptions,
): void {
  program
    .command("disconnect [client]")
    .description("Remove Houston Artifacts from one AI client.")
    .addOption(dataOption(options.defaultDataDirectory))
    .action(async (clientName: string | undefined, commandOptions: DataOptions) => {
      const dataDirectory = path.resolve(commandOptions.data);
      const client = await selectDisconnectClient(clientName, dataDirectory);
      const removed = await disconnectMcpClient(client, dataDirectory);
      console.log(JSON.stringify({
        client,
        status: removed ? "disconnected" : "already_disconnected",
      }, null, 2));
    });
}

function configureDoctorCommand(
  program: Command,
  options: McpOnboardingCommandOptions,
): void {
  program
    .command("doctor [client]")
    .description("Inspect local MCP service and client setup without changing it.")
    .addOption(dataOption(options.defaultDataDirectory))
    .action(async (clientName: string | undefined, commandOptions: DataOptions) => {
      const dataDirectory = path.resolve(commandOptions.data);
      const requestedClient = clientName === undefined
        ? null
        : await runCliEffect(parseMcpClientId(clientName));
      const [reachable, relayAddress, localService, profileResult, profileAddress, clients] = await Promise.all([
        relayIsHealthy(dataDirectory),
        readLocalMcpHttpRelayAddress(localMcpHttpRelayAddressPath(dataDirectory)),
        inspectManagedLocalService(dataDirectory),
        resolveDefaultMcpCliProfile(dataDirectory).then(
          (profile) => ({cause: null, error: null, profile}),
          (cause: unknown) => ({
            cause,
            error: cause instanceof Error ? cause.message : String(cause),
            profile: null,
          }),
        ),
        readDefaultMcpCliProfileAddress(dataDirectory),
        inspectMcpClientRegistrations(dataDirectory),
      ]);
      const profile = profileResult.profile;
      const relayAuthentication = reachable
        ? await readRelayAuthenticationStatus(relayAddress?.port)
        : null;
      const shellCredentialStore = profileResult.cause instanceof CliCredentialStoreError
        ? profileResult.cause.reason === "backend_unavailable"
          ? "unavailable"
          : profileResult.cause.reason === "operation_failed"
            ? "rejected"
            : "missing"
        : "available";
      const authentication = relayAuthentication ?? (profile !== null
        ? "authenticated"
        : profileResult.error === null ? "logged_out" : "invalid");
      const authenticationSource = relayAuthentication === null ? "shell" : "relay";
      const selectedClients = requestedClient === null
        ? clients
        : clients.filter((client) => client.client === requestedClient);
      const expectedEndpoint = relayAddress === null
        ? null
        : `${localMcpHttpRelayOrigin(relayAddress.port)}/mcp`;
      const reportedClients = selectedClients.map((client) => {
        const relayEndpointHealthy = client.client !== "claude" && client.client !== "codex"
          ? null
          : client.installed
            && expectedEndpoint !== null
            && client.endpoint === expectedEndpoint
            && reachable;
        return {
          client: client.client,
          endpoint: client.endpoint,
          installed: client.installed,
          managed: client.managed,
          relayEndpointHealthy,
        };
      });
      const isHttpClient = requestedClient === "claude" || requestedClient === "codex";
      const serviceReachable = requestedClient === null
        ? reachable || localService.reachable
        : isHttpClient
          ? reachable
          : localService.reachable;
      const discovery = serviceReachable
        ? {protocol: "streamable-http", status: "healthy" as const}
        : {reason: isHttpClient || requestedClient === null
          ? "The local HTTP auth relay is not reachable."
          : "The local Houston Artifacts service is not reachable.", status: "unhealthy" as const};
      const clientHealthy = reportedClients.every((client) => {
        if (!client.installed) return true;
        if (client.client === "claude" || client.client === "codex") {
          return client.managed && client.relayEndpointHealthy === true;
        }
        return requestedClient === null || client.managed;
      });
      const healthy = serviceReachable
        && discovery.status === "healthy"
        && clientHealthy
        && relayAuthentication !== "unavailable";
      const remediation = [
        ...(!healthy && relayAuthentication === "unavailable"
          ? ["Run artifactserver auth login to repair the configured remote profile credential."]
          : []),
        ...(healthy
          ? (authentication === "logged_out" ? ["Run artifactserver auth login when remote MCP access is needed."] : [])
          : [
            ...reportedClients
              .filter((client) => client.relayEndpointHealthy === false)
              .map((client) => `artifactserver connect ${client.client}`),
            ...(serviceReachable ? [] : [
              `artifactserver connect${requestedClient === null ? "" : ` ${requestedClient}`}`,
            ]),
            ...reportedClients
              .filter((client) => client.installed && !client.managed)
              .map((client) => `artifactserver connect ${client.client}`),
          ]),
      ];
      console.log(JSON.stringify({
        clients: reportedClients,
        dataDirectory,
        discovery,
        remediation: [...new Set(remediation)],
        service: {
          remoteProfile: profileAddress,
          profileError: profileResult.error ?? undefined,
          authentication,
          authenticationSource,
          shellCredentialStore,
          processAlive: isHttpClient || (requestedClient === null && reachable)
            ? reachable
            : localService.processAlive,
          reachable: serviceReachable,
        },
        status: healthy ? "healthy" : "unhealthy",
      }, null, 2));
      if (
        relayAuthentication === "authenticated"
        && (shellCredentialStore === "rejected" || shellCredentialStore === "unavailable")
      ) {
        console.error("Warning: this shell cannot read the credential store, but the running relay is signed in.");
      }
      if (!healthy) process.exitCode = 2;
    });
}

async function selectInstalledClient(
  clientName: string | undefined,
): Promise<McpClientId> {
  const installed = await detectInstalledMcpClients();
  if (clientName !== undefined) {
    const selected = await runCliEffect(parseMcpClientId(clientName));
    if (!installed.includes(selected)) {
      throw new Error(`${selected} is not installed or is not available on PATH.`);
    }
    return selected;
  }
  return selectSingleClient(installed, "installed");
}

async function selectDisconnectClient(
  clientName: string | undefined,
  dataDirectory: string,
): Promise<McpClientId> {
  if (clientName !== undefined) {
    return runCliEffect(parseMcpClientId(clientName));
  }
  const managed = await managedMcpClients(dataDirectory);
  if (managed.length > 0) return selectSingleClient(managed, "connected");
  return selectSingleClient(await detectInstalledMcpClients(), "installed");
}

function selectSingleClient(
  clients: readonly McpClientId[],
  state: "connected" | "installed",
): McpClientId {
  const selected = clients[0];
  if (clients.length === 1 && selected !== undefined) return selected;
  if (clients.length === 0) {
    throw new Error(`No supported ${state} AI client was found.`);
  }
  throw new Error(
    `More than one supported AI client is ${state}: ${clients.join(", ")}. Run the command again with one client name.`,
  );
}

async function relayIsHealthy(dataDirectory: string): Promise<boolean> {
  const address = await readLocalMcpHttpRelayAddress(localMcpHttpRelayAddressPath(dataDirectory));
  if (address === null) return false;
  try {
    await tcpPortIsReachable(address.port);
    const response = await fetch(`${localMcpHttpRelayOrigin(address.port)}/health`, {
      signal: AbortSignal.timeout(750),
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function readRelayAuthenticationStatus(
  port: number | undefined,
): Promise<"authenticated" | "logged_out" | "unavailable" | null> {
  if (port === undefined) return null;
  try {
    const response = await fetch(`${localMcpHttpRelayOrigin(port)}/auth-status`, {
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) return null;
    const body = z.object({
      authentication: z.enum(["authenticated", "logged_out", "unavailable"]),
    }).strict().safeParse(await response.json());
    return body.success ? body.data.authentication : null;
  } catch {
    return null;
  }
}

async function tcpPortIsReachable(port: number): Promise<void> {
  const socket = connectTcp({host: "127.0.0.1", port});
  try {
    await Promise.race([
      once(socket, "connect").then(() => undefined),
      once(socket, "error").then(([error]) => Promise.reject(error)),
      new Promise<never>((_resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("TCP connection timed out.")), 750);
        socket.once("close", () => clearTimeout(timeout));
      }),
    ]);
  } finally {
    socket.destroy();
  }
}

function dataOption(defaultDataDirectory: string): Option {
  return new Option("--data <directory>", "per-user Houston Artifacts data directory")
    .default(defaultDataDirectory);
}

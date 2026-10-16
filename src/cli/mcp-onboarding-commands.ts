import path from "node:path";

import {type Command, Option} from "commander";

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
import {resolveDefaultMcpCliProfile} from "./mcp-cli-profile.js";


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
    .description("Run Artifact Server MCP transports.")
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
    .description("Connect Artifact Server to an installed AI client.")
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
    .description("Remove Artifact Server from one AI client.")
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
      const [reachable, localService, profile, clients] = await Promise.all([
        relayIsHealthy(dataDirectory),
        inspectManagedLocalService(dataDirectory),
        resolveDefaultMcpCliProfile(dataDirectory).catch(() => null),
        inspectMcpClientRegistrations(dataDirectory),
      ]);
      const selectedClients = requestedClient === null
        ? clients
        : clients.filter((client) => client.client === requestedClient);
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
          : "The local Artifact Server service is not reachable.", status: "unhealthy" as const};
      const clientHealthy = requestedClient === null
        || selectedClients.every((client) => client.installed && client.managed);
      const healthy = serviceReachable
        && discovery.status === "healthy"
        && clientHealthy;
      console.log(JSON.stringify({
        clients: selectedClients,
        dataDirectory,
        discovery,
        remediation: healthy
          ? (profile === null ? ["Run artifactserver auth login when remote MCP access is needed."] : [])
          : [`artifactserver connect${requestedClient === null ? "" : ` ${requestedClient}`}`],
        service: {
          authentication: profile === null ? "logged_out" : "authenticated",
          processAlive: isHttpClient || (requestedClient === null && reachable)
            ? reachable
            : localService.processAlive,
          reachable: serviceReachable,
        },
        status: healthy ? "healthy" : "unhealthy",
      }, null, 2));
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
    const response = await fetch(`${localMcpHttpRelayOrigin(address.port)}/health`, {
      signal: AbortSignal.timeout(750),
    });
    return response.ok;
  } catch {
    return false;
  }
}

function dataOption(defaultDataDirectory: string): Option {
  return new Option("--data <directory>", "per-user Artifact Server data directory")
    .default(defaultDataDirectory);
}

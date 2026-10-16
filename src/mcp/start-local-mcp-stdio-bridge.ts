import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import {
  Server,
  type Implementation,
  type ServerCapabilities,
} from "@modelcontextprotocol/server";
import {serveStdio, type StdioServerHandle} from "@modelcontextprotocol/server/stdio";
import {z} from "zod";
import {Redacted} from "effect";

import type {CliInvocation} from "../cli/current-cli-invocation.js";
import {resolveCliServerConnection} from "../cli/cli-server-connection.js";
import {ensureManagedLocalService} from "../cli/local-service-manager.js";
import {readLocalApiCredential} from "../local/local-credentials.js";

const modernProtocolRevision = "2026-07-28";
const forwardedResultSchema = z.object({
  _meta: z.record(z.string(), z.unknown()).optional(),
}).loose();

/** Values needed to expose the existing local HTTP MCP endpoint over stdio. */
export interface LocalMcpStdioBridgeOptions {
  readonly dataDirectory: string;
  readonly invocation: CliInvocation;
  readonly productVersion: string;
  readonly serverOrigin?: string;
}

/** Start a dual-era stdio bridge to the single managed local service. */
export function startLocalMcpStdioBridge(
  options: LocalMcpStdioBridgeOptions,
): StdioServerHandle {
  return serveStdio(
    async () => createForwardingServer(options),
    {
      legacy: "serve",
      maxSubscriptions: 0,
      onerror: () => {
        console.error("Artifact Server MCP bridge error.");
      },
    },
  );
}

async function createForwardingServer(
  options: LocalMcpStdioBridgeOptions,
): Promise<Server> {
  const client = new Client(
    {name: "artifact-server-local-bridge", version: options.productVersion},
    {versionNegotiation: {mode: {pin: modernProtocolRevision}}},
  );
  const origin = options.serverOrigin === undefined
    ? (await ensureManagedLocalService(
      options.dataDirectory,
      options.invocation,
    )).origin
    : options.serverOrigin;
  const transport = new StreamableHTTPClientTransport(new URL("/mcp", origin), {
    authProvider: {
      token: async () => {
        if (options.serverOrigin === undefined) {
          return readLocalApiCredential(options.dataDirectory);
        }
        const connection = await resolveCliServerConnection({
          data: options.dataDirectory,
          profileData: options.dataDirectory,
          server: options.serverOrigin,
        }, "history");
        return Redacted.value(connection.apiToken);
      },
    },
  });
  try {
    await client.connect(transport);
  } catch (error) {
    await client.close();
    throw error;
  }

  const serverInformation = client.getServerVersion() ?? {
    name: "artifact-server",
    version: options.productVersion,
  };
  const capabilities = client.getServerCapabilities() ?? emptyCapabilities;
  const instructions = client.getInstructions();
  const server = new LocalForwardingServer(
    serverInformation,
    capabilities,
    instructions,
    client,
  );
  server.fallbackRequestHandler = (request) =>
    client.request(request, forwardedResultSchema);
  server.fallbackNotificationHandler = (notification) =>
    client.notification(notification);
  return server;
}

const emptyCapabilities: ServerCapabilities = {};

class LocalForwardingServer extends Server {
  readonly #downstream: Client;

  constructor(
    information: Implementation,
    capabilities: ServerCapabilities,
    instructions: string | undefined,
    downstream: Client,
  ) {
    super(
      information,
      instructions === undefined
        ? {capabilities}
        : {capabilities, instructions},
    );
    this.#downstream = downstream;
  }

  override async close(): Promise<void> {
    try {
      await super.close();
    } finally {
      await this.#downstream.close();
    }
  }
}

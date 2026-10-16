import {createServer, type IncomingMessage, type ServerResponse} from "node:http";
import {request as requestHttp} from "node:http";
import {request as requestHttps} from "node:https";
import {once} from "node:events";
import {chmod, mkdir, readFile, rename, writeFile} from "node:fs/promises";
import path from "node:path";

import {z} from "zod";

import {currentCliInvocation, type CliInvocation} from "../cli/current-cli-invocation.js";
import {ensureManagedLocalService} from "../cli/local-service-manager.js";
import {resolveDefaultMcpCliProfile} from "../cli/mcp-cli-profile.js";
import {readLocalApiCredential} from "../local/local-credentials.js";

const healthPath = "/health";
const mcpPath = "/mcp";
const addressSchema = z.object({
  pid: z.number().int().positive(),
  port: z.number().int().min(1).max(65_535),
  schemaVersion: z.literal(1),
}).strict();
const forwardedHeaders = new Set([
  "accept",
  "content-type",
  "content-encoding",
  "content-length",
  "mcp-protocol-version",
  "mcp-session-id",
  "last-event-id",
]);

/** Start a loopback HTTP relay that reuses remote CLI auth or local service auth. */
export async function startLocalMcpHttpRelay(
  profileDirectory: string,
  requestedPort = 0,
  addressFile = localMcpHttpRelayAddressPath(profileDirectory),
  invocation: CliInvocation = currentCliInvocation(),
): Promise<void> {
  let localServicePromise: ReturnType<typeof ensureManagedLocalService> | null = null;
  const localFallback = async (): Promise<{origin: string; token: string}> => {
    localServicePromise ??= ensureManagedLocalService(profileDirectory, invocation);
    try {
      const service = await localServicePromise;
      return {
        origin: service.origin,
        token: await readLocalApiCredential(profileDirectory),
      };
    } catch (error) {
      localServicePromise = null;
      throw error;
    }
  };
  const server = createServer((request, response) => {
    void handleRequest(
      profileDirectory,
      localFallback,
      request,
      response,
      activePort(server),
    ).catch(() => {
      if (!response.headersSent) {
        response.writeHead(502, {"content-type": "application/json"});
      }
      response.end('{"error":"Artifact Server MCP relay failed."}');
    });
  });
  let port = requestedPort;
  if (port === 0) {
    const savedAddress = await readLocalMcpHttpRelayAddress(addressFile);
    if (savedAddress !== null) port = savedAddress.port;
  }
  await listen(server, port);
  const boundPort = activePort(server);
  await writeLocalMcpHttpRelayAddress(addressFile, boundPort);
  const close = (): void => {
    server.close(() => process.exit(0));
  };
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

export function localMcpHttpRelayOrigin(port: number): string {
  return `http://127.0.0.1:${port}`;
}

export function localMcpHttpRelayAddressPath(dataDirectory: string): string {
  return path.join(dataDirectory, "mcp-http-relay.json");
}

export async function readLocalMcpHttpRelayAddress(
  addressFile: string,
): Promise<z.infer<typeof addressSchema> | null> {
  try {
    return addressSchema.parse(JSON.parse(await readFile(addressFile, "utf8")));
  } catch {
    return null;
  }
}

async function writeLocalMcpHttpRelayAddress(
  addressFile: string,
  port: number,
): Promise<void> {
  await mkdir(path.dirname(addressFile), {recursive: true, mode: 0o700});
  const temporary = `${addressFile}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify({
    pid: process.pid,
    port,
    schemaVersion: 1,
  })}\n`, {encoding: "utf8", mode: 0o600});
  await chmod(temporary, 0o600);
  await rename(temporary, addressFile);
}

async function listen(
  server: ReturnType<typeof createServer>,
  port: number,
): Promise<void> {
  const listening = once(server, "listening");
  server.listen(port, "127.0.0.1");
  await listening;
}

function activePort(server: ReturnType<typeof createServer>): number {
  const address = z.object({port: z.number().int().min(1).max(65_535)})
    .passthrough()
    .safeParse(server.address());
  if (!address.success) throw new Error("Artifact Server MCP relay did not bind a TCP port.");
  return address.data.port;
}

async function handleRequest(
  profileDirectory: string,
  localFallback: () => Promise<{origin: string; token: string}>,
  request: IncomingMessage,
  response: ServerResponse,
  port: number,
): Promise<void> {
  if (!isAllowedLoopbackRequest(request, port)) {
    response.writeHead(403).end();
    return;
  }
  const requestUrl = new URL(request.url ?? "/", "http://localhost");
  if (request.method === "GET" && requestUrl.pathname === healthPath) {
    response.writeHead(200, {"content-type": "application/json"});
    response.end('{"status":"ok"}');
    return;
  }
  if (requestUrl.pathname !== mcpPath || !["GET", "POST", "DELETE"].includes(request.method ?? "")) {
    response.writeHead(404).end();
    return;
  }

  let targetOrigin: string;
  let token: string;
  try {
    const profile = await resolveDefaultMcpCliProfile(profileDirectory).catch(() => null);
    if (profile !== null) {
      try {
        token = await profile.token();
        targetOrigin = profile.origin;
      } catch {
        ({origin: targetOrigin, token} = await localFallback());
      }
    } else {
      ({origin: targetOrigin, token} = await localFallback());
    }
  } catch {
    writeLocalServiceUnavailable(response);
    return;
  }
  const target = new URL(mcpPath + requestUrl.search, targetOrigin);
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (value !== undefined && forwardedHeaders.has(name.toLowerCase())) {
      headers[name] = value;
    }
  }
  headers["authorization"] = `Bearer ${token}`;
  headers["host"] = target.host;
  const proxy = (target.protocol === "https:" ? requestHttps : requestHttp)(target, {
    headers,
    method: request.method,
  }, (upstream) => {
    response.writeHead(upstream.statusCode ?? 502, upstream.headers);
    upstream.pipe(response);
  });
  proxy.on("error", () => {
    if (!response.headersSent) response.writeHead(502, {"content-type": "application/json"});
    response.end('{"error":"Artifact Server MCP upstream is unavailable."}');
  });
  request.pipe(proxy);
}

function isAllowedLoopbackRequest(request: IncomingMessage, port: number): boolean {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  if (!allowedHosts.has(request.headers.host ?? "")) return false;
  const origin = request.headers.origin;
  return origin === undefined || origin === `http://127.0.0.1:${port}`
    || origin === `http://localhost:${port}`;
}

function writeLocalServiceUnavailable(response: ServerResponse): void {
  response.writeHead(503, {"content-type": "application/json"});
  response.end(JSON.stringify({
    error: "Artifact Server MCP service is unavailable.",
    message: "Check the local Artifact Server service and retry the MCP request.",
  }));
}

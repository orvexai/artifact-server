import {spawn} from "node:child_process";
import {access, chmod, mkdir, open, readFile, rename, writeFile} from "node:fs/promises";
import {constants} from "node:fs";
import {homedir} from "node:os";
import path from "node:path";

import {z} from "zod";

import {type CliInvocation} from "./current-cli-invocation.js";
import {
  localMcpHttpRelayAddressPath,
  localMcpHttpRelayOrigin,
  readLocalMcpHttpRelayAddress,
} from "../mcp/start-local-mcp-http-relay.js";

const unitName = "artifact-server-mcp-relay.service";
const systemErrorSchema = z.object({code: z.string().optional()});

/** Install and start one persistent per-user HTTP auth relay when systemd is available. */
export async function ensureMcpHttpRelayService(
  dataDirectory: string,
  invocation: CliInvocation,
): Promise<{readonly origin: string; readonly systemdManaged: boolean}> {
  const addressFile = localMcpHttpRelayAddressPath(dataDirectory);
  const activeOrigin = await healthySavedOrigin(addressFile);
  if (activeOrigin !== null) {
    return {origin: activeOrigin, systemdManaged: await isSystemdUserAvailable()};
  }
  const systemctl = await findExecutable("systemctl");
  const manager = systemctl === null
    ? {code: 1, stderr: "systemctl unavailable"}
    : await run(systemctl, ["--user", "show-environment"]);
  if (systemctl === null || manager.code !== 0) {
    await spawnRelay(dataDirectory, invocation);
    const origin = await waitForRelay(addressFile);
    return {origin, systemdManaged: false};
  }

  const unitDirectory = path.join(homedir(), ".config", "systemd", "user");
  const unitPath = path.join(unitDirectory, unitName);
  await mkdir(unitDirectory, {recursive: true, mode: 0o700});
  const executable = quoteUnitArgument(invocation.command);
  const execArguments = [
    ...invocation.prefixArguments,
    "mcp",
    "relay",
    "--data",
    path.resolve(dataDirectory),
    "--address-file",
    path.resolve(addressFile),
    "--port",
    "0",
  ].map(quoteUnitArgument).join(" ");
  const contents = `[Unit]\nDescription=Artifact Server MCP authentication relay\n\n[Service]\nType=simple\nExecStart=${executable} ${execArguments}\nRestart=on-failure\nRestartSec=2s\nUMask=0077\n\n[Install]\nWantedBy=default.target\n`;
  let current = "";
  try {
    current = await readFile(unitPath, "utf8");
  } catch (error) {
    const parsed = systemErrorSchema.safeParse(error);
    if (!parsed.success || parsed.data.code !== "ENOENT") throw error;
  }
  if (current !== contents) {
    const temporary = `${unitPath}.${process.pid}.tmp`;
    await writeFile(temporary, contents, {mode: 0o644});
    await chmod(temporary, 0o644);
    await rename(temporary, unitPath);
    await runRequired(systemctl, ["--user", "daemon-reload"]);
    await runRequired(systemctl, ["--user", "enable", unitName]);
    await runRequired(systemctl, ["--user", "restart", unitName]);
  } else {
    await runRequired(systemctl, ["--user", "enable", "--now", unitName]);
  }
  const origin = await waitForRelay(addressFile);
  return {origin, systemdManaged: true};
}

async function spawnRelay(dataDirectory: string, invocation: CliInvocation): Promise<void> {
  const logPath = path.join(dataDirectory, "mcp-http-relay.log");
  await mkdir(dataDirectory, {recursive: true, mode: 0o700});
  const log = await open(logPath, "a", 0o600);
  try {
    const child = spawn(invocation.command, [
      ...invocation.prefixArguments,
      "mcp",
      "relay",
      "--data",
      path.resolve(dataDirectory),
      "--address-file",
      path.resolve(localMcpHttpRelayAddressPath(dataDirectory)),
      "--port",
      "0",
    ], {detached: true, stdio: ["ignore", log.fd, log.fd]});
    child.unref();
  } finally {
    await log.close();
  }
}

async function waitForRelay(addressFile: string): Promise<string> {
  return waitForRelayAttempt(addressFile, Date.now() + 10_000);
}

async function waitForRelayAttempt(addressFile: string, deadline: number): Promise<string> {
  const address = await readLocalMcpHttpRelayAddress(addressFile);
  const origin = address === null ? null : localMcpHttpRelayOrigin(address.port);
  try {
    const response = origin === null ? null : await fetch(`${origin}/health`, {
      signal: AbortSignal.timeout(500),
    });
    if (response?.ok && origin !== null) return origin;
  } catch {
    // Retry briefly while systemd starts the relay process.
  }
  if (Date.now() >= deadline) {
    throw new Error("The local Artifact Server MCP HTTP relay did not become healthy.");
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
  return waitForRelayAttempt(addressFile, deadline);
}

async function healthySavedOrigin(addressFile: string): Promise<string | null> {
  const address = await readLocalMcpHttpRelayAddress(addressFile);
  if (address === null) return null;
  const origin = localMcpHttpRelayOrigin(address.port);
  try {
    const response = await fetch(`${origin}/health`, {signal: AbortSignal.timeout(500)});
    return response.ok ? origin : null;
  } catch {
    return null;
  }
}

async function isSystemdUserAvailable(): Promise<boolean> {
  const systemctl = await findExecutable("systemctl");
  if (systemctl === null) return false;
  return (await run(systemctl, ["--user", "show-environment"])).code === 0;
}

function quoteUnitArgument(value: string): string {
  return `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

async function findExecutable(name: string): Promise<string | null> {
  const candidates = await Promise.all(
    (process.env["PATH"] ?? "").split(path.delimiter).map(async (directory) => {
      if (directory.length === 0) return null;
      const candidate = path.join(directory, name);
      try {
        await access(candidate, constants.X_OK);
        return candidate;
      } catch {
        return null;
      }
    }),
  );
  return candidates.find((candidate) => candidate !== null) ?? null;
}

async function runRequired(executable: string, args: readonly string[]): Promise<void> {
  const result = await run(executable, args);
  if (result.code !== 0) {
    throw new Error(`systemctl ${args.join(" ")} failed: ${result.stderr.trim() || `exit ${result.code}`}`);
  }
}

function run(executable: string, args: readonly string[]): Promise<{code: number; stderr: string}> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {stdio: ["ignore", "ignore", "pipe"]});
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => resolve({code: code ?? 1, stderr}));
  });
}

# Phase 5b: local MCP onboarding

Status: implemented locally; current-client host qualification remains open

## Outcome

A person installs Artifact Server, runs `artifactserver connect`, selects a
supported AI client only when the command finds more than one, and starts using
Artifact Server without copying a token, reading startup logs, opening a
browser, or running Docker.

The HTTP relay path keeps one lightweight per-user process and reuses the
existing remote product implementation:

```text
Claude Code or Codex
  -> per-user loopback HTTP auth relay
  -> existing authentication, authorization, artifact, version, and storage services
```

The relay uses the bearer credential from the user's default CLI profile when
available. When no usable remote profile is available, it forwards to the
shared per-user local service with that service's private local credential.
The relay does not define tools or manage artifact storage. Credentials are
never printed, placed in client configuration, passed as process arguments, or
returned in diagnostics.

## Commands

### `artifactserver mcp`

- Serves MCP on stdin/stdout using the official TypeScript SDK version 2.
- Writes only MCP protocol messages to stdout; diagnostics go to stderr.
- Starts or locates the per-user loopback service.
- Connects to the loopback `/mcp` endpoint with the private local credential.
- Pins the downstream loopback connection to revision `2026-07-28`.
- Accepts modern stdio clients and the SDK's stateless 2025-era compatibility
  handshake. Both reach the same modern downstream connection and product
  implementation; neither creates an application session.
- Proxies the remote catalog and calls without duplicating tool definitions.
- Shuts down only the stdio bridge when the client closes. The per-user service
  remains available to other registered clients and browser links.

### `artifactserver connect [client]`

- Detects supported installed clients: Codex, Claude Code, Cursor, and VS Code.
- Selects the only detected client automatically. If more than one is found,
  it lists the choices and exits without changing state unless `client` was
  supplied.
- Starts or locates the shared loopback HTTP auth relay.
- Registers Claude Code and Codex with the relay HTTP URL; they connect
  directly without spawning an Artifact Server process per agent.
- Keeps the relay healthy while logged out and serves the existing local
  service; later CLI login switches requests to the remote profile without a
  relay restart.
- Retains the existing local stdio registration for Cursor and VS Code.
- Never prints or stores the private local credential in the target client's
  configuration.

Codex and Claude Code use their native MCP configuration commands. Cursor and
VS Code use their documented user-level JSON files because their command-line
interfaces do not provide a complete add-and-remove lifecycle.

### `artifactserver disconnect [client]`

- Uses the same selection rule as `connect` when the client is omitted.
- Removes only Artifact Server's managed user-level registration.
- Preserves other MCP servers and the per-user Artifact Server data.
- Is idempotent when the managed registration is absent.

### `artifactserver doctor [client]`

- Does not start or change the relay or client configuration.
- Reports the selected data directory, relay health, CLI authentication state,
  and each requested client's registration state.
- Reports safe remediation commands.
- Never includes credential values or credential-bearing URLs.
- Exits unsuccessfully when any requested check is unhealthy.

## Per-user service

The onboarding data directory defaults to `~/.artifact-server`. The existing
`start --data` behavior remains available for explicit project-local or test
servers.

On Linux, onboarding installs and enables the `artifact-server-mcp-relay`
`systemd --user` unit. It starts at user login and restarts after an unexpected
exit. On first start, the relay asks the operating system for an available
loopback port and saves it in the per-user data directory. It reuses that port
on every restart; if another process has claimed it, the relay fails instead
of silently selecting a new URL. It forwards MCP HTTP
traffic to the installation in the current default CLI profile, adding the
credential held in the operating-system credential store. The relay does not
own a database or artifact storage.

The relay starts when no CLI profile is authenticated. MCP requests then use
the shared per-user local service and its private credential. It resolves the
current remote profile on each request, so a later CLI login switches traffic
to that remote installation without restarting the relay or reconfiguring
clients. Claude Code and Codex use the relay's HTTP URL directly; they do not
spawn stdio bridge processes. Systems without a systemd user manager use a
detached per-user relay process.

## Client configuration

The managed server name is `artifact-server`. Claude Code and Codex are
registered with the relay's Streamable HTTP URL. Cursor and VS Code retain
stdio registrations for the local Artifact Server process.

- Codex: `codex mcp add artifact-server --url <saved-loopback-url>/mcp`
- Claude Code: `claude mcp add --transport http --scope user artifact-server <saved-loopback-url>/mcp`
- Cursor: preserve the user JSON document and manage only
  `mcpServers.artifact-server`.
- VS Code: preserve the user JSON document and manage only
  `servers.artifact-server`.

Configuration writes are atomic. Existing entries with the same name that do
not match Artifact Server's managed shape are reported as conflicts and are not
silently overwritten.

## Credential output change

`artifactserver start` continues to create user-only local API and browser
bootstrap credentials because the existing HTTP boundaries require them. It no
longer prints either value or a URL containing either value. Startup output is
limited to the local application address and data directory.

## Verification

The implementation is not complete until tests prove:

1. the relay starts without a CLI profile, returns an auth-required response,
   and begins proxying after a later CLI login without a process restart;
2. concurrent requests share the single relay, and streamable HTTP session
   headers and event-stream responses pass through correctly;
3. Codex and Claude Code receive HTTP registrations while Cursor and VS Code
   preserve their local stdio setup;
4. client adapters preserve unrelated configuration and contain no credential;
5. conflicting, malformed, and unreachable states fail with useful,
   credential-free diagnostics; and
6. `connect`, `disconnect`, `doctor`, service logs, process arguments, client
   files, and test reports contain no local credential.

Real current Codex, Claude Code, Cursor, and VS Code host runs remain the
cross-client release proof in `MCP-019`; adapter and protocol tests do not
pretend to prove host behavior that was not actually exercised.

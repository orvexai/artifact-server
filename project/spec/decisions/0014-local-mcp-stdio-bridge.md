# ADR 0014: local MCP uses a stdio-to-loopback bridge

Status: accepted

## Context

Local users need a zero-copy MCP setup, while the application already owns a
modern authenticated `/mcp` endpoint and one SQLite/local-file runtime. Starting
a second product runtime inside every coding client's stdio process would create
multiple processes that manage the database lifecycle, duplicate behavior, and make returned
browser links depend on the client process staying alive.

The existing MCP registry, HTTP authentication adapter, local server, and
client-facing publishing paths were reviewed. Reusing the HTTP endpoint keeps
all product and authorization behavior on the established path. A new adapter
is still required because local AI clients commonly install stdio commands.

## Decision

`artifactserver mcp` is a transport-only bridge. It serves stdio with the
official SDK and forwards requests to an authenticated `/mcp` endpoint. By
default it uses the per-user service's loopback endpoint; with `--server`, it
uses the saved CLI profile for that exact remote origin. The per-user local
service is started once, owns SQLite and local files, and advertises its
non-secret loopback address through a user-only service record.

The local bridge obtains its credential from private per-user state. The remote
bridge resolves the existing CLI profile through the operating-system
credential store and refreshes it as needed. Credentials never become command
arguments, client configuration fields, stdout values, ordinary log fields, or
diagnostic values.

## Consequences

- HTTP and stdio share one MCP registry and one product implementation.
- Multiple AI clients can use one local database service safely.
- Browser links remain live when one AI client closes.
- The bridge adds one loopback hop, which is bounded and measured by the MCP
  smoke and performance checks.
- The per-user service needs an explicit non-secret discovery record and stale
  state diagnostics.
- Remote clients may use Streamable HTTP and MCP OAuth directly. A local CLI
  may use stdio with its saved API profile, avoiding a second browser login.
  The remote MCP adapter resolves that same admitted principal and applies the
  same product permissions.

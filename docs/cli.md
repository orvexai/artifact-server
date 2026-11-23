# Command-line interface

Agents normally publish through the [Artifact Server Skill](../skills/artifact-server/SKILL.md) or [MCP](./mcp.md). Use the CLI when you want to publish directly or run operator commands from a terminal.

A packaged release will provide the `artifactserver` command. Its download, verification, and `PATH` setup commands will be added on release day. Until then, run the examples from a source checkout by replacing `artifactserver` with `pnpm artifactserver`.

## Publish an artifact

Publish one finished file or a complete directory:

```sh
artifactserver publish ./report.pdf
artifactserver publish ./dist --public --name "Product prototype" --tag prototype
```

Publication returns JSON with three browser links:

| Link | Purpose |
| --- | --- |
| `links.review` | Opens the exact version full screen with comments. Share this link first. |
| `links.artifact` | Opens the stable link that follows the current version. |
| `links.version` | Opens the immutable raw version without the Artifact Server interface. |

## Use a remote server

Sign in once, save a named profile, and use it when publishing:

```sh
artifactserver auth login https://artifacts.example.com --name team
artifactserver auth login https://artifacts.example.com --name team --headless
artifactserver auth login https://artifacts.example.com --name team --device
artifactserver publish ./dist --profile team
```

## Publish another version

Provide the artifact ID and expected current version:

```sh
artifactserver publish ./dist \
  --artifact art_example \
  --expected-version ver_example
```

The expected version prevents an old client from replacing a newer current pointer.

## Read comments

List comments for an artifact (all pages, newest activity first):

```sh
artifactserver comments list art_example --server https://artifacts.example.com
artifactserver comments list art_example --server https://artifacts.example.com --project proj_example --version ver_example --include-replies
```

The command uses the saved CLI profile for that exact server origin and prints
JSON. `--include-replies` adds each thread's replies. It reads comments through
the CLI's authenticated connection; callers do not need to handle an access token.

On a headless host, `auth login --headless` prints the authorization URL. Open it on a machine with a browser, then paste the authorization code (or the full redirect URL) back into the CLI prompt. The CLI uses OAuth authorization code with S256 PKCE and stores the resulting login in the user's local profile; it does not require an API key.
The OAuth client must allow the loopback callback
`http://127.0.0.1:45678/oauth/callback`.

On a host with no browser at all, `auth login --device` prints an address and a short code. Open the address on any phone or computer, enter the code and approve; the CLI waits and saves the same renewable login. The identity provider must support OAuth device authorization and allow it for the `artifact-server` client (in Keycloak, enable OAuth 2.0 Device Authorization Grant on that client). Device sign-in always uses PKCE (S256), so a client that requires PKCE works unchanged. Browser sign-in remains the default.

Credentials use the operating-system keyring when it is reachable. If no keyring
is available, the CLI falls back to
`$XDG_CONFIG_HOME/artifact-server/credentials.json` (or
`~/.config/artifact-server/credentials.json`) with private file permissions.
Set `ARTIFACT_SERVER_CREDENTIAL_STORE=file` to force the file store, or set it
to `keyring` to require the operating-system keyring and disable fallback.
Existing file credentials with group or world read permissions are refused;
change them to mode `0600` before using the file store again.

## Diagnose MCP setup

Run `artifactserver doctor` to inspect the local service, relay, and client setup. Its `service.authentication` is `authenticated`, `logged_out`, `invalid`, or `unavailable`; `service.authenticationSource` is `relay` when a healthy relay answers `/auth-status`, otherwise `shell`. On the shell path, authentication remains `authenticated` for a resolved profile, `logged_out` when no profile exists and resolution succeeds, or `invalid` for any resolution error. `service.shellCredentialStore` is `available`, `unavailable`, `rejected`, or `missing` and separately describes credential access from the doctor process. If the relay is signed in while the shell store is rejected or unavailable, doctor exits successfully and prints one warning line. A relay-reported `unavailable` authentication state makes doctor unhealthy and exits with code 2; `logged_out` remains healthy because the relay can use the local service.

The relay `/auth-status` endpoint is loopback-only. It returns only an authentication state and never returns credentials, server origins, or account details.

Run `artifactserver --help` or `artifactserver <command> --help` for the complete command reference.

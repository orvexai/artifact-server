# Changelog

## 0.1.32

- Share artifacts with public links that visitors can open without signing in, and switch organizations from the catalog and Settings.
- Public links keep working without a copy key, but the Copy link action for an existing link is unavailable until you configure `ARTIFACT_SERVER_PUBLIC_LINK_KEY` or `_FILE`; resetting a link lets you copy it once. Helm uses `secret.keys.publicLinkKey` and `secret.keys.publicLinkKeyPrevious` for rotation. See `docs/deployment.md`.
- Review now uses @plannotator/ui 0.64.0.
- Refreshed the Houston Artifacts look and feel across the product.

## 0.1.31

- Pages open in Review can post a comment thread through `window.artifactServer.comments.create` only after the viewer confirms; the prompt now states the full length when it shows only the first 500 characters, unknown bridge operations are refused, and the page bridge is documented in `docs/page-bridge.md`.
- Settings > Members and Groups now work on phone-width (390 px) screens: rows become cards and nothing scrolls sideways; the Members, Groups and Public links tables also carry explicit table roles for screen readers.
- Test-suite fix: MCP relay tests no longer leave orphaned relay processes. No product change.
- A Review preview left open keeps loading files past 15 minutes: its preview lease extends while the viewer still has access, up to 8 hours after it was issued. Leases issued to API keys and other non-human callers still expire after 15 minutes.
- MCP comments written with an API key or external bearer token that pass `agentName` now show as agentName (via the key or account name); OAuth clients are unchanged.
- In focus mode, a PDF preview starts below the floating focus controls, so the browser PDF toolbar stays usable.
- `artifactserver doctor` reads sign-in status from the running relay and reports the shell credential store separately.

## 0.1.30

- `auth login --device` signs the CLI in from a host without a browser using OAuth device authorization (RFC 8628) protected by S256 PKCE. It prints only a verification address and a short code, never tokens; browser sign-in stays the default and `--headless` is unchanged.
- Review and Settings > Projects now work on phone-width (390 px) screens: the artifact opens first, the catalog and inspector open as full-screen sheets, full-screen controls become a bottom toolbar, and project rows become cards. Settings Members and Groups follow in a later release.

## 0.1.29

- **Behaviour change:** publishing a new version now stores exactly the files in the upload. Files from the previous version are no longer carried forward automatically. To keep them, opt in with `--carry-forward` (CLI) or `carryForward: true` (MCP `artifact_commit_upload` target and the HTTP API), and remove carried files with `--remove <path>` or `removePaths`. Callers that publish partial uploads must now pass this option.
- New operator command `artifactserver member deactivate <org> <email> --yes`. It deactivates one organization member, revokes their browser sessions and personal API keys in the same step, and keeps them out until an owner reactivates them. It refuses the Orvex installation and the last active administrator. Running servers stop accepting the revoked credentials within 30 seconds.
- With organization tenancy on, `maintenance sync-directory` now deactivates Orvex members whose only role came from a tenant group and revokes their sessions and personal API keys, as sign-in already did. Member sync now refuses a pass that would deactivate more members than the larger of `ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS` (default 5) and 20% of active members.
- Directory sync now fails the whole pass, changes nothing and exits non-zero when any directory group's members cannot be read.
- Fixed: turning on organization tenancy for an installation created after the organization registry migration no longer fails with a format error when registering Orvex.
- Test-suite repairs for CI runners (stale conformance expectations, OIDC refusal cookie assertions, permission tests when running as root, service-principal project creator access, longer CLI subprocess test budgets). No product change.

## 0.1.28

- Upgrade the Review frame's annotation viewer (@plannotator/ui) from 0.31.0 to 0.63.0, keeping its sandbox at scripts-only (no dialogs, popups or same-origin).
- Links inside an HTML artifact under Review behave as they did in 0.1.27 in Interact mode: in-page and same-file # links update the address and fire hashchange, History API calls may name only the reviewed document, and links to other files stay inert. In Annotate mode a plain click on a link follows it and Cmd/Ctrl-click pins it for a comment.
- No change to MCP tools, auth, tenancy or stored comment anchors.

## 0.1.27

- Refresh MCP, Hono, Vite, and related dependencies.
- Brand the user-facing web interface and server-rendered pages as **Houston Artifacts**.
- Keep the `artifactserver` CLI, MCP server and tool identifiers, `artifact-server` skill identifier, package names, environment variables, and API paths under their existing Artifact Server names.
- Include the review theme, mark, favicon, and server-page updates from the Houston rebrand, plus the relay doctor/adopt fix.

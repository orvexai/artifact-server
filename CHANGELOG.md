# Changelog

## 0.1.29

• **Behaviour change:** publishing a new version now stores exactly the files in the upload. Files from the previous version are no longer carried forward automatically. To keep them, opt in with --carry-forward (CLI) or carryForward: true (MCP artifact_commit_upload target and the HTTP API), and remove carried files with --remove <path> or removePaths. Callers that publish partial uploads must now pass this option.
• New operator command artifactserver member deactivate <org> <email> --yes. It deactivates one organization member, revokes their browser sessions and personal API keys in the same step, and keeps them out until an owner reactivates them. It refuses the Orvex installation and the last active administrator. Running servers stop accepting the revoked credentials within 30 seconds.
• With organization tenancy on, maintenance sync-directory now deactivates Orvex members whose only role came from a tenant group and revokes their sessions and personal API keys, as sign-in already did. Member sync now refuses a pass that would deactivate more members than the larger of ARTIFACT_SERVER_DIRECTORY_SYNC_MAX_DEACTIVATIONS (default 5) and 20% of active members.
• Directory sync now fails the whole pass, changes nothing and exits non-zero when any directory group's members cannot be read.
• Fixed: turning on organization tenancy for an installation created after the organization registry migration no longer fails with a format error when registering Orvex.
• Test-suite repairs for CI runners (stale conformance expectations, OIDC refusal cookie assertions, permission tests when running as root, service-principal project creator access, longer CLI subprocess test budgets). No product change.

## 0.1.28

- Upgrade the Review frame's annotation viewer (@plannotator/ui) from 0.31.0 to 0.63.0, keeping its sandbox at scripts-only (no dialogs, popups or same-origin).
- Links inside an HTML artifact under Review behave as they did in 0.1.27 in Interact mode: in-page and same-file # links update the address and fire hashchange, History API calls may name only the reviewed document, and links to other files stay inert. In Annotate mode a plain click on a link follows it and Cmd/Ctrl-click pins it for a comment.
- No change to MCP tools, auth, tenancy or stored comment anchors.

## 0.1.27

- Refresh MCP, Hono, Vite, and related dependencies.
- Brand the user-facing web interface and server-rendered pages as **Houston Artifacts**.
- Keep the `artifactserver` CLI, MCP server and tool identifiers, `artifact-server` skill identifier, package names, environment variables, and API paths under their existing Artifact Server names.
- Include the review theme, mark, favicon, and server-page updates from the Houston rebrand, plus the relay doctor/adopt fix.

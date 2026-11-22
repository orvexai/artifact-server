# Changelog

## 0.1.28

- Upgrade the Review frame's annotation viewer (@plannotator/ui) from 0.31.0 to 0.63.0, keeping its sandbox at scripts-only (no dialogs, popups or same-origin).
- Links to other files or sites inside an HTML artifact under Review stay inert; in-page # links scroll. To comment on a link in Annotate mode, Cmd/Ctrl-click it.
- No change to MCP tools, auth, tenancy or stored comment anchors.

## 0.1.27

- Refresh MCP, Hono, Vite, and related dependencies.
- Brand the user-facing web interface and server-rendered pages as **Houston Artifacts**.
- Keep the `artifactserver` CLI, MCP server and tool identifiers, `artifact-server` skill identifier, package names, environment variables, and API paths under their existing Artifact Server names.
- Include the review theme, mark, favicon, and server-page updates from the Houston rebrand, plus the relay doctor/adopt fix.

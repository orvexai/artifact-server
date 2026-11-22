# Changelog

## 0.1.28

- Upgrade the Review frame's annotation viewer (@plannotator/ui) from 0.31.0 to 0.63.0, keeping its sandbox at scripts-only (no dialogs, popups or same-origin).
- Links inside an HTML artifact under Review behave as they did in 0.1.27 in Interact mode: in-page and same-file # links update the address and fire hashchange, History API calls may name only the reviewed document, and links to other files stay inert. In Annotate mode a plain click on a link follows it and Cmd/Ctrl-click pins it for a comment.
- No change to MCP tools, auth, tenancy or stored comment anchors.

## 0.1.27

- Refresh MCP, Hono, Vite, and related dependencies.
- Brand the user-facing web interface and server-rendered pages as **Houston Artifacts**.
- Keep the `artifactserver` CLI, MCP server and tool identifiers, `artifact-server` skill identifier, package names, environment variables, and API paths under their existing Artifact Server names.
- Include the review theme, mark, favicon, and server-page updates from the Houston rebrand, plus the relay doctor/adopt fix.

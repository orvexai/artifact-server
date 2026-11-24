import {readFile} from "node:fs/promises";

import {expect, test} from "vitest";

test("BRD-008-B: MCP and OAuth display identity uses Houston Artifacts with stable identifiers", async () => {
  const [mcp, http, cli] = await Promise.all([
    readFile("src/mcp/artifact-mcp-server.ts", "utf8"),
    readFile("src/http/create-http-app.ts", "utf8"),
    readFile("src/cli/cli-oauth-client.ts", "utf8"),
  ]);

  expect(mcp).toMatch(/\{name:\s*"artifact-server",\s*title:\s*"Houston Artifacts",\s*version:/u);
  expect(http).toMatch(/resourceName:\s*"Houston Artifacts MCP"/u);
  expect(cli).toMatch(/client_name:\s*"Houston Artifacts CLI"/u);
  expect(cli).toMatch(/const cliOAuthClientId = "artifact-server"/u);
  expect(cli).toMatch(/const cliScope = "artifactserver"/u);
  expect(mcp).toMatch(/\{name: "artifact-server"/u);
});

test("BRD-008-F: an old display label or changed protected identifier violates the identity contract", () => {
  const valid = {
    clientId: "artifact-server",
    clientName: "Houston Artifacts CLI",
    resourceName: "Houston Artifacts MCP",
    scope: "artifactserver",
    serverName: "artifact-server",
    serverTitle: "Houston Artifacts",
  };
  expect(identityContractFailures(valid)).toEqual([]);
  expect(identityContractFailures({...valid, serverTitle: "Artifact Server"})).toContain("server title");
  expect(identityContractFailures({...valid, clientId: "houston-artifacts"})).toContain("client id");
  expect(identityContractFailures({...valid, scope: "houston-artifacts"})).toContain("scope");
});

function identityContractFailures(identity: {
  clientId: string;
  clientName: string;
  resourceName: string;
  scope: string;
  serverName: string;
  serverTitle: string;
}): string[] {
  const failures: string[] = [];
  if (identity.serverTitle !== "Houston Artifacts" || /Artifact Server/u.test(identity.serverTitle)) {
    failures.push("server title");
  }
  if (identity.resourceName !== "Houston Artifacts MCP") failures.push("resource name");
  if (identity.clientName !== "Houston Artifacts CLI") failures.push("client name");
  if (identity.clientId !== "artifact-server") failures.push("client id");
  if (identity.serverName !== "artifact-server") failures.push("server name");
  if (identity.scope !== "artifactserver") failures.push("scope");
  return failures;
}

import {Effect, Redacted} from "effect";

import type {ExternalMcpBearerVerifier} from
  "../../src/application/authentication.js";
import {AuthenticationRequired} from "../../src/core/errors.js";

/** A minimal verified MCP OAuth boundary for integration tests. */
export function createTestMcpOAuthVerifier(
  clients: Readonly<Record<string, string>>,
): ExternalMcpBearerVerifier {
  return {
    resolveIdentity: (verified) => Effect.succeed({
      displayName: "Administrator",
      email: "administrator@example.test",
      emailVerified: true,
      groups: null,
      provider: "test-mcp-oauth",
      subject: verified.subject,
    }),
    verify: (credential) => {
      const token = Redacted.value(credential);
      const clientId = clients[token];
      if (clientId === undefined) {
        return Effect.fail(new AuthenticationRequired({
          message: "The test MCP OAuth credential is invalid.",
        }));
      }
      return Effect.succeed({
        clientId,
        expiresAt: Math.floor(Date.now() / 1_000) + 300,
        provider: "test-mcp-oauth",
        scopes: ["openid", "profile", "email"],
        subject: "test-administrator",
      });
    },
  };
}

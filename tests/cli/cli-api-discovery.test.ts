import {createServer} from "node:http";

import {afterEach, describe, expect, test, vi} from "vitest";
import {z} from "zod";

import {discoverCliApi, resolveCliApiBasePath} from "../../src/cli/cli-api-discovery.js";

const servers: Array<ReturnType<typeof createServer>> = [];
const assignedAddressSchema = z.object({port: z.number().int().positive()});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error === undefined ? resolve() : reject(error));
  })));
});

describe("CLI API resource discovery", () => {
  test("discovers root-resource redirects, per-organization resources, and refuses cross-origin redirects", async () => {
    let origin = "";
    let crossOrigin = false;
    let maliciousMetadata = false;
    const server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", origin);
      if (url.pathname === "/api/v1/installation") {
        response.writeHead(308, {
          Location: crossOrigin
            ? "https://outside.example/o/orvex/api/v1/installation"
            : "/o/orvex/api/v1/installation",
        }).end();
        return;
      }
      const slug = /^\/o\/([^/]+)\/api\/v1\/installation$/u.exec(url.pathname)?.[1];
      if (slug !== undefined) {
        const resourceMetadata = maliciousMetadata
          ? "https://evil.example/.well-known/oauth-protected-resource/api"
          : slug === "orvex"
          ? `${origin}/.well-known/oauth-protected-resource/api`
          : `${origin}/.well-known/oauth-protected-resource/o/${slug}/api`;
        response.writeHead(401, {
          "WWW-Authenticate": `Bearer resource_metadata="${resourceMetadata}" scope="artifactserver"`,
        }).end();
        return;
      }
      const metadataMatch = /^\/.well-known\/oauth-protected-resource(?:\/o\/([^/]+))?\/api$/u.exec(url.pathname);
      if (metadataMatch !== null) {
        const resourceSlug = metadataMatch[1];
        const resource = resourceSlug === undefined
          ? `${origin}/api`
          : `${origin}/o/${resourceSlug}/api`;
        response.writeHead(200, {"Content-Type": "application/json"})
          .end(JSON.stringify({authorization_servers: [origin], resource, scopes_supported: ["artifactserver"]}));
        return;
      }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    servers.push(server);
    const address = assignedAddressSchema.parse(server.address());
    origin = `http://127.0.0.1:${address.port}`;

    const root = await discoverCliApi(origin);
    expect(root).toMatchObject({
      apiBasePath: "/o/orvex",
      metadataUrl: new URL(`${origin}/.well-known/oauth-protected-resource/api`),
      resource: new URL(`${origin}/api`),
    });

    const tenant = await discoverCliApi(origin, "/o/acme");
    expect(tenant).toMatchObject({
      apiBasePath: "/o/acme",
      metadataUrl: new URL(`${origin}/.well-known/oauth-protected-resource/o/acme/api`),
      resource: new URL(`${origin}/o/acme/api`),
    });

    maliciousMetadata = true;
    const evilRequests: string[] = [];
    const originalFetch = globalThis.fetch;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const requestUrl = new URL(input instanceof Request ? input.url : String(input));
      if (requestUrl.hostname === "evil.example") evilRequests.push(requestUrl.toString());
      return originalFetch(input, init);
    });
    try {
      await expect(discoverCliApi(origin)).rejects.toThrow(
        "advertised an unsafe resource_metadata URL https://evil.example/",
      );
      expect(evilRequests).toEqual([]);
    } finally {
      fetchSpy.mockRestore();
    }

    maliciousMetadata = false;
    crossOrigin = true;
    await expect(resolveCliApiBasePath(origin)).rejects.toThrow("HTTP 308 and refused unsafe redirect");
  }, 10_000);
});

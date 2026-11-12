import {createServer} from "node:http";

import {describe, expect, test} from "vitest";

import {api} from "../../apps/web/src/api/client.js";

describe("web group role API", () => {
  test("setGroupRole accepts the server's 204 no-content response", async () => {
    let requestMethod: string | undefined;
    let requestPath: string | undefined;
    const server = createServer((request, response) => {
      requestMethod = request.method;
      requestPath = request.url;
      response.writeHead(204).end();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!(address instanceof Object) || !("port" in address)) {
      throw new Error("The test server did not bind to a TCP port.");
    }

    const originalFetch = globalThis.fetch;
    const originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: {cookie: "artifact_csrf=test-csrf"},
    });
    globalThis.fetch = ((input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      return originalFetch(new URL(url, `http://127.0.0.1:${address.port}`), init);
    });
    try {
      await expect(api.setGroupRole("group-acme", "guest")).resolves.toBeUndefined();
      expect(requestMethod).toBe("PUT");
      expect(requestPath).toBe("/api/v1/groups/group-acme/role");
    } finally {
      globalThis.fetch = originalFetch;
      if (originalDocument === undefined) Reflect.deleteProperty(globalThis, "document");
      else Object.defineProperty(globalThis, "document", originalDocument);
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
      });
    }
  });
});

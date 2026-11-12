import {Redacted} from "effect";
import {describe, expect, test} from "vitest";

import {inspectRuntimeConfiguration} from "../../src/lifecycle/runtime-inspection.js";

describe("external runtime inspection resource cleanup", () => {
  test("closes an object-storage provider when Postgres is unavailable", async () => {
    let providerCloseCount = 0;
    let factoryCloseCount = 0;
    const configuration = {
      deploymentMode: "external-storage",
      installationId: "inspection-cleanup-test",
      databaseUrl: Redacted.make("postgres://postgres:postgres@127.0.0.1:1/artifacts?connect_timeout=1"),
      objectStorage: {
        close: async () => { factoryCloseCount += 1; },
        create: (_installationId: string) => ({
          close: async () => { providerCloseCount += 1; },
          readiness: async () => undefined,
        }),
      },
    } satisfies Parameters<typeof inspectRuntimeConfiguration>[0];

    const result = await inspectRuntimeConfiguration(configuration);
    expect(result.status).toBe("not_ready");
    expect(providerCloseCount).toBe(1);
    expect(factoryCloseCount).toBe(1);
  });
});

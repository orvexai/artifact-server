import {Effect, Logger} from "effect";
import {describe, expect, test} from "vitest";

import {
  inFlightReportMilliseconds,
  observeInFlightRequest,
} from "../../src/observability/application-observability.js";

describe("in-flight request reports", () => {
  test("a request still running is logged as a warning with bounded attributes", async () => {
    const lines: string[] = [];
    const capturing = Logger.layer([
      Logger.map(Logger.formatJson, (line) => {
        lines.push(line);
      }),
    ]);
    await Effect.runPromise(
      observeInFlightRequest({
        contentOrigin: true,
        elapsedMilliseconds: 2_000,
        method: "GET",
        requestId: "018c4d0e-8659-4aa0-944f-544b9f78a33e",
        route: "*",
      }).pipe(Effect.provide(capturing)),
    );
    expect(lines).toHaveLength(1);
    const line = lines[0] ?? "";
    expect(line).toContain("http.request.in_flight");
    expect(line).toContain("WARN");
    expect(line).toContain('"elapsed_ms":2000');
    expect(line).toContain('"content_origin":true');
    expect(inFlightReportMilliseconds).toEqual([2_000, 10_000, 30_000]);
  });
});

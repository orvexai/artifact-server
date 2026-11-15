import {defineConfig} from "@playwright/test";

export default defineConfig({
  expect: {timeout: 10_000},
  fullyParallel: false,
  outputDir: "test-results/browser",
  reporter: [
    ["line"],
    ["json", {outputFile: "test-results/browser/playwright-report.json"}],
  ],
  testDir: "tests/browser",
  timeout: 60_000,
  use: {
    headless: true,
    launchOptions: {
      args: ["--host-resolver-rules=MAP *.localhost 127.0.0.1"],
    },
    trace: "retain-on-failure",
  },
  workers: 1,
});

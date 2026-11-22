import {defineConfig} from "vitest/config";

export default defineConfig({
  test: {
    fileParallelism: false,
    include: ["tests/integration/org-tenancy.test.ts", "tests/integration/member-deactivate-cli.test.ts"],
    pool: "forks",
    testTimeout: 60_000,
  },
});

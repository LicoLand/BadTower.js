import { randomBytes } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Test credentials are minted per run, never literal in the tree. Each
// project gets its own key so suites cannot share secrets by accident.
const projectBindings = () => ({
  BADTOWER_STATION_KEY: randomBytes(32).toString("base64url"),
  BADTOWER_METRICS_KEY: randomBytes(32).toString("base64url"),
  BADTOWER_PLAN: "free",
  BADTOWER_MAILBOX_CAPACITY_BYTES: "1000000000",
  BADTOWER_ALLOW_PLAINTEXT: "false",
});

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./apps/station/wrangler.jsonc" },
            miniflare: {
              bindings: projectBindings(),
            },
          }),
        ],
        test: {
          name: "workers",
          include: [
            "test/mailbox.test.ts",
            "test/composition.test.ts",
            "test/metrics.test.ts",
          ],
        },
      },
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./test/harness/wrangler.jsonc" },
            miniflare: {
              bindings: projectBindings(),
            },
          }),
        ],
        test: {
          name: "core",
          include: ["test/native.test.ts", "test/conformance.test.ts"],
        },
      },
      {
        test: {
          name: "node",
          environment: "node",
          include: ["test/*.test.mts"],
        },
      },
    ],
  },
});

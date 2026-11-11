import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const SYNTHETIC_STATION_KEY = Buffer.alloc(32, 1).toString("base64url");
process.env.BADTOWER_STATION_KEY ??= SYNTHETIC_STATION_KEY;

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: {
                BADTOWER_STATION_KEY: SYNTHETIC_STATION_KEY,
                BADTOWER_MAILBOX_CAPACITY_BYTES: "1000000000",
              },
            },
          }),
        ],
        test: {
          name: "workers",
          include: ["test/*.test.ts"],
          exclude: ["test/station.test.mts"],
        },
      },
      {
        test: {
          name: "node",
          environment: "node",
          include: ["test/station.test.mts"],
        },
      },
    ],
  },
});

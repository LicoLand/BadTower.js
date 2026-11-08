import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const SYNTHETIC_OPERATOR_DIGEST = "00".repeat(32);
const SYNTHETIC_CAPABILITY_KEY = Buffer.alloc(32, 1).toString("base64url");
const SYNTHETIC_HANDLE_KEY = Buffer.alloc(32, 2).toString("base64url");
const SYNTHETIC_CAPABILITY_KEYS = JSON.stringify({ activeKeyId: 1, keys: { "1": SYNTHETIC_CAPABILITY_KEY } });
const SYNTHETIC_HANDLE_KEYS = JSON.stringify([{ id: 1, key: SYNTHETIC_HANDLE_KEY, notAfter: null }]);
process.env.BADTOWER_OPERATOR_TOKEN_DIGEST ??= SYNTHETIC_OPERATOR_DIGEST;
process.env.BADTOWER_CAPABILITY_KEYS ??= SYNTHETIC_CAPABILITY_KEYS;
process.env.BADTOWER_HANDLE_KEYS ??= SYNTHETIC_HANDLE_KEYS;
process.env.BADTOWER_HANDLE_CURRENT_SLOT ??= "1";

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: {
                BADTOWER_OPERATOR_TOKEN_DIGEST: SYNTHETIC_OPERATOR_DIGEST,
                BADTOWER_CAPABILITY_KEYS: SYNTHETIC_CAPABILITY_KEYS,
                BADTOWER_HANDLE_KEYS: SYNTHETIC_HANDLE_KEYS,
                BADTOWER_HANDLE_CURRENT_SLOT: "1",
              },
            },
          }),
        ],
        test: {
          name: "workers",
          include: [
            "test/contract.test.ts",
            "test/admission.test.ts",
            "test/access.test.ts",
            "test/reservation.test.ts",
            "test/relay.test.ts",
            "test/security-access.test.ts",
            "test/security-abuse.test.ts",
            "test/security-targets.test.ts",
            "test/security-streaming.test.ts",
            "test/security-relay.test.ts",
            "test/security-responses.test.ts",
            "test/security-observability.test.ts",
          ],
        },
      },
      {
        test: {
          name: "node",
          environment: "node",
          include: ["test/status.test.ts", "test/security-scripts.test.ts", "test/security-surface.test.ts"],
        },
      },
    ],
  },
});

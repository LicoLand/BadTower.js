#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const temporaryDirectory = await mkdtemp(join(tmpdir(), "badtower-js-dryrun-"));
const dataSecretFile = join(temporaryDirectory, "data-secrets.json");
const operatorSecretFile = join(temporaryDirectory, "operator-secrets.json");
try {
  const capabilityKeys = JSON.stringify({
    activeKeyId: 1,
    keys: { "1": randomBytes(32).toString("base64url") },
  });
  await Promise.all([
    writeFile(
      dataSecretFile,
      JSON.stringify({
        BADTOWER_CAPABILITY_KEYS: capabilityKeys,
        BADTOWER_HANDLE_KEYS: JSON.stringify([
          {
            id: 1,
            key: randomBytes(32).toString("base64url"),
            notAfter: Date.now() + 24 * 60 * 60 * 1000,
          },
        ]),
        BADTOWER_HANDLE_CURRENT_SLOT: "1",
      }),
      { mode: 0o600 },
    ),
    writeFile(
      operatorSecretFile,
      JSON.stringify({
        BADTOWER_OPERATOR_TOKEN_DIGEST: randomBytes(32).toString("hex"),
        BADTOWER_CAPABILITY_KEYS: capabilityKeys,
      }),
      { mode: 0o600 },
    ),
  ]);
  const exitCodes = await Promise.all(
    [
      ["wrangler.data.jsonc", dataSecretFile],
      ["wrangler.operator.jsonc", operatorSecretFile],
    ].map(
      ([config, secretFile]) =>
        new Promise((resolve, reject) => {
          const child = spawn(
            process.execPath,
            [
              "node_modules/wrangler/bin/wrangler.js",
              "deploy",
              "--dry-run",
              "--config",
              config,
              "--secrets-file",
              secretFile,
            ],
            { stdio: ["ignore", "pipe", "pipe"] },
          );
          let output = "";
          let settled = false;
          const finish = (code) => {
            if (settled) return;
            settled = true;
            resolve(code);
          };
          const inspect = (chunk) => {
            const text = chunk.toString();
            output = (output + text).slice(-4096);
            process.stdout.write(text);
            if (output.includes("--dry-run: exiting now.")) {
              child.kill("SIGTERM");
              finish(0);
            }
          };
          child.stdout.on("data", inspect);
          child.stderr.on("data", inspect);
          child.once("error", reject);
          child.once("exit", (code) => finish(code ?? 1));
        }),
    ),
  );
  if (exitCodes.some((code) => code !== 0)) process.exitCode = 1;
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

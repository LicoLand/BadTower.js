#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { formatDevVars, materialPaths, parseAction, prepareDirectory, writePrivate } from "./secret-material.mjs";

try {
  const target = parseAction("bootstrap");
  await prepareDirectory(target);
  const operatorSecret = randomBytes(32);
  const operatorToken = `bto1.${operatorSecret.toString("base64url")}`;
  const capabilityKey = randomBytes(32).toString("base64url");
  const handleKey = randomBytes(32).toString("base64url");
  const capabilityKeys = { activeKeyId: 1, keys: { "1": capabilityKey } };
  const handleKeys = [{ id: 1, key: handleKey, notAfter: Date.now() + 90 * 24 * 60 * 60 * 1000 }];
  const dataSecrets = {
    BADTOWER_CAPABILITY_KEYS: JSON.stringify(capabilityKeys),
    BADTOWER_HANDLE_KEYS: JSON.stringify(handleKeys),
    BADTOWER_HANDLE_CURRENT_SLOT: "1",
  };
  const operatorSecrets = {
    BADTOWER_OPERATOR_TOKEN_DIGEST: createHash("sha256").update(operatorSecret).digest("hex"),
    BADTOWER_CAPABILITY_KEYS: dataSecrets.BADTOWER_CAPABILITY_KEYS,
  };
  const paths = materialPaths(target);
  await writePrivate(paths.dataSecrets, `${JSON.stringify(dataSecrets, null, 2)}\n`, false);
  await writePrivate(paths.operatorSecrets, `${JSON.stringify(operatorSecrets, null, 2)}\n`, false);
  await writePrivate(paths.devVars, formatDevVars(dataSecrets, operatorSecrets), false);
  await writePrivate(paths.token, `${operatorToken}\n`, false);
  process.stdout.write("bootstrap complete\n");
} catch {
  process.stderr.write("bootstrap failed\n");
  process.exitCode = 1;
}

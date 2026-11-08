#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { formatDevVars, materialPaths, parseAction, readValidatedMaterial, writePrivate } from "./secret-material.mjs";

try {
  const target = parseAction("rotate");
  const { dataSecrets, operatorSecrets } = await readValidatedMaterial(target);
  const capability = JSON.parse(dataSecrets.BADTOWER_CAPABILITY_KEYS);
  const handles = JSON.parse(dataSecrets.BADTOWER_HANDLE_KEYS);
  const nextCapabilityId = (capability.activeKeyId + 1) & 0xff;
  const nextHandleId = (Number(dataSecrets.BADTOWER_HANDLE_CURRENT_SLOT) + 1) & 0xff;
  if (capability.keys[String(nextCapabilityId)] !== undefined || handles.some(({ id }) => id === nextHandleId)) {
    throw new Error("key identifier is already active");
  }
  if (Object.keys(capability.keys).length >= 4) throw new Error("retire an expired capability key before rotation");
  capability.activeKeyId = nextCapabilityId;
  capability.keys[String(nextCapabilityId)] = randomBytes(32).toString("base64url");
  const liveHandles = handles.filter(({ notAfter }) => notAfter > Date.now()).slice(-2);
  liveHandles.push({
    id: nextHandleId,
    key: randomBytes(32).toString("base64url"),
    notAfter: Date.now() + 90 * 24 * 60 * 60 * 1000,
  });
  const nextData = {
    ...dataSecrets,
    BADTOWER_CAPABILITY_KEYS: JSON.stringify(capability),
    BADTOWER_HANDLE_KEYS: JSON.stringify(liveHandles),
    BADTOWER_HANDLE_CURRENT_SLOT: String(nextHandleId),
  };
  const nextOperator = {
    ...operatorSecrets,
    BADTOWER_CAPABILITY_KEYS: nextData.BADTOWER_CAPABILITY_KEYS,
  };
  const paths = materialPaths(target);
  await writePrivate(paths.dataSecrets, `${JSON.stringify(nextData, null, 2)}\n`, true);
  await writePrivate(paths.operatorSecrets, `${JSON.stringify(nextOperator, null, 2)}\n`, true);
  await writePrivate(paths.devVars, formatDevVars(nextData, nextOperator), true);
  process.stdout.write("rotation complete\n");
} catch {
  process.stderr.write("rotation failed\n");
  process.exitCode = 1;
}

#!/usr/bin/env node
/**
 * Generic container healthcheck: GET an injected endpoint once and exit
 * 0 only on HTTP 200. The deployment supplies the URL and, when the
 * station serves a private CA, the trusted CA path — nothing about the
 * station's own address is baked into the image.
 */
import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const target = process.env.BADTOWER_HEALTHCHECK_URL;
if (target === undefined || target === "") {
  console.error("BADTOWER_HEALTHCHECK_URL is not set");
  process.exit(1);
}
const caFile = process.env.BADTOWER_HEALTHCHECK_CA;
const ca = caFile === undefined ? undefined : fs.readFileSync(caFile);
const client = target.startsWith("https:") ? https : http;
const request = client.get(target, { ca }, (response) => {
  response.resume();
  response.on("end", () => process.exit(response.statusCode === 200 ? 0 : 1));
});
request.setTimeout(4_000, () => {
  request.destroy();
  process.exit(1);
});
request.on("error", () => process.exit(1));

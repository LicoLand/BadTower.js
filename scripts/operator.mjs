#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { join } from "node:path";

function usage() {
  process.stderr.write(
    [
      "usage:",
      "  node scripts/operator.mjs invite --operator-origin <url> [--token-file <path>] [--invite-ttl <seconds>] [--access-ttl <seconds>]",
      "  node scripts/operator.mjs status --operator-origin <url> [--token-file <path>] --id <invitation-id>",
      "  node scripts/operator.mjs revoke --operator-origin <url> [--token-file <path>] --id <invitation-id>",
    ].join("\n") + "\n",
  );
  process.exit(2);
}

function option(args, name, required = true) {
  const index = args.indexOf(name);
  if (index === -1) {
    if (required) usage();
    return undefined;
  }
  const value = args[index + 1];
  if (value === undefined) usage();
  return value;
}

function positiveInteger(value, name) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    process.stderr.write(`${name} must be a positive integer\n`);
    process.exit(2);
  }
  return parsed;
}

const args = process.argv.slice(2);
const command = args.shift();
if (command !== "invite" && command !== "status" && command !== "revoke") usage();
const server = option(args, "--operator-origin").replace(/\/$/, "");
const serverUrl = new URL(server);
const loopback =
  serverUrl.hostname === "localhost" ||
  serverUrl.hostname === "127.0.0.1" ||
  serverUrl.hostname === "[::1]";
if (serverUrl.protocol !== "https:" && !(serverUrl.protocol === "http:" && loopback)) {
  process.stderr.write("server must use HTTPS, except for local loopback operation\n");
  process.exit(2);
}
const tokenFile = option(args, "--token-file", false) ?? join("data", "private", "operator-token");
const token = (await readFile(tokenFile, "utf8")).trim();
if (!token.startsWith("bto1.")) {
  process.stderr.write("operator token file is invalid\n");
  process.exit(2);
}

let path;
let method;
let body;
if (command === "invite") {
  path = "/v1/operator/invitations";
  method = "POST";
  const invitationTtlSeconds = positiveInteger(option(args, "--invite-ttl", false), "--invite-ttl");
  const accessTtlSeconds = positiveInteger(option(args, "--access-ttl", false), "--access-ttl");
  body = JSON.stringify({
    ...(invitationTtlSeconds !== undefined ? { invitationTtlSeconds } : {}),
    ...(accessTtlSeconds !== undefined ? { accessTtlSeconds } : {}),
  });
} else {
  const id = option(args, "--id");
  if (!/^[A-Za-z0-9_-]{22}$/.test(id)) {
    process.stderr.write("invitation id is invalid\n");
    process.exit(2);
  }
  path = `/v1/operator/grants/${id}`;
  method = command === "status" ? "GET" : "DELETE";
}

const response = await fetch(`${server}${path}`, {
  method,
  headers: {
    Authorization: `Bearer ${token}`,
    ...(body !== undefined
      ? {
          "Content-Type": "application/json",
          "Content-Length": String(Buffer.byteLength(body)),
        }
      : {}),
  },
  ...(body !== undefined ? { body } : {}),
});

if (response.status === 204) {
  process.stdout.write("revoked\n");
} else {
  const text = await response.text();
  if (!response.ok) {
    process.stderr.write(`request failed with HTTP ${response.status}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`${text}\n`);
  }
}

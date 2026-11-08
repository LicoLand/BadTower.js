#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { readValidatedMaterial } from "./secret-material.mjs";

function parseUniqueJson(text) {
  let offset = 0;
  const whitespace = () => { while (/\s/.test(text[offset] ?? "")) offset += 1; };
  const string = () => {
    const start = offset;
    if (text[offset] !== '"') throw new Error();
    offset += 1;
    while (offset < text.length) {
      if (text[offset] === "\\") { offset += 2; continue; }
      if (text[offset] === '"') { offset += 1; return JSON.parse(text.slice(start, offset)); }
      offset += 1;
    }
    throw new Error();
  };
  const value = () => {
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set();
      if (text[offset] === "}") { offset += 1; return; }
      for (;;) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error();
        keys.add(key);
        whitespace();
        if (text[offset] !== ":") throw new Error();
        offset += 1;
        value();
        whitespace();
        if (text[offset] === "}") { offset += 1; return; }
        if (text[offset] !== ",") throw new Error();
        offset += 1;
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") { offset += 1; return; }
      for (;;) {
        value();
        whitespace();
        if (text[offset] === "]") { offset += 1; return; }
        if (text[offset] !== ",") throw new Error();
        offset += 1;
      }
    }
    if (text[offset] === '"') { string(); return; }
    const start = offset;
    while (offset < text.length && !/[\s,\]}]/.test(text[offset])) offset += 1;
    if (offset === start) throw new Error();
  };
  value();
  whitespace();
  if (offset !== text.length) throw new Error();
  return JSON.parse(text);
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactStrings(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    [...value].sort().every((entry, index) => entry === [...expected].sort()[index]);
}

function validRoute(routes) {
  if (!Array.isArray(routes) || routes.length !== 1 || !exactKeys(routes[0], ["pattern", "custom_domain"])) return false;
  const route = routes[0];
  return route.custom_domain === true &&
    typeof route.pattern === "string" &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(route.pattern) &&
    !route.pattern.endsWith(".invalid") &&
    !route.pattern.includes("*");
}

function validObservability(value) {
  return exactKeys(value, ["enabled", "logs", "traces"]) && value.enabled === false &&
    exactKeys(value.logs, ["enabled", "invocation_logs"]) && value.logs.enabled === false && value.logs.invocation_logs === false &&
    exactKeys(value.traces, ["enabled"]) && value.traces.enabled === false;
}

function validConfig(config, kind) {
  const common = ["$schema", "name", "main", "compatibility_date", "compatibility_flags", "workers_dev", "preview_urls", "routes", "vars", "secrets", "observability", "durable_objects", "ratelimits"];
  const top = kind === "data" ? [...common, "migrations"] : common;
  if (!exactKeys(config, top) || config.workers_dev !== false || config.preview_urls !== false || !validRoute(config.routes) || !validObservability(config.observability)) return false;
  if (!exactStrings(config.compatibility_flags, ["nodejs_compat"])) return false;
  const bindings = config.durable_objects?.bindings;
  const rateNames = config.ratelimits?.map((entry) => entry?.name);
  if (kind === "data") {
    return config.name === "badtower-data" && config.main === "src/data-entry.ts" &&
      exactKeys(config.vars, ["BADTOWER_RUNTIME_MODE"]) && config.vars.BADTOWER_RUNTIME_MODE === "production" &&
      exactKeys(config.secrets, ["required"]) && exactStrings(config.secrets.required, ["BADTOWER_CAPABILITY_KEYS", "BADTOWER_HANDLE_KEYS", "BADTOWER_HANDLE_CURRENT_SLOT"]) &&
      Array.isArray(bindings) && bindings.length === 3 &&
      bindings.every((entry) => exactKeys(entry, ["name", "class_name"])) &&
      exactStrings(bindings.map((entry) => `${entry.name}:${entry.class_name}`), ["ACCESS_GRANTS:AccessGrant", "AFFILIATION_SHARDS:AffiliationShard", "RELAY_HANDLES:RelayHandle"]) &&
      exactStrings(rateNames, ["EDGE_ADMISSION_RATE_LIMITER", "CLIENT_RATE_LIMITER", "SENSITIVE_RATE_LIMITER"]);
  }
  return config.name === "badtower-operator" && config.main === "src/operator-entry.ts" &&
    exactKeys(config.vars, ["BADTOWER_RUNTIME_MODE", "BADTOWER_EDGE_AUTHORIZATION"]) && config.vars.BADTOWER_RUNTIME_MODE === "production" && config.vars.BADTOWER_EDGE_AUTHORIZATION === "mtls" &&
    exactKeys(config.secrets, ["required"]) && exactStrings(config.secrets.required, ["BADTOWER_OPERATOR_TOKEN_DIGEST", "BADTOWER_CAPABILITY_KEYS"]) &&
    Array.isArray(bindings) && bindings.length === 1 && exactKeys(bindings[0], ["name", "class_name", "script_name"]) &&
    bindings[0].name === "ACCESS_GRANTS" && bindings[0].class_name === "AccessGrant" && bindings[0].script_name === "badtower-data" &&
    exactStrings(rateNames, ["SENSITIVE_RATE_LIMITER"]);
}

try {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--target-dir" || args[1] === undefined) throw new Error();
  await readValidatedMaterial(resolve(args[1]));
  for (const [name, kind] of [["wrangler.data.jsonc", "data"], ["wrangler.operator.jsonc", "operator"]]) {
    const text = await readFile(name, "utf8");
    if (/\*|\/\//.test(text)) throw new Error();
    const config = parseUniqueJson(text);
    if (!validConfig(config, kind)) throw new Error();
  }
  process.stdout.write("deployment preflight complete\n");
} catch {
  process.stderr.write("deployment preflight failed\n");
  process.exitCode = 1;
}

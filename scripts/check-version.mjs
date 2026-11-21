#!/usr/bin/env node
/**
 * Version-source check. The root package.json is the only place a
 * release version is chosen; every workspace manifest, the lockfile and
 * the newest CHANGELOG entry must agree with it. This script is run by
 * `npm run check`, so a version bump cannot land half-applied.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function readJson(relative) {
  const file = path.join(ROOT, relative);
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    failures.push(`${relative}: cannot read JSON (${error.message})`);
    return null;
  }
}

function expect(label, actual, expected) {
  if (actual !== expected) {
    failures.push(`${label}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
  }
}

const root = readJson("package.json");
if (root === null) {
  console.error(failures.join("\n"));
  process.exit(1);
}
const version = root.version;
if (typeof version !== "string" || version.length === 0) {
  failures.push("package.json: version must be a non-empty string");
}

/** Expand the small workspace globs this repository uses. */
function workspaceManifests() {
  const manifests = [];
  for (const pattern of root.workspaces ?? []) {
    if (!pattern.endsWith("/*")) {
      failures.push(`package.json: unsupported workspace pattern ${pattern}`);
      continue;
    }
    const parent = pattern.slice(0, -2);
    for (const entry of fs.readdirSync(path.join(ROOT, parent), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const manifest = path.join(parent, entry.name, "package.json");
      if (fs.existsSync(path.join(ROOT, manifest))) manifests.push(manifest);
    }
  }
  return manifests.sort();
}

const manifests = workspaceManifests();
for (const manifest of manifests) {
  const pkg = readJson(manifest);
  if (pkg !== null) expect(`${manifest}: version`, pkg.version, version);
}

const lock = readJson("package-lock.json");
if (lock !== null) {
  expect("package-lock.json: version", lock.version, version);
  expect("package-lock.json: packages[''].version", lock.packages?.[""]?.version, version);
  for (const manifest of manifests) {
    const directory = path.dirname(manifest);
    expect(`package-lock.json: packages['${directory}'].version`, lock.packages?.[directory]?.version, version);
  }
}

const changelogFile = path.join(ROOT, "CHANGELOG.md");
let changelog = "";
try {
  changelog = fs.readFileSync(changelogFile, "utf8");
} catch (error) {
  failures.push(`CHANGELOG.md: cannot read (${error.message})`);
}
const releases = changelog.match(/^##\s+.+$/gm) ?? [];
const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const versionHeading = `^##\\s+\\[?${escaped}\\]?(?:\\s|$)`;
if (releases.length === 0) {
  failures.push("CHANGELOG.md: no release headings; the newest release must record the package version");
} else {
  if (!new RegExp(versionHeading).test(releases[0])) {
    failures.push(`CHANGELOG.md: newest release ${JSON.stringify(releases[0])} is not package version ${version}`);
  }
  const matches = changelog.match(new RegExp(versionHeading, "gm")) ?? [];
  if (matches.length !== 1) {
    failures.push(`CHANGELOG.md: expected exactly one '## [${version}]' heading, found ${matches.length}`);
  }
}

if (failures.length > 0) {
  console.error("version check failed:");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(
  `version check: ${version} consistent across package.json, ` +
    `${manifests.length} workspace manifest(s), package-lock.json and CHANGELOG.md`,
);

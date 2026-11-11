/**
 * Ownership boundary checks: station-core must never reach the plugin or
 * the app, and must never carry listener-specific vocabulary; the plugin
 * may drive the core API but never the app, and must never load a
 * LicoArc checkout. These are source-level invariants, so the test walks
 * the sources rather than the bundled output.
 */
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const sources = (dir: string): string[] =>
  fs.readdirSync(path.join(root, dir), { recursive: true })
    .filter((entry) => String(entry).endsWith(".ts"))
    .map((entry) => path.join(dir, String(entry)));

const grep = (files: string[], pattern: RegExp): string[] =>
  files.flatMap((file) => {
    const text = fs.readFileSync(path.join(root, file), "utf8");
    return text
      .split("\n")
      .flatMap((line, index) => (pattern.test(line) ? [`${file}:${index + 1}`] : []));
  });

const IMPORT = /(?:import|from|import\()\s*['"]([^'"]+)['"]/g;
const importSpecifiers = (file: string): string[] => {
  const text = fs.readFileSync(path.join(root, file), "utf8");
  return [...text.matchAll(IMPORT)].map((match) => match[1]!);
};

const CORE = sources("packages/station-core/src");
const PLUGIN = sources("packages/plugin-licoarc-mailbox/src");

describe("station-core boundary", () => {
  it("imports no plugin or app code", () => {
    for (const file of CORE) {
      for (const specifier of importSpecifiers(file)) {
        expect(specifier, `${file} imports ${specifier}`).not.toMatch(/plugin-licoarc|apps\//);
      }
    }
  });

  it("carries no listener protocol vocabulary", () => {
    const hits = grep(CORE, /licoarc|cbor|mailbox\.v1|Sec-WebSocket-Protocol|Ed25519/i);
    expect(hits).toEqual([]);
  });
});

describe("plugin boundary", () => {
  it("reaches only the core public API, never the app or a LicoArc checkout", () => {
    for (const file of PLUGIN) {
      for (const specifier of importSpecifiers(file)) {
        expect(specifier, `${file} imports ${specifier}`).not.toMatch(/apps\/|LicoArc|licoarc-(rust|client|cli)/i);
      }
    }
  });
});

describe("git boundary", () => {
  it("keeps private output roots ignored by both git and the image", () => {
    const gitignore = fs.readFileSync(path.join(root, ".gitignore"), "utf8");
    const dockerignore = fs.readFileSync(path.join(root, ".dockerignore"), "utf8");
    for (const dir of ["data", "secrets"]) {
      expect(gitignore, dir).toMatch(new RegExp(`^/?${dir}/?$`, "m"));
      expect(dockerignore, dir).toMatch(new RegExp(`^/?${dir}/?$`, "m"));
    }
  });
});

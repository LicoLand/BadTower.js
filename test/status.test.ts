import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = join(ROOT, "src");

function read(relative: string): string {
  return readFileSync(join(ROOT, relative), "utf8");
}

function walkTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkTsFiles(path));
    else if (entry.name.endsWith(".ts")) out.push(path);
  }
  return out;
}

const DOCUMENTS = [
  "README.md",
  "ARCHITECTURE.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "docs/README.md",
  "docs/API.md",
  "docs/OPERATIONS.md",
  "docs/STATUS.md",
];

describe("public repository contract", () => {
  it("documents the implemented open-source public-service boundary", () => {
    for (const relative of DOCUMENTS) expect(existsSync(join(ROOT, relative))).toBe(true);
    const status = read("docs/STATUS.md");
    const normalizedStatus = status.replace(/\s+/g, " ");
    for (const phrase of [
      "open-source",
      "split data/operator entrypoints",
      "proof-bound relay admission",
      "authenticated v2 invitation and access capabilities",
      "revocation",
      "atomic grant budgets",
      "not the Go BadTower implementation",
      "stable LicoArc conformance",
      "endpoint-evidence",
      "anonymity",
      "AFFILIATE",
      "asynchronous `RESERVE`",
      "unsupportedProfile",
      "required signature material",
      "synthetic inputs",
      "real edge framing",
      "certificate",
    ]) {
      expect(normalizedStatus, `missing status fact: ${phrase}`).toContain(phrase);
    }
  });

  it("has an AGPL license and reproducible verification entry points", () => {
    expect(read("LICENSE")).toContain("GNU AFFERO GENERAL PUBLIC LICENSE");
    const pkg = JSON.parse(read("package.json")) as {
      license?: string;
      scripts: Record<string, string>;
    };
    expect(pkg.license).toBe("AGPL-3.0-or-later");
    for (const script of [
      "verify:focused",
      "test:access",
      "test:admission",
      "test:contract",
      "test:reservation",
      "test:relay",
      "test:status",
      "typecheck",
      "check:generated",
      "dryrun",
      "container:up",
      "cloudflare:deploy",
      "operator",
    ]) {
      expect(typeof pkg.scripts[script], `missing script: ${script}`).toBe("string");
    }
  });

  it("ships public CI and dependency update policy without deployment authority", () => {
    const workflow = read(".github/workflows/verify.yml");
    expect(workflow).toContain("permissions:");
    expect(workflow).toContain("contents: read");
    expect(workflow).toContain("npm run check");
    expect(workflow).toContain("push: false");
    expect(workflow).not.toContain("wrangler deploy");
    expect(read(".github/dependabot.yml")).toContain("package-ecosystem: npm");
  });

  it("declares required secrets by name only and all production bindings", () => {
    const data = read("wrangler.data.jsonc");
    const operator = read("wrangler.operator.jsonc");
    const config = `${data}\n${operator}`;
    for (const secret of [
      "BADTOWER_OPERATOR_TOKEN_DIGEST",
      "BADTOWER_CAPABILITY_KEYS",
      "BADTOWER_HANDLE_KEYS",
      "BADTOWER_HANDLE_CURRENT_SLOT",
    ]) {
      expect(config).toContain(secret);
      expect(config).not.toMatch(new RegExp(`"${secret}"\\s*:\\s*"[A-Za-z0-9_-]{20}`));
    }
    for (const binding of [
      "ACCESS_GRANTS",
      "AFFILIATION_SHARDS",
      "RELAY_HANDLES",
      "EDGE_ADMISSION_RATE_LIMITER",
      "CLIENT_RATE_LIMITER",
      "SENSITIVE_RATE_LIMITER",
    ]) {
      expect(config).toContain(binding);
    }
    expect(config).toContain("new_sqlite_classes");
    expect(config).toContain("nodejs_compat");
    expect(config).toContain("observability");
    expect(data).toContain('"workers_dev": false');
    expect(operator).toContain('"workers_dev": false');
  });

  it("ships an isolated container without embedding credentials", () => {
    for (const relative of ["Dockerfile", "compose.yml", ".dockerignore"]) {
      expect(existsSync(join(ROOT, relative))).toBe(true);
    }
    const compose = read("compose.yml");
    expect(compose).toContain("127.0.0.1:${BADTOWER_PORT:-8790}:8787");
    expect(compose).toContain("read_only: true");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toContain("cap_drop:");
    expect(read("Dockerfile")).toContain("USER node");
  });

  it("keeps generated, secret, runtime, and build material ignored", () => {
    const gitignore = read(".gitignore");
    for (const pattern of [
      "node_modules/",
      ".local/",
      ".wrangler/",
      ".dev.vars",
      ".env",
      "coverage/",
      "build/",
      "dist/",
      "*.tsbuildinfo",
      "*.cpuprofile",
      "docs/plans/",
    ]) {
      expect(gitignore, `.gitignore misses pattern: ${pattern}`).toContain(pattern);
    }
    for (const name of [".dev.vars", ".dev.vars.local", ".env", ".env.local"]) {
      expect(existsSync(join(ROOT, name)), `${name} must not exist`).toBe(false);
    }
  });
});

describe("independent runtime", () => {
  it("imports only local modules and platform built-ins", () => {
    for (const file of walkTsFiles(SRC)) {
      const content = readFileSync(file, "utf8");
      for (const line of content.split("\n")) {
        const match = /^\s*import\s+(?:type\s+)?[^"']*?["']([^"']+)["']/.exec(line);
        if (match === null) continue;
        const specifier = match[1]!;
        expect(
          specifier.startsWith("./") ||
            specifier.startsWith("../") ||
            specifier === "cloudflare:workers" ||
            specifier.startsWith("node:"),
          `${file} imports foreign runtime: ${specifier}`,
        ).toBe(true);
      }
    }
  });

  it("uses strict TypeScript and generated binding types", () => {
    const tsconfig = JSON.parse(read("tsconfig.json")) as {
      compilerOptions: { strict?: boolean };
    };
    expect(tsconfig.compilerOptions.strict).toBe(true);
    expect(existsSync(join(ROOT, "worker-configuration.d.ts"))).toBe(true);
    expect(existsSync(join(ROOT, "package-lock.json"))).toBe(true);
  });
});

import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function run(script: string, args: string[], cwd?: string) {
  const child = spawn(process.execPath, [resolve(script), ...args], { cwd, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const code = await new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (value) => resolve(value ?? 1));
  });
  return { code, stdout, stderr };
}

describe("explicit secret lifecycle", () => {
  it("bootstraps and rotates only with explicit confirmation and owner-only files", async () => {
    const root = await mkdtemp(join(tmpdir(), "bt-security-"));
    roots.push(root);
    const target = join(root, "private");
    const boot = await run("scripts/bootstrap-secrets.mjs", ["--target-dir", target, "--confirm", "bootstrap"]);
    expect(boot).toEqual({ code: 0, stdout: "bootstrap complete\n", stderr: "" });
    const before = await readFile(join(target, "cloudflare-data-secrets.json"), "utf8");
    for (const name of ["cloudflare-data-secrets.json", "cloudflare-operator-secrets.json", "operator-token", ".dev.vars"]) {
      expect((await stat(join(target, name))).mode & 0o077).toBe(0);
    }
    const rotate = await run("scripts/rotate-secrets.mjs", ["--target-dir", target, "--confirm", "rotate"]);
    expect(rotate).toEqual({ code: 0, stdout: "rotation complete\n", stderr: "" });
    expect(await readFile(join(target, "cloudflare-data-secrets.json"), "utf8")).not.toBe(before);
    expect(`${boot.stdout}${rotate.stdout}`).not.toContain(target);
  });

  it("fails closed for missing confirmation and broad directory permissions", async () => {
    const root = await mkdtemp(join(tmpdir(), "bt-security-"));
    roots.push(root);
    const target = join(root, "private");
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", target])).code).not.toBe(0);
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", target, "--confirm", "bootstrap"])).code).toBe(0);
    await chmod(target, 0o755);
    const result = await run("scripts/rotate-secrets.mjs", ["--target-dir", target, "--confirm", "rotate"]);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toBe("rotation failed\n");
    expect(result.stderr).not.toContain(target);
  });

  it("keeps ordinary deployment validation-only", async () => {
    const text = await readFile("scripts/deploy-cloudflare.sh", "utf8");
    expect(text).toContain("validate-deployment.mjs");
    expect(text).not.toMatch(/bootstrap|rotate|random|generate/i);
    expect(text).toContain("cloudflare-data-secrets.json");
    expect(text).toContain("cloudflare-operator-secrets.json");
  });

  it("rejects inconsistent credentials, unsafe local variables, exhausted key slots, and placeholder routes", async () => {
    const root = await mkdtemp(join(tmpdir(), "bt-security-"));
    roots.push(root);

    const mismatch = join(root, "mismatch");
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", mismatch, "--confirm", "bootstrap"])).code).toBe(0);
    await writeFile(join(mismatch, "operator-token"), `bto1.${"A".repeat(43)}\n`);
    expect((await run("scripts/rotate-secrets.mjs", ["--target-dir", mismatch, "--confirm", "rotate"])).code).not.toBe(0);

    const broad = join(root, "broad");
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", broad, "--confirm", "bootstrap"])).code).toBe(0);
    await chmod(join(broad, ".dev.vars"), 0o644);
    expect((await run("scripts/rotate-secrets.mjs", ["--target-dir", broad, "--confirm", "rotate"])).code).not.toBe(0);

    const stale = join(root, "stale");
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", stale, "--confirm", "bootstrap"])).code).toBe(0);
    await writeFile(join(stale, ".dev.vars"), "BADTOWER_CAPABILITY_KEYS=\"stale\"\n", { mode: 0o600 });
    expect((await run("scripts/rotate-secrets.mjs", ["--target-dir", stale, "--confirm", "rotate"])).code).not.toBe(0);

    const bounded = join(root, "bounded");
    expect((await run("scripts/bootstrap-secrets.mjs", ["--target-dir", bounded, "--confirm", "bootstrap"])).code).toBe(0);
    for (let index = 0; index < 3; index += 1) {
      expect((await run("scripts/rotate-secrets.mjs", ["--target-dir", bounded, "--confirm", "rotate"])).code).toBe(0);
    }
    expect((await run("scripts/rotate-secrets.mjs", ["--target-dir", bounded, "--confirm", "rotate"])).code).not.toBe(0);

    const preflight = await run("scripts/validate-deployment.mjs", ["--target-dir", bounded]);
    expect(preflight).toEqual({ code: 1, stdout: "", stderr: "deployment preflight failed\n" });
    expect(preflight.stderr).not.toContain(bounded);

    const configured = join(root, "configured");
    await mkdir(configured);
    await Promise.all([
      writeFile(
        join(configured, "wrangler.data.jsonc"),
        (await readFile("wrangler.data.jsonc", "utf8")).replace("data.badtower.invalid", "data.example.com"),
        { flag: "wx" },
      ),
      writeFile(
        join(configured, "wrangler.operator.jsonc"),
        (await readFile("wrangler.operator.jsonc", "utf8")).replace("operator.badtower.invalid", "operator.example.com"),
        { flag: "wx" },
      ),
    ]);
    const validPreflight = await run(
      "scripts/validate-deployment.mjs",
      ["--target-dir", bounded],
      configured,
    );
    expect(validPreflight).toEqual({ code: 0, stdout: "deployment preflight complete\n", stderr: "" });
  });
});

import { spawn } from "node:child_process";

const checks = [
  ["worker-configuration.d.ts", "wrangler.data.jsonc"],
  ["worker-configuration.data.d.ts", "wrangler.data.jsonc"],
  ["worker-configuration.operator.d.ts", "wrangler.operator.jsonc"],
];

const statuses = await Promise.all(
  checks.map(
    ([types, config]) =>
      new Promise((resolve) => {
        const child = spawn(
          process.execPath,
          ["node_modules/wrangler/bin/wrangler.js", "types", types, "--check", "-c", config],
          { stdio: ["ignore", "pipe", "pipe"] },
        );
        let output = "";
        let settled = false;
        const finish = (status) => {
          if (settled) return;
          settled = true;
          resolve(status);
        };
        const inspect = (chunk) => {
          const text = chunk.toString();
          output = (output + text).slice(-4096);
          process.stdout.write(text);
          if (output.includes(`Types at ${types} are up to date.`)) {
            child.kill("SIGTERM");
            finish(0);
          }
        };
        child.stdout.on("data", inspect);
        child.stderr.on("data", inspect);
        child.once("error", () => finish(1));
        child.once("exit", (code) => finish(code ?? 1));
      }),
  ),
);
if (statuses.some((status) => status !== 0)) process.exit(1);

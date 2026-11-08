import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("split production ingress", () => {
  it("keeps entrypoint imports and route ownership disjoint", async () => {
    const [data, operator] = await Promise.all([
      readFile("src/data-entry.ts", "utf8"),
      readFile("src/operator-entry.ts", "utf8"),
    ]);
    expect(data).toContain('./access/data-service');
    expect(data).not.toMatch(/operator-service|operator\/invitations|\/readyz/);
    expect(operator).toContain('./access/operator-service');
    expect(operator).not.toMatch(/transport\/codec|durable\/relay-handle|RELAY_HANDLES/);
    expect(operator).toContain("tlsClientAuth");
  });

  it.each([
    ["wrangler.data.jsonc", "src/data-entry.ts"],
    ["wrangler.operator.jsonc", "src/operator-entry.ts"],
  ])("closes production surfaces in %s", async (path, main) => {
    const config = JSON.parse(await readFile(path, "utf8"));
    expect(config.main).toBe(main);
    expect(config.workers_dev).toBe(false);
    expect(config.preview_urls).toBe(false);
    expect(config.routes).toHaveLength(1);
    expect(config.routes[0].custom_domain).toBe(true);
    expect(config.routes[0].pattern).not.toContain("*");
    expect(config.observability.logs.invocation_logs).toBe(false);
    expect(config.observability.traces.enabled).toBe(false);
    if (path === "wrangler.operator.jsonc") {
      expect(config.vars.BADTOWER_EDGE_AUTHORIZATION).toBe("mtls");
    }
  });

  it("keeps data and operator bindings mutually exclusive", async () => {
    const data = JSON.parse(await readFile("wrangler.data.jsonc", "utf8"));
    const operator = JSON.parse(await readFile("wrangler.operator.jsonc", "utf8"));
    expect(data.durable_objects.bindings.map(({ name }: { name: string }) => name).sort()).toEqual([
      "ACCESS_GRANTS",
      "AFFILIATION_SHARDS",
      "RELAY_HANDLES",
    ]);
    expect(operator.durable_objects.bindings.map(({ name }: { name: string }) => name)).toEqual([
      "ACCESS_GRANTS",
    ]);
  });
});

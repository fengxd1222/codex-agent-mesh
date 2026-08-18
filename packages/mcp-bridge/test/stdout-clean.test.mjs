import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("the stdio bridge emits only MCP JSON-RPC on stdout", () => {
  const entrypoint = fileURLToPath(
    new URL("../dist/index.js", import.meta.url),
  );
  const input = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "stdout-purity-test", version: "1.0.0" },
      },
    },
    {
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  ]
    .map((message) => JSON.stringify(message))
    .join("\n");
  const result = spawnSync(process.execPath, [entrypoint], {
    encoding: "utf8",
    input: `${input}\n`,
    timeout: 10_000,
  });

  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  const output = result.stdout
    .trim()
    .split(/\r?\n/u)
    .filter(Boolean)
    .map(JSON.parse);
  assert.deepEqual(
    output.map((message) => message.id),
    [1, 2],
  );
  assert.equal(
    output.every((message) => message.jsonrpc === "2.0"),
    true,
  );
  assert.equal(output[1].result.tools.length, 8);
  assert.equal(result.stderr, "");
});

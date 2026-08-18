import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";

const [pluginArgument, callerArgument] = process.argv.slice(2);
if (!pluginArgument || !callerArgument) {
  throw new Error("plugin root and caller cwd are required");
}

const pluginRoot = realpathSync(resolve(pluginArgument));
const callerCwd = realpathSync(resolve(callerArgument));
process.chdir(callerCwd);

const manifest = JSON.parse(
  readFileSync(resolve(pluginRoot, ".mcp.json"), "utf8"),
);
const server = manifest?.mcpServers?.["codex-agent-mesh"];
assert.equal(server?.command, "node");
assert.equal(server?.cwd, ".");
assert.deepEqual(server?.args, ["runtime/mcp-bridge/index.js"]);

const serverCwd = realpathSync(resolve(pluginRoot, server.cwd));
assert.equal(serverCwd, pluginRoot);
assert.notEqual(realpathSync(process.cwd()), serverCwd);

const input = [
  {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "installed-path-fixture", version: "1.0.0" },
    },
  },
  { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
]
  .map((message) => JSON.stringify(message))
  .join("\n");

const result = spawnSync(process.execPath, server.args, {
  cwd: serverCwd,
  encoding: "utf8",
  input: `${input}\n`,
  timeout: 15_000,
  windowsHide: true,
});

assert.equal(result.error, undefined);
assert.equal(result.status, 0, result.stderr);
assert.equal(result.stderr, "");
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
assert.equal(output[1]?.result?.tools?.length, 8);

process.stdout.write(
  "Installed-path fixture resolved cwd from the plugin root and listed eight MCP tools.\n",
);

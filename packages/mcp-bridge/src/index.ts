import { runStdioServer } from "./mcp-server.js";
import { NativeHelperTransport } from "./native-transport.js";

const rpc = new NativeHelperTransport();

process.stdin.once("end", () => {
  void rpc.close();
});

process.stdout.once("error", (error: NodeJS.ErrnoException) => {
  if (error.code !== "EPIPE") return;
  // A vanished MCP host closes only this bridge/helper process tree. Durable
  // daemon tasks are never translated into cancellation by transport teardown.
  void rpc.close().finally(() => process.exit(0));
});

runStdioServer(rpc).catch((error: unknown) => {
  const message =
    error instanceof Error ? error.message : "unknown bridge error";
  process.stderr.write(`codex-agent-mesh bridge failed: ${message}\n`);
  process.exitCode = 1;
});

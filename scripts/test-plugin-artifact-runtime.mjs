import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [artifactArgument] = process.argv.slice(2);
if (!artifactArgument) throw new Error("artifact root is required");

const artifactRoot = realpathSync(resolve(artifactArgument));
const transportPath = resolve(
  artifactRoot,
  "runtime/mcp-bridge/native-transport.js",
);
const transport = await import(pathToFileURL(transportPath).href);
const observed = realpathSync(
  transport.resolveBundledSetupHelper(pathToFileURL(transportPath).href),
);
const expected = realpathSync(
  resolve(artifactRoot, "bin/windows-x64/mesh-daemon.exe"),
);
if (observed !== expected) {
  throw new Error("bundled helper did not resolve inside the artifact");
}

process.stdout.write(
  "Plugin artifact runtime layout resolves the bundled helper.\n",
);

import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const forbiddenValue = [
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /sk-[a-z0-9_-]{12,}/i,
  /(?:[a-z]:\\users\\|\/users\/|\/home\/)/i,
];
const forbiddenKey =
  /(?:api[_-]?key|token|password|secret|credential|account(?:_id)?|user_id|organization_id|prompt|objective|context)/i;
function inspect(value, path, rejectSensitiveKeyNames) {
  if (Array.isArray(value))
    return value.forEach((item, index) =>
      inspect(item, `${path}[${index}]`, rejectSensitiveKeyNames),
    );
  if (value && typeof value === "object")
    for (const [key, item] of Object.entries(value)) {
      for (const pattern of forbiddenValue)
        if (pattern.test(key))
          throw new Error(`unsafe fixture key ${path}.${key}`);
      if (rejectSensitiveKeyNames && forbiddenKey.test(key))
        throw new Error(`unsafe fixture key ${path}.${key}`);
      inspect(item, `${path}.${key}`, rejectSensitiveKeyNames);
    }
  if (typeof value === "string")
    for (const pattern of forbiddenValue)
      if (pattern.test(value))
        throw new Error(`unsafe fixture value at ${path}`);
}
const forbidden = [
  /(?:[a-z]:\\users\\|\/users\/|\/home\/)/i,
  /(?:account(?:_id)?|user_id|organization_id)\s*[:=]/i,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /sk-[a-z0-9_-]{12,}/i,
];

async function files(root) {
  const entries = await readdir(root, { withFileTypes: true });
  return (
    await Promise.all(
      entries.map(async (entry) =>
        entry.isDirectory()
          ? files(join(root, entry.name))
          : [join(root, entry.name)],
      ),
    )
  ).flat();
}

const paths = await files(
  fileURLToPath(new URL("../protocol/v1/", import.meta.url)),
);
for (const path of paths) {
  const content = await readFile(path, "utf8");
  for (const pattern of forbidden)
    if (pattern.test(content))
      throw new Error(`unsafe fixture content in ${path}: ${pattern}`);
  if (path.endsWith(".json")) {
    // Every JSON file is parsed and recursively scans keys and values. Contract
    // goldens intentionally contain fields such as objective/context; only
    // persisted provider fixtures reject those semantic key names.
    const providerFixture = path.includes(
      `${join("v1", "fixtures")}${process.platform === "win32" ? "\\" : "/"}`,
    );
    inspect(JSON.parse(content), path, providerFixture);
  }
}

const protocolRoot = fileURLToPath(new URL("../protocol/v1/", import.meta.url));
const schema = JSON.parse(
  await readFile(join(protocolRoot, "schema.json"), "utf8"),
);
const taxonomy = JSON.parse(
  await readFile(join(protocolRoot, "error-taxonomy.json"), "utf8"),
);
const schemaCodes = schema.$defs.error.properties.code.enum;
if (
  JSON.stringify([...schemaCodes].sort()) !==
  JSON.stringify([...taxonomy.error_codes].sort())
)
  throw new Error("schema and error taxonomy code sets differ");
const toolNames = schema["x-mcp-tools"].map((tool) => tool.name);
const expectedTools = [
  "list_agents",
  "delegate_task",
  "inspect_task",
  "wait_task",
  "send_task_input",
  "cancel_task",
  "review_task",
  "improvement_case",
];
if (JSON.stringify(toolNames) !== JSON.stringify(expectedTools))
  throw new Error("schema must advertise exactly the eight M7 MCP tools");
for (const tool of schema["x-mcp-tools"])
  for (const field of ["inputRef", "outputRef"]) {
    const prefix = "#/$defs/";
    if (
      !tool[field].startsWith(prefix) ||
      !schema.$defs[tool[field].slice(prefix.length)]
    )
      throw new Error(`tool ${tool.name} has an unresolved ${field}`);
  }
process.stdout.write(`sanitized ${paths.length} protocol fixtures\n`);

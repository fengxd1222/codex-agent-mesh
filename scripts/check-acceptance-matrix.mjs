import { readFile } from "node:fs/promises";

const rows = JSON.parse(
  await readFile(
    new URL("../tests/acceptance-matrix.json", import.meta.url),
    "utf8",
  ),
);
const expected = new Set(
  Array.from(
    { length: 17 },
    (_, index) => `AC-${String(index).padStart(2, "0")}`,
  ),
);
const seen = new Set();
for (const row of rows) {
  for (const field of [
    "id",
    "test",
    "command",
    "class",
    "platform",
    "feature_flag",
  ])
    if (typeof row[field] !== "string" || row[field].length === 0)
      throw new Error(`matrix ${row.id ?? "row"} lacks ${field}`);
  if (!expected.has(row.id) || seen.has(row.id))
    throw new Error(`invalid or duplicate acceptance criterion ${row.id}`);
  if (!["fake", "live"].includes(row.class))
    throw new Error(`invalid class for ${row.id}`);
  const status = row.status ?? "planned";
  if (!["planned", "opt_in", "enabled"].includes(status))
    throw new Error(`invalid status for ${row.id}`);
  if (status === "enabled") {
    if (row.class === "live")
      throw new Error(
        `enabled criterion ${row.id} cannot depend on a live-only test`,
      );
    if (!/^(npm|cargo|pwsh|python)\s/.test(row.command))
      throw new Error(
        `enabled criterion ${row.id} lacks an executable command`,
      );
  }
  seen.add(row.id);
}
if (seen.size !== expected.size)
  throw new Error(
    `matrix is incomplete: expected ${expected.size}, got ${seen.size}`,
  );
process.stdout.write(
  `acceptance matrix covers ${seen.size} criteria; no planned row is a passing claim\n`,
);

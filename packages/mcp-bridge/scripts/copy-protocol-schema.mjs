import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(
  new URL("../../../protocol/v1/schema.json", import.meta.url),
);
for (const destinationUrl of [
  new URL("../dist/protocol/v1/schema.json", import.meta.url),
  new URL("../dist/bundle/protocol/v1/schema.json", import.meta.url),
]) {
  const destination = fileURLToPath(destinationUrl);
  await mkdir(fileURLToPath(new URL("./", destinationUrl)), {
    recursive: true,
  });
  await copyFile(source, destination);
}

await writeFile(
  fileURLToPath(new URL("../dist/bundle/package.json", import.meta.url)),
  '{"private":true,"type":"module"}\n',
  "utf8",
);

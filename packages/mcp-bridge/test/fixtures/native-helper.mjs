import { readFile } from "node:fs/promises";
import { Buffer } from "node:buffer";
import { setImmediate as immediate } from "node:timers/promises";

const mode = process.argv[2];
if (mode === "exit") process.exit(0);
let buffered = Buffer.alloc(0);
const queued = [];

function frame(value) {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(payload.byteLength);
  return Buffer.concat([prefix, payload]);
}

async function reply(request) {
  if (mode === "hang") return;
  if (mode === "malformed") {
    process.stdout.write(Buffer.from([0, 0, 0, 0]));
    return;
  }
  if (mode === "flood") {
    process.stderr.write("token=top-secret\r\n");
    process.stderr.write(`${`${"x".repeat(4_096)}\r\n`.repeat(100)}`);
  }
  if (mode === "split-stderr") {
    const diagnostic = Buffer.from("Unicode π token=top-secret\r\n", "utf8");
    const split = diagnostic.indexOf(Buffer.from("π", "utf8")) + 1;
    const secretSplit = diagnostic.indexOf(Buffer.from("top-secret", "utf8"));
    process.stderr.write(diagnostic.subarray(0, split));
    await immediate();
    process.stderr.write(diagnostic.subarray(split, secretSplit));
    await immediate();
    process.stderr.write(diagnostic.subarray(secretSplit));
  }
  const fixtureUrl = new URL(
    "../../../../protocol/v1/golden/wire-list-agents-response.json",
    import.meta.url,
  );
  const response = JSON.parse(await readFile(fixtureUrl, "utf8"));
  response.id = request.id;
  return frame(response);
}

async function dispatch(request) {
  if (mode === "coalesced") {
    queued.push(request);
    if (queued.length < 2) return;
    const responses = await Promise.all(queued.splice(0, 2).map(reply));
    process.stdout.write(Buffer.concat(responses), () => process.exit(0));
    return;
  }
  const response = await reply(request);
  if (response) process.stdout.write(response, () => process.exit(0));
}

process.stdin.on("data", (chunk) => {
  buffered = Buffer.concat([buffered, chunk]);
  while (buffered.length >= 4) {
    const length = buffered.readUInt32LE(0);
    if (buffered.length < length + 4) return;
    const request = JSON.parse(
      buffered.subarray(4, length + 4).toString("utf8"),
    );
    buffered = buffered.subarray(length + 4);
    void dispatch(request);
  }
});

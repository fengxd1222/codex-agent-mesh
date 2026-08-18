import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  allowCurrentDirectory,
  canonicalize,
  classifyRetry,
  classifyRetryForAttempt,
  decodeV1,
  decodeWireFrame,
  decodeWireV1,
  digest,
  ERROR_CODES,
  parseStrictJson,
  ProtocolDecodeError,
  validateFrameLength,
} from "../dist/protocol.js";
import { runFakeSequence } from "../dist/fake-adapter.js";
import { MeshRpcError, unwrapRpcResponse } from "../dist/rpc-client.js";

const vectorsPath = fileURLToPath(
  new URL("../../../protocol/v1/digest-vectors.json", import.meta.url),
);
const sequencePath = fileURLToPath(
  new URL("../../../protocol/v1/fake-adapter-sequences.json", import.meta.url),
);
const goldenPath = new URL("../../../protocol/v1/golden/", import.meta.url);
const negativePath = fileURLToPath(
  new URL(
    "../../../protocol/v1/negative/invalid-records.json",
    import.meta.url,
  ),
);
const invalidWireJsonPath = fileURLToPath(
  new URL(
    "../../../protocol/v1/negative/invalid-wire-json.json",
    import.meta.url,
  ),
);
const taxonomyPath = fileURLToPath(
  new URL("../../../protocol/v1/error-taxonomy.json", import.meta.url),
);
const frameVectorsPath = fileURLToPath(
  new URL("../../../protocol/v1/frame-vectors.json", import.meta.url),
);
const bundledSchemaPath = fileURLToPath(
  new URL("../dist/protocol/v1/schema.json", import.meta.url),
);
const sourceSchemaPath = fileURLToPath(
  new URL("../../../protocol/v1/schema.json", import.meta.url),
);

test("the compiled bridge carries the exact authoritative schema", async () => {
  assert.equal(
    await readFile(bundledSchemaPath, "utf8"),
    await readFile(sourceSchemaPath, "utf8"),
  );
});

test("canonicalization matches the shared digest vectors", async () => {
  const vectors = JSON.parse(await readFile(vectorsPath, "utf8"));
  for (const vector of vectors) {
    assert.equal(canonicalize(vector.value), vector.canonical, vector.name);
    assert.equal(digest(vector.value), vector.digest, vector.name);
  }
});

test("the version decoder rejects unknown versions centrally", () => {
  assert.deepEqual(
    decodeV1({
      version: 1,
      kind: "task_snapshot",
      task_id: "task-001",
      state: "QUEUED",
      generation: 1,
    }),
    {
      version: 1,
      kind: "task_snapshot",
      task_id: "task-001",
      state: "QUEUED",
      generation: 1,
    },
  );
  assert.throws(
    () => decodeV1({ version: 2, kind: "event" }),
    ProtocolDecodeError,
  );
  assert.throws(() => decodeV1({ version: 1 }), ProtocolDecodeError);
});

test("every golden example is decoded by the v1 boundary", async () => {
  for (const name of await readdir(goldenPath)) {
    const value = JSON.parse(await readFile(new URL(name, goldenPath), "utf8"));
    if (value.jsonrpc === "2.0") decodeWireV1(value);
    else decodeV1(value);
  }
});

test("direct event goldens cover every authoritative event discriminator", async () => {
  const schema = JSON.parse(await readFile(sourceSchemaPath, "utf8"));
  const expected = [
    ...schema.$defs.eventBase.properties.event_type.enum,
  ].sort();
  const observed = new Set();
  for (const name of await readdir(goldenPath)) {
    if (!name.startsWith("event") || !name.endsWith(".json")) continue;
    const value = JSON.parse(await readFile(new URL(name, goldenPath), "utf8"));
    if (value.kind === "event") observed.add(value.event_type);
  }
  assert.deepEqual([...observed].sort(), expected);
});

test("interaction command kinds map one-to-one to lossless event outcomes", async () => {
  const schema = JSON.parse(await readFile(sourceSchemaPath, "utf8"));
  const commandKinds = schema.$defs.interactionResponse.oneOf
    .map((variant) => variant.properties.kind.const)
    .sort();
  const eventPairs = schema.$defs.interactionDecidedPayload.oneOf
    .map((variant) => schema.$defs[variant.$ref.slice("#/$defs/".length)])
    .filter((variant) => variant.properties.response_kind)
    .map((variant) => ({
      responseKind: variant.properties.response_kind.const,
      status: variant.properties.status.const,
    }));
  assert.deepEqual(
    eventPairs.map((pair) => pair.responseKind).sort(),
    commandKinds,
  );
  assert.equal(
    eventPairs.find((pair) => pair.responseKind === "text").status,
    "PROVIDED",
  );
});

test("strict wire parsing rejects duplicate keys and invalid frames", () => {
  assert.throws(
    () => parseStrictJson('{"jsonrpc":"2.0","jsonrpc":"2.0"}'),
    /duplicate JSON key/,
  );
  assert.throws(
    () => decodeWireFrame(Uint8Array.from([0, 0, 0, 0])),
    (error) => error.code === "IPC_FRAME_INVALID",
  );
  assert.throws(
    () => decodeWireFrame(Uint8Array.from([1, 0, 16, 0])),
    (error) => error.code === "IPC_FRAME_TOO_LARGE",
  );
});

test("the TypeScript frame boundary consumes every shared frame vector", async () => {
  const vectors = JSON.parse(await readFile(frameVectorsPath, "utf8"));
  for (const vector of vectors) {
    if (typeof vector.declared_length === "number") {
      if (vector.valid) {
        assert.doesNotThrow(
          () => validateFrameLength(vector.declared_length),
          vector.name,
        );
      } else {
        assert.throws(
          () => validateFrameLength(vector.declared_length),
          (error) => error.code === vector.error,
          vector.name,
        );
      }
      continue;
    }
    const frame = Buffer.concat([
      Buffer.from(vector.prefix_hex, "hex"),
      Buffer.from(vector.payload_hex ?? "", "hex"),
    ]);
    assert.throws(
      () => decodeWireFrame(frame),
      (error) => error.code === vector.error,
      vector.name,
    );
  }
});

test("every shared invalid wire source is rejected before dispatch", async () => {
  for (const record of JSON.parse(await readFile(invalidWireJsonPath, "utf8")))
    assert.throws(
      () => decodeWireV1(parseStrictJson(record.source)),
      undefined,
      record.name,
    );
});

test("every shared negative record is rejected at the TypeScript boundary", async () => {
  for (const record of JSON.parse(await readFile(negativePath, "utf8")))
    assert.throws(
      () =>
        record.value?.jsonrpc === "2.0"
          ? decodeWireV1(record.value)
          : decodeV1(record.value),
      ProtocolDecodeError,
      record.name,
    );
});

test("improvement_case responses must carry improvement_case_result", async () => {
  const valid = {
    jsonrpc: "2.0",
    id: "rpc-1",
    result: {
      kind: "improvement_case_result",
      feature_enabled: false,
      outcome: "INSPECTED",
      case: {
        version: 1,
        kind: "improvement_case",
        case_id: "case-001",
        component: "fake-adapter",
        status: "OBSERVING",
      },
    },
  };
  assert.equal(
    unwrapRpcResponse(valid, "rpc-1", "mesh.improvement_case").kind,
    "improvement_case_result",
  );
  const inspectGolden = JSON.parse(
    await readFile(
      new URL("wire-inspect-task-response.json", goldenPath),
      "utf8",
    ),
  );
  assert.throws(
    () =>
      unwrapRpcResponse(
        { jsonrpc: "2.0", id: "rpc-1", result: inspectGolden.result },
        "rpc-1",
        "mesh.improvement_case",
      ),
    /result kind/,
  );
});

test("RPC errors preserve daemon evidence and cursor data exactly", async () => {
  const message = JSON.parse(
    await readFile(
      new URL("wire-error-cursor-expired.json", goldenPath),
      "utf8",
    ),
  );
  assert.throws(
    () => unwrapRpcResponse(message, String(message.id)),
    (error) => {
      assert.ok(error instanceof MeshRpcError);
      assert.deepEqual(error.errorRecord, message.error.data.error);
      assert.deepEqual(error.cursor, message.error.data.cursor);
      assert.equal(error.diagnosticRef, message.error.data.diagnostic_ref);
      return true;
    },
  );
});

test("canonicalization rejects fractional, unsafe, and negative-zero numbers", () => {
  assert.throws(() => canonicalize(1.5), /safe integers/);
  assert.throws(
    () => canonicalize(Number.MAX_SAFE_INTEGER + 1),
    /safe integers/,
  );
  assert.throws(() => canonicalize(-0), /safe integers/);
  assert.throws(() => canonicalize(String.fromCharCode(0xd800)), /surrogates/);
});

test("retry classification needs lifecycle evidence as well as an error", () => {
  assert.equal(
    classifyRetry(
      "ADAPTER_UNAVAILABLE",
      "UNKNOWN_EFFECT",
      "AFTER_PROCESS_CREATION",
    ),
    "AMBIGUOUS_AFTER_DISPATCH",
  );
  assert.equal(
    classifyRetry(
      "ADAPTER_UNAVAILABLE",
      "UNKNOWN_EFFECT",
      "BEFORE_PROCESS_CREATION",
    ),
    "SAFE_PRE_DISPATCH",
  );
  assert.equal(
    classifyRetry("VALIDATION_FAILED", "NO_EFFECT", "BEFORE_PROCESS_CREATION"),
    "DETERMINISTIC_FAILURE",
  );
  assert.equal(
    classifyRetry(
      "RESPONSE_UNKNOWN",
      "UNKNOWN_EFFECT",
      "AFTER_PROCESS_CREATION",
    ),
    "AMBIGUOUS_AFTER_DISPATCH",
  );
  assert.equal(
    classifyRetry("SETUP_REMOVING", "NO_EFFECT", "BEFORE_PROCESS_CREATION"),
    "SAFE_PRE_DISPATCH",
  );
  assert.equal(
    classifyRetryForAttempt(
      "ADAPTER_UNAVAILABLE",
      "NO_EFFECT",
      "PROCESS_DEAD_NO_EFFECT_PROOF",
      "CURRENT_DIRECTORY",
    ),
    "AMBIGUOUS_AFTER_DISPATCH",
  );
  assert.equal(
    classifyRetryForAttempt(
      "ADAPTER_UNAVAILABLE",
      "UNKNOWN_EFFECT",
      "BEFORE_PROCESS_CREATION",
      "CURRENT_DIRECTORY",
    ),
    "SAFE_PRE_DISPATCH",
  );
  assert.equal(
    classifyRetryForAttempt(
      "ADAPTER_UNAVAILABLE",
      "NO_EFFECT",
      "PROCESS_DEAD_NO_EFFECT_PROOF",
      "ISOLATED_WORKTREE",
    ),
    "SAFE_PROVEN_NO_EFFECT",
  );
});

test("allow_current_directory is absent on the frozen config and optional when true", async () => {
  const frozen = JSON.parse(
    await readFile(new URL("config.json", goldenPath), "utf8"),
  );
  const optedIn = JSON.parse(
    await readFile(
      new URL("config-allow-current-directory.json", goldenPath),
      "utf8",
    ),
  );
  decodeV1(frozen);
  decodeV1(optedIn);
  assert.equal(allowCurrentDirectory(frozen), false);
  assert.equal(allowCurrentDirectory(frozen.settings), false);
  assert.equal(allowCurrentDirectory(optedIn), true);
  assert.equal(allowCurrentDirectory(optedIn.settings), true);
  assert.equal(
    allowCurrentDirectory({ allow_current_directory: false }),
    false,
  );
  assert.equal(
    allowCurrentDirectory({
      kind: "config",
      allow_current_directory: true,
    }),
    false,
  );
  assert.equal(
    allowCurrentDirectory({ allow_current_directory: "yes" }),
    false,
  );
  assert.equal(
    digest(frozen),
    "22a01f7ccf852d7b2032c4c2c0f25df516d9f07e81d0107a3b2036055cfff16b",
  );
});

test("the TypeScript error-code set matches the shared taxonomy", async () => {
  const taxonomy = JSON.parse(await readFile(taxonomyPath, "utf8"));
  assert.deepEqual([...ERROR_CODES].sort(), [...taxonomy.error_codes].sort());
});

test("all fake-adapter fixture paths are deterministic", async () => {
  const sequences = JSON.parse(await readFile(sequencePath, "utf8"));
  for (const sequence of sequences) {
    const received = [];
    const delays = [];
    if (sequence.name === "crash") {
      await assert.rejects(
        runFakeSequence(sequence, (event) => received.push(event), {
          sleep: (milliseconds) => delays.push(milliseconds),
        }),
        /crashed/,
      );
    } else {
      await runFakeSequence(sequence, (event) => received.push(event), {
        sleep: (milliseconds) => delays.push(milliseconds),
      });
      assert.equal(
        received.length,
        sequence.events.filter((event) => event.type !== "delay").length,
      );
    }
    if (sequence.name === "delayed") assert.deepEqual(delays, [25]);
    if (sequence.name === "approval")
      assert.equal(received[0].type, "approval");
    if (sequence.name === "cancellation")
      assert.equal(received.at(-1).type, "cancelled");
    if (sequence.name === "duplicate")
      assert.equal(
        received.filter((event) => event.type === "terminal").length,
        2,
      );
    if (["malformed", "truncated"].includes(sequence.name))
      assert.equal(received[0].type, "raw");
    if (sequence.name === "oversized") assert.equal(received[0].bytes, 1048577);
  }
});

import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  BUNDLED_BRIDGE_BOOTSTRAP_ARGUMENTS,
  emitArtifactTrustWarning,
  NativeHelperTransport,
  parseArtifactMetadata,
  readArtifactMetadata,
  requestDeadlineMs,
  resolveBundledSetupHelper,
} from "../dist/native-transport.js";

test("artifact metadata accepts only the strict bounded trust declaration", () => {
  assert.equal(
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":null}',
    ).runtimeTrust,
    "development-unsigned",
  );
  assert.throws(() => parseArtifactMetadata("{}"));
  assert.throws(() =>
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":null,"extra":true}',
    ),
  );
  assert.throws(() =>
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"official-signed","runtimeSource":"fixture","signerCertificateSha256":"bad"}',
    ),
  );
  assert.throws(() =>
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
    ),
  );
  assert.throws(() =>
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"official-signed","runtimeSource":"fixture","signerCertificateSha256":null}',
    ),
  );
});

test("metadata filesystem failures are redacted as stable setup drift", async () => {
  const root = await mkdtemp(join(process.env.TEMP ?? ".", "mesh-metadata-"));
  const modulePath = join(root, "runtime", "mcp-bridge", "native-transport.js");
  try {
    await mkdir(dirname(modulePath), { recursive: true });
    assert.throws(
      () => readArtifactMetadata(pathToFileURL(modulePath).href),
      (error) =>
        error.code === "SETUP_DRIFTED" &&
        !error.message.includes(root) &&
        error.errorRecord.evidence === "artifact_metadata_read_failed",
    );
    await mkdir(join(root, "ARTIFACT-METADATA.json"));
    assert.throws(
      () => readArtifactMetadata(pathToFileURL(modulePath).href),
      (error) =>
        error.code === "SETUP_DRIFTED" &&
        !error.message.includes(root) &&
        error.errorRecord.evidence === "artifact_metadata_read_failed",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("development artifacts issue one bounded stderr warning while official artifacts stay quiet", () => {
  const warnings = [];
  emitArtifactTrustWarning(
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":null}',
    ),
    (line) => warnings.push(line),
  );
  emitArtifactTrustWarning(
    parseArtifactMetadata(
      '{"formatVersion":1,"runtimeTrust":"official-signed","runtimeSource":"fixture","signerCertificateSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
    ),
    (line) => warnings.push(line),
  );
  assert.deepEqual(warnings, [
    "codex-agent-mesh: development-unsigned plugin artifact; not an official release.\n",
  ]);
});

const fixture = fileURLToPath(
  new URL("./fixtures/native-helper.mjs", import.meta.url),
);

function transport(mode, options = {}) {
  return new NativeHelperTransport({
    helperPath: process.execPath,
    arguments: [fixture, mode],
    ...options,
  });
}

test("wait_task uses the exact five-second margin and 35-second cap", () => {
  assert.equal(requestDeadlineMs("mesh.inspect_task", {}), 5_000);
  assert.equal(
    requestDeadlineMs("mesh.improvement_case", { action: "inspect" }),
    5_000,
  );
  assert.equal(
    requestDeadlineMs("mesh.improvement_case", {
      action: "improvement_propose",
    }),
    10_000,
  );
  assert.equal(requestDeadlineMs("mesh.wait_task", { wait_ms: 0 }), 5_000);
  assert.equal(requestDeadlineMs("mesh.wait_task", { wait_ms: 1 }), 5_001);
  assert.equal(
    requestDeadlineMs("mesh.wait_task", { wait_ms: 30_000 }),
    35_000,
  );
  assert.equal(
    requestDeadlineMs("mesh.wait_task", { wait_ms: 30_001 }),
    35_000,
  );
});

test("native transport reconnects without confusing response generations", async () => {
  const rpc = transport("valid");
  const first = await rpc.request("mesh.list_agents", {});
  assert.equal(first.kind, "list_agents_result");
  await delay(25);
  const second = await rpc.request("mesh.list_agents", {});
  assert.equal(second.kind, "list_agents_result");
  await rpc.close();
});

test("native transport consumes two valid response frames from one chunk", async () => {
  const rpc = transport("coalesced");
  const [first, second] = await Promise.all([
    rpc.request("mesh.list_agents", {}),
    rpc.request("mesh.list_agents", {}),
  ]);
  assert.equal(first.kind, "list_agents_result");
  assert.equal(second.kind, "list_agents_result");
  await rpc.close();
});

test("native transport enforces the negotiated 16-request in-flight bound", async () => {
  const rpc = transport("hang", { requestTimeoutMs: 5_000 });
  const pending = Array.from({ length: 16 }, () =>
    rpc.request("mesh.list_agents", {}),
  );
  await assert.rejects(
    rpc.request("mesh.list_agents", {}),
    (error) =>
      error.code === "OUTPUT_LIMIT_EXCEEDED" &&
      error.errorRecord.retry_class === "SAFE_PRE_DISPATCH",
  );
  await rpc.close();
  await Promise.allSettled(pending);
});

test("native transport kills malformed and timed-out helper generations", async () => {
  const malformed = transport("malformed");
  await assert.rejects(
    malformed.request("mesh.list_agents", {}),
    (error) => error.code === "IPC_FRAME_INVALID",
  );
  await malformed.close();

  const hung = transport("hang", { requestTimeoutMs: 30 });
  await assert.rejects(
    hung.request("mesh.list_agents", {}),
    (error) => error.code === "IPC_IO_TIMEOUT",
  );
  await hung.close();

  const exited = transport("exit");
  await assert.rejects(
    exited.request("mesh.list_agents", {}),
    (error) => error.code === "RESPONSE_UNKNOWN",
  );
  await exited.close();
});

test("native helper creation failure never exposes its local path", async () => {
  const sensitivePath = join(
    process.env.TEMP ?? process.cwd(),
    "private-user-path",
    "missing-helper.exe",
  );
  const rpc = new NativeHelperTransport({
    helperPath: sensitivePath,
    arguments: [],
  });
  await assert.rejects(
    rpc.request("mesh.list_agents", {}),
    (error) =>
      error.code === "SETUP_ABSENT" &&
      error.message === "Native helper process could not be created." &&
      !error.message.includes(sensitivePath),
  );
  await rpc.close();
});

test("native transport rejects a schema-valid result for the wrong method", async () => {
  const rpc = transport("valid");
  await assert.rejects(
    rpc.request("mesh.inspect_task", { task_id: "task-001" }),
    (error) =>
      error.code === "IPC_FRAME_INVALID" &&
      error.errorRecord.evidence ===
        "response_method_kind_mismatch_after_dispatch",
  );
  await rpc.close();
});

test("native helper stderr is redacted and never exceeds its exact budget", async () => {
  let stderr = "";
  const rpc = transport("flood", {
    stderrSink: (line) => {
      stderr += line;
    },
  });
  const result = await rpc.request("mesh.list_agents", {});
  assert.equal(result.kind, "list_agents_result");
  assert.ok(Buffer.byteLength(stderr, "utf8") <= 65_536);
  assert.ok(
    stderr
      .split(/\n/u)
      .filter(Boolean)
      .every((line) => Buffer.byteLength(`${line}\n`, "utf8") <= 4_096),
  );
  assert.doesNotMatch(stderr, /top-secret/u);
  assert.match(stderr, /token=\[redacted\]/u);
  await rpc.close();
});

test("stderr decoding preserves split UTF-8 and treats CRLF as one separator", async () => {
  let stderr = "";
  const rpc = transport("split-stderr", {
    stderrSink: (line) => {
      stderr += line;
    },
  });
  await rpc.request("mesh.list_agents", {});
  assert.equal(stderr.split("\n").filter(Boolean).length, 1);
  assert.match(stderr, /Unicode π token=\[redacted\]/u);
  assert.doesNotMatch(stderr, /�|top-secret/u);
  await rpc.close();
});

test("ordinary traffic enters only cache-local bridge-bootstrap for the stable slot", () => {
  assert.deepEqual(BUNDLED_BRIDGE_BOOTSTRAP_ARGUMENTS, [
    "bridge-bootstrap",
    "--stdio",
    "--install-slot",
    "stable",
  ]);
});

test("bundled setup lookup is import-meta-relative across spaces and Unicode", async () => {
  const root = await mkdtemp(
    join(process.env.TEMP ?? process.cwd(), "mesh 路径 "),
  );
  try {
    const runtime = join(root, "runtime", "mcp-bridge");
    const bin = join(root, "bin", "windows-x64");
    await Promise.all([
      mkdir(runtime, { recursive: true }),
      mkdir(bin, { recursive: true }),
    ]);
    const entrypoint = join(runtime, "index.js");
    const helper = join(bin, "mesh-daemon.exe");
    await Promise.all([
      writeFile(entrypoint, ""),
      writeFile(helper, "fixture"),
    ]);
    assert.equal(
      resolveBundledSetupHelper(pathToFileURL(entrypoint).href),
      helper,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

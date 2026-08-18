import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { decodeWireFrame, decodeWireV1 } from "./protocol.js";
import {
  bridgeRpcError,
  MeshRpcError,
  unwrapRpcResponse,
  type RpcParams,
  type RpcResult,
  type RpcTransport,
} from "./rpc-client.js";

export const BUNDLED_BRIDGE_BOOTSTRAP_ARGUMENTS = [
  "bridge-bootstrap",
  "--stdio",
  "--install-slot",
  "stable",
] as const;
export const BUNDLED_SETUP_ARGUMENTS = [
  "setup",
  "--install-slot",
  "stable",
] as const;
const REQUEST_LIMIT = 1_048_576;
const RESPONSE_LIMIT = 8_388_608;
const STDERR_BUDGET = 65_536;
const STDERR_LINE_LIMIT = 4_096;
const ARTIFACT_METADATA_LIMIT = 4_096;
let developmentWarningEmitted = false;

type ArtifactMetadata = {
  formatVersion: 1;
  runtimeTrust: "development-unsigned" | "official-signed";
  runtimeSource: string;
  signerCertificateSha256: string | null;
};

export function parseArtifactMetadata(source: string): ArtifactMetadata {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Plugin artifact metadata is invalid.",
      "PRE_DISPATCH",
      "artifact_metadata_invalid",
    );
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    Object.keys(value).some(
      (key) =>
        ![
          "formatVersion",
          "runtimeTrust",
          "runtimeSource",
          "signerCertificateSha256",
        ].includes(key),
    )
  )
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Plugin artifact metadata has an invalid shape.",
      "PRE_DISPATCH",
      "artifact_metadata_shape_invalid",
    );
  const metadata = value as Record<string, unknown>;
  if (
    metadata.formatVersion !== 1 ||
    (metadata.runtimeTrust !== "development-unsigned" &&
      metadata.runtimeTrust !== "official-signed") ||
    typeof metadata.runtimeSource !== "string" ||
    metadata.runtimeSource.length === 0 ||
    (metadata.runtimeTrust === "development-unsigned" &&
      metadata.signerCertificateSha256 !== null) ||
    (metadata.runtimeTrust === "official-signed" &&
      (typeof metadata.signerCertificateSha256 !== "string" ||
        !/^[0-9a-f]{64}$/u.test(metadata.signerCertificateSha256)))
  )
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Plugin artifact metadata values are invalid.",
      "PRE_DISPATCH",
      "artifact_metadata_values_invalid",
    );
  return metadata as ArtifactMetadata;
}

export function readArtifactMetadata(
  moduleUrl = import.meta.url,
): ArtifactMetadata {
  const root = fileURLToPath(new URL("../../", moduleUrl));
  const metadataPath = fileURLToPath(
    new URL("../../ARTIFACT-METADATA.json", moduleUrl),
  );
  try {
    const resolvedRoot = realpathSync(root);
    const resolvedMetadata = realpathSync(metadataPath);
    const traversal = relative(resolvedRoot, resolvedMetadata);
    if (
      traversal === "" ||
      traversal.startsWith("..") ||
      resolve(resolvedRoot, traversal) !== resolvedMetadata ||
      statSync(resolvedMetadata).size > ARTIFACT_METADATA_LIMIT
    )
      throw new Error("artifact metadata containment failed");
    return parseArtifactMetadata(readFileSync(resolvedMetadata, "utf8"));
  } catch (error) {
    if (error instanceof MeshRpcError) throw error;
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Plugin artifact metadata could not be verified.",
      "PRE_DISPATCH",
      "artifact_metadata_read_failed",
    );
  }
}

export function emitArtifactTrustWarning(
  metadata: ArtifactMetadata,
  sink: (line: string) => void = (line) => process.stderr.write(line),
): void {
  if (
    metadata.runtimeTrust !== "development-unsigned" ||
    developmentWarningEmitted
  )
    return;
  developmentWarningEmitted = true;
  sink(
    "codex-agent-mesh: development-unsigned plugin artifact; not an official release.\n",
  );
}

/** The cache binary is only a setup artifact; it is never an ordinary RPC peer. */
export function resolveBundledSetupHelper(moduleUrl = import.meta.url): string {
  const pluginRoot = fileURLToPath(new URL("../../", moduleUrl));
  const candidate = fileURLToPath(
    new URL("../../bin/windows-x64/mesh-daemon.exe", moduleUrl),
  );
  if (!existsSync(candidate))
    throw bridgeRpcError(
      "SETUP_ABSENT",
      "Codex Agent Mesh bundled setup helper is not installed.",
      "PRE_DISPATCH",
      "bundled_setup_helper_absent",
    );
  let root: string;
  let helper: string;
  try {
    root = realpathSync(pluginRoot);
    helper = realpathSync(candidate);
  } catch {
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Bundled setup helper identity could not be verified.",
      "PRE_DISPATCH",
      "bundled_setup_helper_identity_failed",
    );
  }
  const traversal = relative(root, helper);
  if (
    traversal === "" ||
    traversal.startsWith("..") ||
    resolve(root, traversal) !== helper
  )
    throw bridgeRpcError(
      "SETUP_DRIFTED",
      "Bundled setup helper escaped the plugin root.",
      "PRE_DISPATCH",
      "bundled_setup_helper_containment_failed",
    );
  return helper;
}

function encodeFrame(value: unknown): Buffer {
  decodeWireV1(value);
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.byteLength > REQUEST_LIMIT)
    throw bridgeRpcError(
      "IPC_FRAME_TOO_LARGE",
      "RPC request exceeds 1 MiB.",
      "PRE_DISPATCH",
      "request_rejected_before_helper_start",
    );
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32LE(payload.byteLength);
  return Buffer.concat([prefix, payload]);
}

function utf8Prefix(value: string, maximumBytes: number): string {
  let output = "";
  let bytes = 0;
  for (const scalar of value) {
    const width = Buffer.byteLength(scalar, "utf8");
    if (bytes + width > maximumBytes) break;
    output += scalar;
    bytes += width;
  }
  return output;
}

function replaceControlCharacters(value: string): string {
  return [...value]
    .map((scalar) => {
      const code = scalar.codePointAt(0) ?? 0;
      return code <= 0x1f || code === 0x7f ? " " : scalar;
    })
    .join("");
}

/** Frozen v1 request deadline; wait_task gets the contract's full 5s margin. */
export function requestDeadlineMs(method: string, params: RpcParams): number {
  if (method === "mesh.health") return 2_000;
  if (method === "mesh.wait_task") {
    const requested = typeof params.wait_ms === "number" ? params.wait_ms : 0;
    return Math.min(35_000, Math.max(5_000, requested + 5_000));
  }
  if (method === "mesh.list_agents" || method === "mesh.inspect_task")
    return 5_000;
  if (method === "mesh.improvement_case" && params.action === "inspect")
    return 5_000;
  return 10_000;
}

type Pending = {
  generation: number;
  method: string;
  timer: ReturnType<typeof setTimeout>;
  resolve(value: RpcResult): void;
  reject(error: Error): void;
};

export type NativeHelperTransportOptions = {
  helperPath?: string;
  arguments?: readonly string[];
  requestTimeoutMs?: number;
  spawnProcess?: typeof spawn;
  stderrSink?: (line: string) => void;
};

export class NativeHelperTransport implements RpcTransport {
  private child: ChildProcessWithoutNullStreams | undefined;
  private generation = 0;
  private nextId = 1;
  private buffered = Buffer.alloc(0);
  private stderrPending = "";
  private stderrDecoder = new StringDecoder("utf8");
  private stderrBytes = 0;
  private stderrSuppressed = false;
  private readonly pending = new Map<string, Pending>();
  private readonly options: NativeHelperTransportOptions;

  constructor(options: NativeHelperTransportOptions = {}) {
    this.options = options;
  }

  private process(): {
    child: ChildProcessWithoutNullStreams;
    generation: number;
  } {
    if (this.child) return { child: this.child, generation: this.generation };
    // Node resolves only the cache-bundled bootstrap from import.meta.url. The
    // Rust bootstrap holds the install admission fence, revalidates every
    // retained artifact, and gives this process's stdio handles directly to
    // the stable runtime. Node never resolves LocalAppData or opens the pipe.
    const helper = this.options.helperPath ?? resolveBundledSetupHelper();
    if (!this.options.helperPath)
      emitArtifactTrustWarning(readArtifactMetadata());
    const args = this.options.arguments ?? BUNDLED_BRIDGE_BOOTSTRAP_ARGUMENTS;
    const spawnProcess = this.options.spawnProcess ?? spawn;
    const generation = this.generation + 1;
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawnProcess(helper, [...args], {
        cwd: dirname(helper),
        windowsHide: true,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      }) as ChildProcessWithoutNullStreams;
    } catch {
      throw bridgeRpcError(
        "SETUP_ABSENT",
        "Native helper process could not be created.",
        "PRE_DISPATCH",
        "transport_helper_process_creation_failed",
      );
    }
    this.generation = generation;
    this.child = child;
    this.buffered = Buffer.alloc(0);
    this.stderrPending = "";
    this.stderrDecoder = new StringDecoder("utf8");
    child.stdout.on("data", (chunk: Buffer) => this.receive(generation, chunk));
    child.stderr.on("data", (chunk: Buffer) =>
      this.drainStderr(generation, chunk),
    );
    child.on("error", () => {
      if (!this.isCurrent(child, generation)) return;
      this.failGeneration(
        generation,
        bridgeRpcError(
          "SETUP_ABSENT",
          "Native helper process could not be created.",
          "PRE_DISPATCH",
          "transport_helper_process_creation_failed",
        ),
      );
    });
    child.on("exit", () => {
      if (!this.isCurrent(child, generation)) return;
      this.failGeneration(
        generation,
        bridgeRpcError(
          "RESPONSE_UNKNOWN",
          "Native helper exited before replying.",
          "OUTCOME_UNKNOWN",
          "transport_helper_exit_after_dispatch",
        ),
      );
    });
    return { child, generation };
  }

  private isCurrent(
    child: ChildProcessWithoutNullStreams,
    generation: number,
  ): boolean {
    return this.child === child && this.generation === generation;
  }

  private drainStderr(generation: number, chunk: Buffer): void {
    if (generation !== this.generation || this.stderrSuppressed) return;
    const retainedBytes = Buffer.byteLength(this.stderrPending, "utf8");
    const sourceBudget = Math.max(0, STDERR_BUDGET - retainedBytes);
    const boundedChunk = chunk.subarray(0, sourceBudget);
    const sourceTruncated = boundedChunk.byteLength < chunk.byteLength;
    this.stderrPending += this.stderrDecoder.write(boundedChunk);
    for (;;) {
      const newline = this.stderrPending.search(/[\r\n]/u);
      if (newline < 0 && !sourceTruncated) return;
      const split = newline < 0 ? this.stderrPending.length : newline;
      const source = this.stderrPending.slice(0, split);
      const separatorWidth =
        newline >= 0 &&
        this.stderrPending[newline] === "\r" &&
        this.stderrPending[newline + 1] === "\n"
          ? 2
          : newline < 0
            ? 0
            : 1;
      this.stderrPending = this.stderrPending.slice(split + separatorWidth);
      this.emitStderrLine(source);
      if (this.stderrSuppressed) {
        this.stderrPending = "";
        return;
      }
      if (newline < 0 && sourceTruncated) {
        this.stderrPending = "";
        this.stderrSuppressed = true;
        return;
      }
    }
  }

  private emitStderrLine(source: string): void {
    const prefix = "mesh helper: ";
    const suffix = "\n";
    const remaining = STDERR_BUDGET - this.stderrBytes;
    const fixedBytes = Buffer.byteLength(prefix + suffix, "utf8");
    if (remaining <= fixedBytes) {
      this.stderrSuppressed = true;
      return;
    }
    const redacted = replaceControlCharacters(
      source.replace(
        /(token|secret|password|authorization)\s*[:=]\s*\S+/giu,
        "$1=[redacted]",
      ),
    );
    const body = utf8Prefix(
      redacted,
      Math.min(STDERR_LINE_LIMIT - fixedBytes, remaining - fixedBytes),
    );
    const line = `${prefix}${body}${suffix}`;
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (lineBytes > remaining) {
      this.stderrSuppressed = true;
      return;
    }
    this.stderrBytes += lineBytes;
    (
      this.options.stderrSink ??
      ((value: string) => process.stderr.write(value))
    )(line);
    if (this.stderrBytes >= STDERR_BUDGET) this.stderrSuppressed = true;
  }

  private receive(generation: number, chunk: Buffer): void {
    if (generation !== this.generation) return;
    this.buffered = Buffer.concat([this.buffered, chunk]);
    while (this.buffered.byteLength >= 4) {
      const length = this.buffered.readUInt32LE(0);
      if (length === 0 || length > RESPONSE_LIMIT) {
        this.failGeneration(
          generation,
          bridgeRpcError(
            length === 0 ? "IPC_FRAME_INVALID" : "IPC_FRAME_TOO_LARGE",
            "Invalid helper frame length.",
            "OUTCOME_UNKNOWN",
            "invalid_response_frame_after_dispatch",
          ),
        );
        return;
      }
      if (this.buffered.byteLength < length + 4) return;
      const frame = this.buffered.subarray(0, length + 4);
      this.buffered = this.buffered.subarray(length + 4);
      try {
        const message = decodeWireFrame(frame, RESPONSE_LIMIT) as unknown as {
          id: string | number;
        };
        const id = String(message.id);
        const pending = this.pending.get(id);
        if (!pending || pending.generation !== generation)
          throw bridgeRpcError(
            "IPC_FRAME_INVALID",
            "Unexpected RPC response ID.",
            "OUTCOME_UNKNOWN",
            "unexpected_response_id_after_dispatch",
          );
        const result = unwrapRpcResponse(message, id, pending.method);
        this.pending.delete(id);
        clearTimeout(pending.timer);
        pending.resolve(result);
      } catch (error) {
        this.failGeneration(
          generation,
          error instanceof Error
            ? error
            : bridgeRpcError(
                "IPC_FRAME_INVALID",
                "Invalid helper frame.",
                "OUTCOME_UNKNOWN",
                "response_decode_failed_after_dispatch",
              ),
        );
        return;
      }
    }
  }

  private failGeneration(generation: number, error: Error): void {
    if (generation !== this.generation) return;
    const child = this.child;
    this.child = undefined;
    this.buffered = Buffer.alloc(0);
    for (const [id, pending] of this.pending) {
      if (pending.generation !== generation) continue;
      clearTimeout(pending.timer);
      pending.reject(error);
      this.pending.delete(id);
    }
    if (child) {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      if (!child.killed) child.kill();
    }
  }

  request(method: string, params: RpcParams): Promise<RpcResult> {
    if (this.pending.size >= 16)
      return Promise.reject(
        bridgeRpcError(
          "OUTPUT_LIMIT_EXCEEDED",
          "Native helper already has 16 requests in flight.",
          "PRE_DISPATCH",
          "negotiated_max_in_flight_reached",
        ),
      );
    const id = String(this.nextId++);
    const request = { jsonrpc: "2.0", id, method, params };
    let frame: Buffer;
    let active: { child: ChildProcessWithoutNullStreams; generation: number };
    try {
      frame = encodeFrame(request);
      active = this.process();
    } catch (error) {
      return Promise.reject(error);
    }
    return new Promise((resolvePromise, reject) => {
      const timeoutMs =
        this.options.requestTimeoutMs ?? requestDeadlineMs(method, params);
      const timer = setTimeout(() => {
        this.failGeneration(
          active.generation,
          bridgeRpcError(
            "IPC_IO_TIMEOUT",
            "Native helper response deadline expired.",
            "OUTCOME_UNKNOWN",
            "response_deadline_expired_after_dispatch",
          ),
        );
      }, timeoutMs);
      this.pending.set(id, {
        generation: active.generation,
        method,
        timer,
        resolve: resolvePromise,
        reject,
      });
      active.child.stdin.write(frame, (error) => {
        if (!error) return;
        this.failGeneration(
          active.generation,
          bridgeRpcError(
            "RESPONSE_UNKNOWN",
            "Native helper request outcome is unknown.",
            "OUTCOME_UNKNOWN",
            "request_write_failed_after_dispatch",
          ),
        );
      });
    });
  }

  async close(): Promise<void> {
    if (!this.child) return;
    this.failGeneration(
      this.generation,
      bridgeRpcError(
        "RESPONSE_UNKNOWN",
        "Bridge transport closed.",
        "OUTCOME_UNKNOWN",
        "bridge_closed_after_dispatch",
      ),
    );
  }
}

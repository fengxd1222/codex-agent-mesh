import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";

export const PROTOCOL_VERSION = 1 as const;
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;

export type RetryClass =
  | "SAFE_PRE_DISPATCH"
  | "SAFE_PROVEN_NO_EFFECT"
  | "DETERMINISTIC_FAILURE"
  | "AMBIGUOUS_AFTER_DISPATCH";
export type EffectClass = "NO_EFFECT" | "POSSIBLE_EFFECT" | "UNKNOWN_EFFECT";
export type LifecycleEvidence =
  | "BEFORE_PROCESS_CREATION"
  | "PROCESS_DEAD_NO_EFFECT_PROOF"
  | "AFTER_PROCESS_CREATION"
  | "UNKNOWN";
export type EffectProfile =
  | "READ_ONLY"
  | "ISOLATED_WORKTREE"
  | "CURRENT_DIRECTORY"
  | "EXTERNAL_SIDE_EFFECTS";
export type WorkspaceMode =
  | "read_only"
  | "isolated_worktree"
  | "current_directory";
export type IsolationLevel =
  | "ENFORCED"
  | "PROTOCOL_MEDIATED"
  | "BEST_EFFORT"
  | "NONE";

export const ERROR_CODES = [
  "VERSION_UNSUPPORTED",
  "VALIDATION_FAILED",
  "IDEMPOTENCY_CONFLICT",
  "ADAPTER_UNAVAILABLE",
  "PROTOCOL_MALFORMED",
  "OUTPUT_LIMIT_EXCEEDED",
  "CANCELLED",
  "APPROVAL_EXPIRED",
  "STORAGE_UNAVAILABLE",
  "AMBIGUOUS_AFTER_DISPATCH",
  "IPC_AUTHENTICATION_FAILED",
  "IPC_FRAME_INVALID",
  "IPC_FRAME_TOO_LARGE",
  "IPC_IO_TIMEOUT",
  "DAEMON_START_TIMEOUT",
  "SINGLETON_CONFLICT",
  "SETUP_ABSENT",
  "SETUP_DISABLED",
  "SETUP_REMOVING",
  "SETUP_DRIFTED",
  "SETUP_ACCESS_DENIED",
  "CURSOR_EXPIRED",
  "RESPONSE_UNKNOWN",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

const DETERMINISTIC_ERRORS = new Set<ErrorCode>([
  "VERSION_UNSUPPORTED",
  "VALIDATION_FAILED",
  "IDEMPOTENCY_CONFLICT",
  "CANCELLED",
  "APPROVAL_EXPIRED",
  "IPC_AUTHENTICATION_FAILED",
  "IPC_FRAME_INVALID",
  "IPC_FRAME_TOO_LARGE",
  "SINGLETON_CONFLICT",
  "SETUP_ABSENT",
  "SETUP_DISABLED",
  "SETUP_DRIFTED",
  "SETUP_ACCESS_DENIED",
  "CURSOR_EXPIRED",
]);

/** Error labels are symptoms; retry safety also requires lifecycle/effect proof. */
export function classifyRetry(
  code: ErrorCode,
  effect: EffectClass,
  evidence: LifecycleEvidence,
): RetryClass {
  if (DETERMINISTIC_ERRORS.has(code)) return "DETERMINISTIC_FAILURE";
  if (evidence === "BEFORE_PROCESS_CREATION") return "SAFE_PRE_DISPATCH";
  if (effect === "NO_EFFECT" && evidence === "PROCESS_DEAD_NO_EFFECT_PROOF")
    return "SAFE_PROVEN_NO_EFFECT";
  return "AMBIGUOUS_AFTER_DISPATCH";
}

/**
 * Current-directory writes cannot prove a no-effect outcome after process
 * start. Absent `allow_current_directory` is false; this classifier is the
 * post-dispatch retry fence for that effect profile.
 */
export function classifyRetryForAttempt(
  code: ErrorCode,
  effect: EffectClass,
  evidence: LifecycleEvidence,
  effectProfile: EffectProfile,
): RetryClass {
  if (
    effectProfile === "CURRENT_DIRECTORY" &&
    evidence !== "BEFORE_PROCESS_CREATION"
  ) {
    return "AMBIGUOUS_AFTER_DISPATCH";
  }
  return classifyRetry(code, effect, evidence);
}

/**
 * Optional safe-settings opt-in. Absent, non-boolean, or any value other
 * than `true` is false. Accepts a `config` record or the settings object.
 * A `config` record is consulted only through its `settings` object.
 */
export function allowCurrentDirectory(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  let settings: Record<string, unknown>;
  if (record.kind === "config") {
    if (
      !record.settings ||
      typeof record.settings !== "object" ||
      Array.isArray(record.settings)
    ) {
      return false;
    }
    settings = record.settings as Record<string, unknown>;
  } else {
    settings = record;
  }
  return settings.allow_current_directory === true;
}

export type ProtocolRecord = Record<string, unknown> & {
  version: typeof PROTOCOL_VERSION;
  kind: string;
};
export type WireMessage = Record<string, unknown> & { jsonrpc: "2.0" };
export type JsonSchema = Record<string, unknown>;
export type McpToolMetadata = {
  name: string;
  description: string;
  inputRef: string;
  outputRef: string;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
};

export class ProtocolDecodeError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "ProtocolDecodeError";
    this.code = code;
  }
}

// Source builds read the repository authority. The build copies those exact
// bytes beside the compiled bridge, which is the path used in the plugin.
const bundledSchemaUrl = new URL("./protocol/v1/schema.json", import.meta.url);
const sourceSchemaUrl = new URL(
  "../../../protocol/v1/schema.json",
  import.meta.url,
);
const schemaUrl = existsSync(bundledSchemaUrl)
  ? bundledSchemaUrl
  : sourceSchemaUrl;
const schema = JSON.parse(readFileSync(schemaUrl, "utf8")) as JsonSchema;
const ajv = new Ajv2020({
  allErrors: false,
  strict: true,
  validateSchema: true,
});
ajv.addKeyword("x-mcp-tools");
ajv.addSchema(schema);
const schemaId = String(schema.$id);
const requiredValidator = (ref: string) => {
  const validator = ajv.getSchema(ref);
  if (!validator) throw new Error(`protocol schema omits validator ${ref}`);
  return validator;
};
const validateDomain = requiredValidator(`${schemaId}#/$defs/domainRecord`);
const validateWire = requiredValidator(`${schemaId}#/$defs/wireMessage`);

export const MCP_TOOL_METADATA = Object.freeze(
  (schema["x-mcp-tools"] as McpToolMetadata[]).map((tool) =>
    Object.freeze({ ...tool, annotations: Object.freeze(tool.annotations) }),
  ),
);

/** Returns a self-contained JSON Schema projection for MCP registration. */
export function schemaProjection(ref: string): JsonSchema {
  if (!ref.startsWith("#/$defs/")) throw new Error("invalid local schema ref");
  const sourceDefs = schema.$defs as Record<string, JsonSchema>;
  const projectedDefs: Record<string, JsonSchema> = {};
  const visit = (definitionRef: string): void => {
    if (!definitionRef.startsWith("#/$defs/")) return;
    const name = definitionRef.slice("#/$defs/".length);
    if (projectedDefs[name]) return;
    const definition = sourceDefs[name];
    if (!definition) throw new Error(`unknown schema definition ${name}`);
    projectedDefs[name] = definition;
    const inspect = (value: unknown): void => {
      if (Array.isArray(value)) {
        for (const item of value) inspect(item);
      } else if (value && typeof value === "object") {
        const record = value as Record<string, unknown>;
        if (typeof record.$ref === "string") visit(record.$ref);
        for (const nested of Object.values(record)) inspect(nested);
      }
    };
    inspect(definition);
  };
  visit(ref);
  return {
    $schema: schema.$schema,
    $ref: ref,
    $defs: projectedDefs,
  };
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function assertRestrictedJson(value: unknown): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (hasLoneSurrogate(value))
      throw new TypeError("restricted JSON rejects lone UTF-16 surrogates");
    return;
  }
  if (typeof value === "number") {
    if (
      !Number.isSafeInteger(value) ||
      Math.abs(value) > MAX_SAFE_INTEGER ||
      Object.is(value, -0)
    )
      throw new TypeError(
        "restricted JSON requires non-negative-zero safe integers only",
      );
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertRestrictedJson(item);
    return;
  }
  if (typeof value === "object") {
    for (const [key, nested] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (hasLoneSurrogate(key))
        throw new TypeError("restricted JSON rejects lone UTF-16 surrogates");
      assertRestrictedJson(nested);
    }
    return;
  }
  throw new TypeError("restricted JSON accepts JSON values only");
}

/** Validates a complete domain record with the committed Draft 2020-12 schema. */
export function decodeDomainV1(value: unknown): ProtocolRecord {
  if (value === null || Array.isArray(value) || typeof value !== "object")
    throw new ProtocolDecodeError(
      "VALIDATION_FAILED",
      "protocol record must be an object",
    );

  const record = value as Record<string, unknown>;
  if ("version" in record && record.version !== PROTOCOL_VERSION)
    throw new ProtocolDecodeError(
      "VERSION_UNSUPPORTED",
      "protocol version must be exactly 1",
    );

  try {
    assertRestrictedJson(value);
  } catch (error) {
    throw new ProtocolDecodeError(
      "VALIDATION_FAILED",
      error instanceof Error ? error.message : "invalid restricted JSON",
    );
  }

  if (!validateDomain(value)) {
    const first = validateDomain.errors?.[0];
    const location = first?.instancePath || "/";
    const keyword = first?.keyword || "schema";
    throw new ProtocolDecodeError(
      "VALIDATION_FAILED",
      `protocol record failed ${keyword} at ${location}`,
    );
  }

  return record as ProtocolRecord;
}

/** Backward-compatible name for the domain-record decoder. */
export const decodeV1 = decodeDomainV1;

/** Validates one strict internal JSON-RPC wire message. */
export function decodeWireV1(value: unknown): WireMessage {
  try {
    assertRestrictedJson(value);
  } catch (error) {
    throw new ProtocolDecodeError(
      "VALIDATION_FAILED",
      error instanceof Error ? error.message : "invalid restricted JSON",
    );
  }
  if (!validateWire(value)) {
    const first = validateWire.errors?.[0];
    const location = first?.instancePath || "/";
    const keyword = first?.keyword || "schema";
    throw new ProtocolDecodeError(
      "VALIDATION_FAILED",
      `wire message failed ${keyword} at ${location}`,
    );
  }
  return value as WireMessage;
}

function assertNoDuplicateJsonKeys(source: string): void {
  let offset = 0;
  const whitespace = (): void => {
    while (/\s/u.test(source[offset] ?? "")) offset += 1;
  };
  const stringToken = (): string => {
    const start = offset;
    if (source[offset] !== '"') throw new SyntaxError("expected JSON string");
    offset += 1;
    while (offset < source.length) {
      const char = source[offset];
      if (char === "\\") {
        offset += 2;
        continue;
      }
      offset += 1;
      if (char === '"')
        return JSON.parse(source.slice(start, offset)) as string;
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const value = (): void => {
    whitespace();
    if (source[offset] === "{") {
      offset += 1;
      const keys = new Set<string>();
      whitespace();
      if (source[offset] === "}") {
        offset += 1;
        return;
      }
      for (;;) {
        whitespace();
        const key = stringToken();
        if (keys.has(key)) throw new SyntaxError(`duplicate JSON key ${key}`);
        keys.add(key);
        whitespace();
        if (source[offset] !== ":") throw new SyntaxError("expected colon");
        offset += 1;
        value();
        whitespace();
        if (source[offset] === "}") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") throw new SyntaxError("expected comma");
        offset += 1;
      }
    }
    if (source[offset] === "[") {
      offset += 1;
      whitespace();
      if (source[offset] === "]") {
        offset += 1;
        return;
      }
      for (;;) {
        value();
        whitespace();
        if (source[offset] === "]") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") throw new SyntaxError("expected comma");
        offset += 1;
      }
    }
    if (source[offset] === '"') {
      stringToken();
      return;
    }
    const start = offset;
    while (offset < source.length && !/[\s,\]}]/u.test(source[offset] ?? ""))
      offset += 1;
    if (start === offset) throw new SyntaxError("expected JSON value");
  };
  value();
  whitespace();
  if (offset !== source.length) throw new SyntaxError("trailing JSON data");
}

/** Parses strict JSON without the duplicate-key loss of JSON.parse alone. */
export function parseStrictJson(source: string): unknown {
  assertNoDuplicateJsonKeys(source);
  return JSON.parse(source) as unknown;
}

/** Testable byte boundary used by the native transport contract. */
export function validateFrameLength(
  length: number,
  maximumPayloadBytes = 1_048_576,
): void {
  if (length === 0)
    throw new ProtocolDecodeError("IPC_FRAME_INVALID", "zero-length frame");
  if (length > maximumPayloadBytes)
    throw new ProtocolDecodeError(
      "IPC_FRAME_TOO_LARGE",
      "frame exceeds negotiated limit",
    );
}

export function decodeWireFrame(
  bytes: Uint8Array,
  maximumPayloadBytes = 1_048_576,
): WireMessage {
  if (bytes.byteLength < 4)
    throw new ProtocolDecodeError(
      "IPC_FRAME_INVALID",
      "frame header is truncated",
    );
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = view.getUint32(0, true);
  validateFrameLength(length, maximumPayloadBytes);
  if (bytes.byteLength !== length + 4)
    throw new ProtocolDecodeError("IPC_FRAME_INVALID", "frame length mismatch");
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(4),
    );
  } catch {
    throw new ProtocolDecodeError(
      "IPC_FRAME_INVALID",
      "frame is not strict UTF-8",
    );
  }
  try {
    return decodeWireV1(parseStrictJson(source));
  } catch (error) {
    if (error instanceof ProtocolDecodeError) throw error;
    throw new ProtocolDecodeError(
      "IPC_FRAME_INVALID",
      error instanceof Error ? error.message : "invalid JSON frame",
    );
  }
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonical(value: unknown): unknown {
  assertRestrictedJson(value);
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number"
  )
    return value;
  if (Array.isArray(value)) return value.map(canonical);
  const record = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(record)
      .sort(compareUtf8)
      .map((key) => [key, canonical(record[key])]),
  );
}

/**
 * Restricted canonical JSON used by v1 digests: UTF-8 byte key ordering (not
 * RFC 8785), valid Unicode scalar strings, and non-negative-zero safe integers.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(canonical(value));
}

export function digest(value: unknown): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

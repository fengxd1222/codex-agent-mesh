import {
  PROTOCOL_VERSION,
  decodeWireV1,
  type EffectClass,
  type ErrorCode,
  type LifecycleEvidence,
  type RetryClass,
  type WireMessage,
} from "./protocol.js";

export type RpcParams = Record<string, unknown>;
export type RpcResult = Record<string, unknown>;

export type MeshErrorRecord = {
  version: typeof PROTOCOL_VERSION;
  kind: "error";
  code: ErrorCode;
  retry_class: RetryClass;
  effect_class: EffectClass;
  lifecycle: LifecycleEvidence;
  evidence: string;
  message: string;
};

export interface RpcTransport {
  request(method: string, params: RpcParams): Promise<RpcResult>;
  close(): Promise<void>;
}

export class MeshRpcError extends Error {
  constructor(
    readonly errorRecord: MeshErrorRecord,
    readonly diagnosticRef: string,
    readonly cursor?: Record<string, unknown>,
  ) {
    super(errorRecord.message);
    this.name = "MeshRpcError";
  }

  get code(): ErrorCode {
    return this.errorRecord.code;
  }
}

/** Creates a bridge-owned error with explicit lifecycle/effect evidence. */
export function bridgeRpcError(
  code: ErrorCode,
  message: string,
  disposition: "PRE_DISPATCH" | "OUTCOME_UNKNOWN",
  evidence: string,
): MeshRpcError {
  const preDispatch = disposition === "PRE_DISPATCH";
  return new MeshRpcError(
    {
      version: PROTOCOL_VERSION,
      kind: "error",
      code,
      retry_class: preDispatch
        ? "SAFE_PRE_DISPATCH"
        : "AMBIGUOUS_AFTER_DISPATCH",
      effect_class: preDispatch ? "NO_EFFECT" : "UNKNOWN_EFFECT",
      lifecycle: preDispatch
        ? "BEFORE_PROCESS_CREATION"
        : "AFTER_PROCESS_CREATION",
      evidence,
      message,
    },
    "bridge-diagnostic-unavailable",
  );
}

const RESULT_KIND_BY_METHOD = new Map([
  ["mesh.health", "health_result"],
  ["mesh.list_agents", "list_agents_result"],
  ["mesh.delegate_task", "delegate_task_result"],
  ["mesh.inspect_task", "inspect_task_result"],
  ["mesh.wait_task", "wait_task_result"],
  ["mesh.send_task_input", "send_task_input_result"],
  ["mesh.cancel_task", "cancel_task_result"],
  ["mesh.review_task", "review_task_result"],
  ["mesh.improvement_case", "improvement_case_result"],
]);

export function unwrapRpcResponse(
  message: unknown,
  expectedId: string,
  expectedMethod?: string,
): RpcResult {
  const response = decodeWireV1(message) as WireMessage & {
    id: string | number;
    result?: RpcResult;
    error?: {
      message: string;
      data: {
        error: MeshErrorRecord;
        diagnostic_ref: string;
        cursor?: Record<string, unknown>;
      };
    };
  };
  if (String(response.id) !== expectedId)
    throw bridgeRpcError(
      "IPC_FRAME_INVALID",
      "RPC response ID mismatch",
      "OUTCOME_UNKNOWN",
      "response_id_mismatch_after_dispatch",
    );
  if (response.error)
    throw new MeshRpcError(
      response.error.data.error,
      response.error.data.diagnostic_ref,
      response.error.data.cursor,
    );
  if (!response.result)
    throw bridgeRpcError(
      "IPC_FRAME_INVALID",
      "RPC response omitted result",
      "OUTCOME_UNKNOWN",
      "response_shape_invalid_after_dispatch",
    );
  const expectedKind = expectedMethod
    ? RESULT_KIND_BY_METHOD.get(expectedMethod)
    : undefined;
  if (expectedKind && response.result.kind !== expectedKind)
    throw bridgeRpcError(
      "IPC_FRAME_INVALID",
      "RPC result kind does not match its request method",
      "OUTCOME_UNKNOWN",
      "response_method_kind_mismatch_after_dispatch",
    );
  return response.result;
}

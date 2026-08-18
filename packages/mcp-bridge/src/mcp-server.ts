import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import {
  MCP_TOOL_METADATA,
  schemaProjection,
  type ErrorCode,
  type McpToolMetadata,
} from "./protocol.js";
import {
  MeshRpcError,
  bridgeRpcError,
  type RpcResult,
  type RpcTransport,
} from "./rpc-client.js";

export const SERVER_INSTRUCTIONS =
  "Codex Agent Mesh delegates bounded work to durable local agents. Call list_agents before delegation. For every mutation, create one command_key and retain it across retries; an unknown response must be replayed with the same key. Resume task observation with task_id and explicit event cursors. Never infer fallback, approval, retry safety, or completion. Review and acknowledge only the exact result_id, result_version, and ack_token returned by the daemon.";

const ERROR_CODES = new Set<ErrorCode>([
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
]);

function zodSchema(ref: string): z.ZodType<Record<string, unknown>> {
  return z.fromJSONSchema(schemaProjection(ref)) as z.ZodType<
    Record<string, unknown>
  >;
}

function safeError(error: unknown): RpcResult {
  const rpcError =
    error instanceof MeshRpcError
      ? error
      : bridgeRpcError(
          "PROTOCOL_MALFORMED",
          "Codex Agent Mesh rejected the request.",
          "OUTCOME_UNKNOWN",
          "unexpected_bridge_failure_after_dispatch",
        );
  const errorRecord = ERROR_CODES.has(rpcError.code as ErrorCode)
    ? rpcError.errorRecord
    : bridgeRpcError(
        "PROTOCOL_MALFORMED",
        "Codex Agent Mesh returned an unknown error code.",
        "OUTCOME_UNKNOWN",
        "unknown_error_code_after_dispatch",
      ).errorRecord;
  const result: RpcResult = {
    kind: "tool_error",
    error: errorRecord,
    diagnostic_ref: rpcError.diagnosticRef,
  };
  if (rpcError.cursor) result.cursor = rpcError.cursor;
  return result;
}

function methodFor(tool: McpToolMetadata): string {
  return `mesh.${tool.name}`;
}

/** Creates the schema-backed tool facade over an injected native RPC transport. */
export function createMeshServer(rpc: RpcTransport): McpServer {
  const server = new McpServer(
    { name: "codex-agent-mesh", version: "0.1.0" },
    { instructions: SERVER_INSTRUCTIONS },
  );
  for (const tool of MCP_TOOL_METADATA) {
    const inputSchema = zodSchema(tool.inputRef);
    const outputSchema = zodSchema(tool.outputRef);
    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema,
        outputSchema,
        annotations: tool.annotations,
      },
      async (args) => {
        try {
          const data = await rpc.request(
            methodFor(tool),
            args as Record<string, unknown>,
          );
          const structuredContent = { data };
          outputSchema.parse(structuredContent);
          return {
            content: [
              {
                type: "text" as const,
                text: `${tool.name} returned a validated durable mesh response.`,
              },
            ],
            structuredContent,
          };
        } catch (error) {
          const data = safeError(error);
          const structuredContent = { data };
          outputSchema.parse(structuredContent);
          const record = data.error as { code: string; message: string };
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: `${record.code}: ${record.message}`,
              },
            ],
            structuredContent,
          };
        }
      },
    );
  }
  return server;
}

export async function runStdioServer(rpc: RpcTransport): Promise<void> {
  const server = createMeshServer(rpc);
  await server.connect(new StdioServerTransport());
}

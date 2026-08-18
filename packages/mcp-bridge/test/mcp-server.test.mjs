import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMeshServer, SERVER_INSTRUCTIONS } from "../dist/mcp-server.js";
import { NativeHelperTransport } from "../dist/native-transport.js";
import { MeshRpcError } from "../dist/rpc-client.js";

const goldenRoot = new URL("../../../protocol/v1/golden/", import.meta.url);
const methods = [
  ["list_agents", "wire-list-agents"],
  ["delegate_task", "wire-delegate-task"],
  ["inspect_task", "wire-inspect-task"],
  ["wait_task", "wire-wait-task"],
  ["send_task_input", "wire-send-task-input"],
  ["cancel_task", "wire-cancel-task"],
  ["review_task", "wire-review-task"],
  ["improvement_case", null],
];

const improvementProposal = {
  version: 1,
  kind: "command",
  action: "improvement_propose",
  command_key: "improvement-propose-001",
  case_id: "improvement-case-001",
  knob: "quality",
  value: "high",
  hypothesis: "A bounded quality increase improves reviewed outcomes.",
  fixtures: Array.from({ length: 10 }, (_, index) => ({
    fixture_id: `improvement-fixture-${index + 1}`,
    passed: true,
    hard_invariant_failures: 0,
  })),
};

const improvementResult = {
  kind: "improvement_case_result",
  feature_enabled: true,
  outcome: "CANARY",
  case: {
    version: 1,
    kind: "improvement_case",
    case_id: "improvement-case-001",
    component: "prompt-composition",
    status: "OBSERVING",
    parent_config_version: 1,
    candidate_config_version: 2,
    rollback_count: 0,
  },
};

const clone = (value) => JSON.parse(JSON.stringify(value));

async function golden(name) {
  return JSON.parse(
    await readFile(new URL(`${name}.json`, goldenRoot), "utf8"),
  );
}

class FakeRpcTransport {
  calls = [];
  results = new Map();
  closed = false;

  async request(method, params) {
    this.calls.push({ method, params: clone(params) });
    const result = this.results.get(method);
    if (!result) throw new Error(`no fake result for ${method}`);
    return clone(result);
  }

  async close() {
    this.closed = true;
  }
}

async function connected(rpc) {
  const server = createMeshServer(rpc);
  const client = new Client({ name: "mesh-test", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return { server, client };
}

test("MCP advertises exactly eight schema-backed tools with accurate annotations", async () => {
  const rpc = new FakeRpcTransport();
  const { server, client } = await connected(rpc);
  const listed = await client.listTools();
  assert.equal(client.getInstructions(), SERVER_INSTRUCTIONS);
  assert.ok(SERVER_INSTRUCTIONS.slice(0, 512).includes("command_key"));
  assert.deepEqual(
    listed.tools.map((tool) => tool.name),
    methods.map(([name]) => name),
  );
  const improvement = listed.tools.find(
    (tool) => tool.name === "improvement_case",
  );
  assert.deepEqual(improvement.annotations, {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  });
  for (const tool of listed.tools) {
    assert.equal(tool.inputSchema.type, "object", tool.name);
    assert.equal(tool.outputSchema.type, "object", tool.name);
    assert.equal(typeof tool.annotations.readOnlyHint, "boolean", tool.name);
    assert.equal(typeof tool.annotations.destructiveHint, "boolean", tool.name);
    assert.equal(tool.annotations.idempotentHint, true, tool.name);
  }
  await client.close();
  await server.close();
});

test("all schema-backed tools preserve exact params and return validated structured content", async () => {
  const rpc = new FakeRpcTransport();
  for (const [name, fixture] of methods.filter(([, fixture]) => fixture)) {
    const response = await golden(`${fixture}-response`);
    rpc.results.set(`mesh.${name}`, response.result);
  }
  const { server, client } = await connected(rpc);
  for (const [name, fixture] of methods.filter(([, fixture]) => fixture)) {
    const request = await golden(`${fixture}-request`);
    const result = await client.callTool({ name, arguments: request.params });
    assert.equal(result.isError, undefined, name);
    assert.equal(
      result.structuredContent.data.kind,
      (await golden(`${fixture}-response`)).result.kind,
    );
  }
  assert.deepEqual(
    rpc.calls.map((call) => call.method),
    methods.filter(([, fixture]) => fixture).map(([name]) => `mesh.${name}`),
  );
  await client.close();
  await server.close();
});

test("improvement proposals validate strictly and preserve a durable command key", async () => {
  const rpc = new FakeRpcTransport();
  rpc.results.set("mesh.improvement_case", improvementResult);
  const { server, client } = await connected(rpc);

  for (const proposal of [improvementProposal, clone(improvementProposal)]) {
    const result = await client.callTool({
      name: "improvement_case",
      arguments: proposal,
    });
    assert.equal(result.isError, undefined);
    assert.deepEqual(result.structuredContent.data, improvementResult);
  }
  assert.deepEqual(rpc.calls, [
    { method: "mesh.improvement_case", params: improvementProposal },
    { method: "mesh.improvement_case", params: improvementProposal },
  ]);

  const invalid = await client.callTool({
    name: "improvement_case",
    arguments: {
      ...improvementProposal,
      fixtures: improvementProposal.fixtures.slice(0, 9),
    },
  });
  assert.equal(invalid.isError, true);
  assert.equal(rpc.calls.length, 2, "invalid input must not reach RPC");
  await client.close();
  await server.close();
});

test("durable keys and event cursors survive facade retries unchanged", async () => {
  const rpc = new FakeRpcTransport();
  rpc.results.set(
    "mesh.delegate_task",
    (await golden("wire-delegate-task-response")).result,
  );
  rpc.results.set(
    "mesh.wait_task",
    (await golden("wire-wait-task-response")).result,
  );
  const { server, client } = await connected(rpc);
  const delegation = (await golden("wire-delegate-task-request")).params;
  await client.callTool({ name: "delegate_task", arguments: delegation });
  await client.callTool({
    name: "delegate_task",
    arguments: clone(delegation),
  });
  const wait = (await golden("wire-wait-task-request")).params;
  await client.callTool({ name: "wait_task", arguments: wait });
  await client.callTool({
    name: "wait_task",
    arguments: { ...wait, after_seq: 1 },
  });
  assert.equal(
    rpc.calls[0].params.command_key,
    rpc.calls[1].params.command_key,
  );
  assert.deepEqual(
    rpc.calls.slice(2).map((call) => call.params.after_seq),
    [0, 1],
  );
  await client.close();
  await server.close();
});

test("ordinary traffic reports a missing bundled bootstrap before dispatch", async () => {
  const missing = new NativeHelperTransport();
  const { server, client } = await connected(missing);
  const result = await client.callTool({ name: "list_agents", arguments: {} });
  assert.equal(result.isError, true);
  assert.equal(result.structuredContent.data.kind, "tool_error");
  assert.equal(result.structuredContent.data.error.code, "SETUP_ABSENT");
  assert.equal(
    result.structuredContent.data.error.evidence,
    "bundled_setup_helper_absent",
  );
  await client.close();
  await server.close();
});

test("daemon error records pass through without bridge reclassification", async () => {
  const rpc = new FakeRpcTransport();
  const exact = {
    version: 1,
    kind: "error",
    code: "STORAGE_UNAVAILABLE",
    retry_class: "SAFE_PROVEN_NO_EFFECT",
    effect_class: "NO_EFFECT",
    lifecycle: "PROCESS_DEAD_NO_EFFECT_PROOF",
    evidence: "writer_transaction_rolled_back",
    message: "Storage rejected the durable mutation.",
  };
  rpc.request = async () => {
    throw new MeshRpcError(exact, "diagnostic-storage-001");
  };
  const { server, client } = await connected(rpc);
  const request = await golden("wire-delegate-task-request");
  const result = await client.callTool({
    name: "delegate_task",
    arguments: request.params,
  });
  assert.equal(result.isError, true);
  assert.deepEqual(result.structuredContent.data.error, exact);
  assert.equal(
    result.structuredContent.data.diagnostic_ref,
    "diagnostic-storage-001",
  );
  await client.close();
  await server.close();
});

test("cursor-expired recovery bounds remain visible in structured output", async () => {
  const rpc = new FakeRpcTransport();
  const response = await golden("wire-error-cursor-expired");
  rpc.request = async () => {
    throw new MeshRpcError(
      response.error.data.error,
      response.error.data.diagnostic_ref,
      response.error.data.cursor,
    );
  };
  const { server, client } = await connected(rpc);
  const request = await golden("wire-wait-task-request");
  const result = await client.callTool({
    name: "wait_task",
    arguments: request.params,
  });
  assert.equal(result.isError, true);
  assert.deepEqual(
    result.structuredContent.data.cursor,
    response.error.data.cursor,
  );
  await client.close();
  await server.close();
});

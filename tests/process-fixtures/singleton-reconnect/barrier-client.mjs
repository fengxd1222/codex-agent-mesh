import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { setTimeout } from "node:timers";
import { TextDecoder } from "node:util";

const [configPath, readyPath, barrierPath, resultPath] = process.argv.slice(2);
if (!configPath || !readyPath || !barrierPath || !resultPath) process.exit(64);

const config = JSON.parse(readFileSync(configPath, "utf8"));
const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));
const nowEpochMs = () => Date.now();
const timeline = { wrapper_ready_epoch_ms: nowEpochMs() };
writeFileSync(readyPath, JSON.stringify({ pid: process.pid, ...timeline }), {
  flag: "wx",
});

let barrier;
while (!barrier) {
  try {
    barrier = JSON.parse(readFileSync(barrierPath, "utf8"));
  } catch (error) {
    if (error?.code !== "ENOENT" && error?.name !== "SyntaxError") throw error;
    await sleep(2);
  }
}
timeline.barrier_observed_epoch_ms = nowEpochMs();
const monotonicStart = performance.now();

let child;
let stdout = Buffer.alloc(0);
let stderr = Buffer.alloc(0);
let overflow = null;
let timedOut = false;
let closeTimedOut = false;
try {
  child = spawn(config.file, config.arguments, {
    cwd: config.cwd,
    windowsHide: true,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
  timeline.bridge_spawned_epoch_ms = nowEpochMs();
  timeline.bridge_pid = child.pid;
  const closePromise = new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      timeline.bridge_exit_epoch_ms = nowEpochMs();
      timeline.exit_code = code;
      timeline.exit_signal = signal;
    });
    child.once("close", (code, signal) => {
      timeline.bridge_close_epoch_ms = nowEpochMs();
      timeline.close_code = code;
      timeline.close_signal = signal;
      resolve({ code, signal });
    });
    child.once("error", (error) => {
      timeline.launch_error =
        error instanceof Error ? error.message : "bridge spawn error";
    });
  });
  child.stdout.on("data", (chunk) => {
    if (timeline.first_stdout_epoch_ms === undefined)
      timeline.first_stdout_epoch_ms = nowEpochMs();
    const allowed = Math.max(0, 1_048_577 - stdout.byteLength);
    if (allowed > 0)
      stdout = Buffer.concat([stdout, chunk.subarray(0, allowed)]);
    if (stdout.byteLength > 1_048_576) {
      overflow = "stdout";
      child.kill();
    }
  });
  child.stderr.on("data", (chunk) => {
    if (timeline.first_stderr_epoch_ms === undefined)
      timeline.first_stderr_epoch_ms = nowEpochMs();
    const allowed = Math.max(0, 65_537 - stderr.byteLength);
    if (allowed > 0)
      stderr = Buffer.concat([stderr, chunk.subarray(0, allowed)]);
    if (stderr.byteLength > 65_536) {
      overflow = "stderr";
      child.kill();
    }
  });
  const messages = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "singleton-barrier-fixture", version: "1.0.0" },
      },
    },
    { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "list_agents", arguments: {} },
    },
  ];
  timeline.request_write_started_epoch_ms = nowEpochMs();
  child.stdin.end(`${messages.map(JSON.stringify).join("\n")}\n`);
  timeline.request_write_finished_epoch_ms = nowEpochMs();

  const remaining = Math.max(0, barrier.deadline_epoch_ms - nowEpochMs());
  const closed = await Promise.race([
    closePromise,
    sleep(remaining).then(() => ({ timeout: true })),
  ]);
  if (closed.timeout) {
    timedOut = true;
    child.kill();
    const killedClose = await Promise.race([
      closePromise.then(() => ({ closed: true })),
      sleep(500).then(() => ({ closed: false })),
    ]);
    closeTimedOut = !killedClose.closed;
  }
} catch (error) {
  timeline.launch_error =
    error instanceof Error ? error.message : "unknown launch failure";
}

let stdoutText = "";
let stderrText = "";
let strictUtf8 = true;
try {
  stdoutText = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  stderrText = new TextDecoder("utf-8", { fatal: true }).decode(stderr);
} catch {
  strictUtf8 = false;
}
const lines = stdoutText.split(/\r?\n/u);
if (lines.at(-1) === "") lines.pop();
const parsed = [];
let protocolValid =
  strictUtf8 &&
  !closeTimedOut &&
  lines.length === 2 &&
  lines.every((line) => line.length > 0);
for (const line of lines) {
  try {
    const value = JSON.parse(line);
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      value.jsonrpc !== "2.0"
    ) {
      protocolValid = false;
    }
    const hasResult = Object.hasOwn(value, "result");
    const hasError = Object.hasOwn(value, "error");
    if (hasResult === hasError) protocolValid = false;
    parsed.push(value);
  } catch {
    protocolValid = false;
  }
}
const responseIds = parsed
  .filter((value) => Object.hasOwn(value, "id"))
  .map((value) => value.id);
if (JSON.stringify(responseIds) !== JSON.stringify([1, 2]))
  protocolValid = false;
const initialize = parsed.find((value) => value.id === 1);
const initializeResult = initialize?.result;
if (
  initializeResult === null ||
  typeof initializeResult !== "object" ||
  Array.isArray(initializeResult) ||
  initializeResult.protocolVersion !== "2025-06-18" ||
  initializeResult.capabilities === null ||
  typeof initializeResult.capabilities !== "object" ||
  Array.isArray(initializeResult.capabilities) ||
  initializeResult.serverInfo === null ||
  typeof initializeResult.serverInfo !== "object" ||
  Array.isArray(initializeResult.serverInfo) ||
  typeof initializeResult.serverInfo.name !== "string" ||
  typeof initializeResult.serverInfo.version !== "string"
) {
  protocolValid = false;
}
const tool = parsed.find((value) => value.id === 2);
const toolResult = tool?.result;
const toolData = toolResult?.structuredContent?.data;
if (
  toolResult === null ||
  typeof toolResult !== "object" ||
  Array.isArray(toolResult) ||
  !Array.isArray(toolResult.content) ||
  (Object.hasOwn(toolResult, "isError") &&
    typeof toolResult.isError !== "boolean") ||
  toolResult.isError === true ||
  toolResult.structuredContent === null ||
  typeof toolResult.structuredContent !== "object" ||
  Array.isArray(toolResult.structuredContent) ||
  toolData === null ||
  typeof toolData !== "object" ||
  Array.isArray(toolData) ||
  toolData.kind !== "list_agents_result" ||
  !Array.isArray(toolData.agents) ||
  !Number.isSafeInteger(toolData.config_version) ||
  toolData.config_version < 1
) {
  protocolValid = false;
}
const stderrLineBytes = stderrText
  .split(/\r?\n/u)
  .map((line) => Buffer.byteLength(line, "utf8"));

const result = {
  protocol: "codex-agent-mesh-barrier-client-v1",
  client_index: config.clientIndex,
  wrapper_pid: process.pid,
  timeline,
  elapsed_ms: Math.ceil(performance.now() - monotonicStart),
  timed_out: timedOut,
  close_timed_out: closeTimedOut,
  overflow,
  protocol_valid: protocolValid,
  stdout_bytes: stdout.byteLength,
  stdout_line_count: lines.length,
  stderr_bytes: stderr.byteLength,
  maximum_stderr_line_bytes:
    stderrLineBytes.length === 0 ? 0 : Math.max(...stderrLineBytes),
  tool_outcome: protocolValid ? "SUCCESS" : "INVALID",
  tool_result_kind:
    typeof toolData?.kind === "string" ? toolData.kind : "INVALID",
};
writeFileSync(resultPath, JSON.stringify(result), { flag: "wx" });
process.exit(timedOut || closeTimedOut || overflow || !protocolValid ? 1 : 0);

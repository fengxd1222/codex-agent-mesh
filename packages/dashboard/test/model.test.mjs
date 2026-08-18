import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  adapterDisplays,
  artifactHints,
  boundedText,
  eventOutput,
  eventSummary,
  formatTimestamp,
  mergeEvents,
  mergeTaskDetail,
  normalizeSettings,
  parseApiError,
  parseEvent,
  parseOverview,
  parseRoute,
  parseSettings,
  parseSettingsWrite,
  parseTaskDetail,
  parseTaskList,
  ResponseShapeError,
  routeHash,
  statusTone,
} from "../dist/model.js";

test("parseOverview accepts the dashboard_overview contract", () => {
  const overview = parseOverview({
    kind: "dashboard_overview",
    occupancy: { global: 2, per_adapter: { claude: 1, grok: 1 } },
    config: { digest: "abc", value: { agents: [] } },
  });
  assert.equal(overview.occupancy.global, 2);
  assert.equal(overview.occupancy.perAdapter.claude, 1);
  assert.equal(overview.config.digest, "abc");
});

test("parseOverview rejects an unexpected kind", () => {
  assert.throws(
    () =>
      parseOverview({ kind: "list_agents_result", occupancy: {}, config: {} }),
    ResponseShapeError,
  );
});

test("parseTaskList keeps complete summaries and drops incomplete rows", () => {
  const tasks = parseTaskList({
    kind: "dashboard_tasks",
    tasks: [
      {
        task_id: "task-1",
        state: "RUNNING",
        generation: 1,
        last_event_seq: 4,
        created_at_ms: 10,
        updated_at_ms: 20,
      },
      { task_id: "", state: "FAILED" },
      { not: "a task" },
    ],
  });
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].taskId, "task-1");
  assert.equal(tasks[0].lastEventSeq, 4);
});

test("parseTaskDetail keeps token-free terminal review fields", () => {
  const detail = parseTaskDetail({
    kind: "dashboard_task_detail",
    task: {
      task_id: "task-1",
      state: "SUCCEEDED",
      generation: 1,
      last_event_seq: 2,
    },
    attempt: {
      attempt_id: "att-1",
      state: "SUCCEEDED",
      generation: 1,
      adapter_instance_id: "claude",
    },
    interaction: null,
    events: [
      {
        event_id: "evt-1",
        task_id: "task-1",
        seq: 1,
        event_type: "text_delta",
        payload: { text: "hello" },
      },
    ],
    next_seq: 2,
    cursor: { oldest_available_seq: 1, last_committed_seq: 2 },
    terminal_result: {
      result_id: "res-1",
      state: "SUCCEEDED",
      result_version: 1,
      terminal_event_seq: 2,
      ack_status: "PENDING",
      review: { verdict: "ACCEPT", reviewed_at_ms: 30, diagnosis: "ok" },
    },
  });
  assert.equal(detail.task.taskId, "task-1");
  assert.equal(detail.terminalResult?.ackStatus, "PENDING");
  assert.equal(detail.terminalResult?.review?.verdict, "ACCEPT");
  assert.equal(detail.events[0]?.payload.text, "hello");
});

test("parseSettings keeps the CSRF token in the data object only", () => {
  const settings = parseSettings({
    kind: "dashboard_settings",
    config_version: 3,
    csrf_token: "csrf-secret",
    writes_enabled: false,
    settings: {
      enabled_adapters: { claude: true, grok: false, kimi: false },
      improvement_enabled: false,
    },
  });
  assert.equal(settings.configVersion, 3);
  assert.equal(settings.csrfToken, "csrf-secret");
  assert.equal(settings.writesEnabled, false);
  assert.equal(settings.settings.enabled_adapters.claude, true);
});

test("parseSettingsWrite reads hot-reload and restart-required keys", () => {
  const result = parseSettingsWrite({
    kind: "dashboard_settings_write",
    hot_reload: ["improvement_enabled"],
    restart_required: ["concurrency"],
  });
  assert.deepEqual(result.hotReload, ["improvement_enabled"]);
  assert.deepEqual(result.restartRequired, ["concurrency"]);
});

test("normalizeSettings defaults review to luna and freelancer to kimi", () => {
  const settings = normalizeSettings({});
  assert.equal(settings.role_bindings.implementation, "claude");
  assert.equal(settings.role_bindings.research, "grok");
  assert.equal(settings.role_bindings.review, "luna");
  assert.equal(settings.role_bindings.freelancer, "kimi");
  assert.equal(settings.review_chain.reviewer, "luna");
  assert.equal(settings.native_models.luna, "gpt-5.6-luna");
  assert.equal(settings.enabled_adapters.luna, undefined);
  assert.equal(settings.transport_priority.luna, undefined);
});

test("normalizeSettings clamps concurrency and admits only known transports", () => {
  const settings = normalizeSettings({
    concurrency: { global: 99, per_adapter: 0 },
    transport_priority: {
      claude: ["native_json", "pty", "acp"],
      grok: ["nope"],
    },
    quality: { default: "extreme", allowed: ["high", "extreme"] },
    effort: { default: "low", allowed: ["low"] },
  });
  assert.equal(settings.concurrency.global, 3);
  assert.equal(settings.concurrency.per_adapter, 1);
  assert.deepEqual(settings.transport_priority.claude, ["native_json", "acp"]);
  assert.deepEqual(settings.transport_priority.grok, ["acp"]);
  assert.equal(settings.quality.default, "high");
  assert.deepEqual(settings.quality.allowed, ["high"]);
  assert.equal(settings.effort.default, "low");
});

test("eventOutput concatenates text_delta payloads and clips the bound", () => {
  const events = [
    parseEvent({
      event_id: "a",
      task_id: "t",
      seq: 1,
      event_type: "state_changed",
      payload: { state: "RUNNING" },
    }),
    parseEvent({
      event_id: "b",
      task_id: "t",
      seq: 2,
      event_type: "text_delta",
      payload: { text: "hello " },
    }),
    parseEvent({
      event_id: "c",
      task_id: "t",
      seq: 3,
      event_type: "text_delta",
      payload: { text: "world" },
    }),
  ].filter((event) => event !== null);
  const joined = eventOutput(events);
  assert.equal(joined.text, "hello world");
  assert.equal(joined.truncated, false);
  const clipped = eventOutput(events, 7);
  assert.equal(clipped.text, "hello w");
  assert.equal(clipped.truncated, true);
});

test("hostile provider markup stays ordinary text in summaries and output", () => {
  const markup = `</div><img src="http://127.0.0.1/xss" onerror="window.__mesh_xss=1">`;
  const script = `"><a href="javascript:window.__mesh_xss=3">click</a>`;
  const event = parseEvent({
    event_id: "hostile",
    task_id: "t",
    seq: 8,
    event_type: "text_delta",
    payload: { text: `${markup}${script}` },
  });
  assert.ok(event);
  const output = eventOutput([event]);
  assert.equal(output.text.includes("<img"), true);
  assert.equal(output.text.includes("javascript:"), true);
  assert.equal(eventSummary(event), output.text);
  assert.equal(
    boundedText(markup, 20).includes("<img") ||
      boundedText(markup, 20).includes("[输出已截断]"),
    true,
  );
});

test("mergeEvents is last-write-wins by sequence and keeps order", () => {
  const first = parseEvent({
    event_id: "a",
    task_id: "t",
    seq: 2,
    event_type: "text_delta",
    payload: { text: "old" },
  });
  const second = parseEvent({
    event_id: "b",
    task_id: "t",
    seq: 1,
    event_type: "text_delta",
    payload: { text: "one" },
  });
  const replacement = parseEvent({
    event_id: "c",
    task_id: "t",
    seq: 2,
    event_type: "text_delta",
    payload: { text: "new" },
  });
  const merged = mergeEvents(
    [first, second].filter((event) => event !== null),
    [replacement].filter((event) => event !== null),
  );
  assert.deepEqual(
    merged.map((event) => [event.seq, event.payload.text]),
    [
      [1, "one"],
      [2, "new"],
    ],
  );
});

test("mergeTaskDetail keeps earlier events and advances nextSeq", () => {
  const current = parseTaskDetail({
    kind: "dashboard_task_detail",
    task: { task_id: "t", state: "RUNNING", generation: 1, last_event_seq: 1 },
    events: [
      {
        event_id: "a",
        task_id: "t",
        seq: 1,
        event_type: "text_delta",
        payload: { text: "a" },
      },
    ],
    next_seq: 1,
    cursor: { oldest_available_seq: 1, last_committed_seq: 1 },
    terminal_result: null,
  });
  const incoming = parseTaskDetail({
    kind: "dashboard_task_detail",
    task: { task_id: "t", state: "RUNNING", generation: 1, last_event_seq: 2 },
    events: [
      {
        event_id: "b",
        task_id: "t",
        seq: 2,
        event_type: "text_delta",
        payload: { text: "b" },
      },
    ],
    next_seq: 2,
    cursor: { oldest_available_seq: 1, last_committed_seq: 2 },
    terminal_result: null,
  });
  const merged = mergeTaskDetail(current, incoming);
  assert.equal(merged.events.length, 2);
  assert.equal(merged.nextSeq, 2);
});

test("parseRoute and routeHash stay on the allowlisted hash surface", () => {
  assert.deepEqual(parseRoute(""), { view: "overview" });
  assert.deepEqual(parseRoute("#/tasks"), { view: "tasks", taskId: null });
  assert.deepEqual(parseRoute("#/tasks/task-1"), {
    view: "tasks",
    taskId: "task-1",
  });
  assert.deepEqual(parseRoute("#/tasks/../secret"), {
    view: "tasks",
    taskId: null,
  });
  assert.deepEqual(parseRoute("#/settings"), { view: "settings" });
  assert.deepEqual(parseRoute("#/improvement"), { view: "improvement" });
  assert.equal(
    routeHash({ view: "tasks", taskId: "task-1" }),
    "#/tasks/task-1",
  );
});

test("artifactHints collects worktree and blob locators without inventing rows", () => {
  const event = parseEvent({
    event_id: "w",
    task_id: "t",
    seq: 1,
    event_type: "dispatch_phase",
    payload: {
      phase: "worktree",
      worktree_id: "wt-1",
      nested: { blob_hash: "abc", ignored: "no" },
    },
  });
  assert.ok(event);
  const hints = artifactHints([event]);
  assert.deepEqual(hints, [
    { kind: "worktree_id", value: "wt-1" },
    { kind: "blob_hash", value: "abc" },
  ]);
  assert.deepEqual(artifactHints([]), []);
});

test("adapterDisplays falls back to settings when overview has no agents", () => {
  const overview = parseOverview({
    kind: "dashboard_overview",
    occupancy: { global: 0, per_adapter: {} },
    config: { digest: "d", value: { agents: [] } },
  });
  const settings = parseSettings({
    kind: "dashboard_settings",
    config_version: 1,
    csrf_token: "x",
    writes_enabled: false,
    settings: { enabled_adapters: { claude: true, grok: false, kimi: false } },
  });
  const displays = adapterDisplays(overview, settings);
  assert.equal(displays[0]?.name, "claude");
  assert.equal(displays[0]?.status, "CONFIGURED");
  assert.equal(displays[1]?.status, "DISABLED");
});

test("parseApiError prefers the redaction-safe error code", () => {
  assert.equal(parseApiError(403, { error: "csrf_required" }), "csrf_required");
  assert.equal(parseApiError(401, null), "authentication_required");
  assert.equal(parseApiError(503, "nope"), "http_503");
});

test("statusTone and timestamps stay deterministic for empty values", () => {
  assert.equal(statusTone("SUCCEEDED"), "success");
  assert.equal(statusTone("NEEDS_ATTENTION"), "danger");
  assert.equal(formatTimestamp(null), "未记录");
  assert.equal(formatTimestamp(0), "未记录");
});

test("the allowlisted dashboard bundle is the compiled app and never assigns HTML", async () => {
  const bundle = await readFile(
    new URL("../public/dashboard.js", import.meta.url),
    "utf8",
  );
  assert.match(bundle, /\\u7F51\\u683C\\u8FD0\\u7EF4|网格运维/);
  assert.match(bundle, /textContent/);
  assert.doesNotMatch(bundle, /innerHTML/);
  assert.doesNotMatch(bundle, /insertAdjacentHTML/);
  assert.doesNotMatch(bundle, /document\.write/);
});

// src/model.ts
var ADAPTERS = ["claude", "grok", "kimi", "pi"];
var BINDING_TARGETS = [
  "claude",
  "grok",
  "kimi",
  "luna",
  "pi"
];
var TASK_STATES = [
  "QUEUED",
  "PREPARING",
  "RUNNING",
  "WAITING_APPROVAL",
  "RETRY_WAIT",
  "CANCEL_REQUESTED",
  "FINALIZING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "NEEDS_ATTENTION"
];
var ResponseShapeError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "ResponseShapeError";
  }
};
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function requiredRecord(value, label) {
  if (!isRecord(value)) {
    throw new ResponseShapeError(`${label} is not an object`);
  }
  return value;
}
function stringValue(value, fallback = "") {
  return typeof value === "string" ? value : fallback;
}
function numberValue(value, fallback = 0) {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : fallback;
}
function booleanValue(value, fallback = false) {
  return typeof value === "boolean" ? value : fallback;
}
function stringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item) => typeof item === "string");
}
function nullableString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}
function recordField(value, field) {
  return isRecord(value[field]) ? value[field] : {};
}
function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = numberValue(value, fallback);
  return parsed >= minimum && parsed <= maximum ? parsed : fallback;
}
function adapterName(value, fallback) {
  return BINDING_TARGETS.includes(value) ? value : fallback;
}
function policy(value, fallbackDefault, fallbackAllowed, admitted) {
  const source = isRecord(value) ? value : {};
  const allowed = stringArray(source.allowed).filter(
    (item) => admitted.includes(item)
  );
  const normalizedAllowed = allowed.length > 0 ? [...new Set(allowed)] : [...fallbackAllowed];
  const candidateDefault = stringValue(source.default, fallbackDefault);
  const defaultValue = normalizedAllowed.includes(candidateDefault) ? candidateDefault : normalizedAllowed[0] ?? fallbackDefault;
  return { default: defaultValue, allowed: normalizedAllowed };
}
function transports(value, fallback, admitted) {
  const filtered = stringArray(value).filter((item) => admitted.includes(item));
  return filtered.length > 0 ? [...new Set(filtered)].slice(0, 2) : [...fallback];
}
function normalizeSettings(value) {
  const source = isRecord(value) ? value : {};
  const enabled = recordField(source, "enabled_adapters");
  const paths = recordField(source, "executable_paths");
  const priority = recordField(source, "transport_priority");
  const roles = recordField(source, "role_bindings");
  const concurrency = recordField(source, "concurrency");
  const review = recordField(source, "review_chain");
  const retention = recordField(source, "retention");
  const normalized = {
    enabled_adapters: {
      claude: booleanValue(enabled.claude),
      grok: booleanValue(enabled.grok),
      kimi: booleanValue(enabled.kimi),
      pi: booleanValue(enabled.pi)
    },
    executable_paths: {
      claude: nullableString(paths.claude),
      grok: nullableString(paths.grok),
      kimi: nullableString(paths.kimi),
      pi: nullableString(paths.pi)
    },
    transport_priority: {
      claude: transports(
        priority.claude,
        ["native_json"],
        ["native_json", "acp"]
      ),
      grok: transports(priority.grok, ["acp"], ["acp", "stream_json"]),
      kimi: transports(priority.kimi, ["acp"], ["acp", "stream_json"]),
      pi: transports(
        priority.pi,
        ["acp"],
        ["acp", "stream_json", "native_json"]
      )
    },
    role_bindings: {
      implementation: adapterName(roles.implementation, "claude"),
      research: adapterName(roles.research, "grok"),
      review: adapterName(roles.review, "luna"),
      freelancer: adapterName(roles.freelancer, "kimi")
    },
    native_models: {
      luna: stringValue(
        recordField(source, "native_models").luna,
        "gpt-5.6-luna"
      )
    },
    concurrency: {
      global: boundedInteger(concurrency.global, 3, 1, 16),
      per_adapter: boundedInteger(concurrency.per_adapter, 1, 1, 4)
    },
    quality: policy(
      source.quality,
      "standard",
      ["standard"],
      ["low", "standard", "high"]
    ),
    effort: policy(
      source.effort,
      "medium",
      ["medium"],
      ["low", "medium", "high"]
    ),
    review_chain: {
      enabled: booleanValue(review.enabled),
      reviewer: adapterName(review.reviewer, "luna")
    },
    retention: {
      acknowledged_result_days: boundedInteger(
        retention.acknowledged_result_days,
        90,
        30,
        3650
      ),
      acknowledged_blob_terminal_days: boundedInteger(
        retention.acknowledged_blob_terminal_days,
        14,
        1,
        365
      ),
      acknowledged_blob_post_ack_days: boundedInteger(
        retention.acknowledged_blob_post_ack_days,
        7,
        1,
        365
      ),
      successful_worktree_post_ack_days: boundedInteger(
        retention.successful_worktree_post_ack_days,
        7,
        1,
        365
      ),
      non_success_worktree_terminal_days: boundedInteger(
        retention.non_success_worktree_terminal_days,
        30,
        7,
        3650
      ),
      metrics_days: boundedInteger(retention.metrics_days, 90, 30, 3650)
    },
    improvement_enabled: booleanValue(source.improvement_enabled)
  };
  if (typeof source.allow_current_directory === "boolean") {
    normalized.allow_current_directory = source.allow_current_directory;
  }
  return normalized;
}
function parseOverview(value) {
  const root2 = requiredRecord(value, "overview response");
  if (root2.kind !== "dashboard_overview") {
    throw new ResponseShapeError("overview response has an unexpected kind");
  }
  const occupancy = requiredRecord(root2.occupancy, "overview occupancy");
  const rawPerAdapter = requiredRecord(
    occupancy.per_adapter,
    "adapter occupancy"
  );
  const perAdapter = {};
  for (const [key, count] of Object.entries(rawPerAdapter)) {
    if (typeof count === "number" && Number.isSafeInteger(count) && count >= 0) {
      perAdapter[key] = count;
    }
  }
  const config = requiredRecord(root2.config, "overview config");
  const liveAgents = Array.isArray(root2.agents) ? root2.agents.filter(isRecord) : [];
  return {
    occupancy: {
      global: Math.max(0, numberValue(occupancy.global)),
      perAdapter
    },
    config: {
      digest: stringValue(config.digest),
      value: isRecord(config.value) ? config.value : {}
    },
    agents: liveAgents
  };
}
function parseTaskSummary(value) {
  if (!isRecord(value)) {
    return null;
  }
  const taskId = stringValue(value.task_id);
  const state2 = stringValue(value.state);
  if (taskId.length === 0 || state2.length === 0) {
    return null;
  }
  return {
    taskId,
    state: state2,
    generation: Math.max(0, numberValue(value.generation)),
    lastEventSeq: Math.max(0, numberValue(value.last_event_seq)),
    createdAtMs: Math.max(0, numberValue(value.created_at_ms)),
    updatedAtMs: Math.max(0, numberValue(value.updated_at_ms))
  };
}
function parseTaskList(value) {
  const root2 = requiredRecord(value, "task-list response");
  if (root2.kind !== "dashboard_tasks" || !Array.isArray(root2.tasks)) {
    throw new ResponseShapeError("task-list response is invalid");
  }
  return root2.tasks.map(parseTaskSummary).filter((task) => task !== null);
}
function parseTask(value) {
  const source = requiredRecord(value, "task snapshot");
  const taskId = stringValue(source.task_id);
  const state2 = stringValue(source.state);
  if (taskId.length === 0 || state2.length === 0) {
    throw new ResponseShapeError("task snapshot is incomplete");
  }
  return {
    taskId,
    state: state2,
    generation: Math.max(0, numberValue(source.generation)),
    lastEventSeq: Math.max(0, numberValue(source.last_event_seq)),
    attemptId: nullableString(source.attempt_id)
  };
}
function parseAttempt(value) {
  if (!isRecord(value)) {
    return null;
  }
  const attemptId = stringValue(value.attempt_id);
  if (attemptId.length === 0) {
    return null;
  }
  return {
    attemptId,
    state: stringValue(value.state, "UNKNOWN"),
    generation: Math.max(0, numberValue(value.generation)),
    adapterInstanceId: stringValue(value.adapter_instance_id, "unassigned")
  };
}
function parseInteraction(value) {
  if (!isRecord(value)) {
    return null;
  }
  const interactionId = stringValue(value.interaction_id);
  if (interactionId.length === 0) {
    return null;
  }
  return {
    interactionId,
    attemptId: stringValue(value.attempt_id),
    adapterInstanceId: stringValue(value.adapter_instance_id),
    capabilityClass: stringValue(value.capability_class, "unknown"),
    status: stringValue(value.status, "UNKNOWN"),
    createdAtMs: Math.max(0, numberValue(value.created_at_ms)),
    expiresAtMs: Math.max(0, numberValue(value.expires_at_ms))
  };
}
function parseEvent(value) {
  if (!isRecord(value)) {
    return null;
  }
  const eventId = stringValue(value.event_id);
  const taskId = stringValue(value.task_id);
  const eventType = stringValue(value.event_type);
  const seq = numberValue(value.seq, -1);
  if (eventId.length === 0 || taskId.length === 0 || eventType.length === 0 || seq < 1) {
    return null;
  }
  return {
    eventId,
    taskId,
    attemptId: nullableString(value.attempt_id),
    seq,
    occurredAtMs: typeof value.occurred_at_ms === "number" && Number.isSafeInteger(value.occurred_at_ms) ? value.occurred_at_ms : null,
    severity: stringValue(value.severity, "INFO"),
    eventType,
    payload: isRecord(value.payload) ? value.payload : {}
  };
}
function parseReview(value) {
  if (!isRecord(value)) {
    return null;
  }
  const verdict = stringValue(value.verdict);
  if (verdict.length === 0) {
    return null;
  }
  return {
    verdict,
    reviewedAtMs: Math.max(0, numberValue(value.reviewed_at_ms)),
    diagnosis: nullableString(value.diagnosis)
  };
}
function parseTerminalResult(value) {
  if (!isRecord(value)) {
    return null;
  }
  const resultId = stringValue(value.result_id);
  if (resultId.length === 0) {
    return null;
  }
  return {
    resultId,
    state: stringValue(value.state, "UNKNOWN"),
    resultVersion: Math.max(1, numberValue(value.result_version, 1)),
    terminalEventSeq: Math.max(0, numberValue(value.terminal_event_seq)),
    ackStatus: stringValue(value.ack_status, "UNKNOWN"),
    review: parseReview(value.review)
  };
}
function parseTaskDetail(value) {
  const root2 = requiredRecord(value, "task-detail response");
  if (root2.kind !== "dashboard_task_detail") {
    throw new ResponseShapeError("task-detail response has an unexpected kind");
  }
  const events = Array.isArray(root2.events) ? root2.events.map(parseEvent).filter((event) => event !== null) : [];
  const cursor = isRecord(root2.cursor) ? root2.cursor : {};
  return {
    task: parseTask(root2.task),
    attempt: parseAttempt(root2.attempt),
    interaction: parseInteraction(root2.interaction),
    events: mergeEvents([], events),
    nextSeq: Math.max(0, numberValue(root2.next_seq)),
    cursor: {
      oldestAvailableSeq: Math.max(0, numberValue(cursor.oldest_available_seq)),
      lastCommittedSeq: Math.max(0, numberValue(cursor.last_committed_seq))
    },
    terminalResult: parseTerminalResult(root2.terminal_result)
  };
}
function parseSettings(value) {
  const root2 = requiredRecord(value, "settings response");
  if (root2.kind !== "dashboard_settings") {
    throw new ResponseShapeError("settings response has an unexpected kind");
  }
  return {
    configVersion: Math.max(1, numberValue(root2.config_version, 1)),
    settings: normalizeSettings(root2.settings),
    csrfToken: stringValue(root2.csrf_token),
    writesEnabled: booleanValue(root2.writes_enabled)
  };
}
function parseSettingsWrite(value) {
  const root2 = requiredRecord(value, "settings-write response");
  if (root2.kind !== "dashboard_settings_write") {
    throw new ResponseShapeError(
      "settings-write response has an unexpected kind"
    );
  }
  return {
    hotReload: stringArray(root2.hot_reload),
    restartRequired: stringArray(root2.restart_required)
  };
}
function mergeEvents(current, incoming) {
  const bySequence = /* @__PURE__ */ new Map();
  for (const event of current) {
    bySequence.set(event.seq, event);
  }
  for (const event of incoming) {
    bySequence.set(event.seq, event);
  }
  return [...bySequence.values()].sort((left, right) => left.seq - right.seq).slice(-400);
}
function mergeTaskDetail(current, incoming) {
  return {
    task: incoming.task,
    attempt: incoming.attempt,
    interaction: incoming.interaction,
    events: mergeEvents(current.events, incoming.events),
    nextSeq: Math.max(current.nextSeq, incoming.nextSeq),
    cursor: incoming.cursor,
    terminalResult: incoming.terminalResult
  };
}
function isTerminalState(state2) {
  return ["SUCCEEDED", "FAILED", "CANCELLED", "NEEDS_ATTENTION"].includes(
    state2
  );
}
function statusTone(status) {
  switch (status) {
    case "SUCCEEDED":
    case "ENABLED":
    case "ACKNOWLEDGED":
    case "ACCEPTED":
    case "APPROVED":
      return "success";
    case "WAITING_APPROVAL":
    case "RETRY_WAIT":
    case "CANCEL_REQUESTED":
    case "PENDING":
    case "DEGRADED":
      return "warning";
    case "FAILED":
    case "NEEDS_ATTENTION":
    case "UNAVAILABLE":
    case "REJECTED":
    case "DENIED":
    case "ERROR":
      return "danger";
    case "RUNNING":
    case "PREPARING":
    case "FINALIZING":
    case "QUEUED":
      return "info";
    default:
      return "neutral";
  }
}
var STATUS_LABELS = {
  QUEUED: "\u6392\u961F",
  PREPARING: "\u51C6\u5907\u4E2D",
  RUNNING: "\u8FD0\u884C\u4E2D",
  WAITING_APPROVAL: "\u7B49\u5F85\u5BA1\u6279",
  RETRY_WAIT: "\u7B49\u5F85\u91CD\u8BD5",
  CANCEL_REQUESTED: "\u53D6\u6D88\u4E2D",
  FINALIZING: "\u6536\u5C3E\u4E2D",
  SUCCEEDED: "\u5DF2\u6210\u529F",
  FAILED: "\u5DF2\u5931\u8D25",
  CANCELLED: "\u5DF2\u53D6\u6D88",
  NEEDS_ATTENTION: "\u9700\u5173\u6CE8",
  ENABLED: "\u5DF2\u542F\u7528",
  DISABLED: "\u5DF2\u7981\u7528",
  CONFIGURED: "\u5DF2\u914D\u7F6E",
  DEGRADED: "\u964D\u7EA7",
  UNAVAILABLE: "\u4E0D\u53EF\u7528",
  UNKNOWN: "\u672A\u77E5",
  ACKNOWLEDGED: "\u5DF2\u786E\u8BA4",
  PENDING: "\u5F85\u786E\u8BA4",
  ACCEPTED: "\u5DF2\u63A5\u53D7",
  ACCEPT: "\u63A5\u53D7",
  APPROVED: "\u5DF2\u6279\u51C6",
  REJECTED: "\u5DF2\u62D2\u7EDD",
  DENIED: "\u5DF2\u62D2\u7EDD",
  ERROR: "\u9519\u8BEF",
  INFO: "\u4FE1\u606F"
};
var EVENT_TYPE_LABELS = {
  state_changed: "\u72B6\u6001\u53D8\u66F4",
  attempt_started: "\u5C1D\u8BD5\u5F00\u59CB",
  dispatch_phase: "\u8C03\u5EA6\u9636\u6BB5",
  retry_scheduled: "\u5DF2\u5B89\u6392\u91CD\u8BD5",
  recovery_required: "\u9700\u8981\u6062\u590D",
  text_delta: "\u6587\u672C\u589E\u91CF",
  tool_proposal: "\u5DE5\u5177\u63D0\u8BAE",
  interaction_requested: "\u8BF7\u6C42\u4EA4\u4E92",
  interaction_decided: "\u4EA4\u4E92\u5DF2\u51B3",
  usage: "\u7528\u91CF",
  warning: "\u8B66\u544A",
  protocol_error: "\u534F\u8BAE\u9519\u8BEF",
  terminal: "\u7EC8\u6001"
};
function displayStatus(status) {
  return STATUS_LABELS[status] ?? status.replaceAll("_", " ");
}
function displayEventType(eventType) {
  return EVENT_TYPE_LABELS[eventType] ?? eventType.replaceAll("_", " ");
}
function eventSummary(event) {
  const payload = event.payload;
  switch (event.eventType) {
    case "state_changed":
      return `\u4EFB\u52A1\u72B6\u6001\u53D8\u4E3A ${displayStatus(stringValue(payload.state, "UNKNOWN"))}`;
    case "attempt_started":
      return `\u5C1D\u8BD5 ${stringValue(payload.attempt_id, "\u672A\u77E5")} \u5DF2\u5F00\u59CB\uFF08\u5E8F\u53F7 ${numberValue(payload.ordinal)}\uFF09`;
    case "dispatch_phase":
      return `\u8C03\u5EA6\u9636\u6BB5\uFF1A${stringValue(payload.phase, "\u672A\u77E5")}`;
    case "retry_scheduled":
      return `\u5DF2\u5B89\u6392\u5728 ${formatTimestamp(numberValue(payload.retry_at_ms))} \u91CD\u8BD5`;
    case "recovery_required":
      return `\u9700\u8981\u6062\u590D\u64CD\u4F5C\uFF1A${stringValue(payload.action, "\u672A\u77E5")}`;
    case "text_delta":
      return boundedText(stringValue(payload.text), 4e3);
    case "tool_proposal":
      return `\u5DE5\u5177\u63D0\u8BAE\u7B49\u5F85\u4EA4\u4E92 ${stringValue(payload.interaction_id, "\u672A\u77E5")}`;
    case "interaction_requested":
      return `\u8BF7\u6C42\u4EA4\u4E92\uFF1A${stringValue(payload.interaction_id, "\u672A\u77E5")}`;
    case "interaction_decided":
      return `\u4EA4\u4E92${displayStatus(stringValue(payload.status, "decided"))}`;
    case "usage":
      return `\u7528\u91CF\uFF1A\u8F93\u5165 ${numberValue(payload.input_tokens)} / \u8F93\u51FA ${numberValue(payload.output_tokens)} token`;
    case "warning":
      return boundedText(stringValue(payload.warning, "\u8B66\u544A"), 4096);
    case "protocol_error":
      return `${stringValue(payload.code, "protocol_error")}\uFF1A${boundedText(stringValue(payload.message), 4096)}`;
    case "terminal":
      return `\u4EFB\u52A1\u7ED3\u675F\u4E3A ${displayStatus(stringValue(payload.state, "UNKNOWN"))}`;
    default:
      return "\u6301\u4E45\u5316\u4E8B\u4EF6";
  }
}
function eventOutput(events, maximumCharacters = 12e4) {
  const parts = [];
  let total = 0;
  let truncated = false;
  for (const event of events) {
    if (event.eventType !== "text_delta") {
      continue;
    }
    const part = stringValue(event.payload.text);
    if (part.length === 0) {
      continue;
    }
    const remaining = maximumCharacters - total;
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const admitted = part.slice(0, remaining);
    parts.push(admitted);
    total += admitted.length;
    if (admitted.length !== part.length) {
      truncated = true;
      break;
    }
  }
  return { text: parts.join(""), truncated };
}
function adapterDisplays(overview, settings) {
  const agents = overview !== null && overview.agents.length > 0 ? overview.agents : overview?.config.value.agents;
  const records = Array.isArray(agents) ? agents.filter(isRecord) : [];
  return ADAPTERS.map((name) => {
    const live = records.find((candidate) => candidate.adapter === name);
    if (live) {
      const detail = [
        stringValue(live.executable_version),
        stringValue(live.transport)
      ].filter((part) => part.length > 0).join(" / ");
      return {
        name,
        status: stringValue(live.status, "UNKNOWN"),
        detail: detail || stringValue(live.degradation_reason, "\u5DF2\u6709\u80FD\u529B\u8BB0\u5F55")
      };
    }
    const enabled = settings?.settings.enabled_adapters[name] ?? false;
    const transport = settings?.settings.transport_priority[name].join(" \u2192 ") ?? "\u672A\u62A5\u544A";
    return {
      name,
      status: enabled ? "CONFIGURED" : "DISABLED",
      detail: enabled ? `${transport}\uFF1B\u8FD0\u884C\u65F6\u5065\u5EB7\u5C1A\u672A\u62A5\u544A` : transport
    };
  });
}
function formatTimestamp(value) {
  if (value === null || !Number.isFinite(value) || value <= 0) {
    return "\u672A\u8BB0\u5F55";
  }
  try {
    return new Date(value).toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  } catch {
    return "\u65F6\u95F4\u65E0\u6548";
  }
}
function boundedText(value, maximum) {
  if (value.length <= maximum) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maximum - 16))}
[\u8F93\u51FA\u5DF2\u622A\u65AD]`;
}
var TASK_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
var ARTIFACT_KEYS = [
  "worktree_id",
  "worktree_path",
  "artifact_id",
  "artifact_path",
  "blob_hash",
  "locator"
];
function parseRoute(hash) {
  const trimmed = hash.startsWith("#") ? hash.slice(1) : hash;
  const path = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const parts = path.split("/").filter((part) => part.length > 0);
  const head = parts[0];
  if (head === void 0 || head === "overview") {
    return { view: "overview" };
  }
  if (head === "settings") {
    return { view: "settings" };
  }
  if (head === "improvement") {
    return { view: "improvement" };
  }
  if (head === "tasks") {
    const taskId = parts[1];
    if (typeof taskId === "string" && TASK_ID_PATTERN.test(taskId)) {
      return { view: "tasks", taskId };
    }
    return { view: "tasks", taskId: null };
  }
  return { view: "overview" };
}
function routeHash(route) {
  switch (route.view) {
    case "overview":
      return "#/overview";
    case "settings":
      return "#/settings";
    case "improvement":
      return "#/improvement";
    case "tasks":
      return route.taskId === null ? "#/tasks" : `#/tasks/${route.taskId}`;
  }
}
function parseApiError(status, body) {
  if (isRecord(body) && typeof body.error === "string" && body.error.length > 0) {
    return body.error;
  }
  if (status === 401) {
    return "authentication_required";
  }
  return `http_${status}`;
}
function artifactHints(events) {
  const seen = /* @__PURE__ */ new Set();
  const hints = [];
  for (const event of events) {
    collectArtifactHints(event.payload, hints, seen, 0);
    if (hints.length >= 40) {
      break;
    }
  }
  return hints;
}
function collectArtifactHints(value, hints, seen, depth) {
  if (depth > 3 || hints.length >= 40) {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 20)) {
      collectArtifactHints(item, hints, seen, depth + 1);
    }
    return;
  }
  if (!isRecord(value)) {
    return;
  }
  for (const key of ARTIFACT_KEYS) {
    const raw = value[key];
    if (typeof raw !== "string" || raw.length === 0) {
      continue;
    }
    const identity = `${key}:${raw}`;
    if (seen.has(identity)) {
      continue;
    }
    seen.add(identity);
    hints.push({ kind: key, value: boundedText(raw, 240) });
    if (hints.length >= 40) {
      return;
    }
  }
  for (const nested of Object.values(value)) {
    if (isRecord(nested) || Array.isArray(nested)) {
      collectArtifactHints(nested, hints, seen, depth + 1);
    }
  }
}

// src/index.ts
var QUALITY_OPTIONS = ["low", "standard", "high"];
var EFFORT_OPTIONS = ["low", "medium", "high"];
var root = document.querySelector("#app");
var state = {
  route: parseRoute(window.location.hash),
  connection: "idle",
  notice: null,
  overview: null,
  tasks: [],
  taskQuery: "",
  taskState: "",
  detail: null,
  settings: null,
  loading: false
};
var csrfToken = "";
var stream = null;
var streamTaskId = null;
var streamFinished = false;
var renderQueued = false;
var loadGeneration = 0;
var liveStatusTimer = null;
function queueRender() {
  if (renderQueued) {
    return;
  }
  renderQueued = true;
  window.requestAnimationFrame(() => {
    renderQueued = false;
    render();
  });
}
function setState(patch) {
  Object.assign(state, patch);
  queueRender();
}
function describeError(code) {
  switch (code) {
    case "authentication_required":
    case "invalid_bootstrap_token":
      return "\u4F1A\u8BDD\u5DF2\u8FC7\u671F\u3002\u8BF7\u7528\u4E00\u6B21\u6027\u5F15\u5BFC\u94FE\u63A5\u91CD\u65B0\u6253\u5F00\u770B\u677F\u3002";
    case "settings_writes_disabled":
      return "\u8BBE\u7F6E\u5199\u5165\u5DF2\u88AB\u529F\u80FD\u95F8\u5173\u95ED\u3002";
    case "csrf_required":
      return "\u8BBE\u7F6E\u5199\u5165\u88AB\u62D2\u7EDD\u3002\u8BF7\u5237\u65B0\u540E\u91CD\u8BD5\u3002";
    case "settings_invalid":
      return "\u8BBE\u7F6E\u6587\u6863\u672A\u901A\u8FC7\u6A21\u5F0F\u6821\u9A8C\u3002";
    case "settings_unavailable":
      return "\u8BBE\u7F6E\u5B58\u50A8\u5F53\u524D\u4E0D\u53EF\u7528\u3002";
    case "task_not_found":
      return "\u627E\u4E0D\u5230\u8BE5\u4EFB\u52A1\u3002";
    case "cursor_expired":
      return "\u4E8B\u4EF6\u6E38\u6807\u5DF2\u8FC7\u671F\u3002\u8BF7\u91CD\u65B0\u52A0\u8F7D\u4EFB\u52A1\u4EE5\u4ECE\u6301\u4E45\u5316\u5386\u53F2\u7EE7\u7EED\u3002";
    case "storage_unavailable":
    case "storage_quarantined":
      return "\u6301\u4E45\u5316\u5B58\u50A8\u6682\u65F6\u4E0D\u53EF\u7528\u3002";
    default:
      return code.replaceAll("_", " ");
  }
}
async function readJson(response) {
  const text = await response.text();
  if (text.length === 0) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { error: "invalid_json" };
  }
}
async function apiGet(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  const body = await readJson(response);
  if (!response.ok) {
    throw new Error(parseApiError(response.status, body));
  }
  return body;
}
async function apiPut(path, payload, token) {
  const response = await fetch(path, {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": token
    },
    body: JSON.stringify(payload)
  });
  const body = await readJson(response);
  if (!response.ok) {
    throw new Error(parseApiError(response.status, body));
  }
  return body;
}
function closeStream() {
  if (stream !== null) {
    stream.close();
    stream = null;
  }
  streamTaskId = null;
  streamFinished = false;
}
function startStream(taskId, afterSeq) {
  closeStream();
  streamTaskId = taskId;
  streamFinished = false;
  const params = new URLSearchParams({
    after_seq: String(Math.max(0, afterSeq)),
    limit: "200"
  });
  const source = new EventSource(
    `/api/v1/tasks/${encodeURIComponent(taskId)}/events/stream?${params.toString()}`
  );
  stream = source;
  setState({ connection: "connected" });
  source.addEventListener("mesh_event", (event) => {
    if (streamTaskId !== taskId) {
      return;
    }
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }
    const parsed = parseEvent(payload);
    if (parsed === null || state.detail === null || state.detail.task.taskId !== taskId) {
      return;
    }
    const incoming = {
      ...state.detail,
      events: [parsed],
      nextSeq: Math.max(state.detail.nextSeq, parsed.seq)
    };
    setState({
      detail: mergeTaskDetail(state.detail, incoming),
      connection: "connected"
    });
  });
  source.addEventListener("mesh_complete", () => {
    finishStream("complete");
  });
  source.addEventListener("mesh_timeout", () => {
    finishStream("timeout");
  });
  source.addEventListener("mesh_error", () => {
    finishStream("error");
  });
  source.onerror = () => {
    if (streamFinished || streamTaskId !== taskId) {
      source.close();
      return;
    }
    source.close();
    setState({ connection: "error" });
  };
}
function finishStream(connection) {
  streamFinished = true;
  if (stream !== null) {
    stream.close();
    stream = null;
  }
  setState({ connection });
}
async function loadOverview() {
  const [overviewBody, settingsBody] = await Promise.allSettled([
    apiGet("/api/v1/overview"),
    apiGet("/api/v1/settings")
  ]);
  const patch = {};
  if (overviewBody.status === "fulfilled") {
    patch.overview = parseOverview(overviewBody.value);
  } else {
    throw overviewBody.reason;
  }
  if (settingsBody.status === "fulfilled") {
    const settings = parseSettings(settingsBody.value);
    csrfToken = settings.csrfToken;
    patch.settings = settings;
  }
  setState(patch);
}
async function loadTasks() {
  const body = await apiGet("/api/v1/tasks?limit=100");
  setState({ tasks: parseTaskList(body) });
}
function taskRouteIs(taskId) {
  return state.route.view === "tasks" && state.route.taskId === taskId;
}
async function loadTask(taskId, generation) {
  let afterSeq = 0;
  let detail = null;
  for (let page = 0; page < 2; page += 1) {
    const body = await apiGet(
      `/api/v1/tasks/${encodeURIComponent(taskId)}?after_seq=${afterSeq}&limit=200`
    );
    if (generation !== loadGeneration || !taskRouteIs(taskId)) {
      return;
    }
    const incoming = parseTaskDetail(body);
    detail = detail === null ? incoming : mergeTaskDetail(detail, incoming);
    if (incoming.events.length === 0 || incoming.nextSeq >= incoming.cursor.lastCommittedSeq) {
      break;
    }
    afterSeq = incoming.nextSeq;
  }
  if (detail === null || generation !== loadGeneration || !taskRouteIs(taskId)) {
    return;
  }
  setState({ detail, connection: "connected" });
  if (!isTerminalState(detail.task.state)) {
    startStream(taskId, detail.nextSeq);
  } else {
    closeStream();
    setState({ connection: "complete" });
  }
}
async function loadSettings() {
  const settings = parseSettings(await apiGet("/api/v1/settings"));
  csrfToken = settings.csrfToken;
  setState({ settings });
}
function startLiveStatus() {
  if (liveStatusTimer !== null) {
    return;
  }
  liveStatusTimer = window.setInterval(() => {
    if (document.visibilityState === "hidden") {
      return;
    }
    if (state.route.view === "overview") {
      void Promise.all([loadOverview(), loadTasks()]).catch(() => void 0);
      return;
    }
    if (state.route.view === "tasks" && state.route.taskId === null) {
      void loadTasks().catch(() => void 0);
    }
  }, 2e3);
}
async function refresh() {
  const generation = loadGeneration + 1;
  loadGeneration = generation;
  setState({ loading: true, notice: null });
  try {
    const { route } = state;
    if (route.view === "overview") {
      await Promise.all([loadOverview(), loadTasks()]);
    } else if (route.view === "tasks") {
      await loadTasks();
      if (generation !== loadGeneration) {
        return;
      }
      if (route.taskId !== null) {
        await loadTask(route.taskId, generation);
      } else {
        closeStream();
        setState({ detail: null, connection: "idle" });
      }
    } else if (route.view === "settings" || route.view === "improvement") {
      closeStream();
      await loadSettings();
      setState({ connection: "idle" });
    }
  } catch (error) {
    if (generation !== loadGeneration) {
      return;
    }
    const code = error instanceof Error ? error.message : "storage_unavailable";
    setState({
      notice: { tone: "error", text: describeError(code) },
      connection: "error"
    });
  } finally {
    if (generation === loadGeneration) {
      setState({ loading: false });
    }
  }
}
function navigate(route) {
  const hash = routeHash(route);
  if (window.location.hash !== hash) {
    window.location.hash = hash;
    return;
  }
  state.route = route;
  void refresh();
}
function element(tag, options = {}) {
  const node = document.createElement(tag);
  if (options.className !== void 0) {
    node.className = options.className;
  }
  if (options.id !== void 0) {
    node.id = options.id;
  }
  if (options.text !== void 0) {
    node.textContent = options.text;
  }
  if (options.attrs !== void 0) {
    for (const [name, value] of Object.entries(options.attrs)) {
      node.setAttribute(name, value);
    }
  }
  return node;
}
function button(label, className, onClick, disabled = false) {
  const node = element("button", {
    className,
    text: label,
    attrs: { type: "button" }
  });
  node.disabled = disabled;
  node.addEventListener("click", onClick);
  return node;
}
function policyLabel(value) {
  switch (value) {
    case "low":
      return "\u4F4E";
    case "standard":
      return "\u6807\u51C6";
    case "medium":
      return "\u4E2D";
    case "high":
      return "\u9AD8";
    default:
      return value;
  }
}
function connectionLabel(connection) {
  switch (connection) {
    case "connected":
      return "\u5B9E\u65F6\u56DE\u653E\u5DF2\u8FDE\u63A5";
    case "complete":
      return "\u6301\u4E45\u5316\u8FFD\u8D76\u5DF2\u5B8C\u6210";
    case "timeout":
      return "\u56DE\u653E\u5DF2\u5230\u6D41\u5BFF\u547D\u4E0A\u9650";
    case "error":
      return "\u56DE\u653E\u4E2D\u65AD";
    default:
      return "\u7A7A\u95F2";
  }
}
function filteredTasks() {
  const query = state.taskQuery.trim().toLowerCase();
  return state.tasks.filter((task) => {
    if (state.taskState.length > 0 && task.state !== state.taskState) {
      return false;
    }
    if (query.length === 0) {
      return true;
    }
    return task.taskId.toLowerCase().includes(query) || task.state.toLowerCase().includes(query);
  });
}
function renderBadge(status) {
  return element("span", {
    className: `status-badge ${statusTone(status)}`,
    text: displayStatus(status)
  });
}
function renderNotice() {
  if (state.notice === null) {
    return null;
  }
  const box = element("div", {
    className: `notice ${state.notice.tone}`,
    attrs: { role: "status", "aria-live": "polite" }
  });
  box.append(element("p", { text: state.notice.text }));
  return box;
}
function renderKeyValues(entries) {
  const list = element("dl", { className: "key-values" });
  for (const [key, value] of entries) {
    list.append(element("dt", { text: key }), element("dd", { text: value }));
  }
  return list;
}
function renderOverview() {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "\u8FD0\u884C\u603B\u89C8" }),
    element("p", {
      text: "\u9002\u914D\u5668\u5065\u5EB7\u3001\u5360\u7528\u548C\u8BC4\u5BA1\u72B6\u6001\u4E0E MCP \u8BFB\u53D6\u540C\u4E00\u4EFD\u6301\u4E45\u5316\u6295\u5F71\u3002\u4EFB\u52A1\u7684\u6279\u51C6\u3001\u53D6\u6D88\u3001\u91CD\u8BD5\u548C\u786E\u8BA4\u4ECD\u7531 Codex \u8D1F\u8D23\u3002"
    })
  );
  heading.append(titles);
  fragment.append(heading);
  const occupancy = state.overview?.occupancy.global ?? 0;
  const cap = state.settings?.settings.concurrency.global ?? 3;
  const metrics = element("div", { className: "metric-grid" });
  const cards = [
    ["\u5F53\u524D\u5360\u7528", String(occupancy), `\u5168\u5C40\u9650\u989D ${cap}`],
    ["\u53EF\u89C1\u4EFB\u52A1", String(state.tasks.length), "\u6700\u65B0\u5728\u524D\uFF0C\u6700\u591A 100 \u6761"],
    [
      "\u914D\u7F6E\u6458\u8981",
      state.overview?.config.digest.slice(0, 12) || "\u4E0D\u53EF\u7528",
      "\u5DF2\u6301\u4E45\u5316\u914D\u7F6E\u7684\u6307\u7EB9"
    ],
    [
      "\u6539\u8FDB\u56DE\u8DEF",
      state.settings?.settings.improvement_enabled === true ? "\u5DF2\u542F\u7528" : "\u5DF2\u5173\u95ED",
      "\u672C\u91CC\u7A0B\u7891\u4E0D\u505A\u5728\u7EBF\u664B\u7EA7"
    ]
  ];
  for (const [label, value, note] of cards) {
    const card = element("article", { className: "metric" });
    card.append(
      element("p", { className: "metric-label", text: label }),
      element("p", { className: "metric-value", text: value }),
      element("p", { className: "metric-note", text: note })
    );
    metrics.append(card);
  }
  fragment.append(metrics);
  const grid = element("div", { className: "dashboard-grid" });
  const adapters = element("section", { className: "panel" });
  adapters.append(element("div", { className: "section-title" }));
  adapters.firstElementChild?.append(
    element("h2", { text: "\u9002\u914D\u5668\u5065\u5EB7" }),
    element("small", {
      text: "\u6709\u5B9E\u65F6\u63A2\u6D4B\u8BB0\u5F55\u5219\u663E\u793A\uFF1B\u5426\u5219\u53EA\u770B\u8BBE\u7F6E"
    })
  );
  const list = element("div", { className: "adapter-list" });
  const displays = adapterDisplays(state.overview, state.settings);
  for (const display of displays) {
    list.append(renderAdapterRow(display));
  }
  adapters.append(list);
  const occupancyPanel = element("section", { className: "panel" });
  occupancyPanel.append(element("div", { className: "section-title" }));
  occupancyPanel.firstElementChild?.append(
    element("h2", { text: "\u5360\u7528" }),
    element("small", { text: "\u8C03\u5EA6\u5668\u6295\u5F71" })
  );
  const occupancyList = element("div", { className: "occupancy-list" });
  const perAdapter = state.overview?.occupancy.perAdapter ?? {};
  const rows = [
    ["\u5168\u5C40", occupancy, cap],
    ...ADAPTERS.map((name) => [
      name,
      perAdapter[name] ?? 0,
      state.settings?.settings.concurrency.per_adapter ?? 1
    ])
  ];
  for (const [label, count, limit] of rows) {
    occupancyList.append(renderOccupancy(label, count, limit));
  }
  occupancyPanel.append(occupancyList);
  const digest = element("p", { className: "readonly-note" });
  digest.append(
    document.createTextNode("\u914D\u7F6E\u6458\u8981 "),
    element("span", {
      className: "digest",
      text: state.overview?.config.digest || "\u672A\u62A5\u544A"
    })
  );
  occupancyPanel.append(digest);
  grid.append(adapters, occupancyPanel);
  fragment.append(grid);
  const improvement = element("section", { className: "panel" });
  const title = element("div", { className: "section-title" });
  title.append(
    element("h2", { text: "\u6539\u8FDB\u5BA1\u8BA1" }),
    button("\u6253\u5F00\u5BA1\u8BA1", "button-link", () => navigate({ view: "improvement" }))
  );
  improvement.append(
    title,
    element("p", {
      className: "readonly-note",
      text: state.settings?.settings.improvement_enabled === true ? "\u6539\u8FDB\u5F00\u5173\u5DF2\u6253\u5F00\uFF0C\u4F46\u8FD8\u6CA1\u6709\u53F0\u8D26\u6295\u5F71\u3002\u6848\u4F8B\u4F1A\u5728\u5177\u5907\u6295\u5F71\u540E\u51FA\u73B0\u5728\u8FD9\u91CC\u3002" : "\u6539\u8FDB\u56DE\u8DEF\u5DF2\u5173\u95ED\u3002\u770B\u677F\u4E0D\u4F1A\u7F16\u9020\u6848\u4F8B\u6216\u664B\u7EA7\u72B6\u6001\u3002"
    })
  );
  fragment.append(improvement);
  return fragment;
}
function renderAdapterRow(display) {
  const row = element("div", { className: "adapter-row" });
  row.append(
    element("div", { className: "adapter-name", text: display.name }),
    element("div", { className: "adapter-meta", text: display.detail }),
    renderBadge(display.status)
  );
  return row;
}
function renderOccupancy(label, count, limit) {
  const row = element("div", { className: "occupancy-line" });
  const track = element("div", { className: "occupancy-track" });
  const fill = element("div", { className: "occupancy-fill" });
  const percent = limit <= 0 ? 0 : Math.min(100, Math.round(count / limit * 100));
  fill.style.width = `${Math.max(percent, count > 0 ? 8 : 0)}%`;
  track.append(fill);
  row.append(
    element("div", { className: "occupancy-label", text: label }),
    track,
    element("div", { className: "occupancy-value", text: `${count}/${limit}` })
  );
  return row;
}
function renderTasks() {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "\u4EFB\u52A1" }),
    element("p", {
      text: "\u53EA\u8BFB\u5217\u8868\u4E0E\u56DE\u653E\u3002\u6279\u51C6\u3001\u53D6\u6D88\u3001\u91CD\u8BD5\u3001\u5408\u5E76\u548C\u786E\u8BA4\u90FD\u662F MCP \u64CD\u4F5C\u3002"
    })
  );
  heading.append(titles);
  fragment.append(heading);
  const toolbar = element("div", { className: "task-toolbar" });
  const searchField = element("div", { className: "field field-search" });
  searchField.append(
    element("label", { text: "\u641C\u7D22", attrs: { for: "task-search" } })
  );
  const search = element("input", {
    id: "task-search",
    attrs: {
      type: "search",
      value: state.taskQuery,
      placeholder: "\u4EFB\u52A1 ID \u6216\u72B6\u6001",
      autocomplete: "off"
    }
  });
  search.addEventListener("input", () => {
    state.taskQuery = search.value;
    queueRender();
  });
  searchField.append(search);
  const stateField = element("div", { className: "field field-state" });
  stateField.append(
    element("label", { text: "\u72B6\u6001", attrs: { for: "task-state-filter" } })
  );
  const select = element("select", { id: "task-state-filter" });
  const any = element("option", { text: "\u5168\u90E8\u72B6\u6001", attrs: { value: "" } });
  if (state.taskState === "") {
    any.selected = true;
  }
  select.append(any);
  for (const item of TASK_STATES) {
    const option = element("option", {
      text: displayStatus(item),
      attrs: { value: item }
    });
    option.selected = state.taskState === item;
    select.append(option);
  }
  select.addEventListener("change", () => {
    state.taskState = select.value;
    queueRender();
  });
  stateField.append(select);
  toolbar.append(searchField, stateField);
  fragment.append(toolbar);
  const layout = element("div", { className: "task-layout" });
  layout.append(renderTaskTable(), renderTaskDetail());
  fragment.append(layout);
  return fragment;
}
function renderTaskTable() {
  const wrap = element("div", { className: "task-table-wrap panel-plain" });
  const table = element("table", { className: "task-table" });
  const head = element("thead");
  const headRow = element("tr");
  for (const label of ["\u4EFB\u52A1", "\u72B6\u6001", "\u66F4\u65B0\u65F6\u95F4"]) {
    headRow.append(element("th", { text: label }));
  }
  head.append(headRow);
  const body = element("tbody");
  const tasks = filteredTasks();
  if (tasks.length === 0) {
    const empty = element("tr");
    const cell = element("td", {
      text: "\u6CA1\u6709\u7B26\u5408\u7B5B\u9009\u6761\u4EF6\u7684\u6301\u4E45\u5316\u4EFB\u52A1\u3002",
      attrs: { colspan: "3" }
    });
    empty.append(cell);
    body.append(empty);
  } else {
    for (const task of tasks) {
      const selected = state.route.view === "tasks" && state.route.taskId === task.taskId;
      const row = element("tr", {
        className: selected ? "selected" : "",
        attrs: { tabindex: "0" }
      });
      const idCell = element("td");
      idCell.append(
        element("span", { className: "task-id", text: task.taskId })
      );
      const stateCell = element("td", { className: "task-state-cell" });
      stateCell.append(renderBadge(task.state));
      row.append(
        idCell,
        stateCell,
        element("td", { text: formatTimestamp(task.updatedAtMs) })
      );
      const open = () => navigate({ view: "tasks", taskId: task.taskId });
      row.addEventListener("click", open);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          open();
        }
      });
      body.append(row);
    }
  }
  table.append(head, body);
  wrap.append(table);
  return wrap;
}
function renderTaskDetail() {
  const panel = element("section", { className: "task-detail panel" });
  const selectedId = state.route.view === "tasks" ? state.route.taskId : null;
  if (selectedId === null) {
    const empty = element("div", { className: "empty-state" });
    empty.append(
      element("strong", { text: "\u8BF7\u9009\u62E9\u4EFB\u52A1" }),
      document.createTextNode("\u65F6\u95F4\u7EBF\u3001\u8F93\u51FA\u548C\u8BC4\u5BA1\u72B6\u6001\u4F1A\u663E\u793A\u5728\u8FD9\u91CC\u3002")
    );
    panel.append(empty);
    return panel;
  }
  if (state.detail === null || state.detail.task.taskId !== selectedId) {
    panel.append(
      element("div", {
        className: "loading-line",
        text: "\u6B63\u5728\u52A0\u8F7D\u6301\u4E45\u5316\u4EFB\u52A1\u2026"
      })
    );
    return panel;
  }
  const detail = state.detail;
  const heading = element("div", { className: "detail-heading" });
  const titles = element("div");
  titles.append(
    element("h2", { text: detail.task.taskId }),
    element("p", {
      text: `\u4E16\u4EE3 ${detail.task.generation} \xB7 \u6700\u540E\u5E8F\u53F7 ${detail.task.lastEventSeq}`
    })
  );
  heading.append(titles, renderBadge(detail.task.state));
  panel.append(heading);
  const cards = element("div", { className: "detail-grid" });
  const attempt = element("article", { className: "detail-card" });
  attempt.append(element("h3", { text: "\u5C1D\u8BD5" }));
  attempt.append(
    renderKeyValues([
      ["\u5C1D\u8BD5", detail.attempt?.attemptId ?? "\u65E0"],
      ["\u72B6\u6001", detail.attempt ? displayStatus(detail.attempt.state) : "\u65E0"],
      ["\u9002\u914D\u5668", detail.attempt?.adapterInstanceId ?? "\u672A\u5206\u914D"]
    ])
  );
  const interaction = element("article", { className: "detail-card" });
  interaction.append(element("h3", { text: "\u4EA4\u4E92" }));
  interaction.append(
    renderKeyValues(
      detail.interaction === null ? [["\u72B6\u6001", "\u65E0"]] : [
        ["\u6807\u8BC6", detail.interaction.interactionId],
        ["\u7C7B\u578B", detail.interaction.capabilityClass],
        ["\u72B6\u6001", displayStatus(detail.interaction.status)],
        ["\u8FC7\u671F", formatTimestamp(detail.interaction.expiresAtMs)]
      ]
    )
  );
  const review = element("article", { className: "detail-card" });
  review.append(element("h3", { text: "\u7ED3\u679C\u8BC4\u5BA1" }));
  const result = detail.terminalResult;
  review.append(
    renderKeyValues(
      result === null ? [["\u72B6\u6001", "\u5C1A\u65E0\u7EC8\u6001\u7ED3\u679C"]] : [
        ["\u7ED3\u679C", result.resultId],
        ["\u72B6\u6001", displayStatus(result.state)],
        ["\u7248\u672C", String(result.resultVersion)],
        ["\u786E\u8BA4", displayStatus(result.ackStatus)],
        [
          "\u7ED3\u8BBA",
          result.review ? displayStatus(result.review.verdict) : "\u672A\u8BC4\u5BA1"
        ],
        ["\u8BCA\u65AD", result.review?.diagnosis ?? "\u65E0"]
      ]
    )
  );
  cards.append(attempt, interaction, review);
  panel.append(cards);
  const output = eventOutput(detail.events);
  const outputPanel = element("section");
  outputPanel.append(
    element("div", { className: "section-title" }),
    element("pre", {
      className: "output-block",
      text: output.text.length > 0 ? output.text : "\u8FD8\u6CA1\u6709\u6587\u672C\u589E\u91CF\u4E8B\u4EF6\u3002"
    })
  );
  outputPanel.firstElementChild?.append(
    element("h3", { text: "\u8F93\u51FA" }),
    element("small", {
      text: output.truncated ? "\u5DF2\u6309\u770B\u677F\u4E0A\u9650\u622A\u65AD" : "\u4EC5\u4EE5\u7EAF\u6587\u672C\u6E32\u67D3"
    })
  );
  panel.append(outputPanel);
  const artifacts = artifactHints(detail.events);
  const artifactPanel = element("section", { className: "detail-card" });
  artifactPanel.append(element("h3", { text: "\u4EA7\u7269\u4E0E\u5DE5\u4F5C\u6811" }));
  if (artifacts.length === 0) {
    artifactPanel.append(
      element("p", {
        className: "readonly-note",
        text: "\u6301\u4E45\u5316\u4E8B\u4EF6\u91CC\u6CA1\u6709\u5DE5\u4F5C\u6811\u6216\u4EA7\u7269\u5B9A\u4F4D\u7B26\u3002"
      })
    );
  } else {
    artifactPanel.append(
      renderKeyValues(artifacts.map((hint) => [hint.kind, hint.value]))
    );
  }
  panel.append(artifactPanel);
  const timeline = element("ol", { className: "timeline" });
  for (const event of detail.events) {
    const item = element("li", {
      className: `timeline-item ${event.severity.toLowerCase()}`
    });
    const copy = element("div", { className: "timeline-copy" });
    copy.append(
      document.createTextNode(eventSummary(event)),
      element("span", {
        className: "timeline-time",
        text: formatTimestamp(event.occurredAtMs)
      })
    );
    item.append(
      element("div", { className: "timeline-seq", text: String(event.seq) }),
      element("div", {
        className: "timeline-type",
        text: displayEventType(event.eventType)
      }),
      copy
    );
    timeline.append(item);
  }
  const timelineWrap = element("section");
  const timelineTitle = element("div", { className: "section-title" });
  timelineTitle.append(
    element("h3", { text: "\u65F6\u95F4\u7EBF" }),
    element("small", { text: `${detail.events.length} \u6761\u6301\u4E45\u5316\u4E8B\u4EF6` })
  );
  timelineWrap.append(timelineTitle, timeline);
  panel.append(timelineWrap);
  return panel;
}
function renderSettings() {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "\u5B89\u5168\u8BBE\u7F6E" }),
    element("p", {
      text: "\u53EA\u80FD\u7F16\u8F91\u7ECF\u8FC7\u6A21\u5F0F\u6821\u9A8C\u7684\u767D\u540D\u5355\u9879\u3002\u51ED\u8BC1\u3001\u5B89\u88C5\u8EAB\u4EFD\u548C\u6A21\u578B\u540D\u4E0D\u5728\u8FD9\u4E2A\u754C\u9762\u4E0A\u3002"
    })
  );
  heading.append(titles);
  fragment.append(heading);
  if (state.settings === null) {
    fragment.append(
      element("div", { className: "loading-line", text: "\u6B63\u5728\u52A0\u8F7D\u8BBE\u7F6E\u2026" })
    );
    return fragment;
  }
  const form = element("form", {
    className: "settings-form",
    attrs: { autocomplete: "off" }
  });
  const settings = state.settings.settings;
  const writesEnabled = state.settings.writesEnabled;
  form.append(adapterSection(settings));
  form.append(policySection(settings));
  form.append(retentionSection(settings));
  const footer = element("div", { className: "settings-footer" });
  const submit = element("button", {
    className: "button",
    text: writesEnabled ? "\u4FDD\u5B58\u8BBE\u7F6E" : "\u5199\u5165\u5DF2\u5173\u95ED",
    attrs: { type: "submit" }
  });
  submit.disabled = !writesEnabled;
  const status = element("p", {
    className: "settings-status",
    id: "settings-status",
    text: writesEnabled ? `\u914D\u7F6E\u7248\u672C ${state.settings.configVersion}` : "\u8BBE\u7F6E\u5199\u5165\u529F\u80FD\u95F8\u5DF2\u5173\u95ED\u3002\u6570\u503C\u4ECD\u53EF\u67E5\u770B\u3002"
  });
  footer.append(submit, status);
  form.append(footer);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitSettings(form, status);
  });
  fragment.append(form);
  return fragment;
}
function adapterSection(settings) {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "\u9002\u914D\u5668\u4E0E\u89D2\u8272" }),
    element("p", {
      text: "\u53EA\u6539\u89D2\u8272\u7ED1\u5B9A\u548C Luna \u6A21\u578B\u540D\u3002Claude / Grok / Kimi / Pi \u8D70\u672C\u5730 CLI\uFF1BLuna Max \u8D70 Codex \u5B50\u4EE3\u7406\u3002\u4E0D\u8981\u4E3A\u6362\u4EBA\u53BB\u6539 AGENTS.md\u3002"
    })
  );
  const enabled = element("div", { className: "check-row" });
  for (const name of ADAPTERS) {
    enabled.append(
      labeledCheck(
        `enabled-${name}`,
        `\u542F\u7528 ${name}`,
        settings.enabled_adapters[name]
      )
    );
  }
  section.append(enabled);
  const paths = element("div", { className: "settings-grid" });
  for (const name of ADAPTERS) {
    paths.append(
      labeledInput(
        `path-${name}`,
        `${name} \u53EF\u6267\u884C\u6587\u4EF6`,
        settings.executable_paths[name] ?? "",
        "text"
      )
    );
  }
  section.append(paths);
  const transports2 = element("div", { className: "settings-grid" });
  for (const name of ADAPTERS) {
    transports2.append(
      labeledInput(
        `transport-${name}`,
        `${name} \u4F20\u8F93`,
        settings.transport_priority[name].join(", "),
        "text"
      )
    );
  }
  section.append(transports2);
  const roles = element("div", { className: "settings-grid three" });
  roles.append(
    labeledSelect(
      "role-implementation",
      "\u5B9E\u73B0",
      settings.role_bindings.implementation,
      BINDING_TARGETS,
      bindingLabel
    ),
    labeledSelect(
      "role-research",
      "\u7814\u7A76",
      settings.role_bindings.research,
      BINDING_TARGETS,
      bindingLabel
    ),
    labeledSelect(
      "role-review",
      "\u8BC4\u5BA1\uFF08\u9ED8\u8BA4 Luna Max / Codex \u5B50\u4EE3\u7406\uFF09",
      settings.role_bindings.review,
      BINDING_TARGETS,
      bindingLabel
    ),
    labeledSelect(
      "role-freelancer",
      "\u81EA\u7531\u804C\u4E1A\uFF08\u4EC5\u4F60\u70B9\u540D\uFF09",
      settings.role_bindings.freelancer,
      BINDING_TARGETS,
      bindingLabel
    )
  );
  section.append(roles);
  section.append(
    labeledInput(
      "native-luna",
      "Luna Max \u6A21\u578B\uFF08Codex \u5B50\u4EE3\u7406\uFF09",
      settings.native_models.luna,
      "text"
    )
  );
  return section;
}
function policySection(settings) {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "\u5E76\u53D1\u4E0E\u7B56\u7565" }),
    element("p", {
      text: "\u8D28\u91CF\u4E0E\u63A8\u7406\u529B\u5EA6\u5FC5\u987B\u843D\u5728\u5DF2\u51C6\u5165\u767D\u540D\u5355\u5185\u3002\u4E0D\u4F1A\u586B\u5199\u6A21\u578B\u540D\u3002"
    })
  );
  const numbers = element("div", { className: "settings-grid" });
  numbers.append(
    labeledInput(
      "concurrency-global",
      "\u5168\u5C40\u5E76\u53D1",
      String(settings.concurrency.global),
      "number"
    ),
    labeledInput(
      "concurrency-per-adapter",
      "\u6BCF\u9002\u914D\u5668\u5E76\u53D1",
      String(settings.concurrency.per_adapter),
      "number"
    )
  );
  section.append(numbers);
  const quality = element("div", { className: "settings-grid" });
  quality.append(
    labeledSelect(
      "quality-default",
      "\u9ED8\u8BA4\u8D28\u91CF",
      settings.quality.default,
      QUALITY_OPTIONS,
      policyLabel
    )
  );
  const qualityAllowed = element("div", { className: "check-row" });
  for (const option of QUALITY_OPTIONS) {
    qualityAllowed.append(
      labeledCheck(
        `quality-${option}`,
        policyLabel(option),
        settings.quality.allowed.includes(option)
      )
    );
  }
  quality.append(qualityAllowed);
  section.append(quality);
  const effort = element("div", { className: "settings-grid" });
  effort.append(
    labeledSelect(
      "effort-default",
      "\u9ED8\u8BA4\u529B\u5EA6",
      settings.effort.default,
      EFFORT_OPTIONS,
      policyLabel
    )
  );
  const effortAllowed = element("div", { className: "check-row" });
  for (const option of EFFORT_OPTIONS) {
    effortAllowed.append(
      labeledCheck(
        `effort-${option}`,
        policyLabel(option),
        settings.effort.allowed.includes(option)
      )
    );
  }
  effort.append(effortAllowed);
  section.append(effort);
  const flags = element("div", { className: "check-row" });
  flags.append(
    labeledCheck(
      "review-chain",
      "\u542F\u7528\u8BC4\u5BA1\u94FE\uFF08\u8D70\u8BC4\u5BA1\u89D2\u8272\u7ED1\u5B9A\uFF09",
      settings.review_chain.enabled
    ),
    labeledCheck(
      "improvement-enabled",
      "\u542F\u7528\u6539\u8FDB\u53F0\u8D26",
      settings.improvement_enabled
    )
  );
  if (typeof settings.allow_current_directory === "boolean") {
    flags.append(
      labeledCheck(
        "allow-current-directory",
        "\u5141\u8BB8\u5F53\u524D\u76EE\u5F55\u9003\u751F\u8231",
        settings.allow_current_directory
      )
    );
  }
  section.append(flags);
  return section;
}
function retentionSection(settings) {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "\u4FDD\u7559\u7B56\u7565" }),
    element("p", {
      text: "\u6700\u65E9\u53EF\u5783\u573E\u56DE\u6536\u7684\u5929\u6570\u3002\u672A\u786E\u8BA4\u7684\u7ED3\u679C\u6C38\u8FDC\u4E0D\u4F1A\u8FDB\u5165\u56DE\u6536\u3002"
    })
  );
  const grid = element("div", { className: "settings-grid three" });
  const fields = [
    [
      "retention-result",
      "\u5DF2\u786E\u8BA4\u7ED3\u679C\u5929\u6570",
      settings.retention.acknowledged_result_days
    ],
    [
      "retention-blob-terminal",
      "\u7EC8\u6001 blob \u5929\u6570",
      settings.retention.acknowledged_blob_terminal_days
    ],
    [
      "retention-blob-ack",
      "\u786E\u8BA4\u540E blob \u5929\u6570",
      settings.retention.acknowledged_blob_post_ack_days
    ],
    [
      "retention-worktree-success",
      "\u6210\u529F\u5DE5\u4F5C\u6811\u5929\u6570",
      settings.retention.successful_worktree_post_ack_days
    ],
    [
      "retention-worktree-fail",
      "\u5931\u8D25\u5DE5\u4F5C\u6811\u5929\u6570",
      settings.retention.non_success_worktree_terminal_days
    ],
    ["retention-metrics", "\u6307\u6807\u5929\u6570", settings.retention.metrics_days]
  ];
  for (const [id, label, value] of fields) {
    grid.append(labeledInput(id, label, String(value), "number"));
  }
  section.append(grid);
  return section;
}
function labeledInput(id, label, value, type) {
  const field = element("div", { className: "field" });
  field.append(element("label", { text: label, attrs: { for: id } }));
  field.append(element("input", { id, attrs: { type, value, name: id } }));
  return field;
}
function bindingLabel(name) {
  switch (name) {
    case "luna":
      return "Luna Max\uFF08Codex \u5B50\u4EE3\u7406\uFF09";
    case "claude":
      return "Claude\uFF08\u672C\u5730 CLI\uFF09";
    case "grok":
      return "Grok\uFF08\u672C\u5730 CLI\uFF09";
    case "kimi":
      return "Kimi\uFF08\u672C\u5730 CLI\uFF09";
    case "pi":
      return "Pi\uFF08\u672C\u5730 CLI\uFF09";
    default:
      return name;
  }
}
function labeledSelect(id, label, value, options, display = (option) => option) {
  const field = element("div", { className: "field" });
  field.append(element("label", { text: label, attrs: { for: id } }));
  const select = element("select", { id, attrs: { name: id } });
  for (const option of options) {
    const node = element("option", {
      text: display(option),
      attrs: { value: option }
    });
    node.selected = option === value;
    select.append(node);
  }
  field.append(select);
  return field;
}
function labeledCheck(id, label, checked) {
  const node = element("label", {
    className: "check-label",
    attrs: { for: id }
  });
  const input = element("input", {
    id,
    attrs: { type: "checkbox", name: id }
  });
  input.checked = checked;
  node.append(input, document.createTextNode(label));
  return node;
}
function inputValue(form, id) {
  const control = form.elements.namedItem(id);
  if (control instanceof HTMLInputElement || control instanceof HTMLSelectElement) {
    return control.value;
  }
  return "";
}
function inputChecked(form, id) {
  const control = form.elements.namedItem(id);
  return control instanceof HTMLInputElement && control.checked;
}
function settingsFromForm(form, current) {
  const raw = {
    enabled_adapters: {
      claude: inputChecked(form, "enabled-claude"),
      grok: inputChecked(form, "enabled-grok"),
      kimi: inputChecked(form, "enabled-kimi"),
      pi: inputChecked(form, "enabled-pi")
    },
    executable_paths: {
      claude: inputValue(form, "path-claude"),
      grok: inputValue(form, "path-grok"),
      kimi: inputValue(form, "path-kimi"),
      pi: inputValue(form, "path-pi")
    },
    transport_priority: {
      claude: inputValue(form, "transport-claude").split(",").map((item) => item.trim()).filter((item) => item.length > 0),
      grok: inputValue(form, "transport-grok").split(",").map((item) => item.trim()).filter((item) => item.length > 0),
      kimi: inputValue(form, "transport-kimi").split(",").map((item) => item.trim()).filter((item) => item.length > 0),
      pi: inputValue(form, "transport-pi").split(",").map((item) => item.trim()).filter((item) => item.length > 0)
    },
    role_bindings: {
      implementation: inputValue(form, "role-implementation"),
      research: inputValue(form, "role-research"),
      review: inputValue(form, "role-review"),
      freelancer: inputValue(form, "role-freelancer")
    },
    native_models: {
      luna: inputValue(form, "native-luna") || "gpt-5.6-luna"
    },
    concurrency: {
      global: Number(inputValue(form, "concurrency-global")),
      per_adapter: Number(inputValue(form, "concurrency-per-adapter"))
    },
    quality: {
      default: inputValue(form, "quality-default"),
      allowed: QUALITY_OPTIONS.filter(
        (option) => inputChecked(form, `quality-${option}`)
      )
    },
    effort: {
      default: inputValue(form, "effort-default"),
      allowed: EFFORT_OPTIONS.filter(
        (option) => inputChecked(form, `effort-${option}`)
      )
    },
    review_chain: {
      enabled: inputChecked(form, "review-chain"),
      reviewer: inputValue(form, "role-review") || "luna"
    },
    retention: {
      acknowledged_result_days: Number(inputValue(form, "retention-result")),
      acknowledged_blob_terminal_days: Number(
        inputValue(form, "retention-blob-terminal")
      ),
      acknowledged_blob_post_ack_days: Number(
        inputValue(form, "retention-blob-ack")
      ),
      successful_worktree_post_ack_days: Number(
        inputValue(form, "retention-worktree-success")
      ),
      non_success_worktree_terminal_days: Number(
        inputValue(form, "retention-worktree-fail")
      ),
      metrics_days: Number(inputValue(form, "retention-metrics"))
    },
    improvement_enabled: inputChecked(form, "improvement-enabled")
  };
  if (typeof current.allow_current_directory === "boolean") {
    raw.allow_current_directory = inputChecked(form, "allow-current-directory");
  }
  return normalizeSettings(raw);
}
async function submitSettings(form, status) {
  if (state.settings === null) {
    return;
  }
  if (csrfToken.length === 0) {
    status.className = "settings-status error";
    status.textContent = describeError("csrf_required");
    return;
  }
  const next = settingsFromForm(form, state.settings.settings);
  status.className = "settings-status";
  status.textContent = "\u6B63\u5728\u4FDD\u5B58\u2026";
  try {
    const result = parseSettingsWrite(
      await apiPut(
        "/api/v1/settings",
        {
          version: 1,
          kind: "config",
          config_version: state.settings.configVersion,
          settings: next
        },
        csrfToken
      )
    );
    const parts = [
      result.hotReload.length > 0 ? `\u53EF\u70ED\u52A0\u8F7D\uFF1A${result.hotReload.join("\u3001")}` : "",
      result.restartRequired.length > 0 ? `\u9700\u8981\u91CD\u542F\uFF1A${result.restartRequired.join("\u3001")}` : ""
    ].filter((part) => part.length > 0);
    status.className = "settings-status success";
    status.textContent = parts.length > 0 ? parts.join(" \xB7 ") : "\u8BBE\u7F6E\u5DF2\u4FDD\u5B58\u3002";
    await loadSettings();
  } catch (error) {
    const code = error instanceof Error ? error.message : "settings_unavailable";
    status.className = "settings-status error";
    status.textContent = describeError(code);
  }
}
function renderImprovement() {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "\u6539\u8FDB\u5BA1\u8BA1" }),
    element("p", {
      text: "\u6848\u4F8B\u3001\u91D1\u4E1D\u96C0\u548C\u664B\u7EA7\u4EC5\u4F9B\u67E5\u770B\u3002\u53F0\u8D26\u6295\u5F71\u5C1A\u672A\u63A5\u5165\u672C\u754C\u9762\u3002"
    })
  );
  heading.append(titles);
  fragment.append(heading);
  const panel = element("section", { className: "panel" });
  const enabled = state.settings?.settings.improvement_enabled === true;
  panel.append(
    renderBadge(enabled ? "ENABLED" : "DISABLED"),
    element("p", {
      className: "readonly-note",
      text: enabled ? "\u6539\u8FDB\u5F00\u5173\u5DF2\u6253\u5F00\u3002\u8FD8\u6CA1\u6709\u6848\u4F8B\u3001\u5019\u9009\u6216\u91D1\u4E1D\u96C0\u884C\u53EF\u6295\u5F71\u3002" : "\u6539\u8FDB\u56DE\u8DEF\u5DF2\u5173\u95ED\u3002\u770B\u677F\u4E0D\u4F1A\u7F16\u9020\u8D44\u683C\u6216\u664B\u7EA7\u72B6\u6001\u3002"
    })
  );
  fragment.append(panel);
  return fragment;
}
function renderNav() {
  const list = document.getElementById("primary-nav");
  if (!(list instanceof HTMLElement)) {
    return;
  }
  list.replaceChildren();
  const items = [
    ["\u603B\u89C8", { view: "overview" }],
    [
      "\u4EFB\u52A1",
      {
        view: "tasks",
        taskId: state.route.view === "tasks" ? state.route.taskId : null
      }
    ],
    ["\u8BBE\u7F6E", { view: "settings" }]
  ];
  for (const [label, route] of items) {
    const item = element("li");
    const current = route.view === state.route.view || route.view === "tasks" && state.route.view === "tasks";
    const control = button(
      label,
      current ? "nav-button active" : "nav-button",
      () => navigate(route)
    );
    if (current) {
      control.setAttribute("aria-current", "page");
    }
    item.append(control);
    list.append(item);
  }
}
function renderConnection() {
  const label = document.getElementById("connection-label");
  const dot = document.getElementById("connection-dot");
  if (label !== null) {
    label.textContent = connectionLabel(state.connection);
  }
  if (dot !== null) {
    dot.className = `connection-dot ${state.connection === "connected" || state.connection === "complete" ? "connected" : state.connection === "error" || state.connection === "timeout" ? "error" : ""}`;
  }
}
function ensureShell() {
  if (!(root instanceof HTMLElement)) {
    return null;
  }
  let main = document.getElementById("main-content");
  if (main instanceof HTMLElement) {
    return main;
  }
  const shell = element("div", { className: "dashboard-shell" });
  const topbar = element("header", { className: "topbar" });
  const brand = element("div");
  brand.append(
    element("p", { className: "brand", text: "\u7F51\u683C\u8FD0\u7EF4" }),
    element("p", {
      className: "brand-subtitle",
      text: "\u53EA\u8BFB\u672C\u5730\u63A7\u5236\u9762"
    })
  );
  const connection = element("div", {
    className: "connection-state",
    attrs: { role: "status", "aria-live": "polite" }
  });
  connection.append(
    element("span", { className: "connection-dot", id: "connection-dot" }),
    element("span", {
      id: "connection-label",
      text: connectionLabel(state.connection)
    })
  );
  topbar.append(
    brand,
    element("div", { className: "topbar-spacer" }),
    connection,
    button("\u5237\u65B0", "button button-quiet", () => {
      void refresh();
    })
  );
  const body = element("div", { className: "shell-body" });
  const nav = element("nav", {
    className: "side-nav",
    attrs: { "aria-label": "Dashboard" }
  });
  nav.append(
    element("p", { className: "nav-label", text: "\u5BFC\u822A" }),
    element("ul", { className: "nav-list", id: "primary-nav" })
  );
  main = element("main", {
    className: "main-area",
    id: "main-content",
    attrs: { tabindex: "-1" }
  });
  body.append(nav, main);
  shell.append(topbar, body);
  root.replaceChildren(shell);
  return main;
}
function render() {
  const focused = document.activeElement;
  const focusedId = focused instanceof HTMLElement ? focused.id : "";
  const selectionStart = focused instanceof HTMLInputElement || focused instanceof HTMLTextAreaElement ? focused.selectionStart : null;
  const selectionEnd = focused instanceof HTMLInputElement || focused instanceof HTMLTextAreaElement ? focused.selectionEnd : null;
  const main = ensureShell();
  if (!(main instanceof HTMLElement)) {
    return;
  }
  const scrollTop = main.scrollTop;
  const output = document.querySelector(".output-block");
  const outputScroll = output instanceof HTMLElement ? output.scrollTop : null;
  renderConnection();
  renderNav();
  const content = document.createDocumentFragment();
  const notice = renderNotice();
  if (notice !== null) {
    content.append(notice);
  }
  if (state.loading && state.overview === null && state.tasks.length === 0 && state.settings === null) {
    content.append(
      element("div", {
        className: "loading-line",
        text: "\u6B63\u5728\u52A0\u8F7D\u6301\u4E45\u5316\u72B6\u6001\u2026"
      })
    );
  } else if (state.route.view === "overview") {
    content.append(renderOverview());
  } else if (state.route.view === "tasks") {
    content.append(renderTasks());
  } else if (state.route.view === "settings") {
    content.append(renderSettings());
  } else {
    content.append(renderImprovement());
  }
  main.replaceChildren(content);
  main.scrollTop = scrollTop;
  const nextOutput = document.querySelector(".output-block");
  if (nextOutput instanceof HTMLElement && outputScroll !== null) {
    nextOutput.scrollTop = outputScroll;
  }
  if (focusedId.length > 0) {
    const restored = document.getElementById(focusedId);
    restored?.focus();
    if ((restored instanceof HTMLInputElement || restored instanceof HTMLTextAreaElement) && selectionStart !== null && selectionEnd !== null) {
      restored.setSelectionRange(selectionStart, selectionEnd);
    }
  }
}
function onHashChange() {
  const route = parseRoute(window.location.hash);
  state.route = route;
  if (route.view !== "tasks" || route.taskId !== streamTaskId) {
    closeStream();
  }
  void refresh();
}
window.addEventListener("hashchange", onHashChange);
startLiveStatus();
if (window.location.hash.length === 0) {
  window.location.hash = "#/overview";
} else {
  render();
  void refresh();
}

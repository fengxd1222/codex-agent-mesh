export const ADAPTERS = ["claude", "grok", "kimi", "pi"] as const;
export const BINDING_TARGETS = [
  "claude",
  "grok",
  "kimi",
  "luna",
  "pi",
] as const;
export const ROLES = [
  "implementation",
  "research",
  "review",
  "freelancer",
] as const;
export const TASK_STATES = [
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
  "NEEDS_ATTENTION",
] as const;

export type AdapterName = (typeof ADAPTERS)[number];
export type BindingTarget = (typeof BINDING_TARGETS)[number];
export type JsonObject = Record<string, unknown>;

export interface OverviewData {
  occupancy: {
    global: number;
    perAdapter: Record<string, number>;
  };
  config: {
    digest: string;
    value: JsonObject;
  };
  agents: JsonObject[];
}

export interface TaskSummary {
  taskId: string;
  state: string;
  generation: number;
  lastEventSeq: number;
  createdAtMs: number;
  updatedAtMs: number;
}

export interface TaskSnapshot {
  taskId: string;
  state: string;
  generation: number;
  lastEventSeq: number;
  attemptId: string | null;
}

export interface AttemptSnapshot {
  attemptId: string;
  state: string;
  generation: number;
  adapterInstanceId: string;
}

export interface InteractionSnapshot {
  interactionId: string;
  attemptId: string;
  adapterInstanceId: string;
  capabilityClass: string;
  status: string;
  createdAtMs: number;
  expiresAtMs: number;
}

export interface ReviewSnapshot {
  verdict: string;
  reviewedAtMs: number;
  diagnosis: string | null;
}

export interface TerminalResult {
  resultId: string;
  state: string;
  resultVersion: number;
  terminalEventSeq: number;
  ackStatus: string;
  review: ReviewSnapshot | null;
}

export interface TaskEvent {
  eventId: string;
  taskId: string;
  attemptId: string | null;
  seq: number;
  occurredAtMs: number | null;
  severity: string;
  eventType: string;
  payload: JsonObject;
}

export interface TaskDetail {
  task: TaskSnapshot;
  attempt: AttemptSnapshot | null;
  interaction: InteractionSnapshot | null;
  events: TaskEvent[];
  nextSeq: number;
  cursor: {
    oldestAvailableSeq: number;
    lastCommittedSeq: number;
  };
  terminalResult: TerminalResult | null;
}

export interface AdapterFlags {
  claude: boolean;
  grok: boolean;
  kimi: boolean;
  pi: boolean;
}

export interface AdapterPaths {
  claude: string | null;
  grok: string | null;
  kimi: string | null;
  pi: string | null;
}

export interface AdapterTransports {
  claude: string[];
  grok: string[];
  kimi: string[];
  pi: string[];
}

export interface RoleBindings {
  implementation: BindingTarget;
  research: BindingTarget;
  review: BindingTarget;
  freelancer: BindingTarget;
}

export interface ValuePolicy {
  default: string;
  allowed: string[];
}

export interface RetentionSettings {
  acknowledged_result_days: number;
  acknowledged_blob_terminal_days: number;
  acknowledged_blob_post_ack_days: number;
  successful_worktree_post_ack_days: number;
  non_success_worktree_terminal_days: number;
  metrics_days: number;
}

export interface SafeSettings {
  enabled_adapters: AdapterFlags;
  executable_paths: AdapterPaths;
  transport_priority: AdapterTransports;
  role_bindings: RoleBindings;
  native_models: {
    luna: string;
  };
  concurrency: {
    global: number;
    per_adapter: number;
  };
  quality: ValuePolicy;
  effort: ValuePolicy;
  review_chain: {
    enabled: boolean;
    reviewer: BindingTarget;
  };
  retention: RetentionSettings;
  improvement_enabled: boolean;
  allow_current_directory?: boolean;
}

export interface SettingsData {
  configVersion: number;
  settings: SafeSettings;
  csrfToken: string;
  writesEnabled: boolean;
}

export interface SettingsWriteResult {
  hotReload: string[];
  restartRequired: string[];
}

export interface AdapterDisplay {
  name: AdapterName;
  status: string;
  detail: string;
}

export class ResponseShapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ResponseShapeError";
  }
}

export function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredRecord(value: unknown, label: string): JsonObject {
  if (!isRecord(value)) {
    throw new ResponseShapeError(`${label} is not an object`);
  }
  return value;
}

export function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

export function numberValue(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isSafeInteger(value)
    ? value
    : fallback;
}

export function booleanValue(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

export function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string");
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function recordField(value: JsonObject, field: string): JsonObject {
  return isRecord(value[field]) ? value[field] : {};
}

function boundedInteger(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const parsed = numberValue(value, fallback);
  return parsed >= minimum && parsed <= maximum ? parsed : fallback;
}

function adapterName(value: unknown, fallback: BindingTarget): BindingTarget {
  return BINDING_TARGETS.includes(value as BindingTarget)
    ? (value as BindingTarget)
    : fallback;
}

function policy(
  value: unknown,
  fallbackDefault: string,
  fallbackAllowed: readonly string[],
  admitted: readonly string[],
): ValuePolicy {
  const source = isRecord(value) ? value : {};
  const allowed = stringArray(source.allowed).filter((item) =>
    admitted.includes(item),
  );
  const normalizedAllowed =
    allowed.length > 0 ? [...new Set(allowed)] : [...fallbackAllowed];
  const candidateDefault = stringValue(source.default, fallbackDefault);
  const defaultValue = normalizedAllowed.includes(candidateDefault)
    ? candidateDefault
    : (normalizedAllowed[0] ?? fallbackDefault);
  return { default: defaultValue, allowed: normalizedAllowed };
}

function transports(
  value: unknown,
  fallback: readonly string[],
  admitted: readonly string[],
): string[] {
  const filtered = stringArray(value).filter((item) => admitted.includes(item));
  return filtered.length > 0
    ? [...new Set(filtered)].slice(0, 2)
    : [...fallback];
}

export function normalizeSettings(value: unknown): SafeSettings {
  const source = isRecord(value) ? value : {};
  const enabled = recordField(source, "enabled_adapters");
  const paths = recordField(source, "executable_paths");
  const priority = recordField(source, "transport_priority");
  const roles = recordField(source, "role_bindings");
  const concurrency = recordField(source, "concurrency");
  const review = recordField(source, "review_chain");
  const retention = recordField(source, "retention");
  const normalized: SafeSettings = {
    enabled_adapters: {
      claude: booleanValue(enabled.claude),
      grok: booleanValue(enabled.grok),
      kimi: booleanValue(enabled.kimi),
      pi: booleanValue(enabled.pi),
    },
    executable_paths: {
      claude: nullableString(paths.claude),
      grok: nullableString(paths.grok),
      kimi: nullableString(paths.kimi),
      pi: nullableString(paths.pi),
    },
    transport_priority: {
      claude: transports(
        priority.claude,
        ["native_json"],
        ["native_json", "acp"],
      ),
      grok: transports(priority.grok, ["acp"], ["acp", "stream_json"]),
      kimi: transports(priority.kimi, ["acp"], ["acp", "stream_json"]),
      pi: transports(
        priority.pi,
        ["acp"],
        ["acp", "stream_json", "native_json"],
      ),
    },
    role_bindings: {
      implementation: adapterName(roles.implementation, "claude"),
      research: adapterName(roles.research, "grok"),
      review: adapterName(roles.review, "luna"),
      freelancer: adapterName(roles.freelancer, "kimi"),
    },
    native_models: {
      luna: stringValue(
        recordField(source, "native_models").luna,
        "gpt-5.6-luna",
      ),
    },
    concurrency: {
      global: boundedInteger(concurrency.global, 3, 1, 16),
      per_adapter: boundedInteger(concurrency.per_adapter, 1, 1, 4),
    },
    quality: policy(
      source.quality,
      "standard",
      ["standard"],
      ["low", "standard", "high"],
    ),
    effort: policy(
      source.effort,
      "medium",
      ["medium"],
      ["low", "medium", "high"],
    ),
    review_chain: {
      enabled: booleanValue(review.enabled),
      reviewer: adapterName(review.reviewer, "luna"),
    },
    retention: {
      acknowledged_result_days: boundedInteger(
        retention.acknowledged_result_days,
        90,
        30,
        3650,
      ),
      acknowledged_blob_terminal_days: boundedInteger(
        retention.acknowledged_blob_terminal_days,
        14,
        1,
        365,
      ),
      acknowledged_blob_post_ack_days: boundedInteger(
        retention.acknowledged_blob_post_ack_days,
        7,
        1,
        365,
      ),
      successful_worktree_post_ack_days: boundedInteger(
        retention.successful_worktree_post_ack_days,
        7,
        1,
        365,
      ),
      non_success_worktree_terminal_days: boundedInteger(
        retention.non_success_worktree_terminal_days,
        30,
        7,
        3650,
      ),
      metrics_days: boundedInteger(retention.metrics_days, 90, 30, 3650),
    },
    improvement_enabled: booleanValue(source.improvement_enabled),
  };
  if (typeof source.allow_current_directory === "boolean") {
    normalized.allow_current_directory = source.allow_current_directory;
  }
  return normalized;
}

export function parseOverview(value: unknown): OverviewData {
  const root = requiredRecord(value, "overview response");
  if (root.kind !== "dashboard_overview") {
    throw new ResponseShapeError("overview response has an unexpected kind");
  }
  const occupancy = requiredRecord(root.occupancy, "overview occupancy");
  const rawPerAdapter = requiredRecord(
    occupancy.per_adapter,
    "adapter occupancy",
  );
  const perAdapter: Record<string, number> = {};
  for (const [key, count] of Object.entries(rawPerAdapter)) {
    if (
      typeof count === "number" &&
      Number.isSafeInteger(count) &&
      count >= 0
    ) {
      perAdapter[key] = count;
    }
  }
  const config = requiredRecord(root.config, "overview config");
  const liveAgents = Array.isArray(root.agents)
    ? root.agents.filter(isRecord)
    : [];
  return {
    occupancy: {
      global: Math.max(0, numberValue(occupancy.global)),
      perAdapter,
    },
    config: {
      digest: stringValue(config.digest),
      value: isRecord(config.value) ? config.value : {},
    },
    agents: liveAgents,
  };
}

function parseTaskSummary(value: unknown): TaskSummary | null {
  if (!isRecord(value)) {
    return null;
  }
  const taskId = stringValue(value.task_id);
  const state = stringValue(value.state);
  if (taskId.length === 0 || state.length === 0) {
    return null;
  }
  return {
    taskId,
    state,
    generation: Math.max(0, numberValue(value.generation)),
    lastEventSeq: Math.max(0, numberValue(value.last_event_seq)),
    createdAtMs: Math.max(0, numberValue(value.created_at_ms)),
    updatedAtMs: Math.max(0, numberValue(value.updated_at_ms)),
  };
}

export function parseTaskList(value: unknown): TaskSummary[] {
  const root = requiredRecord(value, "task-list response");
  if (root.kind !== "dashboard_tasks" || !Array.isArray(root.tasks)) {
    throw new ResponseShapeError("task-list response is invalid");
  }
  return root.tasks
    .map(parseTaskSummary)
    .filter((task): task is TaskSummary => task !== null);
}

function parseTask(value: unknown): TaskSnapshot {
  const source = requiredRecord(value, "task snapshot");
  const taskId = stringValue(source.task_id);
  const state = stringValue(source.state);
  if (taskId.length === 0 || state.length === 0) {
    throw new ResponseShapeError("task snapshot is incomplete");
  }
  return {
    taskId,
    state,
    generation: Math.max(0, numberValue(source.generation)),
    lastEventSeq: Math.max(0, numberValue(source.last_event_seq)),
    attemptId: nullableString(source.attempt_id),
  };
}

function parseAttempt(value: unknown): AttemptSnapshot | null {
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
    adapterInstanceId: stringValue(value.adapter_instance_id, "unassigned"),
  };
}

function parseInteraction(value: unknown): InteractionSnapshot | null {
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
    expiresAtMs: Math.max(0, numberValue(value.expires_at_ms)),
  };
}

export function parseEvent(value: unknown): TaskEvent | null {
  if (!isRecord(value)) {
    return null;
  }
  const eventId = stringValue(value.event_id);
  const taskId = stringValue(value.task_id);
  const eventType = stringValue(value.event_type);
  const seq = numberValue(value.seq, -1);
  if (
    eventId.length === 0 ||
    taskId.length === 0 ||
    eventType.length === 0 ||
    seq < 1
  ) {
    return null;
  }
  return {
    eventId,
    taskId,
    attemptId: nullableString(value.attempt_id),
    seq,
    occurredAtMs:
      typeof value.occurred_at_ms === "number" &&
      Number.isSafeInteger(value.occurred_at_ms)
        ? value.occurred_at_ms
        : null,
    severity: stringValue(value.severity, "INFO"),
    eventType,
    payload: isRecord(value.payload) ? value.payload : {},
  };
}

function parseReview(value: unknown): ReviewSnapshot | null {
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
    diagnosis: nullableString(value.diagnosis),
  };
}

function parseTerminalResult(value: unknown): TerminalResult | null {
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
    review: parseReview(value.review),
  };
}

export function parseTaskDetail(value: unknown): TaskDetail {
  const root = requiredRecord(value, "task-detail response");
  if (root.kind !== "dashboard_task_detail") {
    throw new ResponseShapeError("task-detail response has an unexpected kind");
  }
  const events = Array.isArray(root.events)
    ? root.events
        .map(parseEvent)
        .filter((event): event is TaskEvent => event !== null)
    : [];
  const cursor = isRecord(root.cursor) ? root.cursor : {};
  return {
    task: parseTask(root.task),
    attempt: parseAttempt(root.attempt),
    interaction: parseInteraction(root.interaction),
    events: mergeEvents([], events),
    nextSeq: Math.max(0, numberValue(root.next_seq)),
    cursor: {
      oldestAvailableSeq: Math.max(0, numberValue(cursor.oldest_available_seq)),
      lastCommittedSeq: Math.max(0, numberValue(cursor.last_committed_seq)),
    },
    terminalResult: parseTerminalResult(root.terminal_result),
  };
}

export function parseSettings(value: unknown): SettingsData {
  const root = requiredRecord(value, "settings response");
  if (root.kind !== "dashboard_settings") {
    throw new ResponseShapeError("settings response has an unexpected kind");
  }
  return {
    configVersion: Math.max(1, numberValue(root.config_version, 1)),
    settings: normalizeSettings(root.settings),
    csrfToken: stringValue(root.csrf_token),
    writesEnabled: booleanValue(root.writes_enabled),
  };
}

export function parseSettingsWrite(value: unknown): SettingsWriteResult {
  const root = requiredRecord(value, "settings-write response");
  if (root.kind !== "dashboard_settings_write") {
    throw new ResponseShapeError(
      "settings-write response has an unexpected kind",
    );
  }
  return {
    hotReload: stringArray(root.hot_reload),
    restartRequired: stringArray(root.restart_required),
  };
}

export function mergeEvents(
  current: readonly TaskEvent[],
  incoming: readonly TaskEvent[],
): TaskEvent[] {
  const bySequence = new Map<number, TaskEvent>();
  for (const event of current) {
    bySequence.set(event.seq, event);
  }
  for (const event of incoming) {
    bySequence.set(event.seq, event);
  }
  return [...bySequence.values()]
    .sort((left, right) => left.seq - right.seq)
    .slice(-400);
}

export function mergeTaskDetail(
  current: TaskDetail,
  incoming: TaskDetail,
): TaskDetail {
  return {
    task: incoming.task,
    attempt: incoming.attempt,
    interaction: incoming.interaction,
    events: mergeEvents(current.events, incoming.events),
    nextSeq: Math.max(current.nextSeq, incoming.nextSeq),
    cursor: incoming.cursor,
    terminalResult: incoming.terminalResult,
  };
}

export function isTerminalState(state: string): boolean {
  return ["SUCCEEDED", "FAILED", "CANCELLED", "NEEDS_ATTENTION"].includes(
    state,
  );
}

export function statusTone(
  status: string,
): "success" | "warning" | "danger" | "info" | "neutral" {
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

const STATUS_LABELS: Record<string, string> = {
  QUEUED: "排队",
  PREPARING: "准备中",
  RUNNING: "运行中",
  WAITING_APPROVAL: "等待审批",
  RETRY_WAIT: "等待重试",
  CANCEL_REQUESTED: "取消中",
  FINALIZING: "收尾中",
  SUCCEEDED: "已成功",
  FAILED: "已失败",
  CANCELLED: "已取消",
  NEEDS_ATTENTION: "需关注",
  ENABLED: "已启用",
  DISABLED: "已禁用",
  CONFIGURED: "已配置",
  DEGRADED: "降级",
  UNAVAILABLE: "不可用",
  UNKNOWN: "未知",
  ACKNOWLEDGED: "已确认",
  PENDING: "待确认",
  ACCEPTED: "已接受",
  ACCEPT: "接受",
  APPROVED: "已批准",
  REJECTED: "已拒绝",
  DENIED: "已拒绝",
  ERROR: "错误",
  INFO: "信息",
};

const EVENT_TYPE_LABELS: Record<string, string> = {
  state_changed: "状态变更",
  attempt_started: "尝试开始",
  dispatch_phase: "调度阶段",
  retry_scheduled: "已安排重试",
  recovery_required: "需要恢复",
  text_delta: "文本增量",
  tool_proposal: "工具提议",
  interaction_requested: "请求交互",
  interaction_decided: "交互已决",
  usage: "用量",
  warning: "警告",
  protocol_error: "协议错误",
  terminal: "终态",
};

export function displayStatus(status: string): string {
  return STATUS_LABELS[status] ?? status.replaceAll("_", " ");
}

export function displayEventType(eventType: string): string {
  return EVENT_TYPE_LABELS[eventType] ?? eventType.replaceAll("_", " ");
}

export function eventSummary(event: TaskEvent): string {
  const payload = event.payload;
  switch (event.eventType) {
    case "state_changed":
      return `任务状态变为 ${displayStatus(stringValue(payload.state, "UNKNOWN"))}`;
    case "attempt_started":
      return `尝试 ${stringValue(payload.attempt_id, "未知")} 已开始（序号 ${numberValue(payload.ordinal)}）`;
    case "dispatch_phase":
      return `调度阶段：${stringValue(payload.phase, "未知")}`;
    case "retry_scheduled":
      return `已安排在 ${formatTimestamp(numberValue(payload.retry_at_ms))} 重试`;
    case "recovery_required":
      return `需要恢复操作：${stringValue(payload.action, "未知")}`;
    case "text_delta":
      return boundedText(stringValue(payload.text), 4000);
    case "tool_proposal":
      return `工具提议等待交互 ${stringValue(payload.interaction_id, "未知")}`;
    case "interaction_requested":
      return `请求交互：${stringValue(payload.interaction_id, "未知")}`;
    case "interaction_decided":
      return `交互${displayStatus(stringValue(payload.status, "decided"))}`;
    case "usage":
      return `用量：输入 ${numberValue(payload.input_tokens)} / 输出 ${numberValue(payload.output_tokens)} token`;
    case "warning":
      return boundedText(stringValue(payload.warning, "警告"), 4096);
    case "protocol_error":
      return `${stringValue(payload.code, "protocol_error")}：${boundedText(stringValue(payload.message), 4096)}`;
    case "terminal":
      return `任务结束为 ${displayStatus(stringValue(payload.state, "UNKNOWN"))}`;
    default:
      return "持久化事件";
  }
}

export function eventOutput(
  events: readonly TaskEvent[],
  maximumCharacters = 120_000,
): {
  text: string;
  truncated: boolean;
} {
  const parts: string[] = [];
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

export function adapterDisplays(
  overview: OverviewData | null,
  settings: SettingsData | null,
): AdapterDisplay[] {
  const agents =
    overview !== null && overview.agents.length > 0
      ? overview.agents
      : overview?.config.value.agents;
  const records = Array.isArray(agents) ? agents.filter(isRecord) : [];
  return ADAPTERS.map((name) => {
    const live = records.find((candidate) => candidate.adapter === name);
    if (live) {
      const detail = [
        stringValue(live.executable_version),
        stringValue(live.transport),
      ]
        .filter((part) => part.length > 0)
        .join(" / ");
      return {
        name,
        status: stringValue(live.status, "UNKNOWN"),
        detail: detail || stringValue(live.degradation_reason, "已有能力记录"),
      };
    }
    const enabled = settings?.settings.enabled_adapters[name] ?? false;
    const transport =
      settings?.settings.transport_priority[name].join(" → ") ?? "未报告";
    return {
      name,
      status: enabled ? "CONFIGURED" : "DISABLED",
      detail: enabled ? `${transport}；运行时健康尚未报告` : transport,
    };
  });
}

export function formatTimestamp(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value <= 0) {
    return "未记录";
  }
  try {
    return new Date(value).toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "时间无效";
  }
}

export function boundedText(value: string, maximum: number): string {
  if (value.length <= maximum) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maximum - 16))}\n[输出已截断]`;
}

export type DashboardRoute =
  | { view: "overview" }
  | { view: "tasks"; taskId: string | null }
  | { view: "settings" }
  | { view: "improvement" };

export interface ArtifactHint {
  kind: string;
  value: string;
}

const TASK_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const ARTIFACT_KEYS = [
  "worktree_id",
  "worktree_path",
  "artifact_id",
  "artifact_path",
  "blob_hash",
  "locator",
] as const;

export function parseRoute(hash: string): DashboardRoute {
  const trimmed = hash.startsWith("#") ? hash.slice(1) : hash;
  const path = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const parts = path.split("/").filter((part) => part.length > 0);
  const head = parts[0];
  if (head === undefined || head === "overview") {
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

export function routeHash(route: DashboardRoute): string {
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

export function parseApiError(status: number, body: unknown): string {
  if (
    isRecord(body) &&
    typeof body.error === "string" &&
    body.error.length > 0
  ) {
    return body.error;
  }
  if (status === 401) {
    return "authentication_required";
  }
  return `http_${status}`;
}

export function artifactHints(events: readonly TaskEvent[]): ArtifactHint[] {
  const seen = new Set<string>();
  const hints: ArtifactHint[] = [];
  for (const event of events) {
    collectArtifactHints(event.payload, hints, seen, 0);
    if (hints.length >= 40) {
      break;
    }
  }
  return hints;
}

function collectArtifactHints(
  value: unknown,
  hints: ArtifactHint[],
  seen: Set<string>,
  depth: number,
): void {
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

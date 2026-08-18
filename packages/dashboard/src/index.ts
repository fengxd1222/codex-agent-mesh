import {
  ADAPTERS,
  BINDING_TARGETS,
  TASK_STATES,
  adapterDisplays,
  artifactHints,
  displayEventType,
  displayStatus,
  eventOutput,
  eventSummary,
  formatTimestamp,
  isTerminalState,
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
  routeHash,
  statusTone,
  type DashboardRoute,
  type OverviewData,
  type SafeSettings,
  type SettingsData,
  type TaskDetail,
  type TaskSummary,
} from "./model.js";

type ConnectionState = "idle" | "connected" | "error" | "complete" | "timeout";

interface Notice {
  tone: "info" | "warning" | "error" | "success";
  text: string;
}

interface AppState {
  route: DashboardRoute;
  connection: ConnectionState;
  notice: Notice | null;
  overview: OverviewData | null;
  tasks: TaskSummary[];
  taskQuery: string;
  taskState: string;
  detail: TaskDetail | null;
  settings: SettingsData | null;
  loading: boolean;
}

const QUALITY_OPTIONS = ["low", "standard", "high"] as const;
const EFFORT_OPTIONS = ["low", "medium", "high"] as const;

const root = document.querySelector("#app");
const state: AppState = {
  route: parseRoute(window.location.hash),
  connection: "idle",
  notice: null,
  overview: null,
  tasks: [],
  taskQuery: "",
  taskState: "",
  detail: null,
  settings: null,
  loading: false,
};

let csrfToken = "";
let stream: EventSource | null = null;
let streamTaskId: string | null = null;
let streamFinished = false;
let renderQueued = false;
let loadGeneration = 0;
let liveStatusTimer: number | null = null;

function queueRender(): void {
  if (renderQueued) {
    return;
  }
  renderQueued = true;
  window.requestAnimationFrame(() => {
    renderQueued = false;
    render();
  });
}

function setState(patch: Partial<AppState>): void {
  Object.assign(state, patch);
  queueRender();
}

function describeError(code: string): string {
  switch (code) {
    case "authentication_required":
    case "invalid_bootstrap_token":
      return "会话已过期。请用一次性引导链接重新打开看板。";
    case "settings_writes_disabled":
      return "设置写入已被功能闸关闭。";
    case "csrf_required":
      return "设置写入被拒绝。请刷新后重试。";
    case "settings_invalid":
      return "设置文档未通过模式校验。";
    case "settings_unavailable":
      return "设置存储当前不可用。";
    case "task_not_found":
      return "找不到该任务。";
    case "cursor_expired":
      return "事件游标已过期。请重新加载任务以从持久化历史继续。";
    case "storage_unavailable":
    case "storage_quarantined":
      return "持久化存储暂时不可用。";
    default:
      return code.replaceAll("_", " ");
  }
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { error: "invalid_json" };
  }
}

async function apiGet(path: string): Promise<unknown> {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  const body = await readJson(response);
  if (!response.ok) {
    throw new Error(parseApiError(response.status, body));
  }
  return body;
}

async function apiPut(
  path: string,
  payload: unknown,
  token: string,
): Promise<unknown> {
  const response = await fetch(path, {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": token,
    },
    body: JSON.stringify(payload),
  });
  const body = await readJson(response);
  if (!response.ok) {
    throw new Error(parseApiError(response.status, body));
  }
  return body;
}

function closeStream(): void {
  if (stream !== null) {
    stream.close();
    stream = null;
  }
  streamTaskId = null;
  streamFinished = false;
}

function startStream(taskId: string, afterSeq: number): void {
  closeStream();
  streamTaskId = taskId;
  streamFinished = false;
  const params = new URLSearchParams({
    after_seq: String(Math.max(0, afterSeq)),
    limit: "200",
  });
  const source = new EventSource(
    `/api/v1/tasks/${encodeURIComponent(taskId)}/events/stream?${params.toString()}`,
  );
  stream = source;
  setState({ connection: "connected" });

  source.addEventListener("mesh_event", (event) => {
    if (streamTaskId !== taskId) {
      return;
    }
    let payload: unknown;
    try {
      payload = JSON.parse(event.data) as unknown;
    } catch {
      return;
    }
    const parsed = parseEvent(payload);
    if (
      parsed === null ||
      state.detail === null ||
      state.detail.task.taskId !== taskId
    ) {
      return;
    }
    const incoming = {
      ...state.detail,
      events: [parsed],
      nextSeq: Math.max(state.detail.nextSeq, parsed.seq),
    };
    setState({
      detail: mergeTaskDetail(state.detail, incoming),
      connection: "connected",
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

function finishStream(connection: ConnectionState): void {
  streamFinished = true;
  if (stream !== null) {
    stream.close();
    stream = null;
  }
  setState({ connection });
}

async function loadOverview(): Promise<void> {
  const [overviewBody, settingsBody] = await Promise.allSettled([
    apiGet("/api/v1/overview"),
    apiGet("/api/v1/settings"),
  ]);
  const patch: Partial<AppState> = {};
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

async function loadTasks(): Promise<void> {
  const body = await apiGet("/api/v1/tasks?limit=100");
  setState({ tasks: parseTaskList(body) });
}

function taskRouteIs(taskId: string): boolean {
  return state.route.view === "tasks" && state.route.taskId === taskId;
}

async function loadTask(taskId: string, generation: number): Promise<void> {
  let afterSeq = 0;
  let detail: TaskDetail | null = null;
  for (let page = 0; page < 2; page += 1) {
    const body = await apiGet(
      `/api/v1/tasks/${encodeURIComponent(taskId)}?after_seq=${afterSeq}&limit=200`,
    );
    if (generation !== loadGeneration || !taskRouteIs(taskId)) {
      return;
    }
    const incoming = parseTaskDetail(body);
    detail = detail === null ? incoming : mergeTaskDetail(detail, incoming);
    if (
      incoming.events.length === 0 ||
      incoming.nextSeq >= incoming.cursor.lastCommittedSeq
    ) {
      break;
    }
    afterSeq = incoming.nextSeq;
  }
  if (
    detail === null ||
    generation !== loadGeneration ||
    !taskRouteIs(taskId)
  ) {
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

async function loadSettings(): Promise<void> {
  const settings = parseSettings(await apiGet("/api/v1/settings"));
  csrfToken = settings.csrfToken;
  setState({ settings });
}

function startLiveStatus(): void {
  if (liveStatusTimer !== null) {
    return;
  }
  liveStatusTimer = window.setInterval(() => {
    if (document.visibilityState === "hidden") {
      return;
    }
    if (state.route.view === "overview") {
      void Promise.all([loadOverview(), loadTasks()]).catch(() => undefined);
      return;
    }
    if (state.route.view === "tasks" && state.route.taskId === null) {
      void loadTasks().catch(() => undefined);
    }
  }, 2000);
}

async function refresh(): Promise<void> {
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
      connection: "error",
    });
  } finally {
    if (generation === loadGeneration) {
      setState({ loading: false });
    }
  }
}

function navigate(route: DashboardRoute): void {
  const hash = routeHash(route);
  if (window.location.hash !== hash) {
    window.location.hash = hash;
    return;
  }
  state.route = route;
  void refresh();
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: {
    className?: string;
    text?: string;
    id?: string;
    attrs?: Record<string, string>;
  } = {},
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.className !== undefined) {
    node.className = options.className;
  }
  if (options.id !== undefined) {
    node.id = options.id;
  }
  if (options.text !== undefined) {
    node.textContent = options.text;
  }
  if (options.attrs !== undefined) {
    for (const [name, value] of Object.entries(options.attrs)) {
      node.setAttribute(name, value);
    }
  }
  return node;
}

function button(
  label: string,
  className: string,
  onClick: () => void,
  disabled = false,
): HTMLButtonElement {
  const node = element("button", {
    className,
    text: label,
    attrs: { type: "button" },
  });
  node.disabled = disabled;
  node.addEventListener("click", onClick);
  return node;
}

function policyLabel(value: string): string {
  switch (value) {
    case "low":
      return "低";
    case "standard":
      return "标准";
    case "medium":
      return "中";
    case "high":
      return "高";
    default:
      return value;
  }
}

function connectionLabel(connection: ConnectionState): string {
  switch (connection) {
    case "connected":
      return "实时回放已连接";
    case "complete":
      return "持久化追赶已完成";
    case "timeout":
      return "回放已到流寿命上限";
    case "error":
      return "回放中断";
    default:
      return "空闲";
  }
}

function filteredTasks(): TaskSummary[] {
  const query = state.taskQuery.trim().toLowerCase();
  return state.tasks.filter((task) => {
    if (state.taskState.length > 0 && task.state !== state.taskState) {
      return false;
    }
    if (query.length === 0) {
      return true;
    }
    return (
      task.taskId.toLowerCase().includes(query) ||
      task.state.toLowerCase().includes(query)
    );
  });
}

function renderBadge(status: string): HTMLSpanElement {
  return element("span", {
    className: `status-badge ${statusTone(status)}`,
    text: displayStatus(status),
  });
}

function renderNotice(): HTMLElement | null {
  if (state.notice === null) {
    return null;
  }
  const box = element("div", {
    className: `notice ${state.notice.tone}`,
    attrs: { role: "status", "aria-live": "polite" },
  });
  box.append(element("p", { text: state.notice.text }));
  return box;
}

function renderKeyValues(entries: Array<[string, string]>): HTMLDListElement {
  const list = element("dl", { className: "key-values" });
  for (const [key, value] of entries) {
    list.append(element("dt", { text: key }), element("dd", { text: value }));
  }
  return list;
}

function renderOverview(): DocumentFragment {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "运行总览" }),
    element("p", {
      text: "适配器健康、占用和评审状态与 MCP 读取同一份持久化投影。任务的批准、取消、重试和确认仍由 Codex 负责。",
    }),
  );
  heading.append(titles);
  fragment.append(heading);

  const occupancy = state.overview?.occupancy.global ?? 0;
  const cap = state.settings?.settings.concurrency.global ?? 3;
  const metrics = element("div", { className: "metric-grid" });
  const cards: Array<[string, string, string]> = [
    ["当前占用", String(occupancy), `全局限额 ${cap}`],
    ["可见任务", String(state.tasks.length), "最新在前，最多 100 条"],
    [
      "配置摘要",
      state.overview?.config.digest.slice(0, 12) || "不可用",
      "已持久化配置的指纹",
    ],
    [
      "改进回路",
      state.settings?.settings.improvement_enabled === true
        ? "已启用"
        : "已关闭",
      "本里程碑不做在线晋级",
    ],
  ];
  for (const [label, value, note] of cards) {
    const card = element("article", { className: "metric" });
    card.append(
      element("p", { className: "metric-label", text: label }),
      element("p", { className: "metric-value", text: value }),
      element("p", { className: "metric-note", text: note }),
    );
    metrics.append(card);
  }
  fragment.append(metrics);

  const grid = element("div", { className: "dashboard-grid" });
  const adapters = element("section", { className: "panel" });
  adapters.append(element("div", { className: "section-title" }));
  adapters.firstElementChild?.append(
    element("h2", { text: "适配器健康" }),
    element("small", {
      text: "有实时探测记录则显示；否则只看设置",
    }),
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
    element("h2", { text: "占用" }),
    element("small", { text: "调度器投影" }),
  );
  const occupancyList = element("div", { className: "occupancy-list" });
  const perAdapter = state.overview?.occupancy.perAdapter ?? {};
  const rows = [
    ["全局", occupancy, cap],
    ...ADAPTERS.map((name) => [
      name,
      perAdapter[name] ?? 0,
      state.settings?.settings.concurrency.per_adapter ?? 1,
    ]),
  ] as Array<[string, number, number]>;
  for (const [label, count, limit] of rows) {
    occupancyList.append(renderOccupancy(label, count, limit));
  }
  occupancyPanel.append(occupancyList);

  const digest = element("p", { className: "readonly-note" });
  digest.append(
    document.createTextNode("配置摘要 "),
    element("span", {
      className: "digest",
      text: state.overview?.config.digest || "未报告",
    }),
  );
  occupancyPanel.append(digest);

  grid.append(adapters, occupancyPanel);
  fragment.append(grid);

  const improvement = element("section", { className: "panel" });
  const title = element("div", { className: "section-title" });
  title.append(
    element("h2", { text: "改进审计" }),
    button("打开审计", "button-link", () => navigate({ view: "improvement" })),
  );
  improvement.append(
    title,
    element("p", {
      className: "readonly-note",
      text:
        state.settings?.settings.improvement_enabled === true
          ? "改进开关已打开，但还没有台账投影。案例会在具备投影后出现在这里。"
          : "改进回路已关闭。看板不会编造案例或晋级状态。",
    }),
  );
  fragment.append(improvement);
  return fragment;
}

function renderAdapterRow(
  display: ReturnType<typeof adapterDisplays>[number],
): HTMLElement {
  const row = element("div", { className: "adapter-row" });
  row.append(
    element("div", { className: "adapter-name", text: display.name }),
    element("div", { className: "adapter-meta", text: display.detail }),
    renderBadge(display.status),
  );
  return row;
}

function renderOccupancy(
  label: string,
  count: number,
  limit: number,
): HTMLElement {
  const row = element("div", { className: "occupancy-line" });
  const track = element("div", { className: "occupancy-track" });
  const fill = element("div", { className: "occupancy-fill" });
  const percent =
    limit <= 0 ? 0 : Math.min(100, Math.round((count / limit) * 100));
  fill.style.width = `${Math.max(percent, count > 0 ? 8 : 0)}%`;
  track.append(fill);
  row.append(
    element("div", { className: "occupancy-label", text: label }),
    track,
    element("div", { className: "occupancy-value", text: `${count}/${limit}` }),
  );
  return row;
}

function renderTasks(): DocumentFragment {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "任务" }),
    element("p", {
      text: "只读列表与回放。批准、取消、重试、合并和确认都是 MCP 操作。",
    }),
  );
  heading.append(titles);
  fragment.append(heading);

  const toolbar = element("div", { className: "task-toolbar" });
  const searchField = element("div", { className: "field field-search" });
  searchField.append(
    element("label", { text: "搜索", attrs: { for: "task-search" } }),
  );
  const search = element("input", {
    id: "task-search",
    attrs: {
      type: "search",
      value: state.taskQuery,
      placeholder: "任务 ID 或状态",
      autocomplete: "off",
    },
  });
  search.addEventListener("input", () => {
    state.taskQuery = search.value;
    queueRender();
  });
  searchField.append(search);

  const stateField = element("div", { className: "field field-state" });
  stateField.append(
    element("label", { text: "状态", attrs: { for: "task-state-filter" } }),
  );
  const select = element("select", { id: "task-state-filter" });
  const any = element("option", { text: "全部状态", attrs: { value: "" } });
  if (state.taskState === "") {
    any.selected = true;
  }
  select.append(any);
  for (const item of TASK_STATES) {
    const option = element("option", {
      text: displayStatus(item),
      attrs: { value: item },
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

function renderTaskTable(): HTMLElement {
  const wrap = element("div", { className: "task-table-wrap panel-plain" });
  const table = element("table", { className: "task-table" });
  const head = element("thead");
  const headRow = element("tr");
  for (const label of ["任务", "状态", "更新时间"]) {
    headRow.append(element("th", { text: label }));
  }
  head.append(headRow);
  const body = element("tbody");
  const tasks = filteredTasks();
  if (tasks.length === 0) {
    const empty = element("tr");
    const cell = element("td", {
      text: "没有符合筛选条件的持久化任务。",
      attrs: { colspan: "3" },
    });
    empty.append(cell);
    body.append(empty);
  } else {
    for (const task of tasks) {
      const selected =
        state.route.view === "tasks" && state.route.taskId === task.taskId;
      const row = element("tr", {
        className: selected ? "selected" : "",
        attrs: { tabindex: "0" },
      });
      const idCell = element("td");
      idCell.append(
        element("span", { className: "task-id", text: task.taskId }),
      );
      const stateCell = element("td", { className: "task-state-cell" });
      stateCell.append(renderBadge(task.state));
      row.append(
        idCell,
        stateCell,
        element("td", { text: formatTimestamp(task.updatedAtMs) }),
      );
      const open = (): void => navigate({ view: "tasks", taskId: task.taskId });
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

function renderTaskDetail(): HTMLElement {
  const panel = element("section", { className: "task-detail panel" });
  const selectedId = state.route.view === "tasks" ? state.route.taskId : null;
  if (selectedId === null) {
    const empty = element("div", { className: "empty-state" });
    empty.append(
      element("strong", { text: "请选择任务" }),
      document.createTextNode("时间线、输出和评审状态会显示在这里。"),
    );
    panel.append(empty);
    return panel;
  }
  if (state.detail === null || state.detail.task.taskId !== selectedId) {
    panel.append(
      element("div", {
        className: "loading-line",
        text: "正在加载持久化任务…",
      }),
    );
    return panel;
  }

  const detail = state.detail;
  const heading = element("div", { className: "detail-heading" });
  const titles = element("div");
  titles.append(
    element("h2", { text: detail.task.taskId }),
    element("p", {
      text: `世代 ${detail.task.generation} · 最后序号 ${detail.task.lastEventSeq}`,
    }),
  );
  heading.append(titles, renderBadge(detail.task.state));
  panel.append(heading);

  const cards = element("div", { className: "detail-grid" });
  const attempt = element("article", { className: "detail-card" });
  attempt.append(element("h3", { text: "尝试" }));
  attempt.append(
    renderKeyValues([
      ["尝试", detail.attempt?.attemptId ?? "无"],
      ["状态", detail.attempt ? displayStatus(detail.attempt.state) : "无"],
      ["适配器", detail.attempt?.adapterInstanceId ?? "未分配"],
    ]),
  );
  const interaction = element("article", { className: "detail-card" });
  interaction.append(element("h3", { text: "交互" }));
  interaction.append(
    renderKeyValues(
      detail.interaction === null
        ? [["状态", "无"]]
        : [
            ["标识", detail.interaction.interactionId],
            ["类型", detail.interaction.capabilityClass],
            ["状态", displayStatus(detail.interaction.status)],
            ["过期", formatTimestamp(detail.interaction.expiresAtMs)],
          ],
    ),
  );
  const review = element("article", { className: "detail-card" });
  review.append(element("h3", { text: "结果评审" }));
  const result = detail.terminalResult;
  review.append(
    renderKeyValues(
      result === null
        ? [["状态", "尚无终态结果"]]
        : [
            ["结果", result.resultId],
            ["状态", displayStatus(result.state)],
            ["版本", String(result.resultVersion)],
            ["确认", displayStatus(result.ackStatus)],
            [
              "结论",
              result.review ? displayStatus(result.review.verdict) : "未评审",
            ],
            ["诊断", result.review?.diagnosis ?? "无"],
          ],
    ),
  );
  cards.append(attempt, interaction, review);
  panel.append(cards);

  const output = eventOutput(detail.events);
  const outputPanel = element("section");
  outputPanel.append(
    element("div", { className: "section-title" }),
    element("pre", {
      className: "output-block",
      text: output.text.length > 0 ? output.text : "还没有文本增量事件。",
    }),
  );
  outputPanel.firstElementChild?.append(
    element("h3", { text: "输出" }),
    element("small", {
      text: output.truncated ? "已按看板上限截断" : "仅以纯文本渲染",
    }),
  );
  panel.append(outputPanel);

  const artifacts = artifactHints(detail.events);
  const artifactPanel = element("section", { className: "detail-card" });
  artifactPanel.append(element("h3", { text: "产物与工作树" }));
  if (artifacts.length === 0) {
    artifactPanel.append(
      element("p", {
        className: "readonly-note",
        text: "持久化事件里没有工作树或产物定位符。",
      }),
    );
  } else {
    artifactPanel.append(
      renderKeyValues(artifacts.map((hint) => [hint.kind, hint.value])),
    );
  }
  panel.append(artifactPanel);

  const timeline = element("ol", { className: "timeline" });
  for (const event of detail.events) {
    const item = element("li", {
      className: `timeline-item ${event.severity.toLowerCase()}`,
    });
    const copy = element("div", { className: "timeline-copy" });
    copy.append(
      document.createTextNode(eventSummary(event)),
      element("span", {
        className: "timeline-time",
        text: formatTimestamp(event.occurredAtMs),
      }),
    );
    item.append(
      element("div", { className: "timeline-seq", text: String(event.seq) }),
      element("div", {
        className: "timeline-type",
        text: displayEventType(event.eventType),
      }),
      copy,
    );
    timeline.append(item);
  }
  const timelineWrap = element("section");
  const timelineTitle = element("div", { className: "section-title" });
  timelineTitle.append(
    element("h3", { text: "时间线" }),
    element("small", { text: `${detail.events.length} 条持久化事件` }),
  );
  timelineWrap.append(timelineTitle, timeline);
  panel.append(timelineWrap);
  return panel;
}

function renderSettings(): DocumentFragment {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "安全设置" }),
    element("p", {
      text: "只能编辑经过模式校验的白名单项。凭证、安装身份和模型名不在这个界面上。",
    }),
  );
  heading.append(titles);
  fragment.append(heading);

  if (state.settings === null) {
    fragment.append(
      element("div", { className: "loading-line", text: "正在加载设置…" }),
    );
    return fragment;
  }

  const form = element("form", {
    className: "settings-form",
    attrs: { autocomplete: "off" },
  });
  const settings = state.settings.settings;
  const writesEnabled = state.settings.writesEnabled;

  form.append(adapterSection(settings));
  form.append(policySection(settings));
  form.append(retentionSection(settings));

  const footer = element("div", { className: "settings-footer" });
  const submit = element("button", {
    className: "button",
    text: writesEnabled ? "保存设置" : "写入已关闭",
    attrs: { type: "submit" },
  });
  submit.disabled = !writesEnabled;
  const status = element("p", {
    className: "settings-status",
    id: "settings-status",
    text: writesEnabled
      ? `配置版本 ${state.settings.configVersion}`
      : "设置写入功能闸已关闭。数值仍可查看。",
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

function adapterSection(settings: SafeSettings): HTMLElement {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "适配器与角色" }),
    element("p", {
      text: "只改角色绑定和 Luna 模型名。Claude / Grok / Kimi / Pi 走本地 CLI；Luna Max 走 Codex 子代理。不要为换人去改 AGENTS.md。",
    }),
  );
  const enabled = element("div", { className: "check-row" });
  for (const name of ADAPTERS) {
    enabled.append(
      labeledCheck(
        `enabled-${name}`,
        `启用 ${name}`,
        settings.enabled_adapters[name],
      ),
    );
  }
  section.append(enabled);

  const paths = element("div", { className: "settings-grid" });
  for (const name of ADAPTERS) {
    paths.append(
      labeledInput(
        `path-${name}`,
        `${name} 可执行文件`,
        settings.executable_paths[name] ?? "",
        "text",
      ),
    );
  }
  section.append(paths);

  const transports = element("div", { className: "settings-grid" });
  for (const name of ADAPTERS) {
    transports.append(
      labeledInput(
        `transport-${name}`,
        `${name} 传输`,
        settings.transport_priority[name].join(", "),
        "text",
      ),
    );
  }
  section.append(transports);

  const roles = element("div", { className: "settings-grid three" });
  roles.append(
    labeledSelect(
      "role-implementation",
      "实现",
      settings.role_bindings.implementation,
      BINDING_TARGETS,
      bindingLabel,
    ),
    labeledSelect(
      "role-research",
      "研究",
      settings.role_bindings.research,
      BINDING_TARGETS,
      bindingLabel,
    ),
    labeledSelect(
      "role-review",
      "评审（默认 Luna Max / Codex 子代理）",
      settings.role_bindings.review,
      BINDING_TARGETS,
      bindingLabel,
    ),
    labeledSelect(
      "role-freelancer",
      "自由职业（仅你点名）",
      settings.role_bindings.freelancer,
      BINDING_TARGETS,
      bindingLabel,
    ),
  );
  section.append(roles);
  section.append(
    labeledInput(
      "native-luna",
      "Luna Max 模型（Codex 子代理）",
      settings.native_models.luna,
      "text",
    ),
  );
  return section;
}

function policySection(settings: SafeSettings): HTMLElement {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "并发与策略" }),
    element("p", {
      text: "质量与推理力度必须落在已准入白名单内。不会填写模型名。",
    }),
  );
  const numbers = element("div", { className: "settings-grid" });
  numbers.append(
    labeledInput(
      "concurrency-global",
      "全局并发",
      String(settings.concurrency.global),
      "number",
    ),
    labeledInput(
      "concurrency-per-adapter",
      "每适配器并发",
      String(settings.concurrency.per_adapter),
      "number",
    ),
  );
  section.append(numbers);

  const quality = element("div", { className: "settings-grid" });
  quality.append(
    labeledSelect(
      "quality-default",
      "默认质量",
      settings.quality.default,
      QUALITY_OPTIONS,
      policyLabel,
    ),
  );
  const qualityAllowed = element("div", { className: "check-row" });
  for (const option of QUALITY_OPTIONS) {
    qualityAllowed.append(
      labeledCheck(
        `quality-${option}`,
        policyLabel(option),
        settings.quality.allowed.includes(option),
      ),
    );
  }
  quality.append(qualityAllowed);
  section.append(quality);

  const effort = element("div", { className: "settings-grid" });
  effort.append(
    labeledSelect(
      "effort-default",
      "默认力度",
      settings.effort.default,
      EFFORT_OPTIONS,
      policyLabel,
    ),
  );
  const effortAllowed = element("div", { className: "check-row" });
  for (const option of EFFORT_OPTIONS) {
    effortAllowed.append(
      labeledCheck(
        `effort-${option}`,
        policyLabel(option),
        settings.effort.allowed.includes(option),
      ),
    );
  }
  effort.append(effortAllowed);
  section.append(effort);

  const flags = element("div", { className: "check-row" });
  flags.append(
    labeledCheck(
      "review-chain",
      "启用评审链（走评审角色绑定）",
      settings.review_chain.enabled,
    ),
    labeledCheck(
      "improvement-enabled",
      "启用改进台账",
      settings.improvement_enabled,
    ),
  );
  if (typeof settings.allow_current_directory === "boolean") {
    flags.append(
      labeledCheck(
        "allow-current-directory",
        "允许当前目录逃生舱",
        settings.allow_current_directory,
      ),
    );
  }
  section.append(flags);
  return section;
}

function retentionSection(settings: SafeSettings): HTMLElement {
  const section = element("section", { className: "settings-section" });
  section.append(
    element("h2", { text: "保留策略" }),
    element("p", {
      text: "最早可垃圾回收的天数。未确认的结果永远不会进入回收。",
    }),
  );
  const grid = element("div", { className: "settings-grid three" });
  const fields: Array<[string, string, number]> = [
    [
      "retention-result",
      "已确认结果天数",
      settings.retention.acknowledged_result_days,
    ],
    [
      "retention-blob-terminal",
      "终态 blob 天数",
      settings.retention.acknowledged_blob_terminal_days,
    ],
    [
      "retention-blob-ack",
      "确认后 blob 天数",
      settings.retention.acknowledged_blob_post_ack_days,
    ],
    [
      "retention-worktree-success",
      "成功工作树天数",
      settings.retention.successful_worktree_post_ack_days,
    ],
    [
      "retention-worktree-fail",
      "失败工作树天数",
      settings.retention.non_success_worktree_terminal_days,
    ],
    ["retention-metrics", "指标天数", settings.retention.metrics_days],
  ];
  for (const [id, label, value] of fields) {
    grid.append(labeledInput(id, label, String(value), "number"));
  }
  section.append(grid);
  return section;
}

function labeledInput(
  id: string,
  label: string,
  value: string,
  type: string,
): HTMLElement {
  const field = element("div", { className: "field" });
  field.append(element("label", { text: label, attrs: { for: id } }));
  field.append(element("input", { id, attrs: { type, value, name: id } }));
  return field;
}

function bindingLabel(name: string): string {
  switch (name) {
    case "luna":
      return "Luna Max（Codex 子代理）";
    case "claude":
      return "Claude（本地 CLI）";
    case "grok":
      return "Grok（本地 CLI）";
    case "kimi":
      return "Kimi（本地 CLI）";
    case "pi":
      return "Pi（本地 CLI）";
    default:
      return name;
  }
}

function labeledSelect(
  id: string,
  label: string,
  value: string,
  options: readonly string[],
  display: (option: string) => string = (option) => option,
): HTMLElement {
  const field = element("div", { className: "field" });
  field.append(element("label", { text: label, attrs: { for: id } }));
  const select = element("select", { id, attrs: { name: id } });
  for (const option of options) {
    const node = element("option", {
      text: display(option),
      attrs: { value: option },
    });
    node.selected = option === value;
    select.append(node);
  }
  field.append(select);
  return field;
}

function labeledCheck(
  id: string,
  label: string,
  checked: boolean,
): HTMLLabelElement {
  const node = element("label", {
    className: "check-label",
    attrs: { for: id },
  });
  const input = element("input", {
    id,
    attrs: { type: "checkbox", name: id },
  });
  input.checked = checked;
  node.append(input, document.createTextNode(label));
  return node;
}

function inputValue(form: HTMLFormElement, id: string): string {
  const control = form.elements.namedItem(id);
  if (
    control instanceof HTMLInputElement ||
    control instanceof HTMLSelectElement
  ) {
    return control.value;
  }
  return "";
}

function inputChecked(form: HTMLFormElement, id: string): boolean {
  const control = form.elements.namedItem(id);
  return control instanceof HTMLInputElement && control.checked;
}

function settingsFromForm(
  form: HTMLFormElement,
  current: SafeSettings,
): SafeSettings {
  const raw: Record<string, unknown> = {
    enabled_adapters: {
      claude: inputChecked(form, "enabled-claude"),
      grok: inputChecked(form, "enabled-grok"),
      kimi: inputChecked(form, "enabled-kimi"),
      pi: inputChecked(form, "enabled-pi"),
    },
    executable_paths: {
      claude: inputValue(form, "path-claude"),
      grok: inputValue(form, "path-grok"),
      kimi: inputValue(form, "path-kimi"),
      pi: inputValue(form, "path-pi"),
    },
    transport_priority: {
      claude: inputValue(form, "transport-claude")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
      grok: inputValue(form, "transport-grok")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
      kimi: inputValue(form, "transport-kimi")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
      pi: inputValue(form, "transport-pi")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    },
    role_bindings: {
      implementation: inputValue(form, "role-implementation"),
      research: inputValue(form, "role-research"),
      review: inputValue(form, "role-review"),
      freelancer: inputValue(form, "role-freelancer"),
    },
    native_models: {
      luna: inputValue(form, "native-luna") || "gpt-5.6-luna",
    },
    concurrency: {
      global: Number(inputValue(form, "concurrency-global")),
      per_adapter: Number(inputValue(form, "concurrency-per-adapter")),
    },
    quality: {
      default: inputValue(form, "quality-default"),
      allowed: QUALITY_OPTIONS.filter((option) =>
        inputChecked(form, `quality-${option}`),
      ),
    },
    effort: {
      default: inputValue(form, "effort-default"),
      allowed: EFFORT_OPTIONS.filter((option) =>
        inputChecked(form, `effort-${option}`),
      ),
    },
    review_chain: {
      enabled: inputChecked(form, "review-chain"),
      reviewer: inputValue(form, "role-review") || "luna",
    },
    retention: {
      acknowledged_result_days: Number(inputValue(form, "retention-result")),
      acknowledged_blob_terminal_days: Number(
        inputValue(form, "retention-blob-terminal"),
      ),
      acknowledged_blob_post_ack_days: Number(
        inputValue(form, "retention-blob-ack"),
      ),
      successful_worktree_post_ack_days: Number(
        inputValue(form, "retention-worktree-success"),
      ),
      non_success_worktree_terminal_days: Number(
        inputValue(form, "retention-worktree-fail"),
      ),
      metrics_days: Number(inputValue(form, "retention-metrics")),
    },
    improvement_enabled: inputChecked(form, "improvement-enabled"),
  };
  if (typeof current.allow_current_directory === "boolean") {
    raw.allow_current_directory = inputChecked(form, "allow-current-directory");
  }
  return normalizeSettings(raw);
}

async function submitSettings(
  form: HTMLFormElement,
  status: HTMLElement,
): Promise<void> {
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
  status.textContent = "正在保存…";
  try {
    const result = parseSettingsWrite(
      await apiPut(
        "/api/v1/settings",
        {
          version: 1,
          kind: "config",
          config_version: state.settings.configVersion,
          settings: next,
        },
        csrfToken,
      ),
    );
    const parts = [
      result.hotReload.length > 0
        ? `可热加载：${result.hotReload.join("、")}`
        : "",
      result.restartRequired.length > 0
        ? `需要重启：${result.restartRequired.join("、")}`
        : "",
    ].filter((part) => part.length > 0);
    status.className = "settings-status success";
    status.textContent = parts.length > 0 ? parts.join(" · ") : "设置已保存。";
    await loadSettings();
  } catch (error) {
    const code =
      error instanceof Error ? error.message : "settings_unavailable";
    status.className = "settings-status error";
    status.textContent = describeError(code);
  }
}

function renderImprovement(): DocumentFragment {
  const fragment = document.createDocumentFragment();
  const heading = element("div", { className: "page-heading" });
  const titles = element("div");
  titles.append(
    element("h1", { text: "改进审计" }),
    element("p", {
      text: "案例、金丝雀和晋级仅供查看。台账投影尚未接入本界面。",
    }),
  );
  heading.append(titles);
  fragment.append(heading);
  const panel = element("section", { className: "panel" });
  const enabled = state.settings?.settings.improvement_enabled === true;
  panel.append(
    renderBadge(enabled ? "ENABLED" : "DISABLED"),
    element("p", {
      className: "readonly-note",
      text: enabled
        ? "改进开关已打开。还没有案例、候选或金丝雀行可投影。"
        : "改进回路已关闭。看板不会编造资格或晋级状态。",
    }),
  );
  fragment.append(panel);
  return fragment;
}

function renderNav(): void {
  const list = document.getElementById("primary-nav");
  if (!(list instanceof HTMLElement)) {
    return;
  }
  list.replaceChildren();
  const items: Array<[string, DashboardRoute]> = [
    ["总览", { view: "overview" }],
    [
      "任务",
      {
        view: "tasks",
        taskId: state.route.view === "tasks" ? state.route.taskId : null,
      },
    ],
    ["设置", { view: "settings" }],
  ];
  for (const [label, route] of items) {
    const item = element("li");
    const current =
      route.view === state.route.view ||
      (route.view === "tasks" && state.route.view === "tasks");
    const control = button(
      label,
      current ? "nav-button active" : "nav-button",
      () => navigate(route),
    );
    if (current) {
      control.setAttribute("aria-current", "page");
    }
    item.append(control);
    list.append(item);
  }
}

function renderConnection(): void {
  const label = document.getElementById("connection-label");
  const dot = document.getElementById("connection-dot");
  if (label !== null) {
    label.textContent = connectionLabel(state.connection);
  }
  if (dot !== null) {
    dot.className = `connection-dot ${state.connection === "connected" || state.connection === "complete" ? "connected" : state.connection === "error" || state.connection === "timeout" ? "error" : ""}`;
  }
}

function ensureShell(): HTMLElement | null {
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
    element("p", { className: "brand", text: "网格运维" }),
    element("p", {
      className: "brand-subtitle",
      text: "只读本地控制面",
    }),
  );
  const connection = element("div", {
    className: "connection-state",
    attrs: { role: "status", "aria-live": "polite" },
  });
  connection.append(
    element("span", { className: "connection-dot", id: "connection-dot" }),
    element("span", {
      id: "connection-label",
      text: connectionLabel(state.connection),
    }),
  );
  topbar.append(
    brand,
    element("div", { className: "topbar-spacer" }),
    connection,
    button("刷新", "button button-quiet", () => {
      void refresh();
    }),
  );

  const body = element("div", { className: "shell-body" });
  const nav = element("nav", {
    className: "side-nav",
    attrs: { "aria-label": "Dashboard" },
  });
  nav.append(
    element("p", { className: "nav-label", text: "导航" }),
    element("ul", { className: "nav-list", id: "primary-nav" }),
  );
  main = element("main", {
    className: "main-area",
    id: "main-content",
    attrs: { tabindex: "-1" },
  });
  body.append(nav, main);
  shell.append(topbar, body);
  root.replaceChildren(shell);
  return main;
}

function render(): void {
  const focused = document.activeElement;
  const focusedId = focused instanceof HTMLElement ? focused.id : "";
  const selectionStart =
    focused instanceof HTMLInputElement ||
    focused instanceof HTMLTextAreaElement
      ? focused.selectionStart
      : null;
  const selectionEnd =
    focused instanceof HTMLInputElement ||
    focused instanceof HTMLTextAreaElement
      ? focused.selectionEnd
      : null;
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
  if (
    state.loading &&
    state.overview === null &&
    state.tasks.length === 0 &&
    state.settings === null
  ) {
    content.append(
      element("div", {
        className: "loading-line",
        text: "正在加载持久化状态…",
      }),
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
    if (
      (restored instanceof HTMLInputElement ||
        restored instanceof HTMLTextAreaElement) &&
      selectionStart !== null &&
      selectionEnd !== null
    ) {
      restored.setSelectionRange(selectionStart, selectionEnd);
    }
  }
}

function onHashChange(): void {
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

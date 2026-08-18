/**
 * Local preview of the compiled dashboard. Serves the same asset paths as
 * the daemon and answers the read APIs with sample persisted-shaped JSON.
 * Not a production server: no session cookie, CSRF, or loopback guards.
 */
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const publicRoot = fileURLToPath(new URL("../public", import.meta.url));
const port = Number(process.env.MESH_DASHBOARD_PREVIEW_PORT ?? 43127);
const now = Date.now();

const tasks = [
  {
    task_id: "task-impl-042",
    state: "RUNNING",
    generation: 1,
    last_event_seq: 6,
    created_at_ms: now - 12 * 60_000,
    updated_at_ms: now - 8_000,
  },
  {
    task_id: "task-review-018",
    state: "SUCCEEDED",
    generation: 1,
    last_event_seq: 5,
    created_at_ms: now - 3_600_000,
    updated_at_ms: now - 40 * 60_000,
  },
  {
    task_id: "task-research-007",
    state: "NEEDS_ATTENTION",
    generation: 2,
    last_event_seq: 4,
    created_at_ms: now - 86_400_000,
    updated_at_ms: now - 2 * 3_600_000,
  },
];

const eventsByTask = {
  "task-impl-042": [
    event("task-impl-042", 1, "state_changed", { state: "RUNNING" }),
    event("task-impl-042", 2, "attempt_started", {
      attempt_id: "att-impl-1",
      ordinal: 1,
    }),
    event("task-impl-042", 3, "text_delta", {
      text: "正在实现环回看板视图。\n",
    }),
    event("task-impl-042", 4, "text_delta", {
      text: "时间线、输出和评审状态都是只读的。\n",
    }),
    event("task-impl-042", 5, "dispatch_phase", { phase: "PROVIDER_OBSERVED" }),
    event("task-impl-042", 6, "usage", {
      input_tokens: 812,
      output_tokens: 240,
    }),
  ],
  "task-review-018": [
    event("task-review-018", 1, "state_changed", { state: "SUCCEEDED" }),
    event("task-review-018", 2, "text_delta", {
      text: "评审完成。隔离是分离工作树，不是沙箱。\n",
    }),
    event("task-review-018", 3, "dispatch_phase", {
      phase: "worktree",
      worktree_id: "wt-review-018",
    }),
    event("task-review-018", 4, "terminal", { state: "SUCCEEDED" }),
  ],
  "task-research-007": [
    event("task-research-007", 1, "state_changed", {
      state: "NEEDS_ATTENTION",
    }),
    event("task-research-007", 2, "warning", {
      warning: "派发后的提供方效果不明确。",
    }),
    event("task-research-007", 3, "protocol_error", {
      code: "AMBIGUOUS_AFTER_DISPATCH",
      message: "不会自动重试。必须由 Codex 决定。",
    }),
    event("task-research-007", 4, "terminal", { state: "NEEDS_ATTENTION" }),
  ],
};

function event(taskId, seq, eventType, payload) {
  return {
    version: 1,
    kind: "event",
    event_id: `${taskId}-${seq}`,
    task_id: taskId,
    seq,
    occurred_at_ms: now - (10 - seq) * 30_000,
    severity: eventType === "protocol_error" ? "ERROR" : "INFO",
    event_type: eventType,
    payload,
  };
}

function taskDetail(taskId) {
  const summary = tasks.find((task) => task.task_id === taskId);
  if (!summary) {
    return null;
  }
  const events = eventsByTask[taskId] ?? [];
  const terminal =
    summary.state === "SUCCEEDED" || summary.state === "NEEDS_ATTENTION";
  return {
    kind: "dashboard_task_detail",
    task: {
      task_id: summary.task_id,
      state: summary.state,
      generation: summary.generation,
      last_event_seq: summary.last_event_seq,
      attempt_id: `att-${taskId}`,
    },
    attempt: {
      attempt_id: `att-${taskId}`,
      state: summary.state,
      generation: summary.generation,
      adapter_instance_id: summary.task_id.includes("review")
        ? "kimi"
        : summary.task_id.includes("research")
          ? "grok"
          : "claude",
    },
    interaction: summary.state === "RUNNING" ? null : null,
    events,
    next_seq: summary.last_event_seq,
    cursor: {
      oldest_available_seq: 1,
      last_committed_seq: summary.last_event_seq,
    },
    terminal_result: terminal
      ? {
          result_id: `res-${taskId}`,
          state: summary.state,
          result_version: 1,
          terminal_event_seq: summary.last_event_seq,
          ack_status: summary.state === "SUCCEEDED" ? "PENDING" : "PENDING",
          review:
            summary.state === "SUCCEEDED"
              ? {
                  verdict: "ACCEPT",
                  reviewed_at_ms: summary.updated_at_ms,
                  diagnosis: "看起来正确；确认仍由 Codex 完成。",
                }
              : null,
        }
      : null,
  };
}

const settings = {
  kind: "dashboard_settings",
  config_version: 1,
  csrf_token: "preview-csrf-not-a-secret",
  writes_enabled: false,
  settings: {
    enabled_adapters: { claude: true, grok: true, kimi: true, pi: false },
    executable_paths: { claude: null, grok: null, kimi: null, pi: null },
    transport_priority: {
      claude: ["native_json"],
      grok: ["acp"],
      kimi: ["acp"],
      pi: ["acp"],
    },
    role_bindings: {
      implementation: "claude",
      research: "grok",
      review: "luna",
      freelancer: "kimi",
    },
    native_models: { luna: "gpt-5.6-luna" },
    concurrency: { global: 3, per_adapter: 1 },
    quality: { default: "standard", allowed: ["standard"] },
    effort: { default: "medium", allowed: ["medium"] },
    review_chain: { enabled: false, reviewer: "luna" },
    retention: {
      acknowledged_result_days: 90,
      acknowledged_blob_terminal_days: 14,
      acknowledged_blob_post_ack_days: 7,
      successful_worktree_post_ack_days: 7,
      non_success_worktree_terminal_days: 30,
      metrics_days: 90,
    },
    improvement_enabled: false,
  },
};

const overview = {
  kind: "dashboard_overview",
  occupancy: { global: 1, per_adapter: { claude: 1, grok: 0, kimi: 0 } },
  config: {
    digest: "9f2c1a0bpreviewdigest0000000000000000000000000000000000000001",
    value: {
      agents: [
        {
          adapter: "claude",
          status: "DEGRADED",
          executable_version: "preview",
          transport: "native_json",
          degradation_reason: "预览样例；生产派发仍关闭",
        },
        {
          adapter: "grok",
          status: "CONFIGURED",
          executable_version: "1.0.4",
          transport: "acp",
        },
        {
          adapter: "kimi",
          status: "CONFIGURED",
          executable_version: "0.28.1",
          transport: "acp",
        },
      ],
    },
  },
};

const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  response.end(body);
}

async function serveAsset(response, name) {
  const allowed = {
    "dashboard.css": "dashboard.css",
    "dashboard.js": "dashboard.js",
    "index.html": "index.html",
  };
  const file = allowed[name];
  if (!file) {
    json(response, 404, { error: "asset_not_found" });
    return;
  }
  const bytes = await readFile(join(publicRoot, file));
  response.writeHead(200, {
    "content-type": mime[extname(file)] ?? "application/octet-stream",
    "cache-control": "no-store",
  });
  response.end(bytes);
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  try {
    if (
      request.method === "GET" &&
      (url.pathname === "/" || url.pathname === "/index.html")
    ) {
      await serveAsset(response, "index.html");
      return;
    }
    if (request.method === "GET" && url.pathname.startsWith("/assets/")) {
      await serveAsset(response, url.pathname.slice("/assets/".length));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/overview") {
      json(response, 200, overview);
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/tasks") {
      json(response, 200, { kind: "dashboard_tasks", tasks });
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/settings") {
      json(response, 200, settings);
      return;
    }
    const detail = /^\/api\/v1\/tasks\/([^/]+)$/.exec(url.pathname);
    if (request.method === "GET" && detail) {
      const body = taskDetail(decodeURIComponent(detail[1]));
      if (!body) {
        json(response, 404, { error: "task_not_found" });
        return;
      }
      json(response, 200, body);
      return;
    }
    const stream = /^\/api\/v1\/tasks\/([^/]+)\/events\/stream$/.exec(
      url.pathname,
    );
    if (request.method === "GET" && stream) {
      const taskId = decodeURIComponent(stream[1]);
      const after = Number(url.searchParams.get("after_seq") ?? "0");
      const body = taskDetail(taskId);
      if (!body) {
        json(response, 404, { error: "task_not_found" });
        return;
      }
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
      });
      for (const item of body.events.filter((entry) => entry.seq > after)) {
        response.write(
          `id: ${item.seq}\nevent: mesh_event\ndata: ${JSON.stringify(item)}\n\n`,
        );
      }
      response.write("event: mesh_complete\ndata: {}\n\n");
      response.end();
      return;
    }
    json(response, 404, { error: "not_found" });
  } catch (error) {
    json(response, 500, {
      error: error instanceof Error ? error.message : "preview_failed",
    });
  }
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(
    `dashboard preview: http://127.0.0.1:${port}/#/overview\n`,
  );
});

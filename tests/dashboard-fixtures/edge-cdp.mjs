import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, watchFile, unwatchFile } from "node:fs";
import { join } from "node:path";
import process from "node:process";

const timeoutMs = 75_000;
const deadline = Date.now() + timeoutMs;
const evidence = {
  status: "FAIL",
  hostile_output: "FAIL",
  console_overflow: "FAIL",
  token_leakage: "FAIL",
  cross_site: "FAIL",
  reason: null,
};

function fail(reason) {
  evidence.reason = reason;
  writeEvidence();
  process.exit(1);
}

function writeEvidence() {
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
}

function remaining() {
  return Math.max(250, deadline - Date.now());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    process.stdin.on("error", reject);
  });
}

function waitForPortFile(profileDir) {
  const path = join(profileDir, "DevToolsActivePort");
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      unwatchFile(path);
      reject(new Error("DevToolsActivePort was not published"));
    }, remaining());
    const check = () => {
      try {
        const text = readFileSync(path, "utf8").trim();
        const [portLine, target] = text.split(/\r?\n/);
        const port = Number(portLine);
        if (Number.isInteger(port) && port > 0) {
          clearTimeout(timer);
          unwatchFile(path);
          resolve({ port, target: target || "" });
        }
      } catch {
        // still waiting
      }
    };
    watchFile(path, { interval: 50 }, check);
    check();
  });
}

class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.exceptions = [];
    this.console = [];
    this.requests = [];
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id !== undefined && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) {
          reject(new Error(message.error.message || "cdp error"));
        } else {
          resolve(message.result);
        }
        return;
      }
      this.events.push(message);
      if (message.method === "Runtime.exceptionThrown") {
        this.exceptions.push(message.params);
      }
      if (
        message.method === "Runtime.consoleAPICalled" ||
        message.method === "Log.entryAdded"
      ) {
        this.console.push(message.params);
      }
      if (message.method === "Network.requestWillBeSent") {
        this.requests.push(message.params.request?.url || "");
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    this.socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`CDP timeout: ${method}`)),
        remaining(),
      );
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
  }

  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.text || "evaluate failed");
    }
    return result.result?.value;
  }
}

async function connectCdp(port) {
  const started = Date.now();
  let debuggerUrl = "";
  while (Date.now() - started < remaining()) {
    try {
      const list = await fetch(`http://127.0.0.1:${port}/json/list`);
      const pages = await list.json();
      const page = pages.find(
        (item) => item.type === "page" && item.webSocketDebuggerUrl,
      );
      if (page) {
        debuggerUrl = page.webSocketDebuggerUrl;
        break;
      }
    } catch {
      // debugger HTTP is not ready yet
    }
    await sleep(100);
  }
  if (debuggerUrl.length === 0) {
    throw new Error("no page CDP target");
  }
  const socket = new WebSocket(debuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener(
      "error",
      () => reject(new Error("cdp websocket failed")),
      {
        once: true,
      },
    );
  });
  return new Cdp(socket);
}

function startAttacker() {
  return new Promise((resolve) => {
    const server = createServer((request, response) => {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><title>attacker</title><p>attacker</p>");
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: server.address().port });
    });
  });
}

function killTree(pid) {
  if (!pid) {
    return;
  }
  try {
    execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
      stdio: "ignore",
    });
  } catch {
    // already gone
  }
}

async function waitFor(cdp, expression, label) {
  const started = Date.now();
  while (Date.now() - started < remaining()) {
    const value = await cdp.evaluate(expression);
    if (value) {
      return value;
    }
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const config = await readStdin();
const edgePath = config.edgePath;
const profileDir = config.profileDir;
const bootstrapUrl = config.bootstrapUrl;
const taskId = config.taskId;
const secretMarker = config.secretMarker;
if (!edgePath || !profileDir || !bootstrapUrl || !taskId || !secretMarker) {
  fail("driver config is incomplete");
}

const edge = spawn(
  edgePath,
  [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    `--user-data-dir=${profileDir}`,
    "--remote-debugging-port=0",
    "about:blank",
  ],
  { windowsHide: true, stdio: "ignore" },
);

let attacker;
try {
  const { port } = await waitForPortFile(profileDir);
  const cdp = await connectCdp(port);
  await cdp.send("Runtime.enable");
  await cdp.send("Log.enable");
  await cdp.send("Page.enable");
  await cdp.send("Network.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: 1280,
    height: 720,
    deviceScaleFactor: 1,
    mobile: false,
  });

  await cdp.send("Page.navigate", { url: bootstrapUrl });
  await waitFor(
    cdp,
    "document.querySelector('.dashboard-shell') !== null",
    "dashboard shell",
  );
  const afterBootstrap = await cdp.evaluate(`({
    href: location.href,
    cookie: document.cookie,
    hasBootstrap: location.href.includes('token='),
    storage: Object.keys(localStorage).length + Object.keys(sessionStorage).length
  })`);
  if (afterBootstrap.hasBootstrap) {
    fail("bootstrap token remained visible after redirect");
  }
  if (
    typeof afterBootstrap.cookie === "string" &&
    afterBootstrap.cookie.includes("mesh_dashboard_session")
  ) {
    fail("session cookie is visible to document.cookie");
  }

  await cdp.send("Page.navigate", {
    url: `http://127.0.0.1:${new URL(bootstrapUrl).port}/#/tasks/${taskId}`,
  });
  await waitFor(
    cdp,
    "document.querySelector('.output-block') !== null",
    "task output",
  );
  await sleep(250);

  const csrfToken = await cdp.evaluate(
    "fetch('/api/v1/settings', { credentials: 'include' }).then((response) => response.json()).then((body) => body.csrf_token || '')",
  );

  const rendered = await cdp.evaluate(`(() => {
    const output = document.querySelector('.output-block');
    const markupNodes = output
      ? output.querySelectorAll('script, img, svg, iframe, a[href^="javascript"]')
      : [];
    return {
      outputText: output ? output.textContent : '',
      html: document.documentElement.textContent,
      hostileNodes: markupNodes.length,
      xss: window.__mesh_xss ?? null,
      overflow: document.scrollingElement.scrollWidth <= document.scrollingElement.clientWidth,
      cookie: document.cookie,
      href: location.href,
      storage: JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
    };
  })()`);

  const hasMarkupAsText =
    rendered.outputText.includes("<img") &&
    rendered.outputText.includes("javascript:");
  const secretAbsent =
    !rendered.html.includes(secretMarker) &&
    !rendered.outputText.includes(secretMarker);
  const redactedPresent = rendered.outputText.includes("[redacted]");
  const csrfLeaked =
    typeof csrfToken === "string" &&
    csrfToken.length > 0 &&
    [
      rendered.html,
      rendered.outputText,
      rendered.href,
      rendered.storage,
      JSON.stringify(cdp.console),
      JSON.stringify(cdp.requests),
    ].some((value) => value.includes(csrfToken));
  if (
    hasMarkupAsText &&
    rendered.hostileNodes === 0 &&
    rendered.xss === null &&
    secretAbsent &&
    redactedPresent &&
    !csrfLeaked
  ) {
    evidence.hostile_output = "PASS";
  } else {
    evidence.reason = JSON.stringify({
      message:
        "hostile output did not stay text-only or leaked the secret marker",
      outputLength: rendered.outputText.length,
      hasMarkupAsText,
      hostileNodes: rendered.hostileNodes,
      xss: rendered.xss,
      secretAbsent,
      redactedPresent,
      csrfLeaked,
      href: rendered.href,
    });
  }

  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: 375,
    height: 667,
    deviceScaleFactor: 2,
    mobile: true,
  });
  await sleep(200);
  const mobileOverflow = await cdp.evaluate(
    "document.scrollingElement.scrollWidth <= document.scrollingElement.clientWidth + 1",
  );
  const cspViolations = cdp.console.some((entry) => {
    const text = JSON.stringify(entry);
    return (
      text.toLowerCase().includes("csp") ||
      text.toLowerCase().includes("security")
    );
  });
  if (
    rendered.overflow &&
    mobileOverflow &&
    cdp.exceptions.length === 0 &&
    !cspViolations
  ) {
    evidence.console_overflow = "PASS";
  }

  const leaked =
    JSON.stringify(cdp.console).includes(secretMarker) ||
    JSON.stringify(cdp.requests).includes(secretMarker) ||
    rendered.cookie.includes("mesh_dashboard_session") ||
    rendered.href.includes("token=");
  if (!leaked && secretAbsent) {
    evidence.token_leakage = "PASS";
  }

  attacker = await startAttacker();
  const dashboardOrigin = `http://127.0.0.1:${new URL(bootstrapUrl).port}`;
  await cdp.send("Page.navigate", {
    url: `http://127.0.0.1:${attacker.port}/`,
  });
  await waitFor(cdp, "document.title === 'attacker'", "attacker page");
  const cross = await cdp.evaluate(`(async () => {
    const target = ${JSON.stringify(dashboardOrigin)};
    const result = { getStatus: null, putStatus: null, cors: null, error: null };
    try {
      const get = await fetch(target + '/api/v1/overview', { credentials: 'include' });
      result.getStatus = get.status;
      result.cors = get.headers.get('access-control-allow-origin');
    } catch (error) {
      result.error = 'get_blocked';
    }
    try {
      const put = await fetch(target + '/api/v1/settings', {
        method: 'PUT',
        credentials: 'include',
        headers: { 'content-type': 'application/json', 'x-csrf-token': 'forged' },
        body: JSON.stringify({ version: 1, kind: 'config', config_version: 1, settings: {} })
      });
      result.putStatus = put.status;
    } catch {
      result.putStatus = 'blocked';
    }
    return result;
  })()`);
  const rejected =
    (cross.getStatus === 403 || cross.error === "get_blocked") &&
    (cross.putStatus === 403 || cross.putStatus === "blocked") &&
    cross.cors !== "*";
  if (rejected) {
    evidence.cross_site = "PASS";
  }

  if (
    evidence.hostile_output === "PASS" &&
    evidence.console_overflow === "PASS" &&
    evidence.token_leakage === "PASS" &&
    evidence.cross_site === "PASS"
  ) {
    evidence.status = "PASS";
    evidence.reason = null;
    writeEvidence();
    process.exit(0);
  }
  if (!evidence.reason) {
    evidence.reason = "one or more browser cases failed";
  }
  writeEvidence();
  process.exit(1);
} catch (error) {
  fail(error instanceof Error ? error.message : "edge driver failed");
} finally {
  if (attacker?.server) {
    attacker.server.close();
  }
  killTree(edge.pid);
}

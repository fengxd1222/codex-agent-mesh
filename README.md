# Codex Agent Mesh

Codex Agent Mesh is a Windows-first local delegation control plane for Codex.
It will provide durable, observable hand-offs to locally installed external
agents while Codex remains the planner and reviewer.

Milestones 1 and 2 now provide the strict shared protocol and durable daemon
core. The Windows Milestone 3 implementation also includes the audited native
boundary, protected LocalAppData install slot, owned on-demand Scheduled Task,
authenticated named pipe, native cache-to-stable trampoline, and the eight-tool
STDIO MCP bridge. Removal retains data and installation identity by default.

Milestone 4 scheduler occupancy, detached Git worktrees, and process ownership
are implemented behind an explicit supervisor API: suspended create, Job Object
assignment, generation-bound receipt, then resume. A test-only
`mesh-fake-adapter` process covers execute, crash, hang, cancel, and tree-kill.
One-shot approvals and the disabled-by-default current-directory escape hatch
are implemented. The fake-adapter crash-matrix / evidence-based retry proof
covers only `SAFE_PRE_DISPATCH` / `SAFE_PROVEN_NO_EFFECT` automatic retry.
Production daemon dispatch launches a settings-enabled local Claude, Grok, or Kimi CLI through the supervisor and persists live events for the dashboard and `wait_task`. Role bindings are live settings (`implementation`/`research`/`review`/`freelancer`). GPT bind targets such as Luna Max are Codex-native: Codex creates a subagent and mesh never probes or spawns a CLI.

This is still a development checkpoint, not an end-to-end provider release.
Claude, Grok, and Kimi have offline adapter fixtures for tests. Production
admission uses the installed executable, a parsed version for identification
and audit, the current help/transport surface, and settings enablement.
Fixture `proven_version` is not a runtime pin. Unsupported transport or
capability surfaces stay unadmitted, including Grok/Kimi cancellation until a
cancel round-trip is proven.
Production `list_agents` reports the live probe. A role is usable only when that record is `ENABLED`.
The privileged pipe matrix, true standard-user Scheduled Task/Job fixture,
100-client singleton fixture, process-boundary reconnect matrix, and clean-
profile remove/purge journey remain release gates. The project guarantees
tested process-crash and I/O recovery boundaries; it makes no sudden-power-loss
durability claim.

The complete product roadmap is M0–M8; project-local planning notes are kept
outside the published source tree. M4 fake-adapter crash/retry proof and the M5
adapter cuts are implemented;
production dispatch is wired through the settings-backed registry. M6 covers the production dashboard and
configuration projection, M7 the guarded improvement ledger, and M8 the
clean-profile release/AC-00 gate.

## Development baseline

Requires Windows x64, PowerShell 7 (`pwsh`), Node.js 22+, and Rust 1.96+
with the MSVC toolchain and Windows SDK. Fresh clones do not contain build
output: run `npm ci`, then package the plugin before installing it.

```powershell
npm ci
npm run format:check
npm run lint
npm run typecheck
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run package:verify
npm run tracked:verify
```

The source plugin is at `plugins/codex-agent-mesh`. Packaging produces an exact,
checksummed Windows x64 bundle, but the bundle is not yet an end-to-end external
agent release. Setup is always explicit: from an installed development bundle,
run:

```powershell
$releaseExe = "release\codex-agent-mesh\bin\windows-x64\mesh-daemon.exe"
& $releaseExe setup --install-slot stable
& $releaseExe status --install-slot stable
```

The MCP bridge never installs or trusts the cache copy implicitly. Before setup
it reports a bounded setup-state diagnostic; after setup it trampolines to and
authenticates the exact retained runtime. Do not submit delegation work unless
`list_agents` reports a matching enabled adapter.

The MCP manifest deliberately uses `"cwd": "."`; Codex resolves that relative
working directory against the installed plugin root. Path handling with spaces,
Unicode, and a different caller working directory has deterministic and partial
live coverage, but the final clean-profile install fixture remains a release
gate.

Release/package inputs are constrained by `config/tracked-paths.txt` and
`config/plugin-package-paths.txt`; use explicit paths when staging and never
stage generated runtime state or unrelated platform directories. The tracked
allowlist verifier checks both the Git index and the untracked product sources.

## Installation and setup

On a new machine: clone this repo, run `npm ci`, package the plugin, then ask
Codex to install and configure using
`plugins/codex-agent-mesh/skills/codex-agent-mesh/references/install-and-configure.md`.
Role defaults live in `crates/mesh-daemon/src/settings/default-config.toml`.
Per-machine data under `%LOCALAPPDATA%\codex-agent-mesh` is created by
`setup` and must not be committed. Role changes stay in mesh settings,
not `AGENTS.md`.

This plugin targets Windows x64. Fresh clones must install dependencies and
package a local bundle before any personal-marketplace install. `release/` is
generated and ignored; it is never published with the source.

```powershell
npm ci
python $env:USERPROFILE/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py plugins/codex-agent-mesh
pwsh -NoProfile -File scripts/package-plugin.ps1
```

The resulting bundle is staged at `release/codex-agent-mesh`. Its MCP manifest
uses the fixed relative working directory `.` so Codex starts the bridge from
the installed plugin root, even when Codex starts elsewhere. Setup remains
explicit:

```powershell
$releaseExe = "release\codex-agent-mesh\bin\windows-x64\mesh-daemon.exe"
& $releaseExe setup --install-slot stable
& $releaseExe status --install-slot stable
```

Setup-state errors are bounded diagnostics. Never repair them by bypassing the
bridge or modifying cache files.

No marketplace manifest is committed: repository-level local-platform dot
directories are intentionally excluded from published source. After packaging, create the
local `.agents/plugins/marketplace.json` and register this clone using the safe
sequence in the installation reference. Keep that local manifest, credentials,
runtime data, logs, and provider state out of Git.

## Adapter support and routing

`list_agents` is the runtime source of truth. A role is usable only when its
specific executable/version/transport probe and admitted capability record are
enabled. A changed or unsupported version is unavailable.

| Role                 | Default adapter | Dispatch rule                                                    |
| -------------------- | --------------- | ---------------------------------------------------------------- |
| Implementation       | Claude          | Rebind in settings only (`role_bindings`). CLI or `luna`.        |
| Research             | Grok            | Rebind in settings only.                                         |
| Review               | Luna Max        | Settings `review` + `native_models.luna`. Do not edit AGENTS.md. |
| Freelancer           | Kimi            | Only when the user explicitly names this role; never inferred.   |
| Unsupported provider | None            | Do not delegate or fall back across roles.                       |

Call `list_agents` before `delegate_task`; pass a bounded objective, desired
role, repository/isolation requirements, and one fresh `command_key`. Retain
that key for uncertain mutation retries, save the returned `task_id`, and never
create a replacement key to guess whether work happened. Use `inspect_task` and
`wait_task` with explicit event cursors. After reconnect, inspect the same task
and resume from the last persisted cursor.

Approval/input requests are durable and one-shot: answer only with the exact
generation, nonce, and digest returned by `send_task_input`. For a terminal
result, inspect the evidence before `review_task`, then ACK only its matching
`result_id`, `result_version`, and `ack_token`. `NEEDS_ATTENTION`, expired
cursors, uncertain dispatch, and unavailable adapters require an explicit human
decision rather than automatic retry or provider substitution.

Write work uses a detached mesh-owned worktree at the requested base commit. It
is never automatically merged, rebased, or cherry-picked. The current-directory
escape hatch is disabled by default and requires both a safe configuration opt-in
and explicit approval.

## Dashboard, configuration, and improvement

When the dashboard capability is enabled, the local loopback dashboard renders
the same durable task evidence as MCP. Its bootstrap URL is single-use and
short-lived: open it only locally and do not share it. Dashboard startup
failure disables only that browser capability; MCP task operations remain
available and the failure is reported as a bounded diagnostic. Task routes are
read-only. Settings writes are separately gated,
schema-validated, allowlisted, atomically written, and secret-free on export;
disabled settings or improvement controls remain unavailable rather than being
simulated. Portable import never replaces the retained install identity.

Improvement candidates are immutable, evidence-bearing, single-knob diffs in a
safety allowlist. They need deterministic offline fixtures before a canary;
promotion requires the documented time/task/safety thresholds. Rollback is
atomic, and two rollbacks freeze that component for manual review. No
improvement workflow edits executable code or silently changes prompts.

## Data, retention, security, and removal

Runtime data lives at `%LOCALAPPDATA%\codex-agent-mesh`. The dashboard binds to
loopback with one-time bootstrap exchange, session/CSRF controls, bounded output,
and redaction. The named-pipe bridge authenticates the retained runtime rather
than trusting a plugin-cache peer. Unacknowledged results and rendering blobs
are never GC-eligible; acknowledged result/outbox/review/event data remains at
least 90 days after terminal/ACK conditions. Result/event blobs remain through
the later of 14 days after terminal or 7 days after ACK. Successful worktrees
become eligible after ACK plus 7 days; failed, cancelled, and `NEEDS_ATTENTION`
worktrees remain at least 30 days. Install tombstones persist until explicit
purge.

Remove the owned task and executable while retaining data and identity:

```powershell
bin\windows-x64\mesh-daemon.exe remove --install-slot stable
```

Delete retained data only as a separate deliberate action:

```powershell
bin\windows-x64\mesh-daemon.exe remove --purge-data --install-slot stable
```

Purge removes identity last; later setup creates a new identity. Drift or
partial removal retains the install record and binaries for recovery.

## Package trust and troubleshooting

`SHA256SUMS` covers every artifact file except itself. `SBOM.cdx.json` is a
deterministic CycloneDX 1.5 inventory of the payload, and the exact allowlist
rejects extras such as runtime state or dependency trees. Verify a staged bundle:

```powershell
pwsh -NoProfile -File scripts/verify-plugin-artifact.ps1 -ArtifactRoot release/codex-agent-mesh
```

An official artifact requires an explicitly supplied signed runtime and the
pinned `CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256`. Without release credentials,
packaging emits `development-unsigned`: local development only, never an
official release. Clean-profile install, the three-role AC-00 journey,
dashboard bootstrap, reconnect, purge, and final AC-16 evidence remain required
before making an official availability claim.
